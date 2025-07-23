package main

import (
	"context"
	"fmt"
	"log/slog"
)

// PluginIntegration provides integration between the plugin system and container runtime
type PluginIntegration struct {
	pluginManager *PluginManager
	eventBus      *PluginEventBus
	logger        *slog.Logger
}

// NewPluginIntegration creates a new plugin integration
func NewPluginIntegration(ctx context.Context, pm *PluginManager) *PluginIntegration {
	return &PluginIntegration{
		pluginManager: pm,
		eventBus:      pm.eventBus,
		logger:        Logger(ctx).With("component", "plugin-integration"),
	}
}

// IntegrateWithContainer integrates plugins with the container lifecycle
func (pi *PluginIntegration) IntegrateWithContainer(container *Container) error {
	if container == nil {
		return fmt.Errorf("container cannot be nil")
	}
	
	pi.logger.Info("Integrating plugins with container", "container", container.Config.Runtime.Name)
	
	// Subscribe storage plugins to storage events
	storagePlugins := pi.pluginManager.ListPluginsByType(PluginTypeStorage)
	for _, plugin := range storagePlugins {
		if handler, ok := plugin.plugin.(PluginEventHandler); ok {
			if err := pi.eventBus.Subscribe(plugin.Info.Name, handler, 20); err != nil {
				pi.logger.Warn("Failed to subscribe storage plugin to events", 
					"plugin", plugin.Info.Name, "error", err)
			}
		}
	}
	
	// Subscribe network plugins to network events
	networkPlugins := pi.pluginManager.ListPluginsByType(PluginTypeNetwork)
	for _, plugin := range networkPlugins {
		if handler, ok := plugin.plugin.(PluginEventHandler); ok {
			if err := pi.eventBus.Subscribe(plugin.Info.Name, handler, 30); err != nil {
				pi.logger.Warn("Failed to subscribe network plugin to events", 
					"plugin", plugin.Info.Name, "error", err)
			}
		}
	}
	
	// Subscribe monitoring plugins to all container events
	monitoringPlugins := pi.pluginManager.ListPluginsByType(PluginTypeMonitoring)
	for _, plugin := range monitoringPlugins {
		if handler, ok := plugin.plugin.(PluginEventHandler); ok {
			if err := pi.eventBus.Subscribe(plugin.Info.Name, handler, 50); err != nil {
				pi.logger.Warn("Failed to subscribe monitoring plugin to events", 
					"plugin", plugin.Info.Name, "error", err)
			}
		}
	}
	
	return nil
}

// EmitContainerEvent emits container lifecycle events to plugins
func (pi *PluginIntegration) EmitContainerEvent(eventType PluginEventType, containerName string, data map[string]interface{}) {
	event := NewContainerEvent(eventType, containerName, data)
	pi.eventBus.Emit(event)
	pi.logger.Debug("Emitted container event", "type", eventType, "container", containerName)
}

// EmitStorageEvent emits storage events to plugins
func (pi *PluginIntegration) EmitStorageEvent(eventType PluginEventType, containerName, mountPath string, data map[string]interface{}) {
	event := NewStorageEvent(eventType, containerName, mountPath, data)
	pi.eventBus.Emit(event)
	pi.logger.Debug("Emitted storage event", "type", eventType, "container", containerName, "mount", mountPath)
}

// EmitNetworkEvent emits network events to plugins
func (pi *PluginIntegration) EmitNetworkEvent(eventType PluginEventType, containerName, networkName string, data map[string]interface{}) {
	event := NewNetworkEvent(eventType, containerName, networkName, data)
	pi.eventBus.Emit(event)
	pi.logger.Debug("Emitted network event", "type", eventType, "container", containerName, "network", networkName)
}

// GetStoragePlugins returns available storage plugins
func (pi *PluginIntegration) GetStoragePlugins() []*PluginInstance {
	return pi.pluginManager.ListPluginsByType(PluginTypeStorage)
}

// GetNetworkPlugins returns available network plugins  
func (pi *PluginIntegration) GetNetworkPlugins() []*PluginInstance {
	return pi.pluginManager.ListPluginsByType(PluginTypeNetwork)
}

// GetMonitoringPlugins returns available monitoring plugins
func (pi *PluginIntegration) GetMonitoringPlugins() []*PluginInstance {
	return pi.pluginManager.ListPluginsByType(PluginTypeMonitoring)
}

// Add plugin integration to the existing Container struct
func (c *Container) integratePlugins(ctx context.Context, pluginIntegration *PluginIntegration) error {
	if pluginIntegration == nil {
		return nil // No plugin integration configured
	}
	
	// Integrate plugins with this container
	if err := pluginIntegration.IntegrateWithContainer(c); err != nil {
		return fmt.Errorf("failed to integrate plugins: %w", err)
	}
	
	// Store plugin integration reference
	c.pluginIntegration = pluginIntegration
	
	return nil
}

// Add plugin integration field to Container (this would be added to existing Container struct)
type ContainerWithPlugins struct {
	*Container
	pluginIntegration *PluginIntegration
}

// Enhanced container setup with plugin events
func (c *Container) setupWithPlugins(ctx context.Context, pid int) error {
	// Emit container created event
	if c.pluginIntegration != nil {
		c.pluginIntegration.EmitContainerEvent(ContainerEventCreated, c.Config.Runtime.Name, map[string]interface{}{
			"pid": pid,
			"config": c.Config,
		})
	}
	
	// Original setup code would go here
	// For demonstration, we'll call the existing setup methods
	
	// Setup cgroups with plugin events
	if err := c.setupCgroupWithPlugins(ctx, pid); err != nil {
		return err
	}
	
	// Setup network with plugin events
	if err := c.setupNetworkWithPlugins(ctx, pid); err != nil {
		return err
	}
	
	return nil
}

// Enhanced cgroup setup with plugin events
func (c *Container) setupCgroupWithPlugins(ctx context.Context, pid int) error {
	// Call original setup
	if err := c.setupCgroup(ctx, pid); err != nil {
		return err
	}
	
	// Emit events for plugins
	if c.pluginIntegration != nil {
		c.pluginIntegration.EmitContainerEvent(ContainerEventStarting, c.Config.Runtime.Name, map[string]interface{}{
			"pid": pid,
			"cgroup_name": c.Config.Cgroup.Name,
			"memory_limit": c.Config.Cgroup.MemoryLimit,
			"cpu_limit": c.Config.Cgroup.CPULimit,
		})
	}
	
	return nil
}

// Enhanced network setup with plugin events
func (c *Container) setupNetworkWithPlugins(ctx context.Context, pid int) error {
	// Emit pre-setup event
	if c.pluginIntegration != nil {
		c.pluginIntegration.EmitNetworkEvent(NetworkEventSetup, c.Config.Runtime.Name, c.Config.Network.BridgeName, map[string]interface{}{
			"pid": pid,
			"bridge_name": c.Config.Network.BridgeName,
			"network_cidr": c.Config.Network.NetworkCIDR,
		})
	}
	
	// Call original setup
	if err := c.setupNetwork(ctx, pid); err != nil {
		return err
	}
	
	// No post-setup event needed as it's handled in the original setupNetwork
	return nil
}

// Enhanced storage setup with plugin events
func (c *Container) prepareRootfsWithPlugins(ctx context.Context, storage *StorageConfig, containerName string) (string, bool, error) {
	// Emit pre-mount event
	if c.pluginIntegration != nil {
		c.pluginIntegration.EmitStorageEvent(StorageEventMounting, containerName, storage.RootFSSource, map[string]interface{}{
			"source": storage.RootFSSource,
			"driver": storage.Driver,
		})
	}
	
	// Call original preparation (this would be the existing prepareRootfs function)
	rootfsPath, isTemp, err := prepareRootfs(ctx, storage, containerName)
	if err != nil {
		return "", false, err
	}
	
	// Emit post-mount event
	if c.pluginIntegration != nil {
		c.pluginIntegration.EmitStorageEvent(StorageEventMounted, containerName, rootfsPath, map[string]interface{}{
			"source": storage.RootFSSource,
			"target": rootfsPath,
			"temporary": isTemp,
		})
	}
	
	return rootfsPath, isTemp, nil
}

// Enhanced container lifecycle methods with plugin events
func (c *Container) startWithPlugins(ctx context.Context) error {
	// Emit starting event
	if c.pluginIntegration != nil {
		c.pluginIntegration.EmitContainerEvent(ContainerEventStarting, c.Config.Runtime.Name, map[string]interface{}{
			"config": c.Config,
		})
	}
	
	// Start container (original logic would go here)
	c.setState(StateRunning)
	
	// Emit started event  
	if c.pluginIntegration != nil {
		c.pluginIntegration.EmitContainerEvent(ContainerEventStarted, c.Config.Runtime.Name, map[string]interface{}{
			"pid": c.Process.Process.Pid,
			"state": c.state.String(),
		})
	}
	
	return nil
}

func (c *Container) stopWithPlugins(ctx context.Context) error {
	// Emit stopping event
	if c.pluginIntegration != nil {
		c.pluginIntegration.EmitContainerEvent(ContainerEventStopping, c.Config.Runtime.Name, map[string]interface{}{
			"state": c.state.String(),
		})
	}
	
	// Stop container (original logic would go here)
	c.setState(StateStopped)
	
	// Emit stopped event
	if c.pluginIntegration != nil {
		c.pluginIntegration.EmitContainerEvent(ContainerEventStopped, c.Config.Runtime.Name, map[string]interface{}{
			"final_state": c.state.String(),
		})
	}
	
	return nil
}

// Initialize plugin system in dependency injection
func InitializePluginSystem(ctx context.Context) error {
	logger := Logger(ctx).With("component", "plugin-init")
	
	// Create plugin manager configuration
	config := &PluginManagerConfig{
		PluginDirs:      []string{"/usr/local/lib/gophertainer/plugins", "/etc/gophertainer/plugins"},
		ConfigDir:       "/etc/gophertainer/plugin-config",
		EnableSecurity:  true,
		LoadTimeout:     30000, // 30 seconds in milliseconds 
		StartTimeout:    30000, // 30 seconds in milliseconds
		AllowedTypes:    []PluginType{PluginTypeStorage, PluginTypeNetwork, PluginTypeMonitoring, PluginTypeRuntime, PluginTypeSecurity},
		DisabledPlugins: []string{},
		PluginConfig:    make(map[string]map[string]interface{}),
	}
	
	// Create plugin manager
	pluginManager, err := NewPluginManager(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to create plugin manager: %w", err)
	}
	
	// Discover available plugins
	if err := pluginManager.DiscoverPlugins(ctx); err != nil {
		logger.Warn("Plugin discovery failed", "error", err)
	}
	
	// Create plugin integration
	pluginIntegration := NewPluginIntegration(ctx, pluginManager)
	
	// Store in dependency container (assuming we extend the existing DI system)
	deps := GetDeps()
	deps.PluginManager = pluginManager
	deps.PluginIntegration = pluginIntegration
	
	logger.Info("Plugin system initialized successfully")
	return nil
}

// Extend existing Dependencies struct to include plugin system
type ExtendedDependencies struct {
	*Dependencies
	PluginManager     *PluginManager
	PluginIntegration *PluginIntegration
}

// Enhanced container preparation with plugin support
func prepareContainerWithPlugins(ctx context.Context, cfg *Config) (*Container, error) {
	// Create container as usual
	container, err := prepareContainer(ctx, cfg)
	if err != nil {
		return nil, err
	}
	
	// Get plugin integration from dependencies
	deps := GetDeps()
	if extDeps, ok := deps.(*ExtendedDependencies); ok && extDeps.PluginIntegration != nil {
		// Integrate plugins with container
		if err := container.integratePlugins(ctx, extDeps.PluginIntegration); err != nil {
			Logger(ctx).Warn("Failed to integrate plugins with container", "error", err)
			// Don't fail container creation if plugin integration fails
		}
	}
	
	return container, nil
}

// Plugin-aware container cleanup
func (c *Container) cleanupWithPlugins(ctx context.Context) {
	// Emit cleanup events before cleanup
	if c.pluginIntegration != nil {
		// Emit storage unmounting events
		c.pluginIntegration.EmitStorageEvent(StorageEventUnmounting, c.Config.Runtime.Name, c.Config.Storage.RootFSSource, nil)
		
		// Emit network teardown events
		c.pluginIntegration.EmitNetworkEvent(NetworkEventTeardown, c.Config.Runtime.Name, c.Config.Network.BridgeName, nil)
		
		// Emit container deletion event
		c.pluginIntegration.EmitContainerEvent(ContainerEventDeleted, c.Config.Runtime.Name, map[string]interface{}{
			"final_state": c.state.String(),
		})
	}
	
	// Call original cleanup
	c.cleanup(ctx)
	
	// Emit post-cleanup events
	if c.pluginIntegration != nil {
		c.pluginIntegration.EmitStorageEvent(StorageEventUnmounted, c.Config.Runtime.Name, c.Config.Storage.RootFSSource, nil)
	}
}

// Helper function to add plugin integration field to Container
func (c *Container) setPluginIntegration(pi *PluginIntegration) {
	// This would be added to the Container struct
	c.pluginIntegration = pi
}

func (c *Container) getPluginIntegration() *PluginIntegration {
	// This would be added to the Container struct
	return c.pluginIntegration
}

// Add plugin integration field to Container struct definition
// This would be added to the existing Container struct in container.go:
/*
type Container struct {
	Config      *Config
	Process     *exec.Cmd
	CleanupFunc []CleanupFunc
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	state       ContainerState
	stateChange sync.Cond
	once        sync.Once  
	
	// Enhanced hook support
	hookManager *HookManager
	
	// Checkpoint support
	checkpointManager *CheckpointManager
	checkpointEnabled bool
	
	// Sync pipe for parent-child coordination
	syncPipeRead *os.File
	
	// Plugin integration
	pluginIntegration *PluginIntegration  // <-- ADD THIS LINE
}
*/