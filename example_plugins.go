package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// ExampleStoragePlugin demonstrates a storage plugin implementation
type ExampleStoragePlugin struct {
	info   PluginInfo
	config map[string]interface{}
	logger *slog.Logger
	active bool
}

// NewExampleStoragePlugin creates a new example storage plugin
// This function would be exported from a plugin shared object
func NewExampleStoragePlugin() Plugin {
	return &ExampleStoragePlugin{
		info: PluginInfo{
			Name:        "example-storage",
			Version:     "1.0.0",
			Type:        PluginTypeStorage,
			Description: "Example storage plugin for demonstration",
			Author:      "Gophertainer Team",
			License:     "MIT",
			Tags:        []string{"example", "storage", "demo"},
			Capabilities: []string{"mount", "unmount", "snapshot"},
			Config: PluginConfigSchema{
				Properties: map[string]PluginConfigProperty{
					"storage_path": {
						Type:        "string",
						Default:     "/var/lib/example-storage",
						Description: "Base path for storage operations",
					},
					"max_size_gb": {
						Type:        "float64",
						Default:     100.0,
						Description: "Maximum storage size in GB",
						Minimum:     func() *float64 { v := 1.0; return &v }(),
						Maximum:     func() *float64 { v := 1000.0; return &v }(),
					},
					"compression": {
						Type:        "bool",
						Default:     true,
						Description: "Enable compression",
					},
				},
				Required: []string{"storage_path"},
			},
		},
		logger: slog.Default().With("plugin", "example-storage"),
	}
}

func (esp *ExampleStoragePlugin) GetInfo() PluginInfo {
	return esp.info
}

func (esp *ExampleStoragePlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	esp.config = config
	esp.logger.Info("Initializing example storage plugin", "config", config)
	
	// Validate required configuration
	storagePath, ok := config["storage_path"].(string)
	if !ok {
		return fmt.Errorf("storage_path must be a string")
	}
	
	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}
	
	esp.logger.Info("Example storage plugin initialized", "storage_path", storagePath)
	return nil
}

func (esp *ExampleStoragePlugin) Start(ctx context.Context) error {
	esp.logger.Info("Starting example storage plugin")
	esp.active = true
	
	// Start background operations if needed
	go esp.backgroundTasks(ctx)
	
	return nil
}

func (esp *ExampleStoragePlugin) Stop(ctx context.Context) error {
	esp.logger.Info("Stopping example storage plugin")
	esp.active = false
	return nil
}

func (esp *ExampleStoragePlugin) Cleanup(ctx context.Context) error {
	esp.logger.Info("Cleaning up example storage plugin")
	return nil
}

func (esp *ExampleStoragePlugin) backgroundTasks(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !esp.active {
				return
			}
			esp.logger.Debug("Running background storage tasks")
			// Perform storage maintenance tasks
		}
	}
}

// ExampleNetworkPlugin demonstrates a network plugin implementation
type ExampleNetworkPlugin struct {
	info      PluginInfo
	config    map[string]interface{}
	logger    *slog.Logger
	eventBus  *PluginEventBus
	active    bool
}

// NewExampleNetworkPlugin creates a new example network plugin
func NewExampleNetworkPlugin() Plugin {
	return &ExampleNetworkPlugin{
		info: PluginInfo{
			Name:        "example-network",
			Version:     "1.0.0",
			Type:        PluginTypeNetwork,
			Description: "Example network plugin with event handling",
			Author:      "Gophertainer Team",
			License:     "MIT",
			Tags:        []string{"example", "network", "demo"},
			Capabilities: []string{"bridge", "vlan", "monitoring"},
			Config: PluginConfigSchema{
				Properties: map[string]PluginConfigProperty{
					"bridge_name": {
						Type:        "string",
						Default:     "example-br0",
						Description: "Name of the bridge to create",
					},
					"subnet": {
						Type:        "string",
						Default:     "192.168.100.0/24",
						Description: "Subnet for container networking",
					},
					"enable_monitoring": {
						Type:        "bool",
						Default:     true,
						Description: "Enable network monitoring",
					},
				},
				Required: []string{"bridge_name", "subnet"},
			},
		},
		logger: slog.Default().With("plugin", "example-network"),
	}
}

func (enp *ExampleNetworkPlugin) GetInfo() PluginInfo {
	return enp.info
}

func (enp *ExampleNetworkPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	enp.config = config
	enp.logger.Info("Initializing example network plugin", "config", config)
	
	// Validate configuration
	bridgeName, ok := config["bridge_name"].(string)
	if !ok {
		return fmt.Errorf("bridge_name must be a string")
	}
	
	subnet, ok := config["subnet"].(string)
	if !ok {
		return fmt.Errorf("subnet must be a string")
	}
	
	enp.logger.Info("Example network plugin initialized", 
		"bridge_name", bridgeName, 
		"subnet", subnet)
	
	return nil
}

func (enp *ExampleNetworkPlugin) Start(ctx context.Context) error {
	enp.logger.Info("Starting example network plugin")
	enp.active = true
	return nil
}

func (enp *ExampleNetworkPlugin) Stop(ctx context.Context) error {
	enp.logger.Info("Stopping example network plugin")
	enp.active = false
	return nil
}

func (enp *ExampleNetworkPlugin) Cleanup(ctx context.Context) error {
	enp.logger.Info("Cleaning up example network plugin")
	return nil
}

// Implement PluginEventHandler interface
func (enp *ExampleNetworkPlugin) HandleEvent(ctx context.Context, event *PluginEvent) error {
	enp.logger.Info("Handling network event", 
		"event_type", event.Type, 
		"event_id", event.ID)
	
	switch event.Type {
	case ContainerEventStarting:
		return enp.handleContainerStarting(ctx, event)
	case ContainerEventStopped:
		return enp.handleContainerStopped(ctx, event)
	case NetworkEventSetup:
		return enp.handleNetworkSetup(ctx, event)
	case NetworkEventTeardown:
		return enp.handleNetworkTeardown(ctx, event)
	}
	
	return nil
}

func (enp *ExampleNetworkPlugin) GetHandledEvents() []PluginEventType {
	return []PluginEventType{
		ContainerEventStarting,
		ContainerEventStopped,
		NetworkEventSetup,
		NetworkEventTeardown,
	}
}

func (enp *ExampleNetworkPlugin) handleContainerStarting(ctx context.Context, event *PluginEvent) error {
	containerName, _ := event.Data["container_name"].(string)
	enp.logger.Info("Container starting, setting up network", "container", containerName)
	
	// Simulate network setup for container
	time.Sleep(100 * time.Millisecond)
	
	enp.logger.Info("Network setup completed for container", "container", containerName)
	return nil
}

func (enp *ExampleNetworkPlugin) handleContainerStopped(ctx context.Context, event *PluginEvent) error {
	containerName, _ := event.Data["container_name"].(string)
	enp.logger.Info("Container stopped, cleaning up network", "container", containerName)
	
	// Simulate network cleanup
	time.Sleep(50 * time.Millisecond)
	
	enp.logger.Info("Network cleanup completed for container", "container", containerName)
	return nil
}

func (enp *ExampleNetworkPlugin) handleNetworkSetup(ctx context.Context, event *PluginEvent) error {
	networkName, _ := event.Data["network_name"].(string)
	enp.logger.Info("Setting up network", "network", networkName)
	return nil
}

func (enp *ExampleNetworkPlugin) handleNetworkTeardown(ctx context.Context, event *PluginEvent) error {
	networkName, _ := event.Data["network_name"].(string)
	enp.logger.Info("Tearing down network", "network", networkName)
	return nil
}

// ExampleMonitoringPlugin demonstrates a monitoring plugin implementation
type ExampleMonitoringPlugin struct {
	info     PluginInfo
	config   map[string]interface{}
	logger   *slog.Logger
	active   bool
	metrics  map[string]interface{}
}

// NewExampleMonitoringPlugin creates a new example monitoring plugin
func NewExampleMonitoringPlugin() Plugin {
	return &ExampleMonitoringPlugin{
		info: PluginInfo{
			Name:        "example-monitoring",
			Version:     "1.0.0",
			Type:        PluginTypeMonitoring,
			Description: "Example monitoring plugin for metrics collection",
			Author:      "Gophertainer Team",
			License:     "MIT",
			Tags:        []string{"example", "monitoring", "metrics"},
			Capabilities: []string{"metrics", "alerts", "dashboard"},
			Config: PluginConfigSchema{
				Properties: map[string]PluginConfigProperty{
					"metrics_port": {
						Type:        "float64",
						Default:     9090.0,
						Description: "Port for metrics endpoint",
						Minimum:     func() *float64 { v := 1024.0; return &v }(),
						Maximum:     func() *float64 { v := 65535.0; return &v }(),
					},
					"collection_interval": {
						Type:        "string",
						Default:     "30s",
						Description: "Metrics collection interval",
					},
					"enable_alerts": {
						Type:        "bool",
						Default:     true,
						Description: "Enable alerting",
					},
				},
				Required: []string{"metrics_port"},
			},
		},
		logger:  slog.Default().With("plugin", "example-monitoring"),
		metrics: make(map[string]interface{}),
	}
}

func (emp *ExampleMonitoringPlugin) GetInfo() PluginInfo {
	return emp.info
}

func (emp *ExampleMonitoringPlugin) Initialize(ctx context.Context, config map[string]interface{}) error {
	emp.config = config
	emp.logger.Info("Initializing example monitoring plugin", "config", config)
	
	// Initialize metrics
	emp.metrics["containers_running"] = 0
	emp.metrics["containers_total"] = 0
	emp.metrics["network_bytes_sent"] = 0
	emp.metrics["network_bytes_received"] = 0
	
	return nil
}

func (emp *ExampleMonitoringPlugin) Start(ctx context.Context) error {
	emp.logger.Info("Starting example monitoring plugin")
	emp.active = true
	
	// Start metrics collection
	go emp.collectMetrics(ctx)
	
	return nil
}

func (emp *ExampleMonitoringPlugin) Stop(ctx context.Context) error {
	emp.logger.Info("Stopping example monitoring plugin")
	emp.active = false
	return nil
}

func (emp *ExampleMonitoringPlugin) Cleanup(ctx context.Context) error {
	emp.logger.Info("Cleaning up example monitoring plugin")
	return nil
}

func (emp *ExampleMonitoringPlugin) collectMetrics(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !emp.active {
				return
			}
			
			// Simulate metrics collection
			emp.metrics["timestamp"] = time.Now().Unix()
			emp.metrics["uptime_seconds"] = time.Since(time.Now().Add(-1*time.Hour)).Seconds()
			
			emp.logger.Debug("Collected metrics", "metrics", emp.metrics)
		}
	}
}

// GetMetrics returns current metrics (example API extension)
func (emp *ExampleMonitoringPlugin) GetMetrics() map[string]interface{} {
	return emp.metrics
}

// PluginExampleManager demonstrates how to use the plugin system
type PluginExampleManager struct {
	pluginManager *PluginManager
	logger        *slog.Logger
}

// NewPluginExampleManager creates a manager for plugin examples
func NewPluginExampleManager(ctx context.Context) (*PluginExampleManager, error) {
	config := &PluginManagerConfig{
		PluginDirs:   []string{"./examples/plugins"},
		ConfigDir:    "./examples/config",
		LoadTimeout:  30 * time.Second,
		StartTimeout: 30 * time.Second,
		AllowedTypes: []PluginType{PluginTypeStorage, PluginTypeNetwork, PluginTypeMonitoring},
		PluginConfig: map[string]map[string]interface{}{
			"example-storage": {
				"storage_path": "/tmp/example-storage",
				"max_size_gb":  50.0,
				"compression":  true,
			},
			"example-network": {
				"bridge_name":       "demo-br0",
				"subnet":            "10.0.1.0/24",
				"enable_monitoring": true,
			},
			"example-monitoring": {
				"metrics_port":        9091.0,
				"collection_interval": "15s",
				"enable_alerts":       true,
			},
		},
	}
	
	pm, err := NewPluginManager(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin manager: %w", err)
	}
	
	return &PluginExampleManager{
		pluginManager: pm,
		logger:        Logger(ctx).With("component", "plugin-example-manager"),
	}, nil
}

// RunExamples demonstrates the plugin system functionality
func (pem *PluginExampleManager) RunExamples(ctx context.Context) error {
	pem.logger.Info("Running plugin system examples")
	
	// Example 1: Manual plugin creation and management
	if err := pem.demonstrateManualPlugins(ctx); err != nil {
		return fmt.Errorf("manual plugin demonstration failed: %w", err)
	}
	
	// Example 2: Event system demonstration
	if err := pem.demonstrateEventSystem(ctx); err != nil {
		return fmt.Errorf("event system demonstration failed: %w", err)
	}
	
	// Example 3: Plugin lifecycle management
	if err := pem.demonstrateLifecycle(ctx); err != nil {
		return fmt.Errorf("lifecycle demonstration failed: %w", err)
	}
	
	pem.logger.Info("Plugin system examples completed successfully")
	return nil
}

func (pem *PluginExampleManager) demonstrateManualPlugins(ctx context.Context) error {
	pem.logger.Info("=== Manual Plugin Creation Example ===")
	
	// Create example plugins (simulating loaded plugins)
	plugins := map[string]Plugin{
		"example-storage":    NewExampleStoragePlugin(),
		"example-network":    NewExampleNetworkPlugin(),
		"example-monitoring": NewExampleMonitoringPlugin(),
	}
	
	// Manually register plugins
	for name, plugin := range plugins {
		instance := &PluginInstance{
			Info:     plugin.GetInfo(),
			State:    PluginStateLoaded,
			Path:     fmt.Sprintf("/tmp/plugins/%s.so", name),
			LoadTime: time.Now(),
			plugin:   plugin,
		}
		
		pem.pluginManager.plugins[name] = instance
		pem.logger.Info("Registered plugin", "name", name, "type", instance.Info.Type)
	}
	
	// Initialize and start plugins
	for name := range plugins {
		if err := pem.pluginManager.InitializePlugin(ctx, name); err != nil {
			return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
		}
		
		if err := pem.pluginManager.StartPlugin(ctx, name); err != nil {
			return fmt.Errorf("failed to start plugin %s: %w", name, err)
		}
	}
	
	// List active plugins
	activePlugins := pem.pluginManager.ListPlugins()
	pem.logger.Info("Active plugins", "count", len(activePlugins))
	for _, plugin := range activePlugins {
		pem.logger.Info("Plugin status", 
			"name", plugin.Info.Name,
			"type", plugin.Info.Type,
			"state", plugin.State,
			"version", plugin.Info.Version)
	}
	
	return nil
}

func (pem *PluginExampleManager) demonstrateEventSystem(ctx context.Context) error {
	pem.logger.Info("=== Event System Example ===")
	
	// Get the network plugin that implements event handling
	networkPlugin, exists := pem.pluginManager.GetPlugin("example-network")
	if !exists {
		return fmt.Errorf("network plugin not found")
	}
	
	// Subscribe to events
	if handler, ok := networkPlugin.plugin.(PluginEventHandler); ok {
		if err := pem.pluginManager.eventBus.Subscribe("example-network", handler, 10); err != nil {
			return fmt.Errorf("failed to subscribe to events: %w", err)
		}
		pem.logger.Info("Subscribed network plugin to events")
	}
	
	// Simulate container lifecycle events
	events := []*PluginEvent{
		NewContainerEvent(ContainerEventStarting, "test-container-1", map[string]interface{}{
			"image": "nginx:latest",
		}),
		NewNetworkEvent(NetworkEventSetup, "test-container-1", "default", nil),
		{
			Type:      ContainerEventStarted,
			Source:    "example-demo",
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"container_name": "test-container-1",
				"pid":           12345,
			},
		},
		NewContainerEvent(ContainerEventStopped, "test-container-1", map[string]interface{}{
			"exit_code": 0,
		}),
		NewNetworkEvent(NetworkEventTeardown, "test-container-1", "default", nil),
	}
	
	// Emit events with delays
	for _, event := range events {
		pem.logger.Info("Emitting event", "type", event.Type)
		pem.pluginManager.eventBus.Emit(event)
		time.Sleep(500 * time.Millisecond) // Allow time for processing
	}
	
	// Show event statistics
	stats := pem.pluginManager.eventBus.GetEventStats()
	pem.logger.Info("Event bus statistics", "stats", stats)
	
	return nil
}

func (pem *PluginExampleManager) demonstrateLifecycle(ctx context.Context) error {
	pem.logger.Info("=== Plugin Lifecycle Example ===")
	
	plugins := pem.pluginManager.ListPlugins()
	
	// Stop all plugins
	for _, plugin := range plugins {
		if plugin.State == PluginStateActive {
			if err := pem.pluginManager.StopPlugin(ctx, plugin.Info.Name); err != nil {
				pem.logger.Warn("Failed to stop plugin", "name", plugin.Info.Name, "error", err)
			}
		}
	}
	
	// Start them again
	for _, plugin := range plugins {
		if plugin.State == PluginStateInitialized {
			if err := pem.pluginManager.StartPlugin(ctx, plugin.Info.Name); err != nil {
				pem.logger.Warn("Failed to restart plugin", "name", plugin.Info.Name, "error", err)
			}
		}
	}
	
	pem.logger.Info("Plugin lifecycle demonstration completed")
	return nil
}

// SaveExamplePluginConfigs creates example plugin configuration files
func SaveExamplePluginConfigs(configDir string) error {
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// Storage plugin config
	storageConfig := map[string]interface{}{
		"name":        "example-storage",
		"enabled":     true,
		"storage_path": "/var/lib/example-storage",
		"max_size_gb": 100.0,
		"compression": true,
		"backup": map[string]interface{}{
			"enabled":  true,
			"interval": "1h",
			"retention": "7d",
		},
	}
	
	// Network plugin config
	networkConfig := map[string]interface{}{
		"name":               "example-network",
		"enabled":            true,
		"bridge_name":        "example-br0",
		"subnet":             "192.168.100.0/24",
		"enable_monitoring":  true,
		"bandwidth_limit":    "1Gbps",
	}
	
	// Monitoring plugin config
	monitoringConfig := map[string]interface{}{
		"name":                "example-monitoring",
		"enabled":             true,
		"metrics_port":        9090,
		"collection_interval": "30s",
		"enable_alerts":       true,
		"alert_thresholds": map[string]interface{}{
			"cpu_percent":    80.0,
			"memory_percent": 85.0,
			"disk_percent":   90.0,
		},
	}
	
	configs := map[string]interface{}{
		"example-storage":    storageConfig,
		"example-network":    networkConfig,
		"example-monitoring": monitoringConfig,
	}
	
	for name, config := range configs {
		configPath := filepath.Join(configDir, name+".json")
		data, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal config for %s: %w", name, err)
		}
		
		if err := os.WriteFile(configPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write config file %s: %w", configPath, err)
		}
	}
	
	return nil
}