package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"plugin"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

// PluginType represents different types of plugins
type PluginType string

const (
	PluginTypeStorage   PluginType = "storage"
	PluginTypeNetwork   PluginType = "network"
	PluginTypeMonitoring PluginType = "monitoring"
	PluginTypeRuntime   PluginType = "runtime"
	PluginTypeSecurity  PluginType = "security"
)

// PluginState represents the current state of a plugin
type PluginState int

const (
	PluginStateUnloaded PluginState = iota
	PluginStateLoaded
	PluginStateInitialized
	PluginStateActive
	PluginStateError
)

func (s PluginState) String() string {
	switch s {
	case PluginStateUnloaded:
		return "unloaded"
	case PluginStateLoaded:
		return "loaded"
	case PluginStateInitialized:
		return "initialized"
	case PluginStateActive:
		return "active"
	case PluginStateError:
		return "error"
	default:
		return "unknown"
	}
}

// Plugin represents the core plugin interface that all plugins must implement
type Plugin interface {
	// GetInfo returns basic plugin information
	GetInfo() PluginInfo
	
	// Initialize initializes the plugin with configuration
	Initialize(ctx context.Context, config map[string]interface{}) error
	
	// Start starts the plugin
	Start(ctx context.Context) error
	
	// Stop stops the plugin
	Stop(ctx context.Context) error
	
	// Cleanup cleans up plugin resources
	Cleanup(ctx context.Context) error
}

// PluginInfo contains metadata about a plugin
type PluginInfo struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Type        PluginType        `json:"type"`
	Description string            `json:"description"`
	Author      string            `json:"author"`
	License     string            `json:"license"`
	Homepage    string            `json:"homepage"`
	Tags        []string          `json:"tags"`
	Capabilities []string         `json:"capabilities"`
	Dependencies []PluginDependency `json:"dependencies"`
	Config      PluginConfigSchema `json:"config_schema"`
}

// PluginDependency represents a plugin dependency
type PluginDependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
}

// PluginConfigSchema defines the configuration schema for a plugin
type PluginConfigSchema struct {
	Properties map[string]PluginConfigProperty `json:"properties"`
	Required   []string                        `json:"required"`
}

// PluginConfigProperty defines a configuration property
type PluginConfigProperty struct {
	Type        string      `json:"type"`
	Default     interface{} `json:"default"`
	Description string      `json:"description"`
	Enum        []string    `json:"enum,omitempty"`
	Minimum     *float64    `json:"minimum,omitempty"`
	Maximum     *float64    `json:"maximum,omitempty"`
}

// PluginInstance represents a loaded plugin instance
type PluginInstance struct {
	Info     PluginInfo            `json:"info"`
	State    PluginState           `json:"state"`
	Config   map[string]interface{} `json:"config"`
	Path     string                `json:"path"`
	LoadTime time.Time             `json:"load_time"`
	Error    string                `json:"error,omitempty"`
	
	// Internal fields
	plugin   Plugin         `json:"-"`
	soPlugin *plugin.Plugin `json:"-"`
	mu       sync.RWMutex   `json:"-"`
}

// GetState returns the current plugin state
func (pi *PluginInstance) GetState() PluginState {
	pi.mu.RLock()
	defer pi.mu.RUnlock()
	return pi.State
}

// SetState sets the plugin state
func (pi *PluginInstance) SetState(state PluginState) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	pi.State = state
}

// SetError sets an error and changes state to error
func (pi *PluginInstance) SetError(err error) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	pi.State = PluginStateError
	if err != nil {
		pi.Error = err.Error()
	}
}

// PluginManager manages the plugin system
type PluginManager struct {
	plugins   map[string]*PluginInstance
	registry  *PluginRegistry
	config    *PluginManagerConfig
	logger    *slog.Logger
	mu        sync.RWMutex
	eventBus  *PluginEventBus
}

// PluginManagerConfig contains configuration for the plugin manager
type PluginManagerConfig struct {
	PluginDirs      []string          `json:"plugin_dirs"`
	ConfigDir       string            `json:"config_dir"`
	EnableSecurity  bool              `json:"enable_security"`
	LoadTimeout     time.Duration     `json:"load_timeout"`
	StartTimeout    time.Duration     `json:"start_timeout"`
	AllowedTypes    []PluginType      `json:"allowed_types"`
	DisabledPlugins []string          `json:"disabled_plugins"`
	PluginConfig    map[string]map[string]interface{} `json:"plugin_config"`
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(ctx context.Context, config *PluginManagerConfig) (*PluginManager, error) {
	if config == nil {
		config = &PluginManagerConfig{
			PluginDirs:     []string{"/usr/local/lib/gophertainer/plugins", "/etc/gophertainer/plugins"},
			ConfigDir:      "/etc/gophertainer/plugin-config",
			EnableSecurity: true,
			LoadTimeout:    30 * time.Second,
			StartTimeout:   30 * time.Second,
			AllowedTypes:   []PluginType{PluginTypeStorage, PluginTypeNetwork, PluginTypeMonitoring, PluginTypeRuntime, PluginTypeSecurity},
			PluginConfig:   make(map[string]map[string]interface{}),
		}
	}
	
	pm := &PluginManager{
		plugins:  make(map[string]*PluginInstance),
		config:   config,
		logger:   Logger(ctx).With("component", "plugin-manager"),
		eventBus: NewPluginEventBus(ctx),
	}
	
	registry, err := NewPluginRegistry(ctx, pm)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin registry: %w", err)
	}
	pm.registry = registry
	
	pm.logger.Info("Plugin manager created", "plugin_dirs", config.PluginDirs)
	return pm, nil
}

// LoadPlugin loads a plugin from a file
func (pm *PluginManager) LoadPlugin(ctx context.Context, pluginPath string) (*PluginInstance, error) {
	pm.logger.Info("Loading plugin", "path", pluginPath)
	
	// Security check
	if pm.config.EnableSecurity {
		if err := pm.validatePluginSecurity(pluginPath); err != nil {
			return nil, fmt.Errorf("security validation failed: %w", err)
		}
	}
	
	// Load the shared object
	soPlugin, err := plugin.Open(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open plugin: %w", err)
	}
	
	// Look for the NewPlugin symbol
	newPluginSym, err := soPlugin.Lookup("NewPlugin")
	if err != nil {
		return nil, fmt.Errorf("plugin does not export NewPlugin function: %w", err)
	}
	
	// Cast to function
	newPluginFunc, ok := newPluginSym.(func() Plugin)
	if !ok {
		return nil, fmt.Errorf("NewPlugin symbol is not a function")
	}
	
	// Create plugin instance
	pluginImpl := newPluginFunc()
	info := pluginImpl.GetInfo()
	
	// Validate plugin type
	if !pm.isAllowedType(info.Type) {
		return nil, fmt.Errorf("plugin type %s is not allowed", info.Type)
	}
	
	// Check if plugin is disabled
	if pm.isDisabled(info.Name) {
		return nil, fmt.Errorf("plugin %s is disabled", info.Name)
	}
	
	// Create plugin instance
	instance := &PluginInstance{
		Info:     info,
		State:    PluginStateLoaded,
		Path:     pluginPath,
		LoadTime: time.Now(),
		plugin:   pluginImpl,
		soPlugin: soPlugin,
	}
	
	pm.mu.Lock()
	pm.plugins[info.Name] = instance
	pm.mu.Unlock()
	
	// Emit event
	pm.eventBus.Emit(&PluginEvent{
		Type:       PluginEventLoaded,
		PluginName: info.Name,
		Timestamp:  time.Now(),
	})
	
	pm.logger.Info("Plugin loaded successfully", "name", info.Name, "version", info.Version, "type", info.Type)
	return instance, nil
}

// InitializePlugin initializes a loaded plugin
func (pm *PluginManager) InitializePlugin(ctx context.Context, pluginName string) error {
	pm.mu.RLock()
	instance, exists := pm.plugins[pluginName]
	pm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}
	
	if instance.GetState() != PluginStateLoaded {
		return fmt.Errorf("plugin %s is not in loaded state", pluginName)
	}
	
	// Get plugin configuration
	config := pm.getPluginConfig(pluginName)
	
	// Validate configuration
	if err := pm.validatePluginConfig(instance.Info, config); err != nil {
		instance.SetError(err)
		return fmt.Errorf("configuration validation failed: %w", err)
	}
	
	// Initialize plugin with timeout
	initCtx, cancel := context.WithTimeout(ctx, pm.config.LoadTimeout)
	defer cancel()
	
	if err := instance.plugin.Initialize(initCtx, config); err != nil {
		instance.SetError(err)
		return fmt.Errorf("plugin initialization failed: %w", err)
	}
	
	instance.SetState(PluginStateInitialized)
	instance.Config = config
	
	// Emit event
	pm.eventBus.Emit(&PluginEvent{
		Type:       PluginEventInitialized,
		PluginName: pluginName,
		Timestamp:  time.Now(),
	})
	
	pm.logger.Info("Plugin initialized", "name", pluginName)
	return nil
}

// StartPlugin starts an initialized plugin
func (pm *PluginManager) StartPlugin(ctx context.Context, pluginName string) error {
	pm.mu.RLock()
	instance, exists := pm.plugins[pluginName]
	pm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}
	
	if instance.GetState() != PluginStateInitialized {
		return fmt.Errorf("plugin %s is not initialized", pluginName)
	}
	
	// Start plugin with timeout
	startCtx, cancel := context.WithTimeout(ctx, pm.config.StartTimeout)
	defer cancel()
	
	if err := instance.plugin.Start(startCtx); err != nil {
		instance.SetError(err)
		return fmt.Errorf("plugin start failed: %w", err)
	}
	
	instance.SetState(PluginStateActive)
	
	// Emit event
	pm.eventBus.Emit(&PluginEvent{
		Type:       PluginEventStarted,
		PluginName: pluginName,
		Timestamp:  time.Now(),
	})
	
	pm.logger.Info("Plugin started", "name", pluginName)
	return nil
}

// StopPlugin stops an active plugin
func (pm *PluginManager) StopPlugin(ctx context.Context, pluginName string) error {
	pm.mu.RLock()
	instance, exists := pm.plugins[pluginName]
	pm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("plugin %s not found", pluginName)
	}
	
	if instance.GetState() != PluginStateActive {
		return fmt.Errorf("plugin %s is not active", pluginName)
	}
	
	if err := instance.plugin.Stop(ctx); err != nil {
		instance.SetError(err)
		return fmt.Errorf("plugin stop failed: %w", err)
	}
	
	instance.SetState(PluginStateInitialized)
	
	// Emit event
	pm.eventBus.Emit(&PluginEvent{
		Type:       PluginEventStopped,
		PluginName: pluginName,
		Timestamp:  time.Now(),
	})
	
	pm.logger.Info("Plugin stopped", "name", pluginName)
	return nil
}

// UnloadPlugin unloads a plugin
func (pm *PluginManager) UnloadPlugin(ctx context.Context, pluginName string) error {
	pm.mu.Lock()
	instance, exists := pm.plugins[pluginName]
	if !exists {
		pm.mu.Unlock()
		return fmt.Errorf("plugin %s not found", pluginName)
	}
	delete(pm.plugins, pluginName)
	pm.mu.Unlock()
	
	// Stop plugin if running
	if instance.State == PluginStateActive {
		if err := instance.plugin.Stop(ctx); err != nil {
			pm.logger.Warn("Failed to stop plugin during unload", "name", pluginName, "error", err)
		}
	}
	
	// Cleanup plugin
	if err := instance.plugin.Cleanup(ctx); err != nil {
		pm.logger.Warn("Plugin cleanup failed", "name", pluginName, "error", err)
	}
	
	instance.SetState(PluginStateUnloaded)
	
	// Emit event
	pm.eventBus.Emit(&PluginEvent{
		Type:       PluginEventUnloaded,
		PluginName: pluginName,
		Timestamp:  time.Now(),
	})
	
	pm.logger.Info("Plugin unloaded", "name", pluginName)
	return nil
}

// GetPlugin returns a plugin instance by name
func (pm *PluginManager) GetPlugin(name string) (*PluginInstance, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	instance, exists := pm.plugins[name]
	return instance, exists
}

// ListPlugins returns all loaded plugins
func (pm *PluginManager) ListPlugins() []*PluginInstance {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	plugins := make([]*PluginInstance, 0, len(pm.plugins))
	for _, instance := range pm.plugins {
		plugins = append(plugins, instance)
	}
	
	// Sort by name for consistent ordering
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Info.Name < plugins[j].Info.Name
	})
	
	return plugins
}

// ListPluginsByType returns plugins of a specific type
func (pm *PluginManager) ListPluginsByType(pluginType PluginType) []*PluginInstance {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	var plugins []*PluginInstance
	for _, instance := range pm.plugins {
		if instance.Info.Type == pluginType {
			plugins = append(plugins, instance)
		}
	}
	
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].Info.Name < plugins[j].Info.Name
	})
	
	return plugins
}

// DiscoverPlugins discovers plugins in configured directories
func (pm *PluginManager) DiscoverPlugins(ctx context.Context) error {
	pm.logger.Info("Discovering plugins", "dirs", pm.config.PluginDirs)
	
	for _, dir := range pm.config.PluginDirs {
		if err := pm.discoverInDirectory(ctx, dir); err != nil {
			pm.logger.Warn("Failed to discover plugins in directory", "dir", dir, "error", err)
		}
	}
	
	return nil
}

// LoadAllPlugins loads all discovered plugins
func (pm *PluginManager) LoadAllPlugins(ctx context.Context) error {
	pluginPaths, err := pm.registry.GetAvailablePlugins()
	if err != nil {
		return fmt.Errorf("failed to get available plugins: %w", err)
	}
	
	var loadErrors []error
	for _, pluginPath := range pluginPaths {
		if _, err := pm.LoadPlugin(ctx, pluginPath); err != nil {
			pm.logger.Error("Failed to load plugin", "path", pluginPath, "error", err)
			loadErrors = append(loadErrors, fmt.Errorf("failed to load %s: %w", pluginPath, err))
		}
	}
	
	if len(loadErrors) > 0 {
		return fmt.Errorf("failed to load %d plugins: %v", len(loadErrors), loadErrors)
	}
	
	return nil
}

// InitializeAllPlugins initializes all loaded plugins
func (pm *PluginManager) InitializeAllPlugins(ctx context.Context) error {
	plugins := pm.ListPlugins()
	var initErrors []error
	
	for _, instance := range plugins {
		if instance.State == PluginStateLoaded {
			if err := pm.InitializePlugin(ctx, instance.Info.Name); err != nil {
				pm.logger.Error("Failed to initialize plugin", "name", instance.Info.Name, "error", err)
				initErrors = append(initErrors, fmt.Errorf("failed to initialize %s: %w", instance.Info.Name, err))
			}
		}
	}
	
	if len(initErrors) > 0 {
		return fmt.Errorf("failed to initialize %d plugins: %v", len(initErrors), initErrors)
	}
	
	return nil
}

// Shutdown gracefully shuts down all plugins
func (pm *PluginManager) Shutdown(ctx context.Context) error {
	pm.logger.Info("Shutting down plugin manager")
	
	plugins := pm.ListPlugins()
	var shutdownErrors []error
	
	// Stop active plugins first
	for _, instance := range plugins {
		if instance.State == PluginStateActive {
			if err := pm.StopPlugin(ctx, instance.Info.Name); err != nil {
				pm.logger.Error("Failed to stop plugin during shutdown", "name", instance.Info.Name, "error", err)
				shutdownErrors = append(shutdownErrors, err)
			}
		}
	}
	
	// Then unload all plugins
	for _, instance := range plugins {
		if err := pm.UnloadPlugin(ctx, instance.Info.Name); err != nil {
			pm.logger.Error("Failed to unload plugin during shutdown", "name", instance.Info.Name, "error", err)
			shutdownErrors = append(shutdownErrors, err)
		}
	}
	
	if len(shutdownErrors) > 0 {
		return fmt.Errorf("shutdown completed with %d errors: %v", len(shutdownErrors), shutdownErrors)
	}
	
	pm.logger.Info("Plugin manager shutdown complete")
	return nil
}

// Helper methods

func (pm *PluginManager) discoverInDirectory(ctx context.Context, dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil // Directory doesn't exist, skip
	}
	
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			return nil
		}
		
		// Look for .so files (shared objects)
		if strings.HasSuffix(path, ".so") {
			pm.registry.RegisterPluginPath(path)
		}
		
		return nil
	})
}

func (pm *PluginManager) isAllowedType(pluginType PluginType) bool {
	if len(pm.config.AllowedTypes) == 0 {
		return true // No restrictions
	}
	
	for _, allowedType := range pm.config.AllowedTypes {
		if allowedType == pluginType {
			return true
		}
	}
	
	return false
}

func (pm *PluginManager) isDisabled(pluginName string) bool {
	for _, disabled := range pm.config.DisabledPlugins {
		if disabled == pluginName {
			return true
		}
	}
	return false
}

func (pm *PluginManager) getPluginConfig(pluginName string) map[string]interface{} {
	if config, exists := pm.config.PluginConfig[pluginName]; exists {
		return config
	}
	return make(map[string]interface{})
}

func (pm *PluginManager) validatePluginConfig(info PluginInfo, config map[string]interface{}) error {
	// Check required properties
	for _, required := range info.Config.Required {
		if _, exists := config[required]; !exists {
			return fmt.Errorf("required configuration property %s is missing", required)
		}
	}
	
	// Validate property types and constraints
	for key, value := range config {
		if prop, exists := info.Config.Properties[key]; exists {
			if err := pm.validateConfigProperty(key, value, prop); err != nil {
				return err
			}
		}
	}
	
	return nil
}

func (pm *PluginManager) validateConfigProperty(key string, value interface{}, prop PluginConfigProperty) error {
	// Type validation
	expectedType := prop.Type
	actualType := reflect.TypeOf(value).Kind().String()
	
	if expectedType != actualType && expectedType != "any" {
		return fmt.Errorf("configuration property %s has wrong type: expected %s, got %s", key, expectedType, actualType)
	}
	
	// Enum validation
	if len(prop.Enum) > 0 {
		strValue := fmt.Sprintf("%v", value)
		found := false
		for _, enumValue := range prop.Enum {
			if enumValue == strValue {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("configuration property %s value %v is not in allowed values: %v", key, value, prop.Enum)
		}
	}
	
	// Numeric range validation
	if prop.Minimum != nil || prop.Maximum != nil {
		var numValue float64
		switch v := value.(type) {
		case int:
			numValue = float64(v)
		case int64:
			numValue = float64(v)
		case float32:
			numValue = float64(v)
		case float64:
			numValue = v
		default:
			return fmt.Errorf("configuration property %s is not numeric but has numeric constraints", key)
		}
		
		if prop.Minimum != nil && numValue < *prop.Minimum {
			return fmt.Errorf("configuration property %s value %v is below minimum %v", key, value, *prop.Minimum)
		}
		
		if prop.Maximum != nil && numValue > *prop.Maximum {
			return fmt.Errorf("configuration property %s value %v is above maximum %v", key, value, *prop.Maximum)
		}
	}
	
	return nil
}

func (pm *PluginManager) validatePluginSecurity(pluginPath string) error {
	// Basic security checks
	if !filepath.IsAbs(pluginPath) {
		return fmt.Errorf("plugin path must be absolute")
	}
	
	// Check if file exists and is readable
	info, err := os.Stat(pluginPath)
	if err != nil {
		return fmt.Errorf("cannot stat plugin file: %w", err)
	}
	
	// Check permissions (should not be world-writable)
	if info.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("plugin file is world-writable, security risk")
	}
	
	// Add more security checks as needed
	return nil
}