package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Standard CNI directories
var (
	DefaultCNIBinDirs = []string{
		"/opt/cni/bin",
		"/usr/libexec/cni",
		"/usr/local/libexec/cni",
		"/usr/lib/cni",
	}
	DefaultCNIConfigDirs = []string{
		"/etc/cni/net.d",
		"/usr/local/etc/cni/net.d",
	}
)

// CNIManager manages CNI plugin operations
type CNIManager struct {
	config    *CNIConfig
	logger    *slog.Logger
	binPaths  []string
	configDir string
}

// NewCNIManager creates a new CNI manager instance
func NewCNIManager(ctx context.Context, config *CNIConfig) (*CNIManager, error) {
	if config == nil {
		return nil, fmt.Errorf("CNI config cannot be nil")
	}
	
	logger := Logger(ctx)
	
	// Set up binary search paths
	binPaths := make([]string, 0)
	if len(config.BinDir) > 0 {
		binPaths = append(binPaths, config.BinDir...)
	}
	binPaths = append(binPaths, DefaultCNIBinDirs...)
	
	// Set up config directory
	configDir := config.ConfigDir
	if configDir == "" {
		// Find first available config directory
		for _, dir := range DefaultCNIConfigDirs {
			if _, err := os.Stat(dir); err == nil {
				configDir = dir
				break
			}
		}
	}
	
	if configDir == "" {
		return nil, fmt.Errorf("no CNI configuration directory found")
	}
	
	manager := &CNIManager{
		config:    config,
		logger:    logger,
		binPaths:  binPaths,
		configDir: configDir,
	}
	
	logger.Info("CNI manager initialized", 
		"config_dir", configDir, 
		"bin_paths", binPaths,
		"network_name", config.NetworkName)
	
	return manager, nil
}

// DiscoverPlugins discovers available CNI plugins in the configured directories
func (cni *CNIManager) DiscoverPlugins(ctx context.Context) (map[string]string, error) {
	plugins := make(map[string]string)
	
	for _, binDir := range cni.binPaths {
		if _, err := os.Stat(binDir); os.IsNotExist(err) {
			continue
		}
		
		entries, err := os.ReadDir(binDir)
		if err != nil {
			cni.logger.Warn("Failed to read CNI bin directory", "dir", binDir, "error", err)
			continue
		}
		
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			
			// Check if file is executable
			info, err := entry.Info()
			if err != nil {
				continue
			}
			
			if info.Mode()&0111 == 0 {
				continue // Not executable
			}
			
			pluginName := entry.Name()
			pluginPath := filepath.Join(binDir, pluginName)
			
			// Don't overwrite if we already found this plugin in an earlier directory
			if _, exists := plugins[pluginName]; !exists {
				plugins[pluginName] = pluginPath
			}
		}
	}
	
	pluginNames := make([]string, 0, len(plugins))
	for name := range plugins {
		pluginNames = append(pluginNames, name)
	}
	cni.logger.Debug("Discovered CNI plugins", "count", len(plugins), "plugins", pluginNames)
	return plugins, nil
}

// LoadNetworkConfig loads the CNI network configuration from the config directory
func (cni *CNIManager) LoadNetworkConfig(ctx context.Context) (*CNINetworkConfig, error) {
	if cni.config.NetworkName == "" {
		return nil, fmt.Errorf("no network name specified in CNI config")
	}
	
	// Look for configuration files in the config directory
	configFiles, err := cni.findNetworkConfigFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to find network config files: %w", err)
	}
	
	// Find the configuration for the specified network
	for _, configFile := range configFiles {
		networkConfig, err := cni.loadSingleConfigFile(configFile)
		if err != nil {
			cni.logger.Warn("Failed to load config file", "file", configFile, "error", err)
			continue
		}
		
		if networkConfig.Name == cni.config.NetworkName {
			cni.logger.Info("Loaded CNI network configuration", 
				"network", networkConfig.Name, 
				"type", networkConfig.Type,
				"file", configFile)
			return networkConfig, nil
		}
	}
	
	return nil, fmt.Errorf("network configuration for '%s' not found", cni.config.NetworkName)
}

// findNetworkConfigFiles finds all CNI configuration files in the config directory
func (cni *CNIManager) findNetworkConfigFiles() ([]string, error) {
	var configFiles []string
	
	err := filepath.WalkDir(cni.configDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		if d.IsDir() {
			return nil
		}
		
		// CNI config files are typically .conf or .json files
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".conf" || ext == ".json" {
			configFiles = append(configFiles, path)
		}
		
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	// Sort files to ensure consistent ordering
	sort.Strings(configFiles)
	return configFiles, nil
}

// loadSingleConfigFile loads a single CNI configuration file
func (cni *CNIManager) loadSingleConfigFile(configFile string) (*CNINetworkConfig, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configFile, err)
	}
	
	var networkConfig CNINetworkConfig
	if err := json.Unmarshal(data, &networkConfig); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", configFile, err)
	}
	
	return &networkConfig, nil
}

// SetupNetwork sets up the network using CNI plugins
func (cni *CNIManager) SetupNetwork(ctx context.Context, containerID, netNS string) (*CNIResult, error) {
	networkConfig, err := cni.LoadNetworkConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load network config: %w", err)
	}
	
	// Execute ADD operation
	result, err := cni.executeCNIPlugin(ctx, "ADD", containerID, netNS, networkConfig)
	if err != nil {
		return nil, fmt.Errorf("CNI ADD operation failed: %w", err)
	}
	
	cni.logger.Info("CNI network setup completed", 
		"container_id", containerID, 
		"network", networkConfig.Name,
		"interfaces", len(result.Interfaces),
		"ips", len(result.IPs))
	
	return result, nil
}

// TeardownNetwork tears down the network using CNI plugins
func (cni *CNIManager) TeardownNetwork(ctx context.Context, containerID, netNS string) error {
	networkConfig, err := cni.LoadNetworkConfig(ctx)
	if err != nil {
		// If we can't load the config, log a warning but don't fail cleanup
		cni.logger.Warn("Failed to load network config for teardown", "error", err)
		return nil
	}
	
	// Execute DEL operation
	_, err = cni.executeCNIPlugin(ctx, "DEL", containerID, netNS, networkConfig)
	if err != nil {
		return fmt.Errorf("CNI DEL operation failed: %w", err)
	}
	
	cni.logger.Info("CNI network teardown completed", 
		"container_id", containerID, 
		"network", networkConfig.Name)
	
	return nil
}

// executeCNIPlugin executes a CNI plugin with the given command
func (cni *CNIManager) executeCNIPlugin(ctx context.Context, command, containerID, netNS string, networkConfig *CNINetworkConfig) (*CNIResult, error) {
	// Find the plugin binary
	plugins, err := cni.DiscoverPlugins(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover plugins: %w", err)
	}
	
	pluginPath, exists := plugins[networkConfig.Type]
	if !exists {
		return nil, fmt.Errorf("CNI plugin '%s' not found", networkConfig.Type)
	}
	
	// Prepare CNI environment variables
	env := []string{
		fmt.Sprintf("CNI_COMMAND=%s", command),
		fmt.Sprintf("CNI_CONTAINERID=%s", containerID),
		fmt.Sprintf("CNI_NETNS=%s", netNS),
		fmt.Sprintf("CNI_IFNAME=eth0"),
		fmt.Sprintf("CNI_PATH=%s", strings.Join(cni.binPaths, ":")),
	}
	env = append(env, os.Environ()...)
	
	// Prepare network configuration as JSON
	configJSON, err := json.Marshal(networkConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal network config: %w", err)
	}
	
	// Create context with timeout
	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	// Execute the plugin
	cmd := exec.CommandContext(execCtx, pluginPath)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(string(configJSON))
	
	cni.logger.Debug("Executing CNI plugin", 
		"plugin", networkConfig.Type, 
		"command", command, 
		"container_id", containerID)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("CNI plugin execution failed: %w (output: %s)", err, string(output))
	}
	
	// Parse result for ADD commands
	if command == "ADD" {
		var result CNIResult
		if err := json.Unmarshal(output, &result); err != nil {
			return nil, fmt.Errorf("failed to parse CNI result: %w (output: %s)", err, string(output))
		}
		return &result, nil
	}
	
	// For DEL commands, we don't expect structured output
	return nil, nil
}

// ValidateConfig validates the CNI configuration
func (cni *CNIManager) ValidateConfig(ctx context.Context) error {
	if !cni.config.Enabled {
		return fmt.Errorf("CNI is not enabled")
	}
	
	if cni.config.NetworkName == "" {
		return fmt.Errorf("CNI network name is required")
	}
	
	// Check if config directory exists
	if _, err := os.Stat(cni.configDir); os.IsNotExist(err) {
		return fmt.Errorf("CNI config directory does not exist: %s", cni.configDir)
	}
	
	// Check if at least one bin directory exists
	binDirExists := false
	for _, dir := range cni.binPaths {
		if _, err := os.Stat(dir); err == nil {
			binDirExists = true
			break
		}
	}
	
	if !binDirExists {
		return fmt.Errorf("no CNI binary directories found: %v", cni.binPaths)
	}
	
	// Try to load the network configuration
	_, err := cni.LoadNetworkConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load network configuration: %w", err)
	}
	
	return nil
}

// GetNetworkStatus returns status information about the CNI network setup
func (cni *CNIManager) GetNetworkStatus(ctx context.Context) (map[string]interface{}, error) {
	status := map[string]interface{}{
		"enabled":     cni.config.Enabled,
		"config_dir":  cni.configDir,
		"bin_paths":   cni.binPaths,
		"network_name": cni.config.NetworkName,
	}
	
	// Add plugin information
	plugins, err := cni.DiscoverPlugins(ctx)
	if err != nil {
		status["plugins_error"] = err.Error()
	} else {
		status["available_plugins"] = len(plugins)
		pluginNames := make([]string, 0, len(plugins))
		for name := range plugins {
			pluginNames = append(pluginNames, name)
		}
		status["plugin_names"] = pluginNames
	}
	
	// Add network config information
	networkConfig, err := cni.LoadNetworkConfig(ctx)
	if err != nil {
		status["network_config_error"] = err.Error()
	} else {
		status["network_type"] = networkConfig.Type
		status["cni_version"] = networkConfig.CNIVersion
	}
	
	return status, nil
}