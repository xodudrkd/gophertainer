package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// PluginRegistry manages plugin discovery and registration
type PluginRegistry struct {
	pluginPaths  map[string]string // name -> path
	pluginInfos  map[string]PluginInfo // name -> info
	searchPaths  []string
	manager     *PluginManager
	logger      *slog.Logger
	mu          sync.RWMutex
	lastScan    time.Time
}

// PluginRegistryEntry represents a plugin entry in the registry
type PluginRegistryEntry struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	Info        PluginInfo `json:"info"`
	Available   bool      `json:"available"`
	LastChecked time.Time `json:"last_checked"`
	Error       string    `json:"error,omitempty"`
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry(ctx context.Context, manager *PluginManager) (*PluginRegistry, error) {
	return &PluginRegistry{
		pluginPaths: make(map[string]string),
		pluginInfos: make(map[string]PluginInfo),
		searchPaths: manager.config.PluginDirs,
		manager:     manager,
		logger:      Logger(ctx).With("component", "plugin-registry"),
	}, nil
}

// RegisterPluginPath registers a plugin path for discovery
func (pr *PluginRegistry) RegisterPluginPath(path string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	
	// Extract plugin name from filename
	filename := filepath.Base(path)
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	
	pr.pluginPaths[name] = path
	pr.logger.Debug("Registered plugin path", "name", name, "path", path)
}

// GetAvailablePlugins returns all discovered plugin paths
func (pr *PluginRegistry) GetAvailablePlugins() ([]string, error) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	
	paths := make([]string, 0, len(pr.pluginPaths))
	for _, path := range pr.pluginPaths {
		paths = append(paths, path)
	}
	
	sort.Strings(paths)
	return paths, nil
}

// GetPluginInfo returns information about a specific plugin
func (pr *PluginRegistry) GetPluginInfo(name string) (PluginInfo, bool) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	
	info, exists := pr.pluginInfos[name]
	return info, exists
}

// GetPluginPath returns the path for a specific plugin
func (pr *PluginRegistry) GetPluginPath(name string) (string, bool) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	
	path, exists := pr.pluginPaths[name]
	return path, exists
}

// ScanForPlugins scans configured directories for plugins
func (pr *PluginRegistry) ScanForPlugins(ctx context.Context) error {
	pr.logger.Info("Scanning for plugins", "search_paths", pr.searchPaths)
	
	foundCount := 0
	
	for _, searchPath := range pr.searchPaths {
		count, err := pr.scanDirectory(ctx, searchPath)
		if err != nil {
			pr.logger.Warn("Failed to scan directory", "path", searchPath, "error", err)
			continue
		}
		foundCount += count
	}
	
	pr.lastScan = time.Now()
	pr.logger.Info("Plugin scan completed", "found_plugins", foundCount)
	
	return nil
}

// scanDirectory scans a single directory for plugins
func (pr *PluginRegistry) scanDirectory(ctx context.Context, dir string) (int, error) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		pr.logger.Debug("Plugin directory does not exist", "dir", dir)
		return 0, nil
	}
	
	foundCount := 0
	
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			pr.logger.Warn("Error walking plugin directory", "path", path, "error", err)
			return nil // Continue walking
		}
		
		if info.IsDir() {
			return nil
		}
		
		// Check for plugin files (shared objects)
		if strings.HasSuffix(path, ".so") {
			pr.RegisterPluginPath(path)
			foundCount++
			pr.logger.Debug("Found plugin file", "path", path)
		}
		
		return nil
	})
	
	return foundCount, err
}

// LoadPluginInfo attempts to load plugin information without fully loading the plugin
func (pr *PluginRegistry) LoadPluginInfo(ctx context.Context, pluginPath string) (*PluginInfo, error) {
	// First check if we have cached info
	name := strings.TrimSuffix(filepath.Base(pluginPath), ".so")
	
	pr.mu.RLock()
	if info, exists := pr.pluginInfos[name]; exists {
		pr.mu.RUnlock()
		return &info, nil
	}
	pr.mu.RUnlock()
	
	// Try to load plugin info from metadata file
	metadataPath := strings.TrimSuffix(pluginPath, ".so") + ".json"
	if info, err := pr.loadPluginInfoFromMetadata(metadataPath); err == nil {
		pr.mu.Lock()
		pr.pluginInfos[name] = *info
		pr.mu.Unlock()
		return info, nil
	}
	
	// As a last resort, try to briefly load the plugin to get info
	// This is more expensive but ensures we can get plugin information
	return pr.loadPluginInfoFromBinary(ctx, pluginPath)
}

// loadPluginInfoFromMetadata loads plugin info from a JSON metadata file
func (pr *PluginRegistry) loadPluginInfoFromMetadata(metadataPath string) (*PluginInfo, error) {
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}
	
	var info PluginInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}
	
	pr.logger.Debug("Loaded plugin info from metadata", "path", metadataPath, "name", info.Name)
	return &info, nil
}

// loadPluginInfoFromBinary loads plugin info by briefly loading the shared object
func (pr *PluginRegistry) loadPluginInfoFromBinary(ctx context.Context, pluginPath string) (*PluginInfo, error) {
	// This is a simplified approach - in production, you might want to use a separate process
	// or sandbox to load plugins safely for inspection
	
	// For now, we'll create a temporary plugin instance to get the info
	tempInstance, err := pr.manager.LoadPlugin(ctx, pluginPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load plugin for info extraction: %w", err)
	}
	
	info := tempInstance.Info
	
	// Unload the temporary instance
	if err := pr.manager.UnloadPlugin(ctx, tempInstance.Info.Name); err != nil {
		pr.logger.Warn("Failed to unload temporary plugin instance", "name", tempInstance.Info.Name, "error", err)
	}
	
	// Cache the info
	pr.mu.Lock()
	pr.pluginInfos[info.Name] = info
	pr.mu.Unlock()
	
	return &info, nil
}

// ListRegistryEntries returns all registry entries with their status
func (pr *PluginRegistry) ListRegistryEntries(ctx context.Context) ([]*PluginRegistryEntry, error) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	
	entries := make([]*PluginRegistryEntry, 0, len(pr.pluginPaths))
	
	for name, path := range pr.pluginPaths {
		entry := &PluginRegistryEntry{
			Name:        name,
			Path:        path,
			LastChecked: time.Now(),
		}
		
		// Check if file exists and is accessible
		if _, err := os.Stat(path); err != nil {
			entry.Available = false
			entry.Error = err.Error()
		} else {
			entry.Available = true
		}
		
		// Get plugin info if available
		if info, exists := pr.pluginInfos[name]; exists {
			entry.Info = info
		} else {
			// Try to load info
			if info, err := pr.LoadPluginInfo(ctx, path); err == nil {
				entry.Info = *info
			} else {
				entry.Error = fmt.Sprintf("Failed to load plugin info: %v", err)
			}
		}
		
		entries = append(entries, entry)
	}
	
	// Sort by name
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	
	return entries, nil
}

// SearchPlugins searches for plugins by various criteria
func (pr *PluginRegistry) SearchPlugins(ctx context.Context, criteria PluginSearchCriteria) ([]*PluginRegistryEntry, error) {
	allEntries, err := pr.ListRegistryEntries(ctx)
	if err != nil {
		return nil, err
	}
	
	var matchingEntries []*PluginRegistryEntry
	
	for _, entry := range allEntries {
		if pr.matchesCriteria(entry, criteria) {
			matchingEntries = append(matchingEntries, entry)
		}
	}
	
	return matchingEntries, nil
}

// PluginSearchCriteria defines search criteria for plugins
type PluginSearchCriteria struct {
	Name         string     `json:"name,omitempty"`
	Type         PluginType `json:"type,omitempty"`
	Version      string     `json:"version,omitempty"`
	Author       string     `json:"author,omitempty"`
	Tags         []string   `json:"tags,omitempty"`
	Capabilities []string   `json:"capabilities,omitempty"`
	AvailableOnly bool      `json:"available_only"`
}

// matchesCriteria checks if a plugin entry matches the search criteria
func (pr *PluginRegistry) matchesCriteria(entry *PluginRegistryEntry, criteria PluginSearchCriteria) bool {
	// Check availability
	if criteria.AvailableOnly && !entry.Available {
		return false
	}
	
	// Check name (partial match)
	if criteria.Name != "" && !strings.Contains(strings.ToLower(entry.Name), strings.ToLower(criteria.Name)) {
		return false
	}
	
	// Check type
	if criteria.Type != "" && entry.Info.Type != criteria.Type {
		return false
	}
	
	// Check version (exact match)
	if criteria.Version != "" && entry.Info.Version != criteria.Version {
		return false
	}
	
	// Check author (partial match)
	if criteria.Author != "" && !strings.Contains(strings.ToLower(entry.Info.Author), strings.ToLower(criteria.Author)) {
		return false
	}
	
	// Check tags (must have all specified tags)
	if len(criteria.Tags) > 0 {
		pluginTags := make(map[string]bool)
		for _, tag := range entry.Info.Tags {
			pluginTags[strings.ToLower(tag)] = true
		}
		
		for _, requiredTag := range criteria.Tags {
			if !pluginTags[strings.ToLower(requiredTag)] {
				return false
			}
		}
	}
	
	// Check capabilities (must have all specified capabilities)
	if len(criteria.Capabilities) > 0 {
		pluginCaps := make(map[string]bool)
		for _, cap := range entry.Info.Capabilities {
			pluginCaps[strings.ToLower(cap)] = true
		}
		
		for _, requiredCap := range criteria.Capabilities {
			if !pluginCaps[strings.ToLower(requiredCap)] {
				return false
			}
		}
	}
	
	return true
}

// ValidatePlugin validates a plugin's metadata and structure
func (pr *PluginRegistry) ValidatePlugin(ctx context.Context, pluginPath string) error {
	// Basic file checks
	if !filepath.IsAbs(pluginPath) {
		return fmt.Errorf("plugin path must be absolute")
	}
	
	info, err := os.Stat(pluginPath)
	if err != nil {
		return fmt.Errorf("plugin file not accessible: %w", err)
	}
	
	if !strings.HasSuffix(pluginPath, ".so") {
		return fmt.Errorf("plugin file must have .so extension")
	}
	
	// Check file permissions
	if info.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("plugin file is world-writable")
	}
	
	// Try to load plugin info
	pluginInfo, err := pr.LoadPluginInfo(ctx, pluginPath)
	if err != nil {
		return fmt.Errorf("failed to load plugin info: %w", err)
	}
	
	// Validate plugin info
	if err := pr.validatePluginInfo(*pluginInfo); err != nil {
		return fmt.Errorf("plugin info validation failed: %w", err)
	}
	
	pr.logger.Debug("Plugin validation successful", "path", pluginPath, "name", pluginInfo.Name)
	return nil
}

// validatePluginInfo validates plugin metadata
func (pr *PluginRegistry) validatePluginInfo(info PluginInfo) error {
	if info.Name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}
	
	if info.Version == "" {
		return fmt.Errorf("plugin version cannot be empty")
	}
	
	if info.Type == "" {
		return fmt.Errorf("plugin type cannot be empty")
	}
	
	// Validate type is known
	validTypes := map[PluginType]bool{
		PluginTypeStorage:    true,
		PluginTypeNetwork:    true,
		PluginTypeMonitoring: true,
		PluginTypeRuntime:    true,
		PluginTypeSecurity:   true,
	}
	
	if !validTypes[info.Type] {
		return fmt.Errorf("unknown plugin type: %s", info.Type)
	}
	
	// Validate dependencies
	for _, dep := range info.Dependencies {
		if dep.Name == "" {
			return fmt.Errorf("dependency name cannot be empty")
		}
		if dep.Version == "" {
			return fmt.Errorf("dependency version cannot be empty")
		}
	}
	
	return nil
}

// ExportRegistry exports the plugin registry to a JSON file
func (pr *PluginRegistry) ExportRegistry(ctx context.Context, exportPath string) error {
	entries, err := pr.ListRegistryEntries(ctx)
	if err != nil {
		return fmt.Errorf("failed to list registry entries: %w", err)
	}
	
	registryData := map[string]interface{}{
		"exported_at": time.Now(),
		"scan_time":   pr.lastScan,
		"entries":     entries,
	}
	
	data, err := json.MarshalIndent(registryData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal registry data: %w", err)
	}
	
	if err := os.WriteFile(exportPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write registry file: %w", err)
	}
	
	pr.logger.Info("Registry exported", "path", exportPath, "entries", len(entries))
	return nil
}

// ImportRegistry imports plugin registry from a JSON file
func (pr *PluginRegistry) ImportRegistry(ctx context.Context, importPath string) error {
	data, err := os.ReadFile(importPath)
	if err != nil {
		return fmt.Errorf("failed to read registry file: %w", err)
	}
	
	var registryData struct {
		Entries []*PluginRegistryEntry `json:"entries"`
	}
	
	if err := json.Unmarshal(data, &registryData); err != nil {
		return fmt.Errorf("failed to parse registry file: %w", err)
	}
	
	pr.mu.Lock()
	defer pr.mu.Unlock()
	
	importedCount := 0
	for _, entry := range registryData.Entries {
		// Only import if the plugin file still exists
		if _, err := os.Stat(entry.Path); err == nil {
			pr.pluginPaths[entry.Name] = entry.Path
			pr.pluginInfos[entry.Name] = entry.Info
			importedCount++
		}
	}
	
	pr.logger.Info("Registry imported", "path", importPath, "imported", importedCount, "total", len(registryData.Entries))
	return nil
}

// GetRegistryStats returns statistics about the plugin registry
func (pr *PluginRegistry) GetRegistryStats() map[string]interface{} {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	
	stats := map[string]interface{}{
		"total_plugins":     len(pr.pluginPaths),
		"cached_info":       len(pr.pluginInfos),
		"last_scan":         pr.lastScan,
		"search_paths":      pr.searchPaths,
	}
	
	// Count by type
	typeCount := make(map[PluginType]int)
	for _, info := range pr.pluginInfos {
		typeCount[info.Type]++
	}
	stats["plugins_by_type"] = typeCount
	
	return stats
}

// RefreshRegistry rescans all search paths and updates the registry
func (pr *PluginRegistry) RefreshRegistry(ctx context.Context) error {
	pr.logger.Info("Refreshing plugin registry")
	
	// Clear existing registry
	pr.mu.Lock()
	pr.pluginPaths = make(map[string]string)
	pr.pluginInfos = make(map[string]PluginInfo)
	pr.mu.Unlock()
	
	// Rescan for plugins
	return pr.ScanForPlugins(ctx)
}