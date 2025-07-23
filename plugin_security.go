package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PluginSecurityManager handles security aspects of plugin management
type PluginSecurityManager struct {
	config        *PluginSecurityConfig
	trustedHashes map[string]string // path -> hash
	allowedPaths  map[string]bool   // path -> allowed
	logger        *slog.Logger
	mu            sync.RWMutex
}

// PluginSecurityConfig contains security configuration for plugins
type PluginSecurityConfig struct {
	EnableSigning       bool     `json:"enable_signing"`
	RequireSignature    bool     `json:"require_signature"`
	TrustedPublicKeys   []string `json:"trusted_public_keys"`
	AllowedDirectories  []string `json:"allowed_directories"`
	BlockedDirectories  []string `json:"blocked_directories"`
	RequireHashCheck    bool     `json:"require_hash_check"`
	TrustedHashesFile   string   `json:"trusted_hashes_file"`
	MaxPluginSize       int64    `json:"max_plugin_size"`       // bytes
	AllowWorldWritable  bool     `json:"allow_world_writable"`
	EnableSandbox       bool     `json:"enable_sandbox"`
	SandboxTimeout      time.Duration `json:"sandbox_timeout"`
	AllowedCapabilities []string `json:"allowed_capabilities"`
	DeniedSyscalls      []string `json:"denied_syscalls"`
}

// NewPluginSecurityManager creates a new plugin security manager
func NewPluginSecurityManager(ctx context.Context, config *PluginSecurityConfig) (*PluginSecurityManager, error) {
	if config == nil {
		config = &PluginSecurityConfig{
			EnableSigning:      false,
			RequireSignature:   false,
			RequireHashCheck:   true,
			MaxPluginSize:      50 * 1024 * 1024, // 50MB
			AllowWorldWritable: false,
			EnableSandbox:      true,
			SandboxTimeout:     30 * time.Second,
			AllowedCapabilities: []string{"CAP_NET_RAW", "CAP_NET_ADMIN"},
			DeniedSyscalls:     []string{"execve", "fork", "clone"},
		}
	}
	
	psm := &PluginSecurityManager{
		config:        config,
		trustedHashes: make(map[string]string),
		allowedPaths:  make(map[string]bool),
		logger:        Logger(ctx).With("component", "plugin-security"),
	}
	
	// Load trusted hashes if configured
	if config.TrustedHashesFile != "" {
		if err := psm.loadTrustedHashes(); err != nil {
			psm.logger.Warn("Failed to load trusted hashes", "error", err)
		}
	}
	
	// Process allowed directories
	for _, dir := range config.AllowedDirectories {
		absDir, err := filepath.Abs(dir)
		if err != nil {
			psm.logger.Warn("Invalid allowed directory", "dir", dir, "error", err)
			continue
		}
		psm.allowedPaths[absDir] = true
	}
	
	psm.logger.Info("Plugin security manager initialized", 
		"signing_enabled", config.EnableSigning,
		"require_signature", config.RequireSignature,
		"hash_check", config.RequireHashCheck,
		"sandbox", config.EnableSandbox)
	
	return psm, nil
}

// ValidatePlugin performs comprehensive security validation on a plugin
func (psm *PluginSecurityManager) ValidatePlugin(ctx context.Context, pluginPath string) error {
	psm.logger.Debug("Validating plugin security", "path", pluginPath)
	
	// Basic path validation
	if err := psm.validatePath(pluginPath); err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}
	
	// File size validation
	if err := psm.validateFileSize(pluginPath); err != nil {
		return fmt.Errorf("file size validation failed: %w", err)
	}
	
	// File permissions validation
	if err := psm.validatePermissions(pluginPath); err != nil {
		return fmt.Errorf("permission validation failed: %w", err)
	}
	
	// Hash validation
	if psm.config.RequireHashCheck {
		if err := psm.validateHash(pluginPath); err != nil {
			return fmt.Errorf("hash validation failed: %w", err)
		}
	}
	
	// Signature validation
	if psm.config.RequireSignature {
		if err := psm.validateSignature(pluginPath); err != nil {
			return fmt.Errorf("signature validation failed: %w", err)
		}
	}
	
	// Binary analysis
	if err := psm.analyzeBinary(ctx, pluginPath); err != nil {
		return fmt.Errorf("binary analysis failed: %w", err)
	}
	
	psm.logger.Info("Plugin security validation passed", "path", pluginPath)
	return nil
}

// validatePath validates the plugin path
func (psm *PluginSecurityManager) validatePath(pluginPath string) error {
	// Must be absolute path
	if !filepath.IsAbs(pluginPath) {
		return fmt.Errorf("plugin path must be absolute")
	}
	
	// Clean the path to prevent directory traversal
	cleanPath := filepath.Clean(pluginPath)
	if cleanPath != pluginPath {
		return fmt.Errorf("plugin path contains invalid characters or traversal")
	}
	
	// Check if path is in blocked directories
	for _, blockedDir := range psm.config.BlockedDirectories {
		absBlockedDir, err := filepath.Abs(blockedDir)
		if err != nil {
			continue
		}
		if strings.HasPrefix(cleanPath, absBlockedDir) {
			return fmt.Errorf("plugin path is in blocked directory: %s", blockedDir)
		}
	}
	
	// Check if path is in allowed directories (if configured)
	if len(psm.config.AllowedDirectories) > 0 {
		allowed := false
		for _, allowedDir := range psm.config.AllowedDirectories {
			absAllowedDir, err := filepath.Abs(allowedDir)
			if err != nil {
				continue
			}
			if strings.HasPrefix(cleanPath, absAllowedDir) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("plugin path is not in any allowed directory")
		}
	}
	
	return nil
}

// validateFileSize validates the plugin file size
func (psm *PluginSecurityManager) validateFileSize(pluginPath string) error {
	info, err := os.Stat(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to stat plugin file: %w", err)
	}
	
	if info.Size() > psm.config.MaxPluginSize {
		return fmt.Errorf("plugin file too large: %d bytes (max: %d bytes)", 
			info.Size(), psm.config.MaxPluginSize)
	}
	
	if info.Size() == 0 {
		return fmt.Errorf("plugin file is empty")
	}
	
	return nil
}

// validatePermissions validates file permissions
func (psm *PluginSecurityManager) validatePermissions(pluginPath string) error {
	info, err := os.Stat(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to stat plugin file: %w", err)
	}
	
	// Check if world-writable
	if !psm.config.AllowWorldWritable && info.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("plugin file is world-writable")
	}
	
	// Check if group-writable (additional security)
	if info.Mode().Perm()&0020 != 0 {
		psm.logger.Warn("Plugin file is group-writable", "path", pluginPath)
	}
	
	// Must be executable
	if info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("plugin file is not executable")
	}
	
	return nil
}

// validateHash validates the plugin file hash against trusted hashes
func (psm *PluginSecurityManager) validateHash(pluginPath string) error {
	// Calculate file hash
	hash, err := psm.calculateFileHash(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to calculate file hash: %w", err)
	}
	
	psm.mu.RLock()
	trustedHash, exists := psm.trustedHashes[pluginPath]
	psm.mu.RUnlock()
	
	if !exists {
		// If no trusted hash exists, this might be a new plugin
		// In strict mode, this would be an error
		psm.logger.Warn("No trusted hash found for plugin", "path", pluginPath, "hash", hash)
		return fmt.Errorf("no trusted hash found for plugin")
	}
	
	if hash != trustedHash {
		return fmt.Errorf("plugin hash mismatch: expected %s, got %s", trustedHash, hash)
	}
	
	psm.logger.Debug("Plugin hash validation passed", "path", pluginPath, "hash", hash)
	return nil
}

// validateSignature validates the plugin signature (placeholder implementation)
func (psm *PluginSecurityManager) validateSignature(pluginPath string) error {
	// Look for signature file
	sigPath := pluginPath + ".sig"
	if _, err := os.Stat(sigPath); os.IsNotExist(err) {
		return fmt.Errorf("signature file not found: %s", sigPath)
	}
	
	// In a real implementation, this would verify the signature using public keys
	// For now, just check that the signature file exists and is readable
	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("failed to read signature file: %w", err)
	}
	
	if len(sigData) == 0 {
		return fmt.Errorf("signature file is empty")
	}
	
	// TODO: Implement actual signature verification
	psm.logger.Debug("Plugin signature validation passed", "path", pluginPath)
	return nil
}

// analyzeBinary performs basic binary analysis for security threats
func (psm *PluginSecurityManager) analyzeBinary(ctx context.Context, pluginPath string) error {
	// Open the file for analysis
	file, err := os.Open(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to open plugin for analysis: %w", err)
	}
	defer file.Close()
	
	// Read the first few bytes to check file format
	header := make([]byte, 16)
	if _, err := file.Read(header); err != nil {
		return fmt.Errorf("failed to read file header: %w", err)
	}
	
	// Check for ELF header (Linux shared objects)
	if len(header) >= 4 && string(header[:4]) == "\x7fELF" {
		psm.logger.Debug("Plugin is ELF format", "path", pluginPath)
	} else {
		return fmt.Errorf("plugin is not in expected ELF format")
	}
	
	// TODO: Add more sophisticated binary analysis
	// - Check for suspicious strings
	// - Analyze import tables
	// - Check for shellcode patterns
	// - Validate sections and headers
	
	return nil
}

// CalculateFileHash calculates SHA256 hash of a file
func (psm *PluginSecurityManager) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// AddTrustedHash adds a trusted hash for a plugin
func (psm *PluginSecurityManager) AddTrustedHash(pluginPath, hash string) error {
	if pluginPath == "" || hash == "" {
		return fmt.Errorf("plugin path and hash cannot be empty")
	}
	
	// Validate hash format (SHA256 should be 64 hex characters)
	if len(hash) != 64 {
		return fmt.Errorf("invalid hash format: expected 64 characters, got %d", len(hash))
	}
	
	psm.mu.Lock()
	psm.trustedHashes[pluginPath] = hash
	psm.mu.Unlock()
	
	psm.logger.Info("Added trusted hash", "path", pluginPath, "hash", hash)
	
	// Save to file if configured
	if psm.config.TrustedHashesFile != "" {
		if err := psm.saveTrustedHashes(); err != nil {
			psm.logger.Warn("Failed to save trusted hashes", "error", err)
		}
	}
	
	return nil
}

// RemoveTrustedHash removes a trusted hash for a plugin
func (psm *PluginSecurityManager) RemoveTrustedHash(pluginPath string) bool {
	psm.mu.Lock()
	_, existed := psm.trustedHashes[pluginPath]
	delete(psm.trustedHashes, pluginPath)
	psm.mu.Unlock()
	
	if existed {
		psm.logger.Info("Removed trusted hash", "path", pluginPath)
		
		// Save to file if configured
		if psm.config.TrustedHashesFile != "" {
			if err := psm.saveTrustedHashes(); err != nil {
				psm.logger.Warn("Failed to save trusted hashes", "error", err)
			}
		}
	}
	
	return existed
}

// GetTrustedHashes returns all trusted hashes
func (psm *PluginSecurityManager) GetTrustedHashes() map[string]string {
	psm.mu.RLock()
	defer psm.mu.RUnlock()
	
	hashes := make(map[string]string, len(psm.trustedHashes))
	for path, hash := range psm.trustedHashes {
		hashes[path] = hash
	}
	
	return hashes
}

// loadTrustedHashes loads trusted hashes from file
func (psm *PluginSecurityManager) loadTrustedHashes() error {
	data, err := os.ReadFile(psm.config.TrustedHashesFile)
	if err != nil {
		return fmt.Errorf("failed to read trusted hashes file: %w", err)
	}
	
	lines := strings.Split(string(data), "\n")
	loadedCount := 0
	
	psm.mu.Lock()
	defer psm.mu.Unlock()
	
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}
		
		parts := strings.Fields(line)
		if len(parts) != 2 {
			psm.logger.Warn("Invalid hash file format", "line", i+1, "content", line)
			continue
		}
		
		hash, path := parts[0], parts[1]
		if len(hash) != 64 {
			psm.logger.Warn("Invalid hash length", "line", i+1, "hash", hash)
			continue
		}
		
		psm.trustedHashes[path] = hash
		loadedCount++
	}
	
	psm.logger.Info("Loaded trusted hashes", "count", loadedCount, "file", psm.config.TrustedHashesFile)
	return nil
}

// saveTrustedHashes saves trusted hashes to file
func (psm *PluginSecurityManager) saveTrustedHashes() error {
	if psm.config.TrustedHashesFile == "" {
		return fmt.Errorf("no trusted hashes file configured")
	}
	
	psm.mu.RLock()
	defer psm.mu.RUnlock()
	
	var lines []string
	lines = append(lines, "# Trusted plugin hashes (hash path)")
	lines = append(lines, fmt.Sprintf("# Generated at %s", time.Now().Format(time.RFC3339)))
	
	for path, hash := range psm.trustedHashes {
		lines = append(lines, fmt.Sprintf("%s %s", hash, path))
	}
	
	content := strings.Join(lines, "\n") + "\n"
	
	if err := os.WriteFile(psm.config.TrustedHashesFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write trusted hashes file: %w", err)
	}
	
	psm.logger.Debug("Saved trusted hashes", "count", len(psm.trustedHashes))
	return nil
}

// CreatePluginSandbox creates a sandbox environment for plugin execution
func (psm *PluginSecurityManager) CreatePluginSandbox(ctx context.Context, pluginPath string) (*PluginSandbox, error) {
	if !psm.config.EnableSandbox {
		return nil, fmt.Errorf("sandbox is disabled")
	}
	
	sandbox := &PluginSandbox{
		pluginPath: pluginPath,
		timeout:    psm.config.SandboxTimeout,
		logger:     psm.logger.With("component", "plugin-sandbox", "plugin", filepath.Base(pluginPath)),
	}
	
	return sandbox, nil
}

// PluginSandbox represents a sandboxed environment for plugin execution
type PluginSandbox struct {
	pluginPath string
	timeout    time.Duration
	logger     *slog.Logger
}

// Execute runs a plugin in the sandbox
func (ps *PluginSandbox) Execute(ctx context.Context, function string, args ...interface{}) (interface{}, error) {
	// Create timeout context
	execCtx, cancel := context.WithTimeout(ctx, ps.timeout)
	defer cancel()
	
	ps.logger.Debug("Executing plugin in sandbox", "function", function)
	
	// TODO: Implement actual sandboxing
	// This would involve:
	// 1. Creating a restricted execution environment
	// 2. Limiting system calls using seccomp
	// 3. Setting up namespace isolation
	// 4. Applying resource limits
	// 5. Monitoring plugin behavior
	
	select {
	case <-execCtx.Done():
		return nil, fmt.Errorf("plugin execution timed out")
	default:
		// Placeholder for actual plugin execution
		ps.logger.Debug("Plugin execution completed", "function", function)
		return nil, nil
	}
}

// Cleanup cleans up the sandbox
func (ps *PluginSandbox) Cleanup() error {
	ps.logger.Debug("Cleaning up plugin sandbox")
	// TODO: Implement sandbox cleanup
	return nil
}

// GetSecurityReport generates a security report for a plugin
func (psm *PluginSecurityManager) GetSecurityReport(ctx context.Context, pluginPath string) (*PluginSecurityReport, error) {
	report := &PluginSecurityReport{
		PluginPath:  pluginPath,
		Timestamp:   time.Now(),
		Checks:      make(map[string]PluginSecurityCheck),
	}
	
	// Perform all security checks and record results
	checks := []struct {
		name string
		fn   func(string) error
	}{
		{"path_validation", psm.validatePath},
		{"file_size", psm.validateFileSize},
		{"permissions", psm.validatePermissions},
	}
	
	if psm.config.RequireHashCheck {
		checks = append(checks, struct {
			name string
			fn   func(string) error
		}{"hash_validation", psm.validateHash})
	}
	
	if psm.config.RequireSignature {
		checks = append(checks, struct {
			name string
			fn   func(string) error
		}{"signature_validation", psm.validateSignature})
	}
	
	allPassed := true
	for _, check := range checks {
		start := time.Now()
		err := check.fn(pluginPath)
		duration := time.Since(start)
		
		secCheck := PluginSecurityCheck{
			Name:     check.name,
			Passed:   err == nil,
			Duration: duration,
		}
		
		if err != nil {
			secCheck.Error = err.Error()
			allPassed = false
		}
		
		report.Checks[check.name] = secCheck
	}
	
	report.OverallResult = allPassed
	return report, nil
}

// PluginSecurityReport represents a security validation report
type PluginSecurityReport struct {
	PluginPath    string                          `json:"plugin_path"`
	Timestamp     time.Time                       `json:"timestamp"`
	OverallResult bool                            `json:"overall_result"`
	Checks        map[string]PluginSecurityCheck  `json:"checks"`
}

// PluginSecurityCheck represents the result of a single security check
type PluginSecurityCheck struct {
	Name     string        `json:"name"`
	Passed   bool          `json:"passed"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration"`
}

// GetSecurityStats returns security-related statistics
func (psm *PluginSecurityManager) GetSecurityStats() map[string]interface{} {
	psm.mu.RLock()
	defer psm.mu.RUnlock()
	
	return map[string]interface{}{
		"trusted_hashes_count":   len(psm.trustedHashes),
		"allowed_directories":    len(psm.config.AllowedDirectories),
		"blocked_directories":    len(psm.config.BlockedDirectories),
		"signing_enabled":        psm.config.EnableSigning,
		"signature_required":     psm.config.RequireSignature,
		"hash_check_required":    psm.config.RequireHashCheck,
		"sandbox_enabled":        psm.config.EnableSandbox,
		"max_plugin_size_mb":     psm.config.MaxPluginSize / (1024 * 1024),
		"allow_world_writable":   psm.config.AllowWorldWritable,
	}
}