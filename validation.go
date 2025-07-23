package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Validation constants
const (
	MaxContainerNameLength = 253
	MaxPathLength         = 4096
	MaxCommandLength      = 8192
	MaxEnvVarLength       = 32768
	MaxDNSNameLength      = 253
	MinMemoryMB           = 8
	MaxMemoryMB           = 1024 * 1024 // 1TB
	MaxCPUCores           = 1024
	MinPidsLimit          = 10
	MaxTimeout            = 24 * 60 * 60 // 24 hours in seconds
)

var (
	// Validation regexes
	validContainerNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*[a-zA-Z0-9]$`)
	validDNSNameRegex      = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	validIPv4Regex         = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	validIPv6Regex         = regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`)

)

// ValidationRule represents a single validation rule
type ValidationRule struct {
	Field       string
	Value       interface{}
	ValidatorFn func(interface{}) error
	Required    bool
}

// Validator provides comprehensive input validation
type Validator struct {
	rules  []ValidationRule
	errors []error
}

// NewValidator creates a new validator instance
func NewValidator() *Validator {
	return &Validator{
		rules:  make([]ValidationRule, 0),
		errors: make([]error, 0),
	}
}

// AddRule adds a validation rule
func (v *Validator) AddRule(field string, value interface{}, validatorFn func(interface{}) error, required bool) *Validator {
	v.rules = append(v.rules, ValidationRule{
		Field:       field,
		Value:       value,
		ValidatorFn: validatorFn,
		Required:    required,
	})
	return v
}

// Validate executes all validation rules
func (v *Validator) Validate() error {
	v.errors = v.errors[:0] // Clear previous errors

	for _, rule := range v.rules {
		if rule.Value == nil || (rule.Value == "" && rule.Required) {
			if rule.Required {
				v.errors = append(v.errors, NewContainerError(ErrConfigValidation, 
					fmt.Sprintf("field '%s' is required", rule.Field)).
					WithContext("field", rule.Field))
			}
			continue
		}

		if err := rule.ValidatorFn(rule.Value); err != nil {
			if containerErr, ok := err.(*ContainerError); ok {
				containerErr.WithContext("field", rule.Field)
				v.errors = append(v.errors, containerErr)
			} else {
				v.errors = append(v.errors, WrapConfigError(rule.Field, err))
			}
		}
	}

	if len(v.errors) > 0 {
		errorChain := NewErrorChain("input validation")
		for _, err := range v.errors {
			errorChain.Add(err)
		}
		return errorChain
	}

	return nil
}

// Common validation functions

// ValidateContainerName validates container names
func ValidateContainerName(value interface{}) error {
	name, ok := value.(string)
	if !ok {
		return NewContainerError(ErrConfigValidation, "container name must be a string")
	}

	if name == "" {
		return NewContainerError(ErrConfigValidation, "container name cannot be empty")
	}

	if len(name) > MaxContainerNameLength {
		return NewContainerError(ErrConfigValidation, "container name too long").
			WithContext("length", len(name)).
			WithContext("max_length", MaxContainerNameLength)
	}

	if !validContainerNameRegex.MatchString(name) {
		return NewContainerError(ErrConfigValidation, "invalid container name format").
			WithContext("name", name).
			WithContext("pattern", "alphanumeric, hyphens, underscores, periods; must start and end with alphanumeric")
	}

	// Check for reserved names
	reserved := []string{".", "..", "localhost", "local"}
	for _, r := range reserved {
		if strings.EqualFold(name, r) {
			return NewContainerError(ErrConfigValidation, "container name is reserved").
				WithContext("name", name)
		}
	}

	return nil
}

// ValidatePath validates file/directory paths
func ValidatePath(value interface{}) error {
	path, ok := value.(string)
	if !ok {
		return NewContainerError(ErrConfigValidation, "path must be a string")
	}

	if path == "" {
		return NewContainerError(ErrConfigValidation, "path cannot be empty")
	}

	if len(path) > MaxPathLength {
		return NewContainerError(ErrConfigValidation, "path too long").
			WithContext("length", len(path)).
			WithContext("max_length", MaxPathLength)
	}

	if !filepath.IsAbs(path) {
		return NewContainerError(ErrConfigValidation, "path must be absolute").
			WithContext("path", path)
	}

	// Check for path traversal attempts
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return NewContainerError(ErrConfigValidation, "path contains traversal sequences").
			WithContext("path", path)
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return NewContainerError(ErrConfigValidation, "path contains null bytes").
			WithContext("path", path)
	}

	// Check for symbolic links
	if lstat, err := os.Lstat(path); err == nil && lstat.Mode()&os.ModeSymlink != 0 {
		return NewContainerError(ErrConfigValidation, "path cannot be a symbolic link").
			WithContext("path", path)
	}

	return nil
}

// ValidateExistingPath validates that a path exists
func ValidateExistingPath(value interface{}) error {
	if err := ValidatePath(value); err != nil {
		return err
	}

	path := value.(string)
	if _, err := os.Stat(path); err != nil {
		return NewContainerError(ErrConfigValidation, "path does not exist").
			WithContext("path", path).
			WithContext("error", err.Error())
	}

	return nil
}

// ValidateCommand validates container commands
func ValidateCommand(value interface{}) error {
	cmd, ok := value.(string)
	if !ok {
		return NewContainerError(ErrConfigValidation, "command must be a string")
	}

	if cmd == "" {
		return NewContainerError(ErrConfigValidation, "command cannot be empty")
	}

	if len(cmd) > MaxCommandLength {
		return NewContainerError(ErrConfigValidation, "command too long").
			WithContext("length", len(cmd)).
			WithContext("max_length", MaxCommandLength)
	}

	// Check for null bytes and control characters
	if strings.Contains(cmd, "\x00") {
		return NewContainerError(ErrConfigValidation, "command contains null bytes")
	}
	
	// Check for other dangerous control characters
	for i, r := range cmd {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			return NewContainerError(ErrConfigValidation, "command contains control characters").
				WithContext("command", cmd).
				WithContext("position", i).
				WithContext("character_code", int(r))
		}
	}

	// Enhanced shell injection protection - validate command structure
	if err := validateCommandSafety(cmd); err != nil {
		return NewContainerError(ErrConfigValidation, "command fails security validation").
			WithContext("command", cmd).
			WithContext("error", err.Error())
	}

	return nil
}

// validateCommandSafety performs advanced command safety validation
func validateCommandSafety(cmd string) error {
	cmd = strings.TrimSpace(cmd)

	// The command must be an absolute path to an executable.
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return fmt.Errorf("command cannot be empty")
	}
	executable := parts[0]
	if !filepath.IsAbs(executable) {
		return fmt.Errorf("command executable must be an absolute path: %s", executable)
	}

	// Check for basic shell injection patterns
	injectionPatterns := []string{
		"$(", "${", "`", "&&", "||", ";", "|", "&",
		"<(", ">(", "eval ", "exec ", "source ", ". ",
		"bash -c", "sh -c", "/bin/sh -c", "/bin/bash -c",
		"#",
	}

	cmdLower := strings.ToLower(cmd)
	for _, pattern := range injectionPatterns {
		if strings.Contains(cmdLower, pattern) {
			return fmt.Errorf("command contains potentially dangerous pattern: %s", pattern)
		}
	}

	// Check for environment variable manipulation attempts
	envPatterns := []string{"$PATH", "$IFS", "$HOME", "$USER", "$SHELL", "$LD_PRELOAD"}
	for _, pattern := range envPatterns {
		if strings.Contains(cmd, pattern) {
			return fmt.Errorf("command attempts to access sensitive environment variable: %s", pattern)
		}
	}

	// Check for file system manipulation in arguments
	if len(parts) > 1 {
		for _, arg := range parts[1:] {
			if strings.Contains(arg, "..") {
				return fmt.Errorf("command arguments cannot contain path traversal: %s", arg)
			}
		}
	}

	// Check for network operations
	networkPatterns := []string{
		"wget ", "curl ", "nc ", "netcat ", "telnet ", "ssh ", "scp ",
		"ftp ", "sftp ", "rsync ", "ping ", "nmap ", "nslookup ", "dig ",
	}

	for _, pattern := range networkPatterns {
		if strings.Contains(cmdLower+" ", pattern) {
			return fmt.Errorf("command attempts network operation: %s", pattern)
		}
	}

	// Validate command length and complexity
	if len(parts) > 50 {
		return fmt.Errorf("command too complex (>50 arguments)")
	}

	return nil
}

// ValidateCIDR validates CIDR notation
func ValidateCIDR(value interface{}) error {
	cidr, ok := value.(string)
	if !ok {
		return NewContainerError(ErrConfigValidation, "CIDR must be a string")
	}

	if cidr == "" {
		return NewContainerError(ErrConfigValidation, "CIDR cannot be empty")
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return NewContainerError(ErrConfigValidation, "invalid CIDR format").
			WithContext("cidr", cidr).
			WithContext("error", err.Error())
	}

	// Validate network ranges
	ones, bits := network.Mask.Size()
	if ones == 0 {
		return NewContainerError(ErrConfigValidation, "CIDR network too large").
			WithContext("cidr", cidr)
	}

	if ones >= 31 && bits == 32 { // IPv4
		return NewContainerError(ErrConfigValidation, "IPv4 CIDR has no assignable addresses").
			WithContext("cidr", cidr)
	}

	return nil
}

// ValidateMemoryLimit validates memory limits
func ValidateMemoryLimit(value interface{}) error {
	var memMB int64

	switch v := value.(type) {
	case int64:
		memMB = v
	case int:
		memMB = int64(v)
	case float64:
		memMB = int64(v)
	default:
		return NewContainerError(ErrConfigValidation, "memory limit must be a number")
	}

	if memMB < 0 {
		return NewContainerError(ErrConfigValidation, "memory limit cannot be negative").
			WithContext("value", memMB)
	}

	if memMB > 0 && memMB < MinMemoryMB {
		return NewContainerError(ErrConfigValidation, "memory limit too low").
			WithContext("value", memMB).
			WithContext("minimum", MinMemoryMB)
	}

	if memMB > MaxMemoryMB {
		return NewContainerError(ErrConfigValidation, "memory limit too high").
			WithContext("value", memMB).
			WithContext("maximum", MaxMemoryMB)
	}

	return nil
}

// ValidateCPULimit validates CPU limits
func ValidateCPULimit(value interface{}) error {
	var cpuLimit float64

	switch v := value.(type) {
	case float64:
		cpuLimit = v
	case int:
		cpuLimit = float64(v)
	case int64:
		cpuLimit = float64(v)
	default:
		return NewContainerError(ErrConfigValidation, "CPU limit must be a number")
	}

	if cpuLimit < 0 {
		return NewContainerError(ErrConfigValidation, "CPU limit cannot be negative").
			WithContext("value", cpuLimit)
	}

	if cpuLimit > MaxCPUCores {
		return NewContainerError(ErrConfigValidation, "CPU limit too high").
			WithContext("value", cpuLimit).
			WithContext("maximum", MaxCPUCores)
	}

	return nil
}

// ValidateDNSName validates DNS names
func ValidateDNSName(value interface{}) error {
	name, ok := value.(string)
	if !ok {
		return NewContainerError(ErrConfigValidation, "DNS name must be a string")
	}

	if name == "" {
		return nil // Empty DNS names are allowed
	}

	if len(name) > MaxDNSNameLength {
		return NewContainerError(ErrConfigValidation, "DNS name too long").
			WithContext("length", len(name)).
			WithContext("max_length", MaxDNSNameLength)
	}

	if !validDNSNameRegex.MatchString(name) {
		return NewContainerError(ErrConfigValidation, "invalid DNS name format").
			WithContext("name", name)
	}

	return nil
}

// ValidateIPAddress validates IP addresses
func ValidateIPAddress(value interface{}) error {
	ip, ok := value.(string)
	if !ok {
		return NewContainerError(ErrConfigValidation, "IP address must be a string")
	}

	if ip == "" {
		return NewContainerError(ErrConfigValidation, "IP address cannot be empty")
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return NewContainerError(ErrConfigValidation, "invalid IP address format").
			WithContext("ip", ip)
	}

	// Additional validation for specific IP types
	if parsedIP.IsLoopback() {
		return NewContainerError(ErrConfigValidation, "loopback IP addresses not allowed").
			WithContext("ip", ip)
	}

	if parsedIP.IsMulticast() {
		return NewContainerError(ErrConfigValidation, "multicast IP addresses not allowed").
			WithContext("ip", ip)
	}

	return nil
}

// ValidateEnvironmentVariable validates environment variables
func ValidateEnvironmentVariable(value interface{}) error {
	env, ok := value.(string)
	if !ok {
		return NewContainerError(ErrConfigValidation, "environment variable must be a string")
	}

	if len(env) > MaxEnvVarLength {
		return NewContainerError(ErrConfigValidation, "environment variable too long").
			WithContext("length", len(env)).
			WithContext("max_length", MaxEnvVarLength)
	}

	if !strings.Contains(env, "=") {
		return NewContainerError(ErrConfigValidation, "environment variable must be in KEY=VALUE format").
			WithContext("env", env)
	}

	parts := strings.SplitN(env, "=", 2)
	key := parts[0]
	val := parts[1]

	if key == "" {
		return NewContainerError(ErrConfigValidation, "environment variable key cannot be empty").
			WithContext("env", env)
	}

	// Validate key format
	for i, r := range key {
		if i == 0 && !unicode.IsLetter(r) && r != '_' {
			return NewContainerError(ErrConfigValidation, "environment variable key must start with letter or underscore").
				WithContext("key", key)
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return NewContainerError(ErrConfigValidation, "environment variable key contains invalid characters").
				WithContext("key", key)
		}
	}

	// Sanitize value
	if strings.ContainsAny(val, "\x00\n\r") {
		return NewContainerError(ErrConfigValidation, "environment variable value contains forbidden characters (null, newline)").
			WithContext("key", key)
	}

	// Check for dangerous patterns in the value
	dangerousPatterns := []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "/etc/", "/proc/", "/sys/"}
	for _, pattern := range dangerousPatterns {
		if strings.Contains(strings.ToUpper(key), pattern) || strings.Contains(val, pattern) {
			return NewContainerError(ErrConfigValidation, "environment variable contains dangerous pattern").
				WithContext("key", key).
				WithContext("pattern", pattern)
		}
	}

	return nil
}

// ValidateCapability validates Linux capabilities
func ValidateCapability(value interface{}) error {
	cap, ok := value.(string)
	if !ok {
		return NewContainerError(ErrConfigValidation, "capability must be a string")
	}

	if cap == "" {
		return NewContainerError(ErrConfigValidation, "capability cannot be empty")
	}

	// Normalize capability name
	cap = strings.ToUpper(cap)
	if !strings.HasPrefix(cap, "CAP_") {
		cap = "CAP_" + cap
	}

	if _, exists := CapabilityMap[strings.TrimPrefix(cap, "CAP_")]; !exists {
		return NewContainerError(ErrConfigValidation, "unknown capability").
			WithContext("capability", cap)
	}

	return nil
}

// ValidateSeccompProfile validates seccomp profile paths
func ValidateSeccompProfile(value interface{}) error {
	profile, ok := value.(string)
	if !ok {
		return NewContainerError(ErrConfigValidation, "seccomp profile must be a string")
	}

	if profile == "" || profile == "unconfined" || profile == DefaultSeccompProfileName {
		return nil // These are valid special values
	}

	// Validate as file path
	if err := ValidatePath(profile); err != nil {
		return err
	}

	// Check if file exists and is readable
	if err := ValidateExistingPath(profile); err != nil {
		return err
	}

	// Check file extension
	if !strings.HasSuffix(profile, ".json") {
		return NewContainerError(ErrConfigValidation, "seccomp profile must be a JSON file").
			WithContext("profile", profile)
	}

	return nil
}

// validateConfigSecurely performs comprehensive security-focused validation
func validateConfigSecurely(cfg *Config) error {
	if cfg == nil {
		return NewContainerError(ErrConfigValidation, "configuration cannot be nil")
	}

	validator := NewValidator()

	// Runtime validation
	validator.AddRule("runtime.name", cfg.Runtime.Name, ValidateContainerName, true)
	validator.AddRule("runtime.timeout", cfg.Runtime.Timeout.Seconds(), func(value interface{}) error {
		timeout := value.(float64)
		if timeout < 0 {
			return NewContainerError(ErrConfigValidation, "timeout cannot be negative")
		}
		if timeout > MaxTimeout {
			return NewContainerError(ErrConfigValidation, "timeout too long").
				WithContext("value", timeout).
				WithContext("maximum", MaxTimeout)
		}
		return nil
	}, false)

	// Storage validation
	validator.AddRule("storage.rootfs_source", cfg.Storage.RootFSSource, ValidateExistingPath, true)

	// Network validation
	validator.AddRule("network.network_cidr", cfg.Network.NetworkCIDR, ValidateCIDR, true)
	if cfg.Network.IPv6CIDR != "" {
		validator.AddRule("network.ipv6_cidr", cfg.Network.IPv6CIDR, ValidateCIDR, false)
	}
	
	// Bridge name validation
	validator.AddRule("network.bridge_name", cfg.Network.BridgeName, func(value interface{}) error {
		name := value.(string)
		if len(name) > 15 { // Linux interface name limit
			return NewContainerError(ErrConfigValidation, "bridge name too long").
				WithContext("length", len(name)).
				WithContext("max_length", 15)
		}
		return nil
	}, true)

	// DNS servers validation
	for i, dns := range cfg.Network.DNS {
		validator.AddRule(fmt.Sprintf("network.dns[%d]", i), dns, ValidateIPAddress, false)
	}

	// Process validation
	// Only validate command if not in interactive mode or if command is provided
	if !cfg.Process.Interactive {
		validator.AddRule("process.command", cfg.Process.Command, ValidateCommand, true)
	} else if cfg.Process.Command != "" {
		// In interactive mode, still validate command if one is provided (optional)
		validator.AddRule("process.command", cfg.Process.Command, ValidateCommand, false)
	}
	if cfg.Process.WorkDir != "" {
		validator.AddRule("process.workdir", cfg.Process.WorkDir, ValidatePath, false)
	}

	// Environment variables validation
	for i, env := range cfg.Process.Env {
		validator.AddRule(fmt.Sprintf("process.env[%d]", i), env, ValidateEnvironmentVariable, false)
	}

	// Capabilities validation
	for i, cap := range cfg.Process.CapsToKeep {
		validator.AddRule(fmt.Sprintf("process.caps_to_keep[%d]", i), cap, ValidateCapability, false)
	}
	for i, cap := range cfg.Process.CapsToDrop {
		validator.AddRule(fmt.Sprintf("process.caps_to_drop[%d]", i), cap, ValidateCapability, false)
	}

	// Seccomp validation
	if cfg.Process.SeccompProfile != "" {
		validator.AddRule("process.seccomp_profile", cfg.Process.SeccompProfile, ValidateSeccompProfile, false)
	}

	// Cgroup validation
	if cfg.Cgroup.MemoryLimit > 0 {
		validator.AddRule("cgroup.memory_limit", cfg.Cgroup.MemoryLimit, ValidateMemoryLimit, false)
	}
	if cfg.Cgroup.CPULimit > 0 {
		validator.AddRule("cgroup.cpu_limit", cfg.Cgroup.CPULimit, ValidateCPULimit, false)
	}
	if cfg.Cgroup.PidsLimit > 0 {
		validator.AddRule("cgroup.pids_limit", cfg.Cgroup.PidsLimit, func(value interface{}) error {
			pids := value.(int64)
			if pids < MinPidsLimit {
				return NewContainerError(ErrConfigValidation, "pids limit too low").
					WithContext("value", pids).
					WithContext("minimum", MinPidsLimit)
			}
			return nil
		}, false)
	}

	// Volume validation
	for i, vol := range cfg.Storage.Volumes {
		validator.AddRule(fmt.Sprintf("storage.volumes[%d].source", i), vol.Source, ValidateExistingPath, false)
		validator.AddRule(fmt.Sprintf("storage.volumes[%d].dest", i), vol.Dest, ValidatePath, false)
	}

	// Host entries validation
	for i, host := range cfg.Network.Hosts {
		validator.AddRule(fmt.Sprintf("network.hosts[%d].name", i), host.Name, ValidateDNSName, false)
		validator.AddRule(fmt.Sprintf("network.hosts[%d].ip", i), host.IP, ValidateIPAddress, false)
	}

	return validator.Validate()
}


// validateRootfs performs security validation of the container's root filesystem.
func validateRootfs(rootfsPath string) error {
	// Check for world-writable files and directories
	return filepath.Walk(rootfsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check for world-writable files
		if info.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf("insecure world-writable file found in rootfs: %s", path)
		}

		// Check for setuid/setgid bits
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return fmt.Errorf("insecure setuid/setgid file found in rootfs: %s", path)
		}

		return nil
	})
}