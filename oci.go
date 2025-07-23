package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// OCI Runtime Specification implementation

// OCIRuntime implements OCI runtime specification
type OCIRuntime struct {
	bundlePath string
	spec       *specs.Spec
	state      *OCIContainerState
}

// OCIContainerState represents the OCI container state
type OCIContainerState struct {
	Version     string            `json:"ociVersion"`
	ID          string            `json:"id"`
	Status      OCIStatus         `json:"status"`
	Pid         int               `json:"pid,omitempty"`
	Bundle      string            `json:"bundle"`
	Annotations map[string]string `json:"annotations,omitempty"`
	CreatedAt   time.Time         `json:"createdAt,omitempty"`
}

// OCIStatus represents container status per OCI spec
type OCIStatus string

const (
	OCIStatusCreating OCIStatus = "creating"
	OCIStatusCreated  OCIStatus = "created"
	OCIStatusRunning  OCIStatus = "running"
	OCIStatusStopped  OCIStatus = "stopped"
)

// NewOCIRuntime creates a new OCI-compliant runtime
func NewOCIRuntime(bundlePath string) (*OCIRuntime, error) {
	if bundlePath == "" {
		return nil, fmt.Errorf("bundle path cannot be empty")
	}

	// Validate bundle directory exists
	if _, err := os.Stat(bundlePath); err != nil {
		return nil, fmt.Errorf("bundle path does not exist: %w", err)
	}

	return &OCIRuntime{
		bundlePath: bundlePath,
	}, nil
}

// LoadSpec loads the OCI runtime specification from config.json
func (r *OCIRuntime) LoadSpec() error {
	configPath := filepath.Join(r.bundlePath, "config.json")
	
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config.json: %w", err)
	}

	var spec specs.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return fmt.Errorf("failed to parse config.json: %w", err)
	}

	// Validate required fields
	if err := r.validateSpec(&spec); err != nil {
		return fmt.Errorf("invalid OCI spec: %w", err)
	}

	r.spec = &spec
	return nil
}

// validateSpec validates the OCI specification
func (r *OCIRuntime) validateSpec(spec *specs.Spec) error {
	if spec.Version == "" {
		return fmt.Errorf("ociVersion is required")
	}

	if spec.Process == nil {
		return fmt.Errorf("process configuration is required")
	}

	if len(spec.Process.Args) == 0 {
		return fmt.Errorf("process args cannot be empty")
	}

	if spec.Root == nil {
		return fmt.Errorf("root configuration is required")
	}

	if spec.Root.Path == "" {
		return fmt.Errorf("root path is required")
	}

	// Validate root path exists or is relative to bundle
	rootPath := spec.Root.Path
	if !filepath.IsAbs(rootPath) {
		rootPath = filepath.Join(r.bundlePath, rootPath)
	}
	
	if _, err := os.Stat(rootPath); err != nil {
		return fmt.Errorf("root path does not exist: %w", err)
	}

	return nil
}

// ConvertToConfig converts OCI spec to internal Config format
func (r *OCIRuntime) ConvertToConfig(containerID string) (*Config, error) {
	if r.spec == nil {
		return nil, fmt.Errorf("OCI spec not loaded")
	}

	cfg := &Config{
		Runtime: RuntimeConfig{
			Name:       containerID,
			IsDryRun:   false,
			IsRootless: false, // Will be determined from spec
			StrictMode: true,  // OCI compliance requires strict mode
			Hooks:      make(map[string]HookConfig),
		},
		Network: NetworkConfig{
			BridgeName:  "oci0",
			NetworkCIDR: "172.17.0.0/24",
			DNS:         []string{"8.8.8.8", "1.1.1.1"},
			Hosts:       []HostEntry{},
		},
		Cgroup: CgroupConfig{
			Name:    fmt.Sprintf("oci-%s", containerID),
			Version: "auto",
		},
		Storage: StorageConfig{
			Volumes: []Volume{},
			Mounts:  []MountConfig{},
		},
		Process: ProcessConfig{
			SignalMap:  make(map[os.Signal]bool),
			CapsToDrop: []string{},
			CapsToKeep: []string{},
			Env:        []string{},
		},
	}

	// Convert process configuration
	if err := r.convertProcess(cfg); err != nil {
		return nil, fmt.Errorf("failed to convert process config: %w", err)
	}

	// Convert root filesystem
	if err := r.convertRoot(cfg); err != nil {
		return nil, fmt.Errorf("failed to convert root config: %w", err)
	}

	// Convert mounts
	if err := r.convertMounts(cfg); err != nil {
		return nil, fmt.Errorf("failed to convert mounts: %w", err)
	}

	// Convert hooks
	if err := r.convertHooks(cfg); err != nil {
		return nil, fmt.Errorf("failed to convert hooks: %w", err)
	}

	// Convert Linux-specific configurations
	if r.spec.Linux != nil {
		if err := r.convertLinuxConfig(cfg); err != nil {
			return nil, fmt.Errorf("failed to convert Linux config: %w", err)
		}
	}

	return cfg, nil
}

// convertProcess converts OCI process spec to internal format
func (r *OCIRuntime) convertProcess(cfg *Config) error {
	proc := r.spec.Process

	// Build command from args
	if len(proc.Args) > 0 {
		cfg.Process.Command = strings.Join(proc.Args, " ")
	}

	// Set working directory
	if proc.Cwd != "" {
		cfg.Process.WorkDir = proc.Cwd
	}

	// Set environment variables
	cfg.Process.Env = append(cfg.Process.Env, proc.Env...)

	// Set user (convert to environment for simplicity)
	if proc.User.UID != 0 {
		cfg.Process.Env = append(cfg.Process.Env, fmt.Sprintf("USER_UID=%d", proc.User.UID))
	}
	if proc.User.GID != 0 {
		cfg.Process.Env = append(cfg.Process.Env, fmt.Sprintf("USER_GID=%d", proc.User.GID))
	}

	// Set capabilities
	if proc.Capabilities != nil {
		// Convert effective capabilities to keep list
		for _, cap := range proc.Capabilities.Effective {
			cfg.Process.CapsToKeep = append(cfg.Process.CapsToKeep, cap)
		}
	}

	// Set NoNewPrivileges
	cfg.Process.NoNewPrivs = proc.NoNewPrivileges

	// Set rlimits (store in environment for simplicity)
	for _, rlimit := range proc.Rlimits {
		cfg.Process.Env = append(cfg.Process.Env, 
			fmt.Sprintf("RLIMIT_%s_SOFT=%d", strings.ToUpper(rlimit.Type), rlimit.Soft),
			fmt.Sprintf("RLIMIT_%s_HARD=%d", strings.ToUpper(rlimit.Type), rlimit.Hard))
	}

	return nil
}

// convertRoot converts OCI root spec to internal format
func (r *OCIRuntime) convertRoot(cfg *Config) error {
	root := r.spec.Root

	// Set root filesystem path
	rootPath := root.Path
	if !filepath.IsAbs(rootPath) {
		rootPath = filepath.Join(r.bundlePath, rootPath)
	}
	cfg.Storage.RootFSSource = rootPath

	return nil
}

// convertMounts converts OCI mounts to internal format
func (r *OCIRuntime) convertMounts(cfg *Config) error {
	for _, mount := range r.spec.Mounts {
		mountConfig := MountConfig{
			Source: mount.Source,
			Target: mount.Destination,
			FSType: mount.Type,
			Data:   strings.Join(mount.Options, ","),
		}

		// Convert mount options to flags
		for _, option := range mount.Options {
			switch option {
			case "ro", "readonly":
				mountConfig.Flags |= 0x1 // MS_RDONLY
			case "nosuid":
				mountConfig.Flags |= 0x2 // MS_NOSUID
			case "nodev":
				mountConfig.Flags |= 0x4 // MS_NODEV
			case "noexec":
				mountConfig.Flags |= 0x8 // MS_NOEXEC
			case "bind":
				mountConfig.Flags |= 0x1000 // MS_BIND
			}
		}

		cfg.Storage.Mounts = append(cfg.Storage.Mounts, mountConfig)
	}

	return nil
}

// convertHooks converts OCI hooks to internal format
func (r *OCIRuntime) convertHooks(cfg *Config) error {
	if r.spec.Hooks == nil {
		return nil
	}

	// Convert prestart hooks
	if len(r.spec.Hooks.Prestart) > 0 {
		// Use the first prestart hook (could be enhanced to support multiple)
		hook := r.spec.Hooks.Prestart[0]
		cfg.Runtime.Hooks["prestart"] = HookConfig{
			Path:    hook.Path,
			Args:    hook.Args,
			Env:     hook.Env,
			Timeout: time.Duration(*hook.Timeout) * time.Second,
		}
	}

	// Convert poststart hooks
	if len(r.spec.Hooks.Poststart) > 0 {
		hook := r.spec.Hooks.Poststart[0]
		cfg.Runtime.Hooks["poststart"] = HookConfig{
			Path:    hook.Path,
			Args:    hook.Args,
			Env:     hook.Env,
			Timeout: time.Duration(*hook.Timeout) * time.Second,
		}
	}

	// Convert poststop hooks
	if len(r.spec.Hooks.Poststop) > 0 {
		hook := r.spec.Hooks.Poststop[0]
		cfg.Runtime.Hooks["poststop"] = HookConfig{
			Path:    hook.Path,
			Args:    hook.Args,
			Env:     hook.Env,
			Timeout: time.Duration(*hook.Timeout) * time.Second,
		}
	}

	return nil
}

// convertLinuxConfig converts Linux-specific OCI settings
func (r *OCIRuntime) convertLinuxConfig(cfg *Config) error {
	linux := r.spec.Linux

	// Convert namespaces to rootless mode detection
	hasUserNS := false
	for _, ns := range linux.Namespaces {
		if ns.Type == specs.UserNamespace {
			hasUserNS = true
			break
		}
	}
	cfg.Runtime.IsRootless = hasUserNS

	// Convert cgroup settings
	if linux.Resources != nil {
		if linux.Resources.Memory != nil && linux.Resources.Memory.Limit != nil {
			cfg.Cgroup.MemoryLimit = *linux.Resources.Memory.Limit / (1024 * 1024) // Convert to MB
		}

		if linux.Resources.CPU != nil {
			if linux.Resources.CPU.Quota != nil && linux.Resources.CPU.Period != nil {
				cfg.Cgroup.CPULimit = float64(*linux.Resources.CPU.Quota) / float64(*linux.Resources.CPU.Period)
			}
			if linux.Resources.CPU.Shares != nil {
				cfg.Cgroup.CPUShares = int64(*linux.Resources.CPU.Shares)
			}
		}

		if linux.Resources.Pids != nil && linux.Resources.Pids.Limit != 0 {
			cfg.Cgroup.PidsLimit = linux.Resources.Pids.Limit
		}
	}

	// Convert seccomp
	if linux.Seccomp != nil {
		// For simplicity, use default profile if seccomp is specified
		cfg.Process.SeccompProfile = DefaultSeccompProfileName
	}

	// Convert UID/GID mappings for rootless mode
	if hasUserNS {
		cfg.Runtime.SubUIDMap = []IDMap{}
		cfg.Runtime.SubGIDMap = []IDMap{}

		for _, mapping := range linux.UIDMappings {
			cfg.Runtime.SubUIDMap = append(cfg.Runtime.SubUIDMap, IDMap{
				ContainerID: mapping.ContainerID,
				HostID:      mapping.HostID,
				Size:        mapping.Size,
			})
		}

		for _, mapping := range linux.GIDMappings {
			cfg.Runtime.SubGIDMap = append(cfg.Runtime.SubGIDMap, IDMap{
				ContainerID: mapping.ContainerID,
				HostID:      mapping.HostID,
				Size:        mapping.Size,
			})
		}
	}

	return nil
}

// SaveState saves the container state per OCI spec
func (r *OCIRuntime) SaveState(containerID string, status OCIStatus, pid int) error {
	state := &OCIContainerState{
		Version:   r.spec.Version,
		ID:        containerID,
		Status:    status,
		Pid:       pid,
		Bundle:    r.bundlePath,
		CreatedAt: time.Now(),
	}

	if r.spec.Annotations != nil {
		state.Annotations = r.spec.Annotations
	}

	r.state = state

	// Save state to filesystem (OCI requirement)
	stateDir := fmt.Sprintf("/run/oci-runtime/%s", containerID)
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	stateFile := filepath.Join(stateDir, "state.json")
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	if err := os.WriteFile(stateFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}

// LoadState loads the container state from filesystem
func (r *OCIRuntime) LoadState(containerID string) (*OCIContainerState, error) {
	stateFile := fmt.Sprintf("/run/oci-runtime/%s/state.json", containerID)
	
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	var state OCIContainerState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	return &state, nil
}

// CleanupState removes the container state from filesystem
func (r *OCIRuntime) CleanupState(containerID string) error {
	stateDir := fmt.Sprintf("/run/oci-runtime/%s", containerID)
	return os.RemoveAll(stateDir)
}

// OCICreate implements the OCI "create" operation
func OCICreate(ctx context.Context, containerID, bundlePath string) error {
	logger := Logger(ctx)
	logger.Info("Creating OCI container", "id", containerID, "bundle", bundlePath)

	runtime, err := NewOCIRuntime(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to create OCI runtime: %w", err)
	}

	if err := runtime.LoadSpec(); err != nil {
		return fmt.Errorf("failed to load OCI spec: %w", err)
	}

	// Save initial state
	if err := runtime.SaveState(containerID, OCIStatusCreating, 0); err != nil {
		return fmt.Errorf("failed to save initial state: %w", err)
	}

	// Convert OCI spec to internal config
	cfg, err := runtime.ConvertToConfig(containerID)
	if err != nil {
		return fmt.Errorf("failed to convert OCI spec: %w", err)
	}

	// Validate the converted configuration
	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("converted config validation failed: %w", err)
	}

	// Update state to created
	if err := runtime.SaveState(containerID, OCIStatusCreated, 0); err != nil {
		return fmt.Errorf("failed to save created state: %w", err)
	}

	logger.Info("OCI container created successfully", "id", containerID)
	return nil
}

// OCIStart implements the OCI "start" operation
func OCIStart(ctx context.Context, containerID string) error {
	logger := Logger(ctx)
	logger.Info("Starting OCI container", "id", containerID)

	// Load existing state
	runtime := &OCIRuntime{}
	state, err := runtime.LoadState(containerID)
	if err != nil {
		return fmt.Errorf("failed to load container state: %w", err)
	}

	if state.Status != OCIStatusCreated {
		return fmt.Errorf("container is not in created state: %s", state.Status)
	}

	// Load the runtime spec
	runtime.bundlePath = state.Bundle
	if err := runtime.LoadSpec(); err != nil {
		return fmt.Errorf("failed to load OCI spec: %w", err)
	}

	// Convert to internal config and run
	cfg, err := runtime.ConvertToConfig(containerID)
	if err != nil {
		return fmt.Errorf("failed to convert OCI spec: %w", err)
	}

	// Start the container using our internal runtime
	if err := runContainer(ctx, cfg); err != nil {
		// Update state to indicate error
		runtime.SaveState(containerID, OCIStatusStopped, 0)
		return fmt.Errorf("failed to start container: %w", err)
	}

	logger.Info("OCI container started successfully", "id", containerID)
	return nil
}

// OCIKill implements the OCI "kill" operation
func OCIKill(ctx context.Context, containerID string, signal string) error {
	logger := Logger(ctx)
	logger.Info("Killing OCI container", "id", containerID, "signal", signal)

	runtime := &OCIRuntime{}
	state, err := runtime.LoadState(containerID)
	if err != nil {
		return fmt.Errorf("failed to load container state: %w", err)
	}

	if state.Status != OCIStatusRunning {
		return fmt.Errorf("container is not running: %s", state.Status)
	}

	if state.Pid == 0 {
		return fmt.Errorf("container has no valid PID")
	}

	// Convert signal name to number  
	var sigNum int
	switch strings.ToUpper(signal) {
	case "TERM", "SIGTERM":
		sigNum = int(syscall.SIGTERM)
	case "KILL", "SIGKILL":
		sigNum = int(syscall.SIGKILL)
	case "INT", "SIGINT":
		sigNum = int(syscall.SIGINT)
	default:
		if num, parseErr := strconv.Atoi(signal); parseErr == nil {
			sigNum = num
		} else {
			return fmt.Errorf("invalid signal: %s", signal)
		}
	}

	// Send signal to process
	process, err := os.FindProcess(state.Pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	if err := process.Signal(syscall.Signal(sigNum)); err != nil {
		return fmt.Errorf("failed to send signal: %w", err)
	}

	logger.Info("Signal sent to OCI container", "id", containerID, "signal", signal, "pid", state.Pid)
	return nil
}

// OCIDelete implements the OCI "delete" operation
func OCIDelete(ctx context.Context, containerID string) error {
	logger := Logger(ctx)
	logger.Info("Deleting OCI container", "id", containerID)

	runtime := &OCIRuntime{}
	state, err := runtime.LoadState(containerID)
	if err != nil {
		// Container might already be deleted
		logger.Warn("Failed to load container state for deletion", "id", containerID, "error", err)
		return nil
	}

	if state.Status == OCIStatusRunning {
		return fmt.Errorf("cannot delete running container")
	}

	// Cleanup state
	if err := runtime.CleanupState(containerID); err != nil {
		logger.Warn("Failed to cleanup container state", "id", containerID, "error", err)
	}

	logger.Info("OCI container deleted successfully", "id", containerID)
	return nil
}

// OCIState implements the OCI "state" operation
func OCIState(ctx context.Context, containerID string) (*OCIContainerState, error) {
	runtime := &OCIRuntime{}
	return runtime.LoadState(containerID)
}