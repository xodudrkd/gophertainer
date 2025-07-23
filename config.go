package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// --- Constants ---

const (
	// syncPipeFD is the file descriptor for the synchronization pipe between the parent
	// and child processes.
	syncPipeFD = 3
	// cgroupV2Path is the standard path for the cgroup v2 unified hierarchy.
	cgroupV2Path = "/sys/fs/cgroup"
	// cgroupV1Path is the standard path for cgroup v1 controllers.
	cgroupV1Path = "/sys/fs/cgroup"
	// pipeTimeout is the maximum duration the parent will wait for the child to
	// signal readiness.
	pipeTimeout = 1000 * time.Second
	// DefaultSeccompProfileName is a special value to indicate the use of the default profile.
	DefaultSeccompProfileName = "default"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// loggerKey is the key used to store the slog.Logger in the context.
	loggerKey contextKey = "logger"
)

// --- Configuration Structs ---

// Config is the top-level configuration struct that holds all settings for the container.
type Config struct {
	Runtime RuntimeConfig
	Network NetworkConfig
	Cgroup  CgroupConfig
	Storage StorageConfig
	Process ProcessConfig
}

// RuntimeConfig holds general runtime options for the container.
type RuntimeConfig struct {
	IsDryRun   bool                  // If true, log actions without executing them.
	IsRootless bool                  // If true, enable rootless mode using user namespaces.
	StrictMode bool                  // If true, exit immediately if hooks or other non-critical errors occur.
	SkipSecurityValidation bool      // If true, skip rootfs security validation (world-writable files, setuid/setgid)
	Timeout    time.Duration         // Maximum execution time for the container.
	Name       string                // A unique name for the container.
	SubUIDMap  []IDMap               // User ID mappings for rootless mode.
	SubGIDMap  []IDMap               // Group ID mappings for rootless mode.
	Hooks      map[string]HookConfig // Hooks to run at different lifecycle stages.
	
	// Checkpoint configuration
	Checkpoint CheckpointConfig      // Configuration for checkpoint/restore functionality
}

// NetworkConfig defines the container's network settings.
type NetworkConfig struct {
	BridgeName  string       // Name of the host bridge to connect the container to.
	NetworkCIDR string       // IPv4 CIDR for the container network.
	IPv6CIDR    string       // IPv6 CIDR for the container network (optional).
	DNS         []string     // DNS servers to configure in the container.
	Hosts       []HostEntry  // Custom host entries for /etc/hosts.
	IPAllocator *IPAllocator `json:"-"` // The IP address allocator for this network.
	
	// CNI Configuration
	CNI         CNIConfig    // CNI plugin configuration
}

// CgroupConfig specifies the cgroup settings and resource limits.
type CgroupConfig struct {
	Name        string  // The name of the cgroup slice/directory.
	Version     string  // Cgroup version to use: "v1", "v2", or "auto".
	MemoryLimit int64   // Memory limit in megabytes (MB).
	StackLimit  int64   // Stack limit in megabytes (MB).
	PidsLimit   int64   // Maximum number of processes.
	CPULimit    float64 // CPU limit as a fraction (e.g., 0.5 for 50%, 2.0 for 2 cores).
	CPUShares   int64   // CPU shares (relative weight, cgroup v1 only).
	MsgQueueLimit int64 // Message queue limit in bytes.
	NiceLimit   int64   // Max nice value.
}

// StorageConfig defines the container's filesystem and mounts.
type StorageConfig struct {
	RootFSSource string            // Path to the rootfs (directory, .tar, or .img).
	Volumes      []Volume          // User-defined volume mounts.
	Mounts       []MountConfig     // Additional system mounts.
	
	// Enhanced storage driver configuration
	Driver       StorageDriverConfig `json:"driver,omitempty"`      // Storage driver configuration
	UseDriver    bool                `json:"use_driver,omitempty"`  // Whether to use pluggable storage drivers
}

// ProcessConfig holds settings related to the process running inside the container.
type ProcessConfig struct {
	Command        string           // The command to execute.
	Env            []string         // Environment variables.
	WorkDir        string           // The working directory inside the container.
	CapsToDrop     []string         // Linux capabilities to drop.
	CapsToKeep     []string         // Linux capabilities to keep.
	SignalMap      map[os.Signal]bool `json:"-"` // Signals to forward to the container process.
	InitProcess    bool             // If true, run a minimal init process to reap zombies.
	NoNewPrivs     bool             // If true, set the NO_NEW_PRIVS prctl bit.
	SeccompProfile string           // Path to a seccomp JSON profile. Use "unconfined" to disable seccomp, or "default" for the built-in profile.
	Interactive    bool             // If true, start an interactive shell instead of running the command.
	TTY            bool             // If true, allocate a pseudo-TTY for the process.
}

// HookConfig defines a command to be executed at a specific lifecycle hook.
type HookConfig struct {
	Path    string        // Path to the hook executable.
	Args    []string      // Arguments for the hook.
	Env     []string      // Environment variables for the hook.
	Timeout time.Duration // Maximum execution time for the hook.
}

// Volume represents a bind mount from the host to the container.
type Volume struct {
	Source   string // Path on the host.
	Dest     string // Path in the container.
	ReadOnly bool   // Whether the mount should be read-only.
}

// HostEntry represents a single line in the /etc/hosts file.
type HostEntry struct {
	Name string
	IP   string
}

// MountConfig represents a generic mount operation within the container.
type MountConfig struct {
	Source string
	Target string
	FSType string
	Flags  uintptr `json:"-"`
	Data   string
}

// IDMap defines a mapping from a host UID/GID to a container UID/GID.
type IDMap struct {
	ContainerID uint32
	HostID      uint32
	Size        uint32
}

// CheckpointConfig holds configuration for checkpoint/restore functionality
type CheckpointConfig struct {
	Enabled       bool   `json:"enabled,omitempty"`         // Whether checkpoint functionality is enabled
	WorkDir       string `json:"work_dir,omitempty"`        // Directory to store checkpoint images
	AutoEnable    bool   `json:"auto_enable,omitempty"`     // Automatically enable checkpointing for new containers
	DefaultHooks  bool   `json:"default_hooks,omitempty"`   // Whether to enable default checkpoint hooks
	CRIUPath      string `json:"criu_path,omitempty"`       // Custom path to CRIU binary
	PreDumpEnabled bool  `json:"pre_dump_enabled,omitempty"` // Whether to enable pre-dump by default
}

// ChildError is a struct used to marshal detailed error information from the
// child process back to the parent over the sync pipe.
type ChildError struct {
	Phase string `json:"phase"`
	Msg   string `json:"msg"`
	Err   error  `json:"-"` // Include the original error for better logging
}

// Error implements the error interface for ChildError.
func (e ChildError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("child failed during phase '%s': %s (cause: %v)", e.Phase, e.Msg, e.Err)
	}
	return fmt.Sprintf("child failed during phase '%s': %s", e.Phase, e.Msg)
}

// Unwrap provides compatibility with errors.Is and errors.As.
func (e ChildError) Unwrap() error {
	return e.Err
}

// CNIConfig defines the CNI plugin configuration
type CNIConfig struct {
	Enabled     bool     `json:"enabled"`              // Enable CNI networking
	PluginPaths []string `json:"plugin_paths"`         // Directories to search for CNI plugins  
	ConfigDir   string   `json:"config_dir"`           // Directory containing CNI configuration files
	NetworkName string   `json:"network_name"`         // Name of the CNI network to use
	BinDir      []string `json:"bin_dir"`              // Additional directories for CNI binaries
}

// CNINetworkConfig represents a CNI network configuration
type CNINetworkConfig struct {
	CNIVersion string                 `json:"cniVersion"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Args       map[string]interface{} `json:"args,omitempty"`
	Plugins    []CNIPlugin            `json:"plugins,omitempty"`
	IPAM       CNIIPAMConfig          `json:"ipam,omitempty"`
}

// CNIPlugin represents an individual CNI plugin configuration
type CNIPlugin struct {
	Type string                 `json:"type"`
	Args map[string]interface{} `json:"args,omitempty"`
	IPAM CNIIPAMConfig          `json:"ipam,omitempty"`
}

// CNIIPAMConfig represents CNI IPAM (IP Address Management) configuration
type CNIIPAMConfig struct {
	Type   string                   `json:"type"`
	Subnet string                   `json:"subnet,omitempty"`
	Range  CNIIPRange               `json:"range,omitempty"`
	Routes []CNIRoute               `json:"routes,omitempty"`
	Args   map[string]interface{}   `json:"args,omitempty"`
}

// CNIIPRange represents an IP range for CNI IPAM
type CNIIPRange struct {
	Subnet     string `json:"subnet"`
	RangeStart string `json:"rangeStart,omitempty"`
	RangeEnd   string `json:"rangeEnd,omitempty"`
	Gateway    string `json:"gateway,omitempty"`
}

// CNIRoute represents a route in CNI configuration
type CNIRoute struct {
	Dst string `json:"dst"`
	GW  string `json:"gw,omitempty"`
}

// CNIResult represents the result returned by a CNI plugin
type CNIResult struct {
	CNIVersion string        `json:"cniVersion"`
	Interfaces []CNIInterface `json:"interfaces,omitempty"`
	IPs        []CNIIP       `json:"ips,omitempty"`
	Routes     []CNIRoute    `json:"routes,omitempty"`
	DNS        CNIDNS        `json:"dns,omitempty"`
}

// CNIInterface represents a network interface in CNI results
type CNIInterface struct {
	Name    string `json:"name"`
	Mac     string `json:"mac,omitempty"`
	Sandbox string `json:"sandbox,omitempty"`
}

// CNIIP represents an IP address configuration in CNI results
type CNIIP struct {
	Version   string `json:"version"`
	Interface *int   `json:"interface,omitempty"`
	Address   string `json:"address"`
	Gateway   string `json:"gateway,omitempty"`
}

// CNIDNS represents DNS configuration in CNI results
type CNIDNS struct {
	Nameservers []string `json:"nameservers,omitempty"`
	Domain      string   `json:"domain,omitempty"`
	Search      []string `json:"search,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// Regex for validating container names. Allows alphanumeric characters, hyphens, and underscores.
var validContainerName = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// validateConfig performs comprehensive validation of the container configuration.
func validateConfig(cfg *Config) error {
	if cfg == nil {
		return NewContainerError(ErrConfigValidation, "configuration cannot be nil").
			WithComponent("config")
	}
	
	if cfg.Runtime.Name == "" {
		return NewContainerError(ErrConfigValidation, "container name cannot be empty").
			WithContext("field", "runtime.name").
			WithComponent("config")
	}
	if len(cfg.Runtime.Name) > 253 {
		return NewContainerError(ErrConfigValidation, "container name too long").
			WithContext("field", "runtime.name").
			WithContext("length", len(cfg.Runtime.Name)).
			WithContext("max_length", 253).
			WithComponent("config")
	}
	if !validContainerName.MatchString(cfg.Runtime.Name) {
		return NewContainerError(ErrConfigValidation, "invalid container name format").
			WithContext("field", "runtime.name").
			WithContext("name", cfg.Runtime.Name).
			WithContext("allowed_pattern", "alphanumeric, hyphens, underscores, and periods").
			WithComponent("config")
	}

	if _, _, err := net.ParseCIDR(cfg.Network.NetworkCIDR); err != nil {
		return WrapConfigError("network.network_cidr", err).
			WithContext("cidr", cfg.Network.NetworkCIDR)
	}

	if cfg.Network.IPv6CIDR != "" {
		if _, _, err := net.ParseCIDR(cfg.Network.IPv6CIDR); err != nil {
			return WrapConfigError("network.ipv6_cidr", err).
				WithContext("cidr", cfg.Network.IPv6CIDR)
		}
	}

	if cfg.Cgroup.MemoryLimit > 0 {
		if cfg.Cgroup.MemoryLimit < 8 {
			return NewContainerError(ErrConfigValidation, "memory limit too low").
				WithContext("field", "cgroup.memory_limit").
				WithContext("value", cfg.Cgroup.MemoryLimit).
				WithContext("minimum", 8).
				WithComponent("config")
		}
		// Check for reasonable upper bound (1TB)
		if cfg.Cgroup.MemoryLimit > 1024*1024 {
			return NewContainerError(ErrConfigValidation, "memory limit too high").
				WithContext("field", "cgroup.memory_limit").
				WithContext("value", cfg.Cgroup.MemoryLimit).
				WithContext("maximum", 1024*1024).
				WithComponent("config")
		}
	}

	if _, err := os.Stat(cfg.Storage.RootFSSource); err != nil {
		return WrapConfigError("storage.rootfs_source", err).
			WithContext("path", cfg.Storage.RootFSSource)
	}

	if cfg.Process.SeccompProfile != "" && cfg.Process.SeccompProfile != "unconfined" && cfg.Process.SeccompProfile != DefaultSeccompProfileName {
		if _, err := os.Stat(cfg.Process.SeccompProfile); err != nil {
			return fmt.Errorf("seccomp profile '%s' not found: %w", cfg.Process.SeccompProfile, err)
		}
	}

	if cfg.Cgroup.CPULimit < 0 {
		return errors.New("CPU limit cannot be negative")
	}
	if cfg.Cgroup.CPULimit > 1024 { // Reasonable upper bound for CPU cores
		return fmt.Errorf("CPU limit too high (%.2f): max 1024 cores", cfg.Cgroup.CPULimit)
	}
	
	if cfg.Cgroup.PidsLimit < 0 {
		return errors.New("pids limit cannot be negative")
	}
	if cfg.Cgroup.PidsLimit > 0 && cfg.Cgroup.PidsLimit < 10 {
		return errors.New("pids limit must be at least 10 to be useful")
	}

	if cfg.Process.Command == "" && !cfg.Process.Interactive {
		return errors.New("a command to execute inside the container must be specified")
	}
	if len(cfg.Process.Command) > 8192 { // Reasonable command length limit
		return fmt.Errorf("command too long (%d chars): max 8192", len(cfg.Process.Command))
	}
	
	// Validate working directory if specified
	if cfg.Process.WorkDir != "" {
		if !filepath.IsAbs(cfg.Process.WorkDir) {
			return fmt.Errorf("working directory must be absolute path: %s", cfg.Process.WorkDir)
		}
		if len(cfg.Process.WorkDir) > 4096 {
			return fmt.Errorf("working directory path too long (%d chars): max 4096", len(cfg.Process.WorkDir))
		}
	}
	
	// Validate timeout
	if cfg.Runtime.Timeout < 0 {
		return errors.New("timeout cannot be negative")
	}
	if cfg.Runtime.Timeout > 24*time.Hour {
		return fmt.Errorf("timeout too long (%v): max 24 hours", cfg.Runtime.Timeout)
	}

	return nil
}

// --- Global Maps ---

var (
	seccompActionMap = map[specs.LinuxSeccompAction]uint32{
		specs.ActKill:  unix.SECCOMP_RET_KILL,
		specs.ActTrap:  unix.SECCOMP_RET_TRAP,
		specs.ActErrno: unix.SECCOMP_RET_ERRNO,
		specs.ActTrace: unix.SECCOMP_RET_TRACE,
		specs.ActAllow: unix.SECCOMP_RET_ALLOW,
		specs.ActLog:   unix.SECCOMP_RET_LOG,
	}

	archMap = map[string]specs.Arch{
		"amd64": specs.ArchX86_64,
		"arm64": specs.ArchAARCH64,
	}

	seccompArchConstMap = map[specs.Arch]uint32{
		specs.ArchX86_64:  unix.AUDIT_ARCH_X86_64,
		specs.ArchAARCH64: unix.AUDIT_ARCH_AARCH64,
	}
)