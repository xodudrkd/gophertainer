package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CheckpointManager handles container checkpointing and restoration using CRIU
type CheckpointManager struct {
	criuPath     string
	workDir      string
	logger       *slog.Logger
	imageDir     string
	preHooks     []CheckpointHook
	postHooks    []CheckpointHook
	restoreHooks []CheckpointHook
}

// CheckpointMetadata contains information about a checkpoint
type CheckpointMetadata struct {
	ContainerName    string                 `json:"container_name"`
	CheckpointID     string                 `json:"checkpoint_id"`
	Timestamp        time.Time              `json:"timestamp"`
	ContainerPID     int                    `json:"container_pid"`
	ContainerConfig  *Config                `json:"container_config"`
	CheckpointPath   string                 `json:"checkpoint_path"`
	ImagePath        string                 `json:"image_path"`
	CRIUVersion      string                 `json:"criu_version"`
	NetworkInfo      *NetworkCheckpointInfo `json:"network_info,omitempty"`
	StorageInfo      *StorageCheckpointInfo `json:"storage_info,omitempty"`
	HookResults      map[string]interface{} `json:"hook_results,omitempty"`
	PreDumpCount     int                    `json:"pre_dump_count,omitempty"`
	FilesystemFreeze bool                   `json:"filesystem_freeze,omitempty"`
	TCPEstablished   bool                   `json:"tcp_established,omitempty"`
	RestoreCount     int                    `json:"restore_count,omitempty"`
}

// NetworkCheckpointInfo contains network-related checkpoint information
type NetworkCheckpointInfo struct {
	VethPairs    []string `json:"veth_pairs,omitempty"`
	BridgeName   string   `json:"bridge_name,omitempty"`
	ContainerIP4 string   `json:"container_ip4,omitempty"`
	ContainerIP6 string   `json:"container_ip6,omitempty"`
	RouteInfo    []string `json:"route_info,omitempty"`
}

// StorageCheckpointInfo contains storage-related checkpoint information
type StorageCheckpointInfo struct {
	StorageDriver string            `json:"storage_driver,omitempty"`
	LayerInfo     map[string]string `json:"layer_info,omitempty"`
	MountPoints   []string          `json:"mount_points,omitempty"`
}

// CheckpointHook represents a hook that can be executed during checkpoint/restore operations
type CheckpointHook struct {
	Name        string                                                      `json:"name"`
	Phase       CheckpointPhase                                             `json:"phase"`
	Path        string                                                      `json:"path"`
	Args        []string                                                    `json:"args,omitempty"`
	Env         []string                                                    `json:"env,omitempty"`
	Timeout     time.Duration                                               `json:"timeout,omitempty"`
	FailureMode CheckpointHookFailureMode                                   `json:"failure_mode,omitempty"`
	Condition   CheckpointCondition                                         `json:"condition,omitempty"`
	Handler     func(ctx context.Context, metadata *CheckpointMetadata) error `json:"-"`
}

// CheckpointPhase represents different phases of checkpoint/restore operations
type CheckpointPhase string

const (
	CheckpointPhasePreDump      CheckpointPhase = "pre_dump"
	CheckpointPhasePreCheckpoint CheckpointPhase = "pre_checkpoint"
	CheckpointPhasePostCheckpoint CheckpointPhase = "post_checkpoint"
	CheckpointPhasePreRestore    CheckpointPhase = "pre_restore"
	CheckpointPhasePostRestore   CheckpointPhase = "post_restore"
)

// CheckpointHookFailureMode defines how to handle hook failures
type CheckpointHookFailureMode string

const (
	CheckpointFailureModeIgnore CheckpointHookFailureMode = "ignore"
	CheckpointFailureModeWarn   CheckpointHookFailureMode = "warn"
	CheckpointFailureModeStop   CheckpointHookFailureMode = "stop"
	CheckpointFailureModeFail   CheckpointHookFailureMode = "fail"
)

// CheckpointCondition defines conditions for hook execution
type CheckpointCondition struct {
	Type  string `json:"type"`  // env, config, file, command
	Key   string `json:"key"`   // Variable name, config path, file path, command name
	Op    string `json:"op"`    // eq, ne, exists, not_exists, available
	Value string `json:"value"` // Expected value
}

// CheckpointOptions contains options for checkpoint operations
type CheckpointOptions struct {
	ContainerName    string            `json:"container_name"`
	CheckpointID     string            `json:"checkpoint_id"`
	ImageDir         string            `json:"image_dir"`
	PreDumpDir       string            `json:"pre_dump_dir,omitempty"`
	PreDump          bool              `json:"pre_dump,omitempty"`
	LeaveRunning     bool              `json:"leave_running,omitempty"`
	FileLocks        bool              `json:"file_locks,omitempty"`
	TCPEstablished   bool              `json:"tcp_established,omitempty"`
	ExtUnixSockets   bool              `json:"ext_unix_sockets,omitempty"`
	ShellJob         bool              `json:"shell_job,omitempty"`
	EmptyNS          bool              `json:"empty_ns,omitempty"`
	AutoDedup        bool              `json:"auto_dedup,omitempty"`
	LazyPages        bool              `json:"lazy_pages,omitempty"`
	ExtraOptions     map[string]string `json:"extra_options,omitempty"`
	EnableHooks      bool              `json:"enable_hooks,omitempty"`
}

// RestoreOptions contains options for restore operations
type RestoreOptions struct {
	CheckpointID     string            `json:"checkpoint_id"`
	ImageDir         string            `json:"image_dir"`
	RestorePID       int               `json:"restore_pid,omitempty"`
	InheritFD        bool              `json:"inherit_fd,omitempty"`
	EmptyNS          bool              `json:"empty_ns,omitempty"`
	DetachMode       bool              `json:"detach_mode,omitempty"`
	LazyPages        bool              `json:"lazy_pages,omitempty"`
	ExtraOptions     map[string]string `json:"extra_options,omitempty"`
	EnableHooks      bool              `json:"enable_hooks,omitempty"`
}

// NewCheckpointManager creates a new checkpoint manager instance
func NewCheckpointManager(ctx context.Context, workDir string) (*CheckpointManager, error) {
	// Find CRIU binary
	criuPath, err := exec.LookPath("criu")
	if err != nil {
		return nil, fmt.Errorf("CRIU not found in PATH: %w (install criu package)", err)
	}
	
	// Verify CRIU version and functionality
	if err := verifyCRIUInstallation(ctx, criuPath); err != nil {
		return nil, fmt.Errorf("CRIU installation verification failed: %w", err)
	}
	
	// Ensure work directory exists
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create checkpoint work directory: %w", err)
	}
	
	imageDir := filepath.Join(workDir, "images")
	if err := os.MkdirAll(imageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create checkpoint image directory: %w", err)
	}
	
	return &CheckpointManager{
		criuPath:     criuPath,
		workDir:      workDir,
		imageDir:     imageDir,
		logger:       Logger(ctx).With("component", "checkpoint"),
		preHooks:     []CheckpointHook{},
		postHooks:    []CheckpointHook{},
		restoreHooks: []CheckpointHook{},
	}, nil
}

// verifyCRIUInstallation verifies that CRIU is properly installed and functional
func verifyCRIUInstallation(ctx context.Context, criuPath string) error {
	// Check CRIU version
	cmd := exec.CommandContext(ctx, criuPath, "check", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get CRIU version: %w (output: %s)", err, string(output))
	}
	
	// Check basic functionality
	cmd = exec.CommandContext(ctx, criuPath, "check")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("CRIU functionality check failed: %w (output: %s)", err, string(output))
	}
	
	// Check for required kernel features
	cmd = exec.CommandContext(ctx, criuPath, "check", "--all")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("CRIU kernel features check failed: %w (output: %s)", err, string(output))
	}
	
	return nil
}

// Checkpoint creates a checkpoint of the specified container
func (cm *CheckpointManager) Checkpoint(ctx context.Context, container *Container, opts *CheckpointOptions) (*CheckpointMetadata, error) {
	if container == nil || container.Process == nil || container.Process.Process == nil {
		return nil, fmt.Errorf("invalid container or container not running")
	}
	
	if opts == nil {
		opts = &CheckpointOptions{
			ContainerName: container.Config.Runtime.Name,
			CheckpointID:  fmt.Sprintf("checkpoint-%d", time.Now().Unix()),
		}
	}
	
	if opts.ImageDir == "" {
		opts.ImageDir = filepath.Join(cm.imageDir, opts.CheckpointID)
	}
	
	cm.logger.Info("Starting checkpoint operation", 
		"container", opts.ContainerName,
		"checkpoint_id", opts.CheckpointID,
		"pid", container.Process.Process.Pid)
	
	// Create checkpoint directory
	if err := os.MkdirAll(opts.ImageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create checkpoint image directory: %w", err)
	}
	
	// Collect network information
	networkInfo, err := cm.collectNetworkInfo(ctx, container)
	if err != nil {
		cm.logger.Warn("Failed to collect network information", "error", err)
	}
	
	// Collect storage information
	storageInfo, err := cm.collectStorageInfo(ctx, container)
	if err != nil {
		cm.logger.Warn("Failed to collect storage information", "error", err)
	}
	
	// Create checkpoint metadata
	metadata := &CheckpointMetadata{
		ContainerName:   opts.ContainerName,
		CheckpointID:    opts.CheckpointID,
		Timestamp:       time.Now(),
		ContainerPID:    container.Process.Process.Pid,
		ContainerConfig: container.Config,
		CheckpointPath:  opts.ImageDir,
		ImagePath:       opts.ImageDir,
		NetworkInfo:     networkInfo,
		StorageInfo:     storageInfo,
		HookResults:     make(map[string]interface{}),
	}
	
	// Get CRIU version
	if version, err := cm.getCRIUVersion(ctx); err == nil {
		metadata.CRIUVersion = version
	}
	
	// Execute pre-checkpoint hooks
	if opts.EnableHooks {
		if err := cm.executeCheckpointHooks(ctx, CheckpointPhasePreCheckpoint, metadata); err != nil {
			return nil, fmt.Errorf("pre-checkpoint hooks failed: %w", err)
		}
	}
	
	// Perform pre-dump if requested
	if opts.PreDump {
		if err := cm.performPreDump(ctx, container, opts, metadata); err != nil {
			return nil, fmt.Errorf("pre-dump failed: %w", err)
		}
	}
	
	// Perform the actual checkpoint
	if err := cm.performCheckpoint(ctx, container, opts, metadata); err != nil {
		return nil, fmt.Errorf("checkpoint failed: %w", err)
	}
	
	// Save metadata
	if err := cm.saveMetadata(ctx, metadata); err != nil {
		return nil, fmt.Errorf("failed to save checkpoint metadata: %w", err)
	}
	
	// Execute post-checkpoint hooks
	if opts.EnableHooks {
		if err := cm.executeCheckpointHooks(ctx, CheckpointPhasePostCheckpoint, metadata); err != nil {
			cm.logger.Warn("Post-checkpoint hooks failed", "error", err)
		}
	}
	
	cm.logger.Info("Checkpoint completed successfully", 
		"checkpoint_id", opts.CheckpointID,
		"image_dir", opts.ImageDir)
	
	return metadata, nil
}

// Restore restores a container from a checkpoint
func (cm *CheckpointManager) Restore(ctx context.Context, opts *RestoreOptions) (*exec.Cmd, error) {
	if opts == nil || opts.CheckpointID == "" {
		return nil, fmt.Errorf("restore options and checkpoint ID are required")
	}
	
	if opts.ImageDir == "" {
		opts.ImageDir = filepath.Join(cm.imageDir, opts.CheckpointID)
	}
	
	// Load checkpoint metadata
	metadata, err := cm.loadMetadata(ctx, opts.CheckpointID, opts.ImageDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load checkpoint metadata: %w", err)
	}
	
	cm.logger.Info("Starting restore operation",
		"checkpoint_id", opts.CheckpointID,
		"image_dir", opts.ImageDir,
		"original_container", metadata.ContainerName)
	
	// Execute pre-restore hooks
	if opts.EnableHooks {
		if err := cm.executeCheckpointHooks(ctx, CheckpointPhasePreRestore, metadata); err != nil {
			return nil, fmt.Errorf("pre-restore hooks failed: %w", err)
		}
	}
	
	// Perform the actual restore
	cmd, err := cm.performRestore(ctx, opts, metadata)
	if err != nil {
		return nil, fmt.Errorf("restore failed: %w", err)
	}
	
	// Update restore count in metadata
	metadata.RestoreCount++
	if err := cm.saveMetadata(ctx, metadata); err != nil {
		cm.logger.Warn("Failed to update checkpoint metadata", "error", err)
	}
	
	// Execute post-restore hooks
	if opts.EnableHooks {
		if err := cm.executeCheckpointHooks(ctx, CheckpointPhasePostRestore, metadata); err != nil {
			cm.logger.Warn("Post-restore hooks failed", "error", err)
		}
	}
	
	cm.logger.Info("Restore completed successfully",
		"checkpoint_id", opts.CheckpointID,
		"restored_pid", cmd.Process.Pid)
	
	return cmd, nil
}

// performPreDump performs a pre-dump operation to reduce checkpoint time
func (cm *CheckpointManager) performPreDump(ctx context.Context, container *Container, opts *CheckpointOptions, metadata *CheckpointMetadata) error {
	if opts.PreDumpDir == "" {
		opts.PreDumpDir = filepath.Join(opts.ImageDir, "pre-dump")
	}
	
	if err := os.MkdirAll(opts.PreDumpDir, 0755); err != nil {
		return fmt.Errorf("failed to create pre-dump directory: %w", err)
	}
	
	args := []string{
		"pre-dump",
		"--images-dir", opts.PreDumpDir,
		"--tree", fmt.Sprintf("%d", container.Process.Process.Pid),
	}
	
	if opts.ShellJob {
		args = append(args, "--shell-job")
	}
	if opts.EmptyNS {
		args = append(args, "--empty-ns")
	}
	
	// Execute pre-dump hooks
	if opts.EnableHooks {
		if err := cm.executeCheckpointHooks(ctx, CheckpointPhasePreDump, metadata); err != nil {
			return fmt.Errorf("pre-dump hooks failed: %w", err)
		}
	}
	
	cmd := exec.CommandContext(ctx, cm.criuPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("CRIU pre-dump failed: %w (output: %s)", err, string(output))
	}
	
	metadata.PreDumpCount++
	cm.logger.Info("Pre-dump completed successfully", "pre_dump_dir", opts.PreDumpDir)
	
	return nil
}

// performCheckpoint performs the actual checkpoint operation
func (cm *CheckpointManager) performCheckpoint(ctx context.Context, container *Container, opts *CheckpointOptions, metadata *CheckpointMetadata) error {
	args := []string{
		"dump",
		"--images-dir", opts.ImageDir,
		"--tree", fmt.Sprintf("%d", container.Process.Process.Pid),
		"--leave-stopped", // We'll manage the container lifecycle ourselves
	}
	
	// Add optional flags
	if opts.LeaveRunning {
		args = append(args, "--leave-running")
	}
	if opts.FileLocks {
		args = append(args, "--file-locks")
		metadata.FilesystemFreeze = true
	}
	if opts.TCPEstablished {
		args = append(args, "--tcp-established")
		metadata.TCPEstablished = true
	}
	if opts.ExtUnixSockets {
		args = append(args, "--ext-unix-sk")
	}
	if opts.ShellJob {
		args = append(args, "--shell-job")
	}
	if opts.EmptyNS {
		args = append(args, "--empty-ns")
	}
	if opts.AutoDedup {
		args = append(args, "--auto-dedup")
	}
	if opts.LazyPages {
		args = append(args, "--lazy-pages")
	}
	
	// Add pre-dump directory if it exists
	if opts.PreDump && opts.PreDumpDir != "" {
		args = append(args, "--prev-images-dir", opts.PreDumpDir)
	}
	
	// Add extra options
	for key, value := range opts.ExtraOptions {
		if value == "" {
			args = append(args, "--"+key)
		} else {
			args = append(args, "--"+key, value)
		}
	}
	
	cm.logger.Debug("Executing CRIU checkpoint", "args", args)
	
	cmd := exec.CommandContext(ctx, cm.criuPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("CRIU checkpoint failed: %w (output: %s)", err, string(output))
	}
	
	cm.logger.Debug("CRIU checkpoint output", "output", string(output))
	
	return nil
}

// performRestore performs the actual restore operation
func (cm *CheckpointManager) performRestore(ctx context.Context, opts *RestoreOptions, metadata *CheckpointMetadata) (*exec.Cmd, error) {
	args := []string{
		"restore",
		"--images-dir", opts.ImageDir,
	}
	
	// Add optional flags
	if opts.RestorePID > 0 {
		args = append(args, "--restore-pid", fmt.Sprintf("%d", opts.RestorePID))
	}
	if opts.InheritFD {
		args = append(args, "--inherit-fd")
	}
	if opts.EmptyNS {
		args = append(args, "--empty-ns")
	}
	if opts.DetachMode {
		args = append(args, "--restore-detached")
	}
	if opts.LazyPages {
		args = append(args, "--lazy-pages")
	}
	
	// Add extra options
	for key, value := range opts.ExtraOptions {
		if value == "" {
			args = append(args, "--"+key)
		} else {
			args = append(args, "--"+key, value)
		}
	}
	
	cm.logger.Debug("Executing CRIU restore", "args", args)
	
	cmd := exec.CommandContext(ctx, cm.criuPath, args...)
	
	// Start the restore process
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start CRIU restore: %w", err)
	}
	
	// Wait for the process to complete if not in detached mode
	if !opts.DetachMode {
		if err := cmd.Wait(); err != nil {
			return nil, fmt.Errorf("CRIU restore failed: %w", err)
		}
	}
	
	return cmd, nil
}

// collectNetworkInfo collects network information from the running container
func (cm *CheckpointManager) collectNetworkInfo(ctx context.Context, container *Container) (*NetworkCheckpointInfo, error) {
	info := &NetworkCheckpointInfo{}
	
	if container.Config.Runtime.IsRootless {
		return info, nil // Limited network info in rootless mode
	}
	
	// Collect bridge information
	if container.Config.Network.BridgeName != "" {
		info.BridgeName = container.Config.Network.BridgeName
	}
	
	// Extract IP information from environment
	for _, env := range container.Config.Process.Env {
		switch {
		case strings.HasPrefix(env, "CONTAINER_IP4="):
			info.ContainerIP4 = strings.TrimPrefix(env, "CONTAINER_IP4=")
		case strings.HasPrefix(env, "CONTAINER_IP6="):
			info.ContainerIP6 = strings.TrimPrefix(env, "CONTAINER_IP6=")
		}
	}
	
	// Collect veth pair information
	if vethPairs, err := cm.collectVethPairs(ctx, container); err == nil {
		info.VethPairs = vethPairs
	} else {
		cm.logger.Warn("Failed to collect veth pairs", "error", err)
	}
	
	// Collect route table information
	if routeInfo, err := cm.collectRouteInfo(ctx, container); err == nil {
		info.RouteInfo = routeInfo
	} else {
		cm.logger.Warn("Failed to collect route info", "error", err)
	}
	
	return info, nil
}

// collectVethPairs collects veth pair information for the container
func (cm *CheckpointManager) collectVethPairs(ctx context.Context, container *Container) ([]string, error) {
	if container.Process == nil || container.Process.Process == nil || container.Process.Process.Pid <= 0 {
		return nil, fmt.Errorf("invalid container PID")
	}
	
	var vethPairs []string
	
	// List network interfaces in the container's network namespace
	cmd := exec.CommandContext(ctx, "nsenter", "-t", fmt.Sprintf("%d", container.Process.Process.Pid), "-n", "ip", "link", "show")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}
	
	// Parse the output to find veth interfaces
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "@if") && strings.Contains(line, "veth") {
			// Extract veth interface name
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				vethName := strings.TrimSuffix(parts[1], ":")
				vethPairs = append(vethPairs, vethName)
			}
		}
	}
	
	return vethPairs, nil
}

// collectRouteInfo collects routing table information for the container
func (cm *CheckpointManager) collectRouteInfo(ctx context.Context, container *Container) ([]string, error) {
	if container.Process == nil || container.Process.Process == nil || container.Process.Process.Pid <= 0 {
		return nil, fmt.Errorf("invalid container PID")
	}
	
	var routeInfo []string
	
	// Get IPv4 routing table
	cmd := exec.CommandContext(ctx, "nsenter", "-t", fmt.Sprintf("%d", container.Process.Process.Pid), "-n", "ip", "route", "show")
	output, err := cmd.Output()
	if err != nil {
		cm.logger.Warn("Failed to get IPv4 routes", "error", err)
	} else {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			if line != "" {
				routeInfo = append(routeInfo, "ipv4:"+line)
			}
		}
	}
	
	// Get IPv6 routing table
	cmd = exec.CommandContext(ctx, "nsenter", "-t", fmt.Sprintf("%d", container.Process.Process.Pid), "-n", "ip", "-6", "route", "show")
	output, err = cmd.Output()
	if err != nil {
		cm.logger.Warn("Failed to get IPv6 routes", "error", err)
	} else {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines {
			if line != "" {
				routeInfo = append(routeInfo, "ipv6:"+line)
			}
		}
	}
	
	return routeInfo, nil
}

// collectStorageInfo collects storage information from the running container
func (cm *CheckpointManager) collectStorageInfo(ctx context.Context, container *Container) (*StorageCheckpointInfo, error) {
	info := &StorageCheckpointInfo{}
	
	// Collect storage driver information
	if container.Config.Storage.UseDriver && container.Config.Storage.Driver.Driver != "" {
		info.StorageDriver = container.Config.Storage.Driver.Driver
		info.LayerInfo = make(map[string]string)
		info.LayerInfo["driver"] = container.Config.Storage.Driver.Driver
		info.LayerInfo["graph_root"] = container.Config.Storage.Driver.GraphRoot
	}
	
	// Collect mount point information
	for _, volume := range container.Config.Storage.Volumes {
		info.MountPoints = append(info.MountPoints, volume.Dest)
	}
	
	return info, nil
}

// executeCheckpointHooks executes hooks for the specified checkpoint phase
func (cm *CheckpointManager) executeCheckpointHooks(ctx context.Context, phase CheckpointPhase, metadata *CheckpointMetadata) error {
	var hooks []CheckpointHook
	
	switch phase {
	case CheckpointPhasePreDump, CheckpointPhasePreCheckpoint:
		hooks = cm.preHooks
	case CheckpointPhasePostCheckpoint:
		hooks = cm.postHooks
	case CheckpointPhasePreRestore, CheckpointPhasePostRestore:
		hooks = cm.restoreHooks
	}
	
	for _, hook := range hooks {
		if hook.Phase != phase {
			continue
		}
		
		// Check conditions
		if !cm.evaluateHookCondition(ctx, &hook.Condition, metadata) {
			continue
		}
		
		// Execute hook
		if err := cm.executeHook(ctx, &hook, metadata); err != nil {
			switch hook.FailureMode {
			case CheckpointFailureModeIgnore:
				cm.logger.Debug("Hook failed, ignoring", "hook", hook.Name, "error", err)
			case CheckpointFailureModeWarn:
				cm.logger.Warn("Hook failed", "hook", hook.Name, "error", err)
			case CheckpointFailureModeStop:
				cm.logger.Error("Hook failed, stopping checkpoint operation", "hook", hook.Name, "error", err)
				return fmt.Errorf("hook %s failed: %w", hook.Name, err)
			case CheckpointFailureModeFail:
				return fmt.Errorf("hook %s failed: %w", hook.Name, err)
			default:
				cm.logger.Warn("Hook failed", "hook", hook.Name, "error", err)
			}
		}
	}
	
	return nil
}

// evaluateHookCondition evaluates whether a hook condition is met
func (cm *CheckpointManager) evaluateHookCondition(ctx context.Context, condition *CheckpointCondition, metadata *CheckpointMetadata) bool {
	if condition.Type == "" {
		return true // No condition means always execute
	}
	
	switch condition.Type {
	case "env":
		envValue := os.Getenv(condition.Key)
		switch condition.Op {
		case "eq":
			return envValue == condition.Value
		case "ne":
			return envValue != condition.Value
		case "exists":
			return envValue != ""
		case "not_exists":
			return envValue == ""
		}
	case "file":
		switch condition.Op {
		case "exists":
			_, err := os.Stat(condition.Key)
			return err == nil
		case "not_exists":
			_, err := os.Stat(condition.Key)
			return os.IsNotExist(err)
		}
	case "command":
		if condition.Op == "available" {
			_, err := exec.LookPath(condition.Key)
			return err == nil
		}
	}
	
	return false
}

// executeHook executes a single checkpoint hook
func (cm *CheckpointManager) executeHook(ctx context.Context, hook *CheckpointHook, metadata *CheckpointMetadata) error {
	// Use custom handler if available
	if hook.Handler != nil {
		return hook.Handler(ctx, metadata)
	}
	
	// Use external executable
	if hook.Path == "" {
		return fmt.Errorf("hook %s has no path or handler", hook.Name)
	}
	
	timeout := hook.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	
	hookCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	cmd := exec.CommandContext(hookCtx, hook.Path, hook.Args...)
	cmd.Env = append(os.Environ(), hook.Env...)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("CHECKPOINT_ID=%s", metadata.CheckpointID),
		fmt.Sprintf("CHECKPOINT_PHASE=%s", hook.Phase),
		fmt.Sprintf("CONTAINER_NAME=%s", metadata.ContainerName),
		fmt.Sprintf("CONTAINER_PID=%d", metadata.ContainerPID),
		fmt.Sprintf("CHECKPOINT_PATH=%s", metadata.CheckpointPath),
	)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("hook timed out after %v", timeout)
		}
		return fmt.Errorf("hook execution failed: %w (output: %s)", err, string(output))
	}
	
	// Store hook results in metadata
	if metadata.HookResults == nil {
		metadata.HookResults = make(map[string]interface{})
	}
	metadata.HookResults[hook.Name] = map[string]interface{}{
		"output":    string(output),
		"phase":     string(hook.Phase),
		"timestamp": time.Now(),
	}
	
	return nil
}

// getCRIUVersion gets the CRIU version string
func (cm *CheckpointManager) getCRIUVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, cm.criuPath, "check", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	
	// Parse version from output
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if strings.Contains(line, "Version:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1], nil
			}
		}
	}
	
	return "unknown", nil
}

// saveMetadata saves checkpoint metadata to disk
func (cm *CheckpointManager) saveMetadata(ctx context.Context, metadata *CheckpointMetadata) error {
	metadataPath := filepath.Join(metadata.CheckpointPath, "checkpoint-metadata.json")
	
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint metadata: %w", err)
	}
	
	if err := os.WriteFile(metadataPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write checkpoint metadata: %w", err)
	}
	
	return nil
}

// loadMetadata loads checkpoint metadata from disk
func (cm *CheckpointManager) loadMetadata(ctx context.Context, checkpointID, imageDir string) (*CheckpointMetadata, error) {
	metadataPath := filepath.Join(imageDir, "checkpoint-metadata.json")
	
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint metadata: %w", err)
	}
	
	var metadata CheckpointMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal checkpoint metadata: %w", err)
	}
	
	return &metadata, nil
}

// ListCheckpoints lists available checkpoints
func (cm *CheckpointManager) ListCheckpoints(ctx context.Context) ([]*CheckpointMetadata, error) {
	var checkpoints []*CheckpointMetadata
	
	entries, err := os.ReadDir(cm.imageDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint directory: %w", err)
	}
	
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		metadataPath := filepath.Join(cm.imageDir, entry.Name(), "checkpoint-metadata.json")
		if _, err := os.Stat(metadataPath); err != nil {
			continue
		}
		
		metadata, err := cm.loadMetadata(ctx, entry.Name(), filepath.Join(cm.imageDir, entry.Name()))
		if err != nil {
			cm.logger.Warn("Failed to load checkpoint metadata", "checkpoint", entry.Name(), "error", err)
			continue
		}
		
		checkpoints = append(checkpoints, metadata)
	}
	
	return checkpoints, nil
}

// DeleteCheckpoint deletes a checkpoint and its associated data
func (cm *CheckpointManager) DeleteCheckpoint(ctx context.Context, checkpointID string) error {
	checkpointPath := filepath.Join(cm.imageDir, checkpointID)
	
	if _, err := os.Stat(checkpointPath); err != nil {
		return fmt.Errorf("checkpoint not found: %w", err)
	}
	
	if err := os.RemoveAll(checkpointPath); err != nil {
		return fmt.Errorf("failed to delete checkpoint: %w", err)
	}
	
	cm.logger.Info("Checkpoint deleted successfully", "checkpoint_id", checkpointID)
	return nil
}

// AddHook adds a checkpoint hook
func (cm *CheckpointManager) AddHook(hook CheckpointHook) {
	switch hook.Phase {
	case CheckpointPhasePreDump, CheckpointPhasePreCheckpoint:
		cm.preHooks = append(cm.preHooks, hook)
	case CheckpointPhasePostCheckpoint:
		cm.postHooks = append(cm.postHooks, hook)
	case CheckpointPhasePreRestore, CheckpointPhasePostRestore:
		cm.restoreHooks = append(cm.restoreHooks, hook)
	}
}