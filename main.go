package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// main is the entry point for the program. It dispatches between the parent
// (container manager) and child (container process) logic.
func main() {
	// The "child" argument is a special token to indicate that this process
	// should run as the container's init process inside the new namespaces.
	if len(os.Args) > 1 && os.Args[1] == "child" {
		cfg := &Config{}
		// The child process receives its configuration via its standard input
		// from the parent process to avoid passing complex data via command-line args.
		if err := json.NewDecoder(os.Stdin).Decode(cfg); err != nil {
			// Use a raw Fprintf here because the logger might not be initialized.
			fmt.Fprintf(os.Stderr, "FATAL: Failed to decode config in child: %v\n", err)
			os.Exit(1)
		}

		// Re-initialize logger in the child with the received config.
		// Disable logging for interactive mode to avoid interference
		var logger *slog.Logger
		if cfg.Process.Interactive {
			// Use a no-op logger for interactive shells
			logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
		} else {
			logger = initLogger()
		}
		ctx := WithLogger(context.Background(), logger)

		if err := runChild(ctx, cfg); err != nil {
			logger.Error("Container init failed", "error", err)
			os.Exit(1)
		}
		return
	}

	logger := initLogger()
	ctx := WithLogger(context.Background(), logger)
	
	// Initialize dependency injection container
	if err := InitializeDependencies(ctx); err != nil {
		logger.Error("Failed to initialize dependencies", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := ShutdownDependencies(ctx); err != nil {
			logger.Error("Failed to shutdown dependencies", "error", err)
		}
	}()
	
	// Get dependencies
	deps := GetDeps()
	
	// Initialize security hardening first (non-interactive by default in parent)
	if err := InitializeSecurityHardening(ctx, false); err != nil {
		logger.Error("Failed to initialize security hardening", "error", err)
		deps.MetricsCollector.IncrementSecurityErrors()
		os.Exit(1)
	}
	
	// Initialize monitoring and recovery systems
	if err := InitializeMonitoringAndRecovery(ctx); err != nil {
		logger.Error("Failed to initialize monitoring and recovery", "error", err)
		os.Exit(1)
	}
	
	// Initialize graceful shutdown handling
	InitGracefulShutdown(ctx)
	
	// Check if we're running in OCI mode
	if isOCIMode() {
		if err := handleOCIMode(ctx); err != nil {
			logger.Error("OCI command failed", "error", err)
			os.Exit(1)
		}
		return
	}

	// Check for checkpoint/restore subcommands
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "checkpoint":
			if err := handleCheckpointCommand(ctx, os.Args[2:]); err != nil {
				logger.Error("Checkpoint command failed", "error", err)
				os.Exit(1)
			}
			return
		case "restore":
			if err := handleRestoreCommand(ctx, os.Args[2:]); err != nil {
				logger.Error("Restore command failed", "error", err)
				os.Exit(1)
			}
			return
		case "checkpoint-list":
			if err := handleCheckpointListCommand(ctx, os.Args[2:]); err != nil {
				logger.Error("Checkpoint list command failed", "error", err)
				os.Exit(1)
			}
			return
		case "checkpoint-delete":
			if err := handleCheckpointDeleteCommand(ctx, os.Args[2:]); err != nil {
				logger.Error("Checkpoint delete command failed", "error", err)
				os.Exit(1)
			}
			return
		}
	}

	// If not in "child" mode, run as the parent process.
	cfg, err := parseFlags()
	if err != nil {
		logger.Error("Invalid configuration", "error", err)
		flag.Usage()
		os.Exit(1)
	}

	if cfg.Runtime.IsDryRun {
		logger.Info("DRY RUN MODE: No changes will be made to the system.")
	}

	// Perform dependency validation early.
	if err := validateEnvironment(cfg); err != nil {
		logger.Error("Environment validation failed", "error", err, "suggestion", "Please install missing dependencies or run with --rootless if you are not root.")
		os.Exit(1)
	}
	
	// Perform comprehensive security validation
	if err := validateConfigSecurely(cfg); err != nil {
		logger.Error("Security validation failed", "error", err)
		GetDeps().MetricsCollector.IncrementSecurityErrors()
		os.Exit(1)
	}

	if err := runContainer(ctx, cfg); err != nil {
		logger.Error("Container runtime failed", "error", err)
		GetDeps().MetricsCollector.IncrementFailedContainers()
		os.Exit(1)
	}
}

// runContainer is the main entry point for the parent process. It sets up the
// environment and launches the child process in new namespaces.
func runContainer(ctx context.Context, cfg *Config) (err error) {
	
	// Initialize container tracking and metrics
	startTime := time.Now()
	defer func() {
		deps := GetDeps()
		if err != nil {
			deps.MetricsCollector.IncrementFailedContainers()
		}
		deps.MetricsCollector.RecordAllocationLatency(time.Since(startTime))
	}()

	// Prepare container configuration and environment
	container, err := prepareContainer(ctx, cfg)
	if err != nil {
		return fmt.Errorf("container preparation failed: %w", err)
	}
	defer container.cleanup(ctx)

	// Create and configure child process
	cmd, configPipe, err := createChildProcess(ctx, container)
	if err != nil {
		return fmt.Errorf("child process creation failed: %w", err)
	}

	// Setup child process execution environment
	if err = setupChildExecution(ctx, container, cmd); err != nil {
		return fmt.Errorf("child execution setup failed: %w", err)
	}

	// Start child process and handle lifecycle
	return executeChildProcess(ctx, container, cmd, configPipe)
}

// prepareContainer initializes and configures the container instance
func prepareContainer(ctx context.Context, cfg *Config) (*Container, error) {
	logger := Logger(ctx).With("component", "container-prep")
	deps := GetDeps()
	
	// Track container metrics
	deps.MetricsCollector.IncrementContainerCount()

	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Setup rootless mode if needed
	if cfg.Runtime.IsRootless {
		if err := loadIDMappings(logger, &cfg.Runtime); err != nil {
			logger.Warn("Failed to auto-load ID mappings for rootless mode. This may be expected if you provide them manually.", "error", err)
		}
	}

	// Initialize IP allocator for non-rootless mode
	if err := initializeNetworking(cfg); err != nil {
		return nil, fmt.Errorf("network initialization failed: %w", err)
	}

	// Cleanup any stale resources
	if err := cleanupStaleResources(ctx, cfg); err != nil {
		logger.Warn("Pre-cleanup of stale resources failed. This may be okay.", "error", err)
	}

	// Create container instance
	ctrCtx, cancel := context.WithCancel(ctx)
	container := &Container{
		Config: cfg,
		ctx:    ctrCtx,
		cancel: cancel,
		state:  StateCreated,
	}
	container.stateChange.L = &container.mu
	
	// Initialize enhanced hook system
	if err := container.initializeHookManager(ctx); err != nil {
		logger.Warn("Failed to initialize enhanced hook system, using legacy hooks", "error", err)
	}
	
	// Initialize checkpoint functionality if enabled
	if cfg.Runtime.Checkpoint.Enabled || cfg.Runtime.Checkpoint.AutoEnable {
		workDir := cfg.Runtime.Checkpoint.WorkDir
		if workDir == "" {
			workDir = "/var/lib/gophertainer/checkpoints"
		}
		
		if err := container.EnableCheckpointing(ctx, workDir); err != nil {
			if cfg.Runtime.StrictMode {
				return nil, fmt.Errorf("failed to enable checkpoint functionality in strict mode: %w", err)
			}
			logger.Warn("Failed to enable checkpoint functionality", "error", err)
		} else {
			logger.Info("Checkpoint functionality initialized", "workdir", workDir)
		}
	}
	
	// Register for shutdown management
	globalShutdown.RegisterContainer(cfg.Runtime.Name, container)
	
	return container, nil
}

// initializeNetworking sets up network configuration for the container
func initializeNetworking(cfg *Config) error {
	if cfg.Runtime.IsRootless {
		return nil // Skip network setup in rootless mode
	}

	_, ipNet4, err := net.ParseCIDR(cfg.Network.NetworkCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse network CIDR: %w", err)
	}
	
	var ipNet6 *net.IPNet
	if cfg.Network.IPv6CIDR != "" {
		_, ipNet6, err = net.ParseCIDR(cfg.Network.IPv6CIDR)
		if err != nil {
			return fmt.Errorf("failed to parse IPv6 network CIDR: %w", err)
		}
	}
	
	cfg.Network.IPAllocator = NewIPAllocator(ipNet4, ipNet6)
	return nil
}

// createChildProcess creates and configures the child process
func createChildProcess(ctx context.Context, container *Container) (*exec.Cmd, io.WriteCloser, error) {
	// The child process is invoked by executing the current binary with "child" as the first argument.
	cmd := exec.CommandContext(container.ctx, "/proc/self/exe", "child")

	configPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create config pipe for child: %w", err)
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Configure namespaces and process attributes
	if err := configureProcessAttributes(cmd, container.Config); err != nil {
		return nil, nil, fmt.Errorf("failed to configure process attributes: %w", err)
	}

	// Create sync pipe for parent-child coordination
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create sync pipe: %w", err)
	}
	
	// Pass write end to child, keep read end for parent
	cmd.ExtraFiles = []*os.File{w}
	container.Process = cmd
	
	// Store read end for later use in waitForChildReady
	container.syncPipeRead = r

	return cmd, configPipe, nil
}

// configureProcessAttributes sets up namespaces and process attributes
func configureProcessAttributes(cmd *exec.Cmd, cfg *Config) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:   syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC,
		Unshareflags: syscall.CLONE_NEWNS, // Needed for pivot_root to work.
	}

	if !cfg.Runtime.IsRootless {
		cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNET
	}

	if cfg.Runtime.IsRootless {
		if err := configureRootless(cmd, &cfg.Runtime); err != nil {
			return fmt.Errorf("failed to configure rootless settings: %w", err)
		}
	}

	return nil
}

// setupChildExecution prepares the child process for execution
func setupChildExecution(ctx context.Context, container *Container, cmd *exec.Cmd) error {
	logger := Logger(ctx).With("component", "child-setup")
	
	// Start the child process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start child process: %w", err)
	}
	
	childPid := cmd.Process.Pid
	logger.Info("Started container", "pid", childPid, "name", container.Config.Runtime.Name, "rootless", container.Config.Runtime.IsRootless)

	// Set cgroup name if not provided
	if container.Config.Cgroup.Name == "" {
		container.Config.Cgroup.Name = fmt.Sprintf("gophertainer-%s-%d", container.Config.Runtime.Name, childPid)
	}

	// Setup cgroups and networking if not in dry-run mode
	if !container.Config.Runtime.IsDryRun {
		if err := setupContainerResources(ctx, container, childPid); err != nil {
			cmd.Process.Kill()
			return fmt.Errorf("resource setup failed: %w", err)
		}
	}

	return nil
}

// setupContainerResources configures cgroups and networking for the container
func setupContainerResources(ctx context.Context, container *Container, childPid int) error {
	if err := container.setupCgroup(ctx, childPid); err != nil {
		return fmt.Errorf("cgroup setup failed: %w", err)
	}
	// Add cgroup cleanup
	container.addCleanup("cgroup", func() error {
		return container.cleanupCgroupResources(ctx)
	})

	if err := container.setupNetwork(ctx, childPid); err != nil {
		return fmt.Errorf("network setup failed: %w", err)
	}
	// Add network cleanup
	container.addCleanup("network", func() error {
		return container.cleanupNetworkResources(ctx)
	})
	
	// Add loop device cleanup
	container.addCleanup("loop-devices", func() error {
		return container.cleanupLoopDevices(ctx)
	})

	return nil
}

// executeChildProcess handles the child process lifecycle and communication
func executeChildProcess(ctx context.Context, container *Container, cmd *exec.Cmd, configPipe io.WriteCloser) error {
	logger := Logger(ctx).With("component", "child-execution")
	
	// Send configuration to child process
	if err := sendConfigToChild(ctx, container, configPipe); err != nil {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return fmt.Errorf("config transmission failed: %w", err)
	}

	// Wait for child to signal readiness
	if err := waitForChildReady(ctx, container, cmd); err != nil {
		return fmt.Errorf("child readiness failed: %w", err)
	}

	// Setup cgroups and networking now that the child is ready and waiting.
	if !container.Config.Runtime.IsDryRun {
		if err := setupContainerResources(ctx, container, cmd.Process.Pid); err != nil {
			cmd.Process.Kill()
			return fmt.Errorf("resource setup failed post-child-readiness: %w", err)
		}
	}

	// Run prestart hooks
	if err := container.runHook(ctx, "prestart"); err != nil {
		if container.Config.Runtime.StrictMode {
			cmd.Process.Kill()
			return fmt.Errorf("prestart hook failed in strict mode: %w", err)
		}
		logger.Warn("Prestart hook failed", "error", err)
	}

	// Apply timeout if specified
	if container.Config.Runtime.Timeout > 0 {
		var timeoutCancel context.CancelFunc
		container.ctx, timeoutCancel = context.WithTimeout(container.ctx, container.Config.Runtime.Timeout)
		defer timeoutCancel()
	}

	// Start signal handling and update state
	go container.enhancedHandleSignals(ctx)
	container.setState(StateRunning)

	// Wait for process completion
	err := cmd.Wait()
	container.cancel() // Stop signal handler and other goroutines

	// Run poststop hooks
	if hookErr := container.runHook(context.Background(), "poststop"); hookErr != nil {
		logger.Warn("Poststop hook failed", "error", hookErr)
	}

	// Handle exit status
	if exitErr, ok := err.(*exec.ExitError); ok {
		logger.Info("Container exited", "code", exitErr.ExitCode())
		if exitErr.ExitCode() == 0 {
			return nil
		}
	}
	return err
}

// sendConfigToChild sends the container configuration to the child process synchronously.
func sendConfigToChild(ctx context.Context, container *Container, configPipe io.WriteCloser) error {
	logger := Logger(ctx).With("component", "config-send")

	// Perform a direct, blocking write of the configuration.
	if err := json.NewEncoder(configPipe).Encode(container.Config); err != nil {
		// Do not close the pipe here; the calling function will kill the process,
		// which cleans up the pipe automatically.
		return fmt.Errorf("failed to encode and send config to child: %w", err)
	}

	// On success, close the pipe to signal EOF to the child's decoder.
	if err := configPipe.Close(); err != nil {
		logger.Warn("Failed to close config pipe to child after successful write", "error", err)
	}

	return nil
}

// waitForChildReady waits for the child process to signal readiness
func waitForChildReady(ctx context.Context, container *Container, cmd *exec.Cmd) error {
	// Use the stored sync pipe read end
	if container.syncPipeRead == nil {
		return errors.New("no sync pipe available")
	}
	
	syncPipeRead := container.syncPipeRead
	defer syncPipeRead.Close()

	// Wait for child to signal readiness
	if err := waitForChild(syncPipeRead, cmd); err != nil {
		return err // Error already contains context from child
	}

	return nil
}

// runStorageHook executes a storage-related hook in the child process
func runStorageHook(ctx context.Context, cfg *Config, hookType string) error {
	hook, ok := cfg.Runtime.Hooks[hookType]
	if !ok || hook.Path == "" {
		return nil // No hook defined for this type
	}
	
	logger := Logger(ctx).With("component", "storage-hook")
	logger.Info("Running storage hook", "type", hookType, "path", hook.Path)
	
	// Validate hook path for security
	if !filepath.IsAbs(hook.Path) {
		return fmt.Errorf("hook path must be absolute: %s", hook.Path)
	}
	if _, err := os.Stat(hook.Path); err != nil {
		return fmt.Errorf("hook executable not found: %w", err)
	}
	
	timeout := hook.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}
	
	hookCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	cmd := exec.CommandContext(hookCtx, hook.Path, hook.Args...)
	cmd.Env = append(os.Environ(), hook.Env...)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("CONTAINER_NAME=%s", cfg.Runtime.Name),
		fmt.Sprintf("HOOK_TYPE=%s", hookType),
		fmt.Sprintf("ROOTFS_SOURCE=%s", cfg.Storage.RootFSSource),
	)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(hookCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("storage hook '%s' timed out after %v", hookType, timeout)
		}
		return fmt.Errorf("storage hook '%s' failed: %w (output: %s)", hookType, err, string(output))
	}
	
	return nil
}

// runChild executes inside the new namespaces and sets up the container environment
// before executing the user-specified command.
func runChild(ctx context.Context, cfg *Config) error {
	// Additional security hardening for child process
	if err := applyChildSecurityHardening(); err != nil {
		return fmt.Errorf("child security hardening failed: %w", err)
	}
	
	logger := Logger(ctx).With("context", "child", "pid", os.Getpid())

	pipe := os.NewFile(syncPipeFD, "pipe")
	if pipe == nil {
		// This is a fatal error before we can even communicate with the parent.
		return fmt.Errorf("sync pipe at fd %d is nil", syncPipeFD)
	}
	defer pipe.Close()

	// sendError marshals an error and sends it to the parent, then returns the original error.
	sendError := func(phase string, err error) error {
		logger.Error("Child setup failed", "phase", phase, "error", err)
		errData, jsonErr := json.Marshal(ChildError{Phase: phase, Msg: err.Error(), Err: err})
		if jsonErr != nil {
			// If we can't even marshal the error, send a plain text version.
			fallbackMsg := fmt.Sprintf("{\"phase\":\"%s\",\"msg\":\"%s (json marshal failed: %s)\"}", phase, err.Error(), jsonErr.Error())
			pipe.Write([]byte(fallbackMsg))
		} else {
			pipe.Write(errData)
		}
		return err // Return the original error to be logged and cause exit.
	}

	if cfg.Runtime.IsDryRun {
		logger.Info("[dry-run] Child would set up container environment here.")
		pipe.Write([]byte("1")) // Signal success
		return executeCommand(ctx, &cfg.Process)
	}

	if cfg.Process.InitProcess {
		go reapChildren(logger)
	}

	// Execute pre-mount storage hooks
	// Note: In child process, we need to create a temporary container-like state for hooks
	if len(cfg.Runtime.Hooks) > 0 {
		if err := runStorageHook(ctx, cfg, "storage.pre_mount"); err != nil {
			return sendError("storage_hook", fmt.Errorf("storage pre-mount hook failed: %w", err))
		}
	}
	
	rootfsPath, isTemp, err := prepareRootfs(ctx, &cfg.Storage, cfg.Runtime.Name)
	if err != nil {
		return sendError("rootfs", fmt.Errorf("rootfs preparation failed: %w", err))
	}
	
	// Execute post-mount storage hooks
	if len(cfg.Runtime.Hooks) > 0 {
		if err := runStorageHook(ctx, cfg, "storage.post_mount"); err != nil {
			logger.Warn("Storage post-mount hook failed", "error", err)
			// Don't fail the container for post-mount hook failure
		}
	}
	if isTemp {
		defer func() {
			if err := unmountPath(ctx, rootfsPath); err != nil {
				logger.Warn("Failed to unmount temporary rootfs", "path", rootfsPath, "error", err)
			}
			os.RemoveAll(rootfsPath)
		}()
	}

	if err := mountVolumes(ctx, cfg.Storage.Volumes, rootfsPath); err != nil {
		return sendError("volumes", fmt.Errorf("volume mounting failed: %w", err))
	}

	if err := setupHostsEntries(cfg.Network.Hosts, cfg.Network.DNS, rootfsPath); err != nil {
		return sendError("hosts", fmt.Errorf("hosts entry setup failed: %w", err))
	}

	if err := pivotRoot(logger, rootfsPath); err != nil {
		return sendError("pivot", fmt.Errorf("pivot_root failed: %w", err))
	}

	// Final validation of rootfs before executing command
	// Use "/" as rootfs path since we've pivoted to the new root
	if !cfg.Runtime.SkipSecurityValidation {
		if err := validateRootfs("/"); err != nil {
			return sendError("rootfs_validation", fmt.Errorf("rootfs validation failed after pivot: %w", err))
		}
	}

	if err := setupMounts(ctx, cfg.Storage.Mounts); err != nil {
		return sendError("mounts", fmt.Errorf("standard mount setup failed: %w", err))
	}

	if err := unix.Sethostname([]byte(cfg.Runtime.Name)); err != nil {
		return sendError("hostname", fmt.Errorf("sethostname failed: %w", err))
	}

	if cfg.Process.NoNewPrivs {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return sendError("no_new_privs", fmt.Errorf("failed to set NO_NEW_PRIVS: %w", err))
		}
	}

	if err := applyCapabilities(logger, &cfg.Process); err != nil {
		return sendError("capabilities", fmt.Errorf("failed to apply capabilities: %w", err))
	}

	if err := applySeccomp(ctx, &cfg.Process); err != nil {
		return sendError("seccomp", fmt.Errorf("failed to apply seccomp profile: %w", err))
	}

	if cfg.Process.WorkDir != "" {
		if err := os.Chdir(cfg.Process.WorkDir); err != nil {
			return sendError("workdir", fmt.Errorf("failed to change to workdir '%s': %w", cfg.Process.WorkDir, err))
		}
	}

	// Signal to parent that setup is complete.
	if _, err := pipe.Write([]byte("1")); err != nil {
		// If we can't signal, the parent will time out and kill us, so we just log and proceed.
		logger.Error("Failed to signal parent on sync pipe, parent will likely time out", "error", err)
	}
	pipe.Close()

	// Set up network after parent has prepared the veth interface
	if err := setupContainerNetwork(ctx, cfg); err != nil {
		return sendError("network", fmt.Errorf("container network setup failed: %w", err))
	}

	return executeCommand(ctx, &cfg.Process)
}

// --- Main Helper Functions ---

func parseFlags() (*Config, error) {
	cfg := &Config{
		Runtime: RuntimeConfig{
			Hooks: make(map[string]HookConfig),
		},
		Process: ProcessConfig{
			SignalMap: make(map[os.Signal]bool),
		},
		Network: NetworkConfig{
			DNS: []string{"8.8.8.8", "8.8.4.4"}, // Default DNS servers
		},
	}

	defaultName := fmt.Sprintf("gophertainer-%d", os.Getpid())

	flag.StringVar(&cfg.Process.Command, "cmd", "", "Command to execute (required unless -i is used, wrap in quotes)")
	flag.BoolVar(&cfg.Process.Interactive, "i", false, "Run interactive shell instead of specified command")
	flag.BoolVar(&cfg.Process.TTY, "t", false, "Allocate a pseudo-TTY for the process")
	flag.StringVar(&cfg.Storage.RootFSSource, "rootfs", "", "Path to rootfs directory, .tar, or .img file (required)")
	flag.StringVar(&cfg.Runtime.Name, "name", defaultName, "Container name")
	flag.BoolVar(&cfg.Runtime.IsDryRun, "dry-run", false, "Dry run mode (log actions without executing them)")
	flag.BoolVar(&cfg.Runtime.IsRootless, "rootless", false, "Enable rootless container mode (requires user/group mappings)")
	flag.BoolVar(&cfg.Runtime.StrictMode, "strict", false, "Exit immediately if non-critical operations (like hooks) fail")
	flag.BoolVar(&cfg.Runtime.SkipSecurityValidation, "skip-security-validation", false, "Skip rootfs security validation (allows world-writable files)")
	flag.DurationVar(&cfg.Runtime.Timeout, "timeout", 0, "Container execution timeout (e.g., 30s, 5m)")
	flag.StringVar(&cfg.Network.BridgeName, "bridge", "gophertainer0", "Network bridge name")
	flag.StringVar(&cfg.Network.NetworkCIDR, "net", "172.16.0.0/24", "IPv4 CIDR for the container network")
	flag.StringVar(&cfg.Network.IPv6CIDR, "net6", "", "IPv6 CIDR for the container network (optional)")
	
	// CNI networking flags
	flag.BoolVar(&cfg.Network.CNI.Enabled, "cni", false, "Enable CNI networking instead of bridge networking")
	flag.StringVar(&cfg.Network.CNI.NetworkName, "cni-network", "", "Name of the CNI network to use (required when --cni is enabled)")
	flag.StringVar(&cfg.Network.CNI.ConfigDir, "cni-config-dir", "", "Directory containing CNI configuration files")
	
	flag.Int64Var(&cfg.Cgroup.MemoryLimit, "mem", 256, "Memory limit in megabytes (MB)")
	flag.Float64Var(&cfg.Cgroup.CPULimit, "cpu", 1.0, "CPU limit (e.g., 0.5 for 50%, 2.0 for 2 cores)")
	flag.Int64Var(&cfg.Cgroup.PidsLimit, "pids", 100, "Process limit for the container")
	flag.Int64Var(&cfg.Cgroup.StackLimit, "stack", 8, "Stack limit in megabytes (MB)")
	flag.Int64Var(&cfg.Cgroup.MsgQueueLimit, "msg-queue", 16384, "Message queue limit in bytes")
	flag.Int64Var(&cfg.Cgroup.NiceLimit, "nice", 40, "Maximum nice value for the container")
	flag.BoolVar(&cfg.Process.InitProcess, "init", false, "Run a minimal init process inside the container to reap zombies")
	flag.BoolVar(&cfg.Process.NoNewPrivs, "no-new-privs", true, "Set the no_new_privs bit for the container process")
	flag.StringVar(&cfg.Process.SeccompProfile, "seccomp", DefaultSeccompProfileName, `Path to a seccomp JSON profile. Use "unconfined" to disable, or "default" for the built-in profile.`)

	flag.Parse()

	if (cfg.Process.Command == "" && !cfg.Process.Interactive) || cfg.Storage.RootFSSource == "" {
		return nil, errors.New("missing required flags: --rootfs and either --cmd or -i (interactive)")
	}

	// Auto-enable TTY for interactive mode (user can still disable with explicit --t=false if needed)
	if cfg.Process.Interactive {
		cfg.Process.TTY = true
	}

	// Validate CNI configuration
	if cfg.Network.CNI.Enabled {
		if cfg.Network.CNI.NetworkName == "" {
			return nil, errors.New("--cni-network is required when --cni is enabled")
		}
	}

	cfg.Process.SignalMap[syscall.SIGINT] = true
	cfg.Process.SignalMap[syscall.SIGTERM] = true
	cfg.Process.SignalMap[syscall.SIGHUP] = true

	return cfg, nil
}

func validateEnvironment(cfg *Config) error {
	if cfg == nil {
		return errors.New("config cannot be nil")
	}
	
	// Validate container name early
	if cfg.Runtime.Name == "" {
		return errors.New("container name cannot be empty")
	}
	if len(cfg.Runtime.Name) > 255 {
		return fmt.Errorf("container name too long (%d chars): max 255", len(cfg.Runtime.Name))
	}
	
	if !cfg.Runtime.IsRootless && os.Getuid() != 0 {
		return errors.New("must run as root or enable --rootless mode. Root is required for network and cgroup setup without user namespaces")
	}

	required := []string{"sh"}
	if !cfg.Runtime.IsRootless {
		required = append(required, "ip")
	}
	if strings.HasSuffix(cfg.Storage.RootFSSource, ".img") {
		required = append(required, "losetup", "blkid")
	}

	var missing []string
	for _, bin := range required {
		if _, err := exec.LookPath(bin); err != nil {
			missing = append(missing, bin)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("required binaries not found in PATH: %s", strings.Join(missing, ", "))
	}
	
	// Additional validation for critical paths
	if cfg.Storage.RootFSSource == "" {
		return errors.New("rootfs source cannot be empty")
	}
	
	return nil
}

func waitForChild(r *os.File, cmd *exec.Cmd) error {
	if r == nil {
		return errors.New("sync pipe reader cannot be nil")
	}
	if cmd == nil {
		return errors.New("command cannot be nil")
	}
	if cmd.Process == nil {
		return errors.New("process cannot be nil")
	}
	
	readyChan := make(chan error, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				readyChan <- fmt.Errorf("panic in waitForChild goroutine: %v", rec)
			}
			close(readyChan)
		}()
		
		buf := make([]byte, 1024) // Increased buffer size for more detailed error messages
		n, err := r.Read(buf)
		if err != nil {
			readyChan <- fmt.Errorf("sync pipe read failed: %w", err)
			return
		}

		// The success signal is a single byte '1'.
		if n == 1 && string(buf[:n]) == "1" {
			readyChan <- nil
			return
		}

		// If it's not the success signal, it must be a JSON-encoded ChildError.
		var childErr ChildError
		if jsonErr := json.Unmarshal(buf[:n], &childErr); jsonErr != nil {
			// If we can't decode the error, present the raw data for debugging.
			readyChan <- fmt.Errorf("child sent unexpected data on sync pipe: '%s' (json decode error: %v)", string(buf[:n]), jsonErr)
		} else {
			// The decoded error provides structured context from the child.
			readyChan <- childErr
		}
	}()

	select {
	case err := <-readyChan:
		if err != nil {
			if cmd.Process != nil {
				cmd.Process.Kill() // Ensure the child is terminated on setup failure
			}
			return fmt.Errorf("child setup failed: %w", err)
		}
		return nil
	case <-time.After(pipeTimeout):
		if cmd.Process != nil {
			cmd.Process.Kill() // Terminate the child if it times out
		}
		return fmt.Errorf("timed out waiting for child to be ready after %v", pipeTimeout)
	}
}

func initLogger() *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if os.Getenv("DEBUG") != "" {
		opts.Level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

func Logger(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}


// --- Checkpoint Command Handlers ---

func handleCheckpointCommand(ctx context.Context, args []string) error {
	logger := Logger(ctx)
	
	if len(args) < 1 {
		return fmt.Errorf("usage: gophertainer checkpoint <container-name> [options]")
	}
	
	containerName := args[0]
	
	// Parse checkpoint options from remaining args
	opts := &CheckpointOptions{
		ContainerName: containerName,
		EnableHooks:   true,
	}
	
	// Simple argument parsing for checkpoint options
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--checkpoint-id":
			if i+1 >= len(args) {
				return fmt.Errorf("--checkpoint-id requires a value")
			}
			opts.CheckpointID = args[i+1]
			i++
		case "--image-dir":
			if i+1 >= len(args) {
				return fmt.Errorf("--image-dir requires a value")
			}
			opts.ImageDir = args[i+1]
			i++
		case "--leave-running":
			opts.LeaveRunning = true
		case "--tcp-established":
			opts.TCPEstablished = true
		case "--file-locks":
			opts.FileLocks = true
		case "--pre-dump":
			opts.PreDump = true
		case "--shell-job":
			opts.ShellJob = true
		case "--no-hooks":
			opts.EnableHooks = false
		}
	}
	
	// Set default checkpoint ID if not provided
	if opts.CheckpointID == "" {
		opts.CheckpointID = fmt.Sprintf("%s-checkpoint-%d", containerName, time.Now().Unix())
	}
	
	// Find the running container by name (this is a simplified lookup)
	container, err := findRunningContainer(ctx, containerName)
	if err != nil {
		return fmt.Errorf("failed to find running container: %w", err)
	}
	
	// Create checkpoint manager
	workDir := "/var/lib/gophertainer/checkpoints"
	cm, err := NewCheckpointManager(ctx, workDir)
	if err != nil {
		return fmt.Errorf("failed to create checkpoint manager: %w", err)
	}
	
	// Perform checkpoint
	metadata, err := cm.Checkpoint(ctx, container, opts)
	if err != nil {
		return fmt.Errorf("checkpoint failed: %w", err)
	}
	
	logger.Info("Container checkpointed successfully",
		"container", containerName,
		"checkpoint_id", metadata.CheckpointID,
		"image_path", metadata.ImagePath)
	
	fmt.Printf("Checkpoint created successfully:\n")
	fmt.Printf("  Container: %s\n", metadata.ContainerName)
	fmt.Printf("  Checkpoint ID: %s\n", metadata.CheckpointID)
	fmt.Printf("  Image Path: %s\n", metadata.ImagePath)
	fmt.Printf("  Timestamp: %s\n", metadata.Timestamp.Format(time.RFC3339))
	
	return nil
}

func handleRestoreCommand(ctx context.Context, args []string) error {
	logger := Logger(ctx)
	
	if len(args) < 1 {
		return fmt.Errorf("usage: gophertainer restore <checkpoint-id> [options]")
	}
	
	checkpointID := args[0]
	
	// Parse restore options from remaining args
	opts := &RestoreOptions{
		CheckpointID: checkpointID,
		EnableHooks:  true,
	}
	
	// Simple argument parsing for restore options
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--image-dir":
			if i+1 >= len(args) {
				return fmt.Errorf("--image-dir requires a value")
			}
			opts.ImageDir = args[i+1]
			i++
		case "--detach":
			opts.DetachMode = true
		case "--inherit-fd":
			opts.InheritFD = true
		case "--no-hooks":
			opts.EnableHooks = false
		}
	}
	
	// Create checkpoint manager
	workDir := "/var/lib/gophertainer/checkpoints"
	cm, err := NewCheckpointManager(ctx, workDir)
	if err != nil {
		return fmt.Errorf("failed to create checkpoint manager: %w", err)
	}
	
	// Perform restore
	cmd, err := cm.Restore(ctx, opts)
	if err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}
	
	logger.Info("Container restored successfully",
		"checkpoint_id", checkpointID,
		"restored_pid", cmd.Process.Pid)
	
	fmt.Printf("Container restored successfully:\n")
	fmt.Printf("  Checkpoint ID: %s\n", checkpointID)
	fmt.Printf("  Restored PID: %d\n", cmd.Process.Pid)
	
	if !opts.DetachMode {
		// Wait for the restored process
		err := cmd.Wait()
		if err != nil {
			logger.Warn("Restored process exited with error", "error", err)
		}
	}
	
	return nil
}

func handleCheckpointListCommand(ctx context.Context, args []string) error {
	// Create checkpoint manager
	workDir := "/var/lib/gophertainer/checkpoints"
	cm, err := NewCheckpointManager(ctx, workDir)
	if err != nil {
		return fmt.Errorf("failed to create checkpoint manager: %w", err)
	}
	
	// List checkpoints
	checkpoints, err := cm.ListCheckpoints(ctx)
	if err != nil {
		return fmt.Errorf("failed to list checkpoints: %w", err)
	}
	
	if len(checkpoints) == 0 {
		fmt.Println("No checkpoints found.")
		return nil
	}
	
	fmt.Printf("Available checkpoints:\n\n")
	fmt.Printf("%-30s %-20s %-20s %-10s %s\n", "CHECKPOINT ID", "CONTAINER", "TIMESTAMP", "RESTORES", "IMAGE PATH")
	fmt.Printf("%-30s %-20s %-20s %-10s %s\n", 
		strings.Repeat("-", 30), 
		strings.Repeat("-", 20), 
		strings.Repeat("-", 20), 
		strings.Repeat("-", 10),
		strings.Repeat("-", 20))
	
	for _, checkpoint := range checkpoints {
		fmt.Printf("%-30s %-20s %-20s %-10d %s\n",
			checkpoint.CheckpointID,
			checkpoint.ContainerName,
			checkpoint.Timestamp.Format("2006-01-02 15:04:05"),
			checkpoint.RestoreCount,
			checkpoint.ImagePath)
	}
	
	return nil
}

func handleCheckpointDeleteCommand(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: gophertainer checkpoint-delete <checkpoint-id>")
	}
	
	checkpointID := args[0]
	
	// Create checkpoint manager
	workDir := "/var/lib/gophertainer/checkpoints"
	cm, err := NewCheckpointManager(ctx, workDir)
	if err != nil {
		return fmt.Errorf("failed to create checkpoint manager: %w", err)
	}
	
	// Delete checkpoint
	if err := cm.DeleteCheckpoint(ctx, checkpointID); err != nil {
		return fmt.Errorf("failed to delete checkpoint: %w", err)
	}
	
	fmt.Printf("Checkpoint '%s' deleted successfully.\n", checkpointID)
	return nil
}

// findRunningContainer finds a running container by name using multiple detection methods
func findRunningContainer(ctx context.Context, name string) (*Container, error) {
	logger := Logger(ctx)
	
	// Method 1: Look for container processes by cgroup
	if container, err := findContainerByCgroup(ctx, name); err == nil {
		logger.Info("Found container via cgroup", "name", name, "pid", container.Process.Process.Pid)
		return container, nil
	}
	
	// Method 2: Look for processes with container-specific environment
	if container, err := findContainerByEnvironment(ctx, name); err == nil {
		logger.Info("Found container via environment", "name", name, "pid", container.Process.Process.Pid)
		return container, nil
	}
	
	// Method 3: Look for processes by command line pattern
	if container, err := findContainerByProcess(ctx, name); err == nil {
		logger.Info("Found container via process name", "name", name, "pid", container.Process.Process.Pid)
		return container, nil
	}
	
	return nil, fmt.Errorf("container '%s' not found or not running", name)
}

// findContainerByCgroup looks for container in cgroup hierarchy
func findContainerByCgroup(ctx context.Context, name string) (*Container, error) {
	cgroupPath := fmt.Sprintf("/sys/fs/cgroup/gophertainer-%s", name)
	if _, err := os.Stat(cgroupPath); os.IsNotExist(err) {
		cgroupPath = fmt.Sprintf("/sys/fs/cgroup/gophertainer-%s-*", name)
		matches, err := filepath.Glob(cgroupPath)
		if err != nil || len(matches) == 0 {
			return nil, fmt.Errorf("cgroup not found")
		}
		cgroupPath = matches[0]
	}
	
	// Read the cgroup.procs file to get PIDs
	procsFile := filepath.Join(cgroupPath, "cgroup.procs")
	data, err := os.ReadFile(procsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read cgroup procs: %w", err)
	}
	
	pids := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(pids) == 0 || pids[0] == "" {
		return nil, fmt.Errorf("no processes in cgroup")
	}
	
	// Use the first PID (usually the main container process)
	pid, err := strconv.Atoi(pids[0])
	if err != nil {
		return nil, fmt.Errorf("invalid PID: %w", err)
	}
	
	return createContainerFromPID(ctx, name, pid)
}

// findContainerByEnvironment looks for processes with container-specific environment variables
func findContainerByEnvironment(ctx context.Context, name string) (*Container, error) {
	cmd := exec.CommandContext(ctx, "pgrep", "-f", fmt.Sprintf("CONTAINER_NAME=%s", name))
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("no process found with container environment")
	}
	
	pidStr := strings.TrimSpace(string(output))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid PID: %w", err)
	}
	
	return createContainerFromPID(ctx, name, pid)
}

// findContainerByProcess looks for processes by command line pattern
func findContainerByProcess(ctx context.Context, name string) (*Container, error) {
	cmd := exec.CommandContext(ctx, "pgrep", "-f", name)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("no process found")
	}
	
	pidStr := strings.TrimSpace(string(output))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return nil, fmt.Errorf("invalid PID: %w", err)
	}
	
	return createContainerFromPID(ctx, name, pid)
}

// createContainerFromPID creates a Container object from a PID
func createContainerFromPID(ctx context.Context, name string, pid int) (*Container, error) {
	// Verify the process exists
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
		return nil, fmt.Errorf("process %d does not exist", pid)
	}
	
	// Create a basic container structure
	container := &Container{
		Config: &Config{
			Runtime: RuntimeConfig{Name: name},
		},
		ctx: ctx,
	}
	
	// Create a dummy exec.Cmd to hold the process info
	cmd := &exec.Cmd{}
	cmd.Process = &os.Process{Pid: pid}
	container.Process = cmd
	
	return container, nil
}