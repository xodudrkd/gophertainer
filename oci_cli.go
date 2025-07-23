package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
)

// OCI Command Line Interface implementation

// OCICommand represents an OCI runtime command
type OCICommand struct {
	Name        string
	Description string
	Handler     func(ctx context.Context, args []string) error
}

// Available OCI commands per runtime specification
var ociCommands = map[string]OCICommand{
	"create": {
		Name:        "create",
		Description: "Create a container",
		Handler:     handleOCICreate,
	},
	"start": {
		Name:        "start", 
		Description: "Start a container",
		Handler:     handleOCIStart,
	},
	"kill": {
		Name:        "kill",
		Description: "Kill a container",
		Handler:     handleOCIKill,
	},
	"delete": {
		Name:        "delete",
		Description: "Delete a container",
		Handler:     handleOCIDelete,
	},
	"state": {
		Name:        "state",
		Description: "Get container state",
		Handler:     handleOCIState,
	},
	"list": {
		Name:        "list",
		Description: "List containers",
		Handler:     handleOCIList,
	},
	"run": {
		Name:        "run",
		Description: "Create and start a container",
		Handler:     handleOCIRun,
	},
	"spec": {
		Name:        "spec",
		Description: "Generate OCI spec template",
		Handler:     handleOCISpec,
	},
}

// isOCIMode checks if we're running in OCI mode
func isOCIMode() bool {
	// Check if first argument is an OCI command
	if len(os.Args) > 1 {
		_, exists := ociCommands[os.Args[1]]
		return exists
	}
	return false
}

// handleOCIMode handles OCI runtime commands
func handleOCIMode(ctx context.Context) error {
	if len(os.Args) < 2 {
		return printOCIUsage()
	}

	command := os.Args[1]
	cmd, exists := ociCommands[command]
	if !exists {
		return fmt.Errorf("unknown OCI command: %s", command)
	}

	return cmd.Handler(ctx, os.Args[2:])
}

// printOCIUsage prints OCI command usage
func printOCIUsage() error {
	fmt.Printf("Usage: %s <command> [options]\n\n", os.Args[0])
	fmt.Println("OCI Runtime Commands:")
	
	for _, cmd := range ociCommands {
		fmt.Printf("  %-8s %s\n", cmd.Name, cmd.Description)
	}
	
	fmt.Println("\nFor command-specific help, use: <command> --help")
	return nil
}

// handleOCICreate handles the 'create' command
func handleOCICreate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	bundle := fs.String("bundle", ".", "Path to the bundle directory")
	pidFile := fs.String("pid-file", "", "Path to write the container PID")
	
	fs.Usage = func() {
		fmt.Printf("Usage: %s create [options] <container-id>\n\n", os.Args[0])
		fmt.Println("Create a container")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}
	
	if err := fs.Parse(args); err != nil {
		return err
	}
	
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("container ID is required")
	}
	
	containerID := fs.Arg(0)
	
	// Validate container ID
	if err := validateContainerID(containerID); err != nil {
		return fmt.Errorf("invalid container ID: %w", err)
	}
	
	// Create the container
	if err := OCICreate(ctx, containerID, *bundle); err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}
	
	// Write PID file if requested
	if *pidFile != "" {
		// For create command, we don't have a PID yet, so write 0 or skip
		Logger(ctx).Debug("PID file requested but container not started yet", "pidFile", *pidFile)
	}
	
	fmt.Printf("Container %s created successfully\n", containerID)
	return nil
}

// handleOCIStart handles the 'start' command  
func handleOCIStart(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	
	fs.Usage = func() {
		fmt.Printf("Usage: %s start <container-id>\n\n", os.Args[0])
		fmt.Println("Start a container")
	}
	
	if err := fs.Parse(args); err != nil {
		return err
	}
	
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("container ID is required")
	}
	
	containerID := fs.Arg(0)
	
	if err := OCIStart(ctx, containerID); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}
	
	fmt.Printf("Container %s started successfully\n", containerID)
	return nil
}

// handleOCIKill handles the 'kill' command
func handleOCIKill(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("kill", flag.ExitOnError)
	signal := fs.String("signal", "TERM", "Signal to send")
	
	fs.Usage = func() {
		fmt.Printf("Usage: %s kill [options] <container-id>\n\n", os.Args[0])
		fmt.Println("Kill a container")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}
	
	if err := fs.Parse(args); err != nil {
		return err
	}
	
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("container ID is required")
	}
	
	containerID := fs.Arg(0)
	
	if err := OCIKill(ctx, containerID, *signal); err != nil {
		return fmt.Errorf("failed to kill container: %w", err)
	}
	
	fmt.Printf("Signal %s sent to container %s\n", *signal, containerID)
	return nil
}

// handleOCIDelete handles the 'delete' command
func handleOCIDelete(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	force := fs.Bool("force", false, "Force delete even if container is running")
	
	fs.Usage = func() {
		fmt.Printf("Usage: %s delete [options] <container-id>\n\n", os.Args[0])
		fmt.Println("Delete a container")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}
	
	if err := fs.Parse(args); err != nil {
		return err
	}
	
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("container ID is required")
	}
	
	containerID := fs.Arg(0)
	
	// If force is specified, try to kill the container first
	if *force {
		// Ignore errors from kill, container might already be stopped
		OCIKill(ctx, containerID, "KILL")
	}
	
	if err := OCIDelete(ctx, containerID); err != nil {
		return fmt.Errorf("failed to delete container: %w", err)
	}
	
	fmt.Printf("Container %s deleted successfully\n", containerID)
	return nil
}

// handleOCIState handles the 'state' command
func handleOCIState(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("state", flag.ExitOnError)
	
	fs.Usage = func() {
		fmt.Printf("Usage: %s state <container-id>\n\n", os.Args[0])
		fmt.Println("Get container state")
	}
	
	if err := fs.Parse(args); err != nil {
		return err
	}
	
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("container ID is required")
	}
	
	containerID := fs.Arg(0)
	
	state, err := OCIState(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to get container state: %w", err)
	}
	
	// Output state as JSON per OCI spec
	output, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}
	
	fmt.Println(string(output))
	return nil
}

// handleOCIList handles the 'list' command
func handleOCIList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	format := fs.String("format", "table", "Output format (table|json)")
	
	fs.Usage = func() {
		fmt.Printf("Usage: %s list [options]\n\n", os.Args[0])
		fmt.Println("List containers")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}
	
	if err := fs.Parse(args); err != nil {
		return err
	}
	
	containers, err := listOCIContainers()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}
	
	switch *format {
	case "json":
		output, err := json.MarshalIndent(containers, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal containers: %w", err)
		}
		fmt.Println(string(output))
	case "table":
		fmt.Printf("%-20s %-10s %-8s %-30s\n", "ID", "STATUS", "PID", "BUNDLE")
		fmt.Println(strings.Repeat("-", 70))
		for _, container := range containers {
			fmt.Printf("%-20s %-10s %-8d %-30s\n", 
				container.ID, container.Status, container.Pid, container.Bundle)
		}
	default:
		return fmt.Errorf("unknown format: %s", *format)
	}
	
	return nil
}

// handleOCIRun handles the 'run' command (create + start)
func handleOCIRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	bundle := fs.String("bundle", ".", "Path to the bundle directory")
	pidFile := fs.String("pid-file", "", "Path to write the container PID")
	detach := fs.Bool("detach", false, "Run container in background")
	
	fs.Usage = func() {
		fmt.Printf("Usage: %s run [options] <container-id>\n\n", os.Args[0])
		fmt.Println("Create and start a container")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}
	
	if err := fs.Parse(args); err != nil {
		return err
	}
	
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("container ID is required")
	}
	
	containerID := fs.Arg(0)
	
	// Create the container
	if err := OCICreate(ctx, containerID, *bundle); err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}
	
	// Start the container
	if err := OCIStart(ctx, containerID); err != nil {
		// Cleanup on start failure
		OCIDelete(ctx, containerID)
		return fmt.Errorf("failed to start container: %w", err)
	}
	
	// Write PID file if requested
	if *pidFile != "" {
		state, err := OCIState(ctx, containerID)
		if err == nil && state.Pid > 0 {
			pidContent := fmt.Sprintf("%d\n", state.Pid)
			if err := os.WriteFile(*pidFile, []byte(pidContent), 0644); err != nil {
				Logger(ctx).Warn("Failed to write PID file", "pidFile", *pidFile, "error", err)
			}
		}
	}
	
	if *detach {
		fmt.Printf("Container %s started in background\n", containerID)
	} else {
		fmt.Printf("Container %s started\n", containerID)
		// In non-detached mode, we would typically wait for the container to finish
		// For simplicity, we'll just indicate it started
	}
	
	return nil
}

// handleOCISpec handles the 'spec' command
func handleOCISpec(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("spec", flag.ExitOnError)
	output := fs.String("output", "config.json", "Output file for the spec")
	
	fs.Usage = func() {
		fmt.Printf("Usage: %s spec [options]\n\n", os.Args[0])
		fmt.Println("Generate OCI spec template")
		fmt.Println("\nOptions:")
		fs.PrintDefaults()
	}
	
	if err := fs.Parse(args); err != nil {
		return err
	}
	
	spec, err := generateOCISpecTemplate()
	if err != nil {
		return fmt.Errorf("failed to generate spec template: %w", err)
	}
	
	specData, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal spec: %w", err)
	}
	
	if err := os.WriteFile(*output, specData, 0644); err != nil {
		return fmt.Errorf("failed to write spec file: %w", err)
	}
	
	fmt.Printf("OCI spec template generated: %s\n", *output)
	return nil
}

// Helper functions

// validateContainerID validates container ID per OCI requirements
func validateContainerID(id string) error {
	if id == "" {
		return fmt.Errorf("container ID cannot be empty")
	}
	
	if len(id) > 255 {
		return fmt.Errorf("container ID too long (max 255 characters)")
	}
	
	// Container ID must contain only alphanumeric, dash, underscore, and dot
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || 
			 (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return fmt.Errorf("container ID contains invalid character: %c", r)
		}
	}
	
	return nil
}

// listOCIContainers lists all OCI containers
func listOCIContainers() ([]*OCIContainerState, error) {
	runtimeDir := "/run/oci-runtime"
	
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*OCIContainerState{}, nil
		}
		return nil, err
	}
	
	var containers []*OCIContainerState
	runtime := &OCIRuntime{}
	
	for _, entry := range entries {
		if entry.IsDir() {
			state, err := runtime.LoadState(entry.Name())
			if err != nil {
				// Skip containers with invalid state
				continue
			}
			containers = append(containers, state)
		}
	}
	
	return containers, nil
}

// generateOCISpecTemplate generates a basic OCI spec template
func generateOCISpecTemplate() (*specs.Spec, error) {
	spec := &specs.Spec{
		Version: "1.0.2",
		Process: &specs.Process{
			Terminal: true,
			User: specs.User{
				UID: 0,
				GID: 0,
			},
			Args: []string{"/bin/sh"},
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"TERM=xterm",
			},
			Cwd: "/",
			Capabilities: &specs.LinuxCapabilities{
				Bounding: []string{
					"CAP_AUDIT_WRITE",
					"CAP_KILL",
					"CAP_NET_BIND_SERVICE",
				},
				Effective: []string{
					"CAP_AUDIT_WRITE", 
					"CAP_KILL",
					"CAP_NET_BIND_SERVICE",
				},
				Inheritable: []string{
					"CAP_AUDIT_WRITE",
					"CAP_KILL", 
					"CAP_NET_BIND_SERVICE",
				},
				Permitted: []string{
					"CAP_AUDIT_WRITE",
					"CAP_KILL",
					"CAP_NET_BIND_SERVICE",
				},
			},
			Rlimits: []specs.POSIXRlimit{
				{
					Type: "RLIMIT_NOFILE",
					Hard: 1024,
					Soft: 1024,
				},
			},
			NoNewPrivileges: true,
		},
		Root: &specs.Root{
			Path:     "rootfs",
			Readonly: false,
		},
		Hostname: "container",
		Mounts: []specs.Mount{
			{
				Destination: "/proc",
				Type:        "proc",
				Source:      "proc",
			},
			{
				Destination: "/dev",
				Type:        "tmpfs",
				Source:      "tmpfs",
				Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
			},
			{
				Destination: "/dev/pts",
				Type:        "devpts",
				Source:      "devpts",
				Options:     []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"},
			},
			{
				Destination: "/sys",
				Type:        "sysfs",
				Source:      "sysfs",
				Options:     []string{"nosuid", "noexec", "nodev", "ro"},
			},
		},
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.PIDNamespace},
				{Type: specs.NetworkNamespace},
				{Type: specs.IPCNamespace},
				{Type: specs.UTSNamespace},
				{Type: specs.MountNamespace},
			},
			Resources: &specs.LinuxResources{
				Memory: &specs.LinuxMemory{
					Limit: int64Ptr(256 * 1024 * 1024), // 256MB
				},
				CPU: &specs.LinuxCPU{
					Shares: uint64Ptr(1024),
				},
			},
		},
	}
	
	return spec, nil
}

// Helper function to create int64 pointer
func int64Ptr(v int64) *int64 {
	return &v
}

// Helper function to create uint64 pointer
func uint64Ptr(v uint64) *uint64 {
	return &v
}