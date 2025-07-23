package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Container represents the running container instance.
type Container struct {
	Config      *Config
	Process     *exec.Cmd
	CleanupFunc []CleanupFunc
	mu          sync.RWMutex // Use RWMutex for better read performance
	ctx         context.Context
	cancel      context.CancelFunc
	state       ContainerState
	stateChange sync.Cond // For signaling state changes
	once        sync.Once  // For one-time operations like cleanup
	
	// Enhanced hook support
	hookManager *HookManager
	
	// Checkpoint support
	checkpointManager *CheckpointManager
	checkpointEnabled bool
	
	// Sync pipe for parent-child coordination
	syncPipeRead *os.File
}

// CleanupFunc represents a cleanup function with metadata
type CleanupFunc struct {
	Name string
	Fn   func() error // Return error for better error handling
}

// ContainerState represents the current state of the container
type ContainerState int

const (
	StateCreated ContainerState = iota
	StateRunning
	StateStopped
	StateError
)

func (s ContainerState) String() string {
	switch s {
	case StateCreated:
		return "created"
	case StateRunning:
		return "running"
	case StateStopped:
		return "stopped"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// --- Container Methods (Parent-side Setup) ---

func (c *Container) setupCgroup(ctx context.Context, pid int) error {
	if c == nil || c.Config == nil {
		return errors.New("invalid container or config")
	}
	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}
	
	// Skip cgroup setup in rootless mode if we don't have the necessary permissions
	if c.Config.Runtime.IsRootless && os.Getuid() != 0 {
		Logger(ctx).Info("Skipping cgroup setup in rootless mode (requires root or cgroup delegation)")
		return nil
	}

	if os.Getuid() != 0 && !c.Config.Runtime.IsRootless {
		return fmt.Errorf("cgroup setup requires root privileges, but running as non-root without --rootless")
	}

	if c.Config.Cgroup.Version == "" || c.Config.Cgroup.Version == "auto" {
		if _, err := os.Stat(filepath.Join(cgroupV2Path, "cgroup.controllers")); err == nil {
			c.Config.Cgroup.Version = "v2"
		} else {
			c.Config.Cgroup.Version = "v1"
		}
	}

	Logger(ctx).Info("Setting up cgroup", "version", c.Config.Cgroup.Version)
	var err error
	switch c.Config.Cgroup.Version {
	case "v2":
		err = c.setupCgroupV2(ctx, pid)
	case "v1":
		err = c.setupCgroupV1(ctx, pid)
	default:
		err = fmt.Errorf("unsupported cgroup version: %s", c.Config.Cgroup.Version)
	}

	if err != nil {
		if c.Config.Runtime.StrictMode {
			return fmt.Errorf("cgroup setup failed in strict mode: %w", err)
		}
		Logger(ctx).Warn("Cgroup setup failed, continuing without resource limits", "error", err)
	}
	return nil
}

func (c *Container) setupCgroupV2(ctx context.Context, pid int) error {
	logger := Logger(ctx)

	// In rootless mode, the cgroup path is relative to the user's delegated cgroup slice.
	cgroupPath := filepath.Join(cgroupV2Path, c.Config.Cgroup.Name)
	if c.Config.Runtime.IsRootless {
		userSlice := fmt.Sprintf("user-%d.slice", os.Getuid())
		delegatedPath := filepath.Join(cgroupV2Path, "user.slice", userSlice)
		if _, err := os.Stat(delegatedPath); err == nil {
			cgroupPath = filepath.Join(delegatedPath, c.Config.Cgroup.Name)
			logger.Debug("Using delegated cgroup path", "path", cgroupPath)
		} else {
			// If a delegated path doesn't exist, we likely can't create cgroups.
			logger.Warn("Rootless mode active but no delegated cgroup found. Resource limits may not be applied.")
			return nil
		}
	}

	if err := os.MkdirAll(cgroupPath, 0755); err != nil {
		return fmt.Errorf("failed to create cgroup v2 directory: %w", err)
	}
	c.addCleanup("cgroup-v2", func() error {
		cleanupCgroupV2(ctx, cgroupPath)
		return nil
	})

	// Enable all available controllers for the new cgroup.
	if !c.Config.Runtime.IsRootless {
		parentControllers, err := os.ReadFile(filepath.Join(filepath.Dir(cgroupPath), "cgroup.controllers"))
		if err != nil {
			logger.Warn("Could not read parent cgroup controllers, some limits may not apply", "error", err)
		} else {
			// Enable controllers one by one.
			controllerPath := filepath.Join(cgroupPath, "cgroup.subtree_control")
			for _, controller := range strings.Fields(string(parentControllers)) {
				if err := os.WriteFile(controllerPath, []byte("+"+controller), 0644); err != nil {
					logger.Warn("Failed to enable controller for cgroup", "controller", controller, "path", controllerPath, "error", err)
				}
			}
		}
	}

	limits := make(map[string]string)
	if c.Config.Cgroup.MemoryLimit > 0 {
		limits["memory.max"] = fmt.Sprintf("%d", c.Config.Cgroup.MemoryLimit*1024*1024)
	}
	if c.Config.Cgroup.PidsLimit > 0 {
		limits["pids.max"] = fmt.Sprintf("%d", c.Config.Cgroup.PidsLimit)
	}
	if c.Config.Cgroup.CPULimit > 0 {
		period := 100000 // Standard CFS period
		quota := int(float64(period) * c.Config.Cgroup.CPULimit)
		if quota < 1000 { // Minimum quota is 1ms
			quota = 1000
		}
		limits["cpu.max"] = fmt.Sprintf("%d %d", quota, period)
	}

	for file, value := range limits {
		if err := os.WriteFile(filepath.Join(cgroupPath, file), []byte(value), 0644); err != nil {
			// This is not fatal; the controller might just not be available.
			logger.Warn("Failed to set cgroup v2 limit, controller may be unavailable", "file", file, "error", err)
		}
	}

	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		return fmt.Errorf("failed to add process to cgroup.procs: %w", err)
	}
	return nil
}

func (c *Container) setupCgroupV1(ctx context.Context, pid int) error {
	logger := Logger(ctx)
	subsystems := []string{"memory", "cpu", "pids"}

	for _, subsys := range subsystems {
		cgroupPath := filepath.Join(cgroupV1Path, subsys, c.Config.Cgroup.Name)
		if _, err := os.Stat(filepath.Join(cgroupV1Path, subsys)); os.IsNotExist(err) {
			logger.Warn("Cgroup v1 subsystem not found, skipping", "subsystem", subsys)
			continue
		}

		if err := os.MkdirAll(cgroupPath, 0755); err != nil {
			return fmt.Errorf("failed to create %s cgroup v1 directory: %w", subsys, err)
		}
		c.addCleanup(fmt.Sprintf("cgroup-v1-%s", subsys), func() error {
			return os.Remove(cgroupPath)
		})

		switch subsys {
		case "memory":
			if c.Config.Cgroup.MemoryLimit > 0 {
				limitFile := filepath.Join(cgroupPath, "memory.limit_in_bytes")
				limitValue := fmt.Sprintf("%d", c.Config.Cgroup.MemoryLimit*1024*1024)
				if err := os.WriteFile(limitFile, []byte(limitValue), 0644); err != nil {
					logger.Warn("Failed to set cgroup v1 memory limit", "error", err)
				}
			}
		case "cpu":
			if c.Config.Cgroup.CPULimit > 0 {
				period := 100000 // Standard CFS period
				quota := int(float64(period) * c.Config.Cgroup.CPULimit)
				if quota < 1000 { // Minimum quota is 1ms
					quota = 1000
				}
				periodFile := filepath.Join(cgroupPath, "cpu.cfs_period_us")
				quotaFile := filepath.Join(cgroupPath, "cpu.cfs_quota_us")

				if err := os.WriteFile(periodFile, []byte(fmt.Sprintf("%d", period)), 0644); err != nil {
					logger.Warn("Failed to set cgroup v1 CPU period", "error", err)
				}
				if err := os.WriteFile(quotaFile, []byte(fmt.Sprintf("%d", quota)), 0644); err != nil {
					logger.Warn("Failed to set cgroup v1 CPU quota", "error", err)
				}
			}
			if c.Config.Cgroup.CPUShares > 0 {
				sharesFile := filepath.Join(cgroupPath, "cpu.shares")
				if err := os.WriteFile(sharesFile, []byte(fmt.Sprintf("%d", c.Config.Cgroup.CPUShares)), 0644); err != nil {
					logger.Warn("Failed to set cgroup v1 CPU shares", "error", err)
				}
			}
		case "pids":
			if c.Config.Cgroup.PidsLimit > 0 {
				limitFile := filepath.Join(cgroupPath, "pids.max")
				if err := os.WriteFile(limitFile, []byte(fmt.Sprintf("%d", c.Config.Cgroup.PidsLimit)), 0644); err != nil {
					logger.Warn("Failed to set cgroup v1 pids limit", "error", err)
				}
			}
		}

		// Add process to the cgroup
		if err := os.WriteFile(filepath.Join(cgroupPath, "tasks"), []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
			// This is more critical than setting the limits, so return an error.
			return fmt.Errorf("failed to add process to cgroup v1 subsystem %s: %w", subsys, err)
		}
	}
	return nil
}

func (c *Container) setupNetwork(ctx context.Context, pid int) error {
	if c == nil || c.Config == nil {
		return errors.New("invalid container or config")
	}
	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}
	
	logger := Logger(ctx).With("component", "network-setup")
	
	// Execute pre-setup network hooks
	if err := c.runHookPhase(ctx, HookPhaseNetworkPreSetup); err != nil {
		return fmt.Errorf("network pre-setup hooks failed: %w", err)
	}

	if c.Config.Runtime.IsRootless {
		logger.Info("Skipping bridge network setup in rootless mode")
		// In a truly rootless scenario, networking might be handled by slirp4netns
		// or by inheriting the host network namespace. For now, we do nothing.
		return nil
	}

	// Check if CNI networking is enabled
	if c.Config.Network.CNI.Enabled {
		logger.Info("Using CNI networking")
		return c.setupCNINetwork(ctx, pid)
	}
	
	logger.Info("Using bridge networking")
	return c.setupBridgeNetwork(ctx, pid)
}

// setupCNINetwork sets up networking using CNI plugins
func (c *Container) setupCNINetwork(ctx context.Context, pid int) error {
	logger := Logger(ctx).With("component", "cni-setup")
	
	// Create CNI manager
	cniManager, err := NewCNIManager(ctx, &c.Config.Network.CNI)
	if err != nil {
		return fmt.Errorf("failed to create CNI manager: %w", err)
	}
	
	// Validate CNI configuration
	if err := cniManager.ValidateConfig(ctx); err != nil {
		return fmt.Errorf("CNI validation failed: %w", err)
	}
	
	// Get network namespace path
	netNS := fmt.Sprintf("/proc/%d/ns/net", pid)
	containerID := c.Config.Runtime.Name
	
	// Setup network using CNI
	result, err := cniManager.SetupNetwork(ctx, containerID, netNS)
	if err != nil {
		return fmt.Errorf("CNI network setup failed: %w", err)
	}
	
	// Add CNI cleanup function
	c.addCleanup("cni-network", func() error {
		return cniManager.TeardownNetwork(context.Background(), containerID, netNS)
	})
	
	// Extract network information from CNI result and set environment variables
	if err := c.setCNIEnvironmentVariables(result); err != nil {
		logger.Warn("Failed to set CNI environment variables", "error", err)
	}
	
	logger.Info("CNI network setup completed", 
		"container_id", containerID, 
		"interfaces", len(result.Interfaces),
		"ips", len(result.IPs))
	
	return nil
}

// setupBridgeNetwork sets up networking using traditional bridge networking
func (c *Container) setupBridgeNetwork(ctx context.Context, pid int) error {
	logger := Logger(ctx).With("component", "bridge-setup")
	
	// Create atomic network setup with rollback
	networkGuard := NewCriticalResourceGuard()
	defer func() {
		if err := recover(); err != nil {
			logger.Error("Network setup panic, rolling back", "panic", err)
			networkGuard.Release()
			panic(err) // Re-panic after cleanup
		}
	}()
	
	// Atomic operation wrapper
	var networkErr error
	defer func() {
		if networkErr != nil {
			logger.Error("Network setup failed, rolling back", "error", networkErr)
			if errs := networkGuard.Release(); len(errs) > 0 {
				logger.Error("Rollback errors during network cleanup", "errors", errs)
			}
		}
	}()

	// Create or find the bridge atomically
	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: c.Config.Network.BridgeName}}
	bridgeCreated := false
	if err := netlink.LinkAdd(bridge); err != nil {
		if !errors.Is(err, os.ErrExist) {
			networkErr = fmt.Errorf("failed to create bridge '%s': %w", c.Config.Network.BridgeName, err)
			return networkErr
		}
	} else {
		bridgeCreated = true
		// Add bridge cleanup to guard
		networkGuard.Add(func() error {
			if bridgeCreated {
				if br, err := netlink.LinkByName(c.Config.Network.BridgeName); err == nil {
					return netlink.LinkDel(br)
				}
			}
			return nil
		})
	}

	br, err := netlink.LinkByName(c.Config.Network.BridgeName)
	if err != nil {
		networkErr = fmt.Errorf("failed to get bridge by name: %w", err)
		return networkErr
	}

	// Configure IP addresses on the bridge atomically
	if err := c.configureBridgeIPs(ctx, br); err != nil {
		networkErr = fmt.Errorf("failed to configure bridge IPs: %w", err)
		return networkErr
	}

	// Bring the bridge up
	if err := netlink.LinkSetUp(br); err != nil {
		networkErr = fmt.Errorf("failed to bring up bridge: %w", err)
		return networkErr
	}

	// Create veth pair
	randBytes := make([]byte, 4)
	if _, err := rand.Read(randBytes); err != nil {
		return fmt.Errorf("failed to generate random bytes for veth name: %w", err)
	}
	vethName := fmt.Sprintf("veth-%x", randBytes)
	peerName := fmt.Sprintf("vethp-%x", randBytes)

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: vethName, MTU: 1500},
		PeerName:  peerName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		networkErr = fmt.Errorf("failed to create veth pair: %w", err)
		return networkErr
	}
	
	// Track veth pair for cleanup
	vethID := fmt.Sprintf("veth:%s", vethName)
	globalResourceManager.TrackResource(vethID, ResourceTypeNetworkInterface, vethName, func() error {
		if link, err := netlink.LinkByName(vethName); err == nil {
			return netlink.LinkDel(link)
		}
		return nil
	})
	
	// Add to network guard for rollback
	networkGuard.Add(func() error {
		if link, err := netlink.LinkByName(vethName); err == nil {
			return netlink.LinkDel(link)
		}
		return nil
	})

	// Attach host side of veth to the bridge atomically
	hostVeth, err := netlink.LinkByName(vethName)
	if err != nil {
		networkErr = fmt.Errorf("failed to get host veth interface: %w", err)
		return networkErr
	}
	if err := netlink.LinkSetMaster(hostVeth, br); err != nil {
		networkErr = fmt.Errorf("failed to attach veth to bridge: %w", err)
		return networkErr
	}
	if err := netlink.LinkSetUp(hostVeth); err != nil {
		networkErr = fmt.Errorf("failed to bring up host veth: %w", err)
		return networkErr
	}

	// Move peer side of veth to the container's network namespace atomically
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		networkErr = fmt.Errorf("failed to get peer veth interface: %w", err)
		return networkErr
	}
	if err := netlink.LinkSetNsPid(peer, pid); err != nil {
		networkErr = fmt.Errorf("failed to move veth peer to container namespace: %w", err)
		return networkErr
	}

	// Allocate IP for the container atomically
	key := fmt.Sprintf("container-%s", c.Config.Runtime.Name)
	ip4 := c.Config.Network.IPAllocator.AllocateIPv4(key)
	if ip4 == nil {
		networkErr = fmt.Errorf("failed to allocate IPv4 address for container %s", key)
		return networkErr
	}
	
	// Add IP release to guard for rollback
	networkGuard.Add(func() error {
		c.Config.Network.IPAllocator.Release(key)
		return nil
	})
	
	// Add to container cleanup for normal operation
	c.addCleanup("ip-release", func() error {
		c.Config.Network.IPAllocator.Release(key)
		return nil
	})

	// Pass all necessary network info to the child via environment variables.
	// This is more robust than relying on the child to re-calculate things.
	c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_IP4=%s", ip4))
	c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_NET_CIDR=%s", c.Config.Network.NetworkCIDR))
	c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_GW_IP4=%s", c.Config.Network.IPAllocator.network4.IP))

	if c.Config.Network.IPv6CIDR != "" {
		ip6 := c.Config.Network.IPAllocator.AllocateIPv6(key)
		if ip6 != nil {
			c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_IP6=%s", ip6))
			c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_NET6_CIDR=%s", c.Config.Network.IPv6CIDR))
			c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_GW_IP6=%s", c.Config.Network.IPAllocator.network6.IP))
		}
	}

	// Network setup completed successfully, clear rollback guard
	networkGuard = NewCriticalResourceGuard() // Clear rollback actions
	
	logger.Info("Network configured successfully", "veth", vethName, "ip", ip4, "bridge", c.Config.Network.BridgeName)
	
	// Execute post-setup network hooks
	if err := c.runHookPhase(ctx, HookPhaseNetworkPostSetup); err != nil {
		logger.Warn("Network post-setup hooks failed", "error", err)
		// Don't return error here as network is already configured
	}
	
	return nil
}

// setCNIEnvironmentVariables extracts network information from CNI result and sets environment variables
func (c *Container) setCNIEnvironmentVariables(result *CNIResult) error {
	if result == nil {
		return fmt.Errorf("CNI result is nil")
	}
	
	// Extract IP addresses
	for i, ip := range result.IPs {
		// Set container IP environment variables
		if ip.Version == "4" {
			c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_IP4=%s", ip.Address))
			if ip.Gateway != "" {
				c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_GW_IP4=%s", ip.Gateway))
			}
		} else if ip.Version == "6" {
			c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_IP6=%s", ip.Address))
			if ip.Gateway != "" {
				c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_GW_IP6=%s", ip.Gateway))
			}
		}
		
		// For multiple IPs, add indexed versions
		if len(result.IPs) > 1 {
			c.Config.Process.Env = append(c.Config.Process.Env, 
				fmt.Sprintf("CONTAINER_IP%d_VERSION=%s", i, ip.Version))
			c.Config.Process.Env = append(c.Config.Process.Env, 
				fmt.Sprintf("CONTAINER_IP%d_ADDRESS=%s", i, ip.Address))
			if ip.Gateway != "" {
				c.Config.Process.Env = append(c.Config.Process.Env, 
					fmt.Sprintf("CONTAINER_IP%d_GATEWAY=%s", i, ip.Gateway))
			}
		}
	}
	
	// Extract interface information
	for i, iface := range result.Interfaces {
		if i == 0 && iface.Name != "" {
			c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_INTERFACE=%s", iface.Name))
		}
		
		// For multiple interfaces, add indexed versions
		if len(result.Interfaces) > 1 {
			c.Config.Process.Env = append(c.Config.Process.Env, 
				fmt.Sprintf("CONTAINER_INTERFACE%d_NAME=%s", i, iface.Name))
			if iface.Mac != "" {
				c.Config.Process.Env = append(c.Config.Process.Env, 
					fmt.Sprintf("CONTAINER_INTERFACE%d_MAC=%s", i, iface.Mac))
			}
		}
	}
	
	// Extract DNS information
	if len(result.DNS.Nameservers) > 0 {
		nameservers := strings.Join(result.DNS.Nameservers, ",")
		c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_DNS=%s", nameservers))
	}
	
	if result.DNS.Domain != "" {
		c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_DNS_DOMAIN=%s", result.DNS.Domain))
	}
	
	if len(result.DNS.Search) > 0 {
		searchDomains := strings.Join(result.DNS.Search, ",")
		c.Config.Process.Env = append(c.Config.Process.Env, fmt.Sprintf("CONTAINER_DNS_SEARCH=%s", searchDomains))
	}
	
	return nil
}

func (c *Container) setupRootlessNetwork(ctx context.Context, pid int) error {
	// In rootless mode, we can use slirp4netns or similar
	// For now, just set up lo interface which the child can configure
	Logger(ctx).Info("Using host network namespace in rootless mode")
	return nil
}

func (c *Container) configureBridgeIPs(ctx context.Context, br netlink.Link) error {
	// Allocate and assign IPv4 address to the bridge
	ip4 := c.Config.Network.IPAllocator.AllocateIPv4("bridge")
	if ip4 == nil {
		return fmt.Errorf("failed to allocate bridge IPv4 address")
	}
	addr4 := &netlink.Addr{IPNet: &net.IPNet{
		IP:   ip4,
		Mask: c.Config.Network.IPAllocator.network4.Mask,
	}}
	if err := netlink.AddrAdd(br, addr4); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("failed to add IPv4 address to bridge: %w", err)
	}

	// Allocate and assign IPv6 address to the bridge if configured
	if c.Config.Network.IPv6CIDR != "" && c.Config.Network.IPAllocator.network6 != nil {
		ip6 := c.Config.Network.IPAllocator.AllocateIPv6("bridge")
		if ip6 != nil {
			addr6 := &netlink.Addr{IPNet: &net.IPNet{
				IP:   ip6,
				Mask: c.Config.Network.IPAllocator.network6.Mask,
			}}
			if err := netlink.AddrAdd(br, addr6); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("failed to add IPv6 address to bridge: %w", err)
			}
		}
	}
	return nil
}

func (c *Container) runHook(ctx context.Context, hookType string) error {
	if c == nil || c.Config == nil {
		return errors.New("invalid container or config")
	}
	if hookType == "" {
		return errors.New("hook type cannot be empty")
	}
	
	// Use enhanced hook system if available
	if c.hookManager != nil {
		return c.runHookPhase(ctx, HookPhase(hookType))
	}
	
	// Fallback to legacy hook implementation
	return c.runLegacyHook(ctx, hookType)
}

// runHookPhase executes hooks using the enhanced hook system
func (c *Container) runHookPhase(ctx context.Context, phase HookPhase) error {
	if c.hookManager == nil {
		return c.runLegacyHook(ctx, string(phase)) // Fallback to existing implementation
	}
	
	state := &HookContainerState{
		Config: c.Config,
		State:  c.getState().String(),
	}
	
	if c.Process != nil {
		state.Process = c.Process.Process
	}
	
	return c.hookManager.ExecuteHooks(ctx, phase, state)
}

// runLegacyHook provides the original hook implementation
func (c *Container) runLegacyHook(ctx context.Context, hookType string) error {
	hook, ok := c.Config.Runtime.Hooks[hookType]
	if !ok || hook.Path == "" {
		return nil // No hook defined for this type
	}
	
	// Validate hook path for security
	if !filepath.IsAbs(hook.Path) {
		return fmt.Errorf("hook path must be absolute: %s", hook.Path)
	}
	if _, err := os.Stat(hook.Path); err != nil {
		return fmt.Errorf("hook executable not found: %w", err)
	}

	logger := Logger(ctx)
	logger.Info("Running legacy hook", "type", hookType, "path", hook.Path)

	timeout := hook.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, hook.Path, hook.Args...)
	cmd.Env = append(os.Environ(), hook.Env...)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("CONTAINER_NAME=%s", c.Config.Runtime.Name),
		fmt.Sprintf("HOOK_TYPE=%s", hookType),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("hook '%s' timed out after %v", hookType, timeout)
		}
		return fmt.Errorf("hook '%s' failed: %w (output: %s)", hookType, err, string(output))
	}
	return nil
}

// initializeHookManager initializes the enhanced hook system
func (c *Container) initializeHookManager(ctx context.Context) error {
	if c == nil {
		return errors.New("container cannot be nil")
	}
	
	// Create hook manager
	c.hookManager = NewHookManager(ctx)
	
	// Load hooks from configuration directories
	configDirs := []string{
		"/etc/gophertainer/hooks",
		"/usr/local/etc/gophertainer/hooks",
	}
	
	// Add user-specific config directory if HOME is set
	if home := os.Getenv("HOME"); home != "" {
		configDirs = append(configDirs, filepath.Join(home, ".config/gophertainer/hooks"))
	}
	
	registry := NewHookRegistry(ctx, c.hookManager, configDirs)
	if err := registry.LoadHooks(ctx); err != nil {
		return fmt.Errorf("failed to load hooks: %w", err)
	}
	
	Logger(ctx).Info("Hook manager initialized", "config_dirs", len(configDirs))
	return nil
}

func (c *Container) handleSignals(ctx context.Context) {
	if c == nil || c.Config == nil {
		return
	}
	
	logger := Logger(ctx)
	sigChan := make(chan os.Signal, 1)
	signals := make([]os.Signal, 0, len(c.Config.Process.SignalMap))
	for sig := range c.Config.Process.SignalMap {
		signals = append(signals, sig)
	}
	
	if len(signals) == 0 {
		logger.Debug("No signals configured for forwarding")
		return
	}
	
	signal.Notify(sigChan, signals...)
	defer signal.Stop(sigChan)

	for {
		select {
		case sig := <-sigChan:
			if c.Process != nil && c.Process.Process != nil {
				logger.Debug("Forwarding signal to container", "signal", sig, "pid", c.Process.Process.Pid)
				if err := c.Process.Process.Signal(sig); err != nil {
					logger.Warn("Failed to forward signal", "signal", sig, "error", err)
				}
			} else {
				logger.Warn("Cannot forward signal: process not available", "signal", sig)
			}
		case <-c.ctx.Done():
			if errors.Is(c.ctx.Err(), context.DeadlineExceeded) && c.Process != nil && c.Process.Process != nil {
				logger.Warn("Container timed out, sending SIGKILL", "pid", c.Process.Process.Pid)
				c.Process.Process.Kill()
			}
			return
		}
	}
}

func (c *Container) addCleanup(name string, fn func() error) {
	if c == nil {
		Logger(context.Background()).Error("Cannot add cleanup to nil container")
		return
	}
	if fn == nil {
		Logger(context.Background()).Error("Cannot add nil cleanup function")
		return
	}
	if name == "" {
		name = fmt.Sprintf("unnamed-%d", len(c.CleanupFunc))
	}
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Check if already in cleanup phase - atomically check and add
	if c.state == StateStopped {
		// If already stopped, run cleanup immediately in background
		go func() {
			defer func() {
				if r := recover(); r != nil {
					Logger(context.Background()).Error("Cleanup function panicked", "name", name, "panic", r)
				}
			}()
			if err := fn(); err != nil {
				Logger(context.Background()).Error("Immediate cleanup failed", "name", name, "error", err)
			}
		}()
		return
	}
	
	// Check for duplicate cleanup names to prevent conflicts
	for _, existing := range c.CleanupFunc {
		if existing.Name == name {
			Logger(context.Background()).Warn("Duplicate cleanup function name, skipping", "name", name)
			return
		}
	}
	
	// Prepend so cleanup happens in reverse order of setup
	cleanupFunc := CleanupFunc{Name: name, Fn: fn}
	c.CleanupFunc = append([]CleanupFunc{cleanupFunc}, c.CleanupFunc...)
}




// --- Child-side Setup Functions ---

func pivotRoot(logger *slog.Logger, newRoot string) error {
	// Mount newRoot onto itself as a bind mount. This is a prerequisite for pivot_root.
	if err := unix.Mount(newRoot, newRoot, "bind", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("failed to bind mount new_root: %w", err)
	}

	// Create a directory to hold the old root.
	putOld := filepath.Join(newRoot, ".pivot_root")
	if err := os.MkdirAll(putOld, 0700); err != nil {
		return fmt.Errorf("failed to create .pivot_root directory: %w", err)
	}
	defer os.RemoveAll(putOld)

	// Pivot the root filesystem.
	if err := unix.PivotRoot(newRoot, putOld); err != nil {
		// If pivot_root fails, attempt to clean up and fall back to chroot.
		logger.Warn("pivot_root failed, falling back to chroot", "error", err)
		if err := unix.Chroot(newRoot); err != nil {
			return fmt.Errorf("chroot fallback also failed: %w", err)
		}
		return unix.Chdir("/")
	}

	// Change to the new root directory.
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("failed to chdir to new root: %w", err)
	}

	// Unmount the old root, which is now at /.pivot_root.
	if err := unix.Unmount("/.pivot_root", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("failed to unmount old root: %w", err)
	}
	return nil
}

func setupMounts(ctx context.Context, mounts []MountConfig) error {
	// A standard set of mounts required for a basic Linux environment.
	defaultMounts := []MountConfig{
		{Source: "proc", Target: "/proc", FSType: "proc", Flags: 0},
		{Source: "sysfs", Target: "/sys", FSType: "sysfs", Flags: unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NOEXEC},
		{Source: "tmpfs", Target: "/dev", FSType: "tmpfs", Flags: unix.MS_NOSUID | unix.MS_STRICTATIME, Data: "mode=755,size=65536k"},
		{Source: "devpts", Target: "/dev/pts", FSType: "devpts", Flags: unix.MS_NOSUID | unix.MS_NOEXEC, Data: "newinstance,ptmxmode=0666,mode=0620"},
		{Source: "tmpfs", Target: "/tmp", FSType: "tmpfs", Flags: unix.MS_NOSUID},
	}

	mounts = append(defaultMounts, mounts...)

	for _, m := range mounts {
		// Note: The target path is relative to the new root.
		targetDir := filepath.Join("/", m.Target)
		if err := os.MkdirAll(targetDir, 0755); err != nil && !os.IsExist(err) {
			return fmt.Errorf("failed to create mount point %s: %w", targetDir, err)
		}
		if err := unix.Mount(m.Source, targetDir, m.FSType, m.Flags, m.Data); err != nil {
			return fmt.Errorf("failed to mount %s: %w", targetDir, err)
		}
	}

	// Remount /sys as read-only as an extra precaution.
	if err := unix.Mount("sysfs", "/sys", "sysfs", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("failed to remount /sys: %w", err)
	}

	// Set up essential device nodes
	return setupDeviceNodes(ctx)
}

// setupDeviceNodes creates essential device nodes for the container
func setupDeviceNodes(ctx context.Context) error {
	logger := Logger(ctx).With("component", "device-setup")

	// Create essential device nodes
	devices := []struct {
		path string
		mode uint32
		major, minor uint32
	}{
		{"/dev/null", unix.S_IFCHR | 0666, 1, 3},
		{"/dev/zero", unix.S_IFCHR | 0666, 1, 5},
		{"/dev/full", unix.S_IFCHR | 0666, 1, 7},
		{"/dev/random", unix.S_IFCHR | 0666, 1, 8},
		{"/dev/urandom", unix.S_IFCHR | 0666, 1, 9},
	}

	for _, dev := range devices {
		if err := unix.Mknod(dev.path, dev.mode, int(unix.Mkdev(dev.major, dev.minor))); err != nil && !os.IsExist(err) {
			logger.Warn("Failed to create device node", "path", dev.path, "error", err)
		}
	}

	// Create /dev/ptmx as a symlink to /dev/pts/ptmx (for new devpts instance)
	if err := os.Symlink("pts/ptmx", "/dev/ptmx"); err != nil && !os.IsExist(err) {
		logger.Warn("Failed to create /dev/ptmx symlink", "error", err)
	}

	// Create /dev/console (link to controlling terminal)
	if err := unix.Mknod("/dev/console", unix.S_IFCHR|0600, int(unix.Mkdev(5, 1))); err != nil && !os.IsExist(err) {
		logger.Warn("Failed to create /dev/console", "error", err)
	}

	logger.Debug("Device nodes setup completed")
	return nil
}

func mountVolumes(ctx context.Context, volumes []Volume, rootfs string) error {
	cleanRootfs, err := filepath.Abs(rootfs)
	if err != nil {
		return fmt.Errorf("could not get absolute path for rootfs: %w", err)
	}

	for _, vol := range volumes {
		dest := filepath.Join(cleanRootfs, vol.Dest)
		// Security check: ensure the volume destination is within the rootfs.
		cleanDest, err := filepath.Abs(dest)
		if err != nil {
			return fmt.Errorf("failed to resolve absolute path for volume destination '%s': %w", vol.Dest, err)
		}

		if !strings.HasPrefix(cleanDest, cleanRootfs) {
			return fmt.Errorf("invalid volume destination '%s': attempts to escape rootfs", vol.Dest)
		}

		if err := os.MkdirAll(cleanDest, 0755); err != nil {
			return fmt.Errorf("failed to create volume destination '%s': %w", cleanDest, err)
		}

		flags := uintptr(unix.MS_BIND | unix.MS_REC)
		if vol.ReadOnly {
			flags |= unix.MS_RDONLY
		}

		if err := unix.Mount(vol.Source, cleanDest, "bind", flags, ""); err != nil {
			return fmt.Errorf("failed to mount volume from '%s' to '%s': %w", vol.Source, cleanDest, err)
		}
	}
	return nil
}

func setupHostsEntries(hosts []HostEntry, dns []string, rootfs string) error {
	etcDir := filepath.Join(rootfs, "etc")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		return fmt.Errorf("failed to create /etc directory: %w", err)
	}

	// Create /etc/hosts
	hostsFile := filepath.Join(rootfs, "/etc/hosts")
	var hostsBuilder strings.Builder
	hostsBuilder.WriteString("127.0.0.1\tlocalhost\n::1\tlocalhost\n")
	for _, entry := range hosts {
		hostsBuilder.WriteString(fmt.Sprintf("%s\t%s\n", entry.IP, entry.Name))
	}
	if err := os.WriteFile(hostsFile, []byte(hostsBuilder.String()), 0644); err != nil {
		return fmt.Errorf("failed to write to /etc/hosts: %w", err)
	}

	// Create /etc/resolv.conf
	if len(dns) > 0 {
		resolvFile := filepath.Join(rootfs, "/etc/resolv.conf")
		var resolvContent strings.Builder
		for _, server := range dns {
			resolvContent.WriteString(fmt.Sprintf("nameserver %s\n", server))
		}
		if err := os.WriteFile(resolvFile, []byte(resolvContent.String()), 0644); err != nil {
			return fmt.Errorf("failed to write to /etc/resolv.conf: %w", err)
		}
	}
	return nil
}

func setupContainerNetwork(ctx context.Context, cfg *Config) error {
	logger := Logger(ctx)

	// Bring up the loopback interface first.
	if lo, err := netlink.LinkByName("lo"); err == nil {
		if err := netlink.LinkSetUp(lo); err != nil {
			logger.Warn("Failed to bring up loopback interface", "error", err)
		}
	} else {
		logger.Warn("Could not find loopback interface", "error", err)
	}

	if cfg.Runtime.IsRootless {
		logger.Info("Using host network namespace in rootless mode")
		return nil
	}

	// Find the veth peer interface inside the new namespace with retry logic.
	// There can be a race condition where the interface hasn't fully appeared
	// in the new namespace yet after being moved by the parent process.
	var peer netlink.Link
	maxRetries := 10
	retryDelay := 10 * time.Millisecond
	
	for attempt := 1; attempt <= maxRetries; attempt++ {
		interfaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("failed to list interfaces (attempt %d/%d): %w", attempt, maxRetries, err)
		}

		logger.Debug("Looking for veth peer interface", 
			"attempt", attempt, 
			"total_interfaces", len(interfaces))

		// Log all available interfaces for debugging
		var interfaceNames []string
		for _, iface := range interfaces {
			interfaceNames = append(interfaceNames, iface.Name)
			if strings.HasPrefix(iface.Name, "vethp-") {
				if link, err := netlink.LinkByName(iface.Name); err == nil {
					logger.Info("Found veth peer interface", "name", iface.Name, "attempt", attempt)
					peer = link
					break
				} else {
					logger.Warn("Found veth peer by name but failed to get link", "name", iface.Name, "error", err)
				}
			}
		}
		
		if peer != nil {
			break
		}
		
		logger.Debug("Veth peer not found, retrying", 
			"attempt", attempt, 
			"available_interfaces", interfaceNames,
			"retry_delay_ms", retryDelay.Milliseconds())
		
		if attempt < maxRetries {
			time.Sleep(retryDelay)
			// Exponential backoff with a cap
			retryDelay = time.Duration(float64(retryDelay) * 1.5)
			if retryDelay > 100*time.Millisecond {
				retryDelay = 100 * time.Millisecond
			}
		}
	}
	
	if peer == nil {
		interfaces, _ := net.Interfaces()
		var interfaceNames []string
		for _, iface := range interfaces {
			interfaceNames = append(interfaceNames, iface.Name)
		}
		return fmt.Errorf("veth peer not found in container namespace after %d attempts, available interfaces: %v", 
			maxRetries, interfaceNames)
	}

	// Rename the interface to "eth0".
	if err := netlink.LinkSetName(peer, "eth0"); err != nil {
		return fmt.Errorf("failed to rename interface to eth0: %w", err)
	}
	eth0, err := netlink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("failed to get eth0 interface: %w", err)
	}

	// Assign IP addresses and set up routes from environment variables.
	var ip4, gw4, cidr4, ip6, gw6, cidr6 string
	for _, env := range cfg.Process.Env {
		switch {
		case strings.HasPrefix(env, "CONTAINER_IP4="):
			ip4 = strings.TrimPrefix(env, "CONTAINER_IP4=")
		case strings.HasPrefix(env, "CONTAINER_GW_IP4="):
			gw4 = strings.TrimPrefix(env, "CONTAINER_GW_IP4=")
		case strings.HasPrefix(env, "CONTAINER_NET_CIDR="):
			cidr4 = strings.TrimPrefix(env, "CONTAINER_NET_CIDR=")
		case strings.HasPrefix(env, "CONTAINER_IP6="):
			ip6 = strings.TrimPrefix(env, "CONTAINER_IP6=")
		case strings.HasPrefix(env, "CONTAINER_GW_IP6="):
			gw6 = strings.TrimPrefix(env, "CONTAINER_GW_IP6=")
		case strings.HasPrefix(env, "CONTAINER_NET6_CIDR="):
			cidr6 = strings.TrimPrefix(env, "CONTAINER_NET6_CIDR=")
		}
	}

	if ip4 != "" && cidr4 != "" {
		addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%s", ip4, strings.Split(cidr4, "/")[1]))
		if err != nil {
			return fmt.Errorf("failed to parse container IPv4 address: %w", err)
		}
		if err := netlink.AddrAdd(eth0, addr); err != nil {
			return fmt.Errorf("failed to add IPv4 address to eth0: %w", err)
		}
	}

	if ip6 != "" && cidr6 != "" {
		addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%s", ip6, strings.Split(cidr6, "/")[1]))
		if err != nil {
			return fmt.Errorf("failed to parse container IPv6 address: %w", err)
		}
		if err := netlink.AddrAdd(eth0, addr); err != nil {
			return fmt.Errorf("failed to add IPv6 address to eth0: %w", err)
		}
	}

	// Bring up the eth0 interface.
	if err := netlink.LinkSetUp(eth0); err != nil {
		return fmt.Errorf("failed to bring up eth0: %w", err)
	}

	// Set up default routes.
	if gw4 != "" {
		route4 := &netlink.Route{Gw: net.ParseIP(gw4)}
		if err := netlink.RouteAdd(route4); err != nil && !os.IsExist(err) {
			logger.Warn("Failed to add IPv4 default route", "error", err)
		}
	}

	if gw6 != "" {
		route6 := &netlink.Route{Gw: net.ParseIP(gw6)}
		if err := netlink.RouteAdd(route6); err != nil && !os.IsExist(err) {
			logger.Warn("Failed to add IPv6 default route", "error", err)
		}
	}

	logger.Info("Container network setup complete", "interface", "eth0", "ip4", ip4, "ip6", ip6)
	return nil
}

func applyCapabilities(logger *slog.Logger, cfg *ProcessConfig) error {
	// A sensible default set of capabilities for many common container workloads.
	defaultCaps := []string{
		"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL",
		"MKNOD", "NET_ADMIN", "NET_BIND_SERVICE", "NET_RAW", "SETFCAP", "SETGID", "SETPCAP",
		"SETUID", "SYS_CHROOT",
	}

	finalCaps := make(map[string]bool)
	for _, c := range defaultCaps {
		finalCaps[c] = true
	}

	// Apply user-defined drops.
	for _, capName := range cfg.CapsToDrop {
		capName = strings.ToUpper(capName)
		if _, exists := finalCaps[capName]; exists {
			delete(finalCaps, capName)
			logger.Debug("Dropping capability", "capability", capName)
		} else {
			logger.Warn("Request to drop non-default capability", "capability", capName)
		}
	}

	// Apply user-defined additions.
	for _, capName := range cfg.CapsToKeep {
		capName = strings.ToUpper(capName)
		if _, ok := CapabilityMap[capName]; ok {
			if !finalCaps[capName] {
				finalCaps[capName] = true
				logger.Debug("Keeping capability", "capability", capName)
			}
		} else {
			logger.Warn("Unknown capability requested to keep", "capability", capName)
		}
	}

	var capData [2]unix.CapUserData
	// Build the capability sets.
	for capName := range finalCaps {
		c, ok := CapabilityMap[capName]
		if !ok {
			continue // Should not happen due to the check above, but good practice.
		}
		mask := uint32(1 << (c % 32))
		if c < 32 {
			capData[0].Effective |= mask
			capData[0].Permitted |= mask
			capData[0].Inheritable |= mask // Inheritable for processes spawned by the container command
		} else {
			capData[1].Effective |= mask
			capData[1].Permitted |= mask
			capData[1].Inheritable |= mask
		}
	}

	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	// Apply the capabilities using the capset syscall.
	if err := unix.Capset(&header, &capData[0]); err != nil {
		return fmt.Errorf("failed to set capabilities: %w", err)
	}
	logger.Info("Successfully applied container capabilities.")
	return nil
}

func configureRootless(cmd *exec.Cmd, cfg *RuntimeConfig) error {
	if len(cfg.SubUIDMap) == 0 || len(cfg.SubGIDMap) == 0 {
		return errors.New("rootless mode requires subuid/subgid mappings, but none were loaded or provided")
	}

	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER
	cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{}
	cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{}

	// Map the current user to root (UID 0) inside the container
	cmd.SysProcAttr.UidMappings = append(cmd.SysProcAttr.UidMappings, syscall.SysProcIDMap{
		ContainerID: 0,
		HostID:      os.Getuid(),
		Size:        1,
	})
	cmd.SysProcAttr.GidMappings = append(cmd.SysProcAttr.GidMappings, syscall.SysProcIDMap{
		ContainerID: 0,
		HostID:      os.Getgid(),
		Size:        1,
	})

	// Apply subuid/subgid mappings from config
	// These map container UIDs 1+ to the allocated subuid range
	for _, m := range cfg.SubUIDMap {
		cmd.SysProcAttr.UidMappings = append(cmd.SysProcAttr.UidMappings, syscall.SysProcIDMap{
			ContainerID: 1, // Start mapping from UID 1 in container
			HostID:      int(m.HostID),
			Size:        int(m.Size) - 1, // Subtract 1 because we already mapped UID 0
		})
	}
	for _, m := range cfg.SubGIDMap {
		cmd.SysProcAttr.GidMappings = append(cmd.SysProcAttr.GidMappings, syscall.SysProcIDMap{
			ContainerID: 1, // Start mapping from GID 1 in container
			HostID:      int(m.HostID),
			Size:        int(m.Size) - 1, // Subtract 1 because we already mapped GID 0
		})
	}

	return nil
}

func loadIDMappings(logger *slog.Logger, cfg *RuntimeConfig) error {
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("could not get current user: %w", err)
	}

	uidMap, err := parseIDMapFile("/etc/subuid", currentUser.Username)
	if err != nil {
		// Log a warning if the file can't be read, but don't fail yet.
		// The failure will happen in configureRootless if mappings are required but absent.
		logger.Warn("Failed to parse /etc/subuid, proceeding without subuid mappings.", "error", err)
	}
	cfg.SubUIDMap = uidMap

	gidMap, err := parseIDMapFile("/etc/subgid", currentUser.Username)
	if err != nil {
		logger.Warn("Failed to parse /etc/subgid, proceeding without subgid mappings.", "error", err)
	}
	cfg.SubGIDMap = gidMap

	if len(uidMap) > 0 || len(gidMap) > 0 {
		logger.Info("Loaded ID mappings for user", "user", currentUser.Username, "uids", len(uidMap), "gids", len(gidMap))
	}
	return nil
}

func parseIDMapFile(path, username string) ([]IDMap, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var maps []IDMap
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		// Format is user:start_id:count
		if len(parts) != 3 || parts[0] != username {
			continue
		}
		hostID, err1 := strconv.Atoi(parts[1])
		size, err2 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil {
			// Skip malformed lines
			continue
		}
		// The subuid/gid range on the host is allocated to this user
		// We map these to container IDs starting from 1 (since 0 is mapped to the current user)
		maps = append(maps, IDMap{
			ContainerID: 1, // Will be adjusted in configureRootless
			HostID:      uint32(hostID),
			Size:        uint32(size),
		})
	}
	return maps, scanner.Err()
}

func reapChildren(logger *slog.Logger) {
	sigChan := make(chan os.Signal, 1)
	// We only care about SIGCHLD.
	signal.Notify(sigChan, syscall.SIGCHLD)

	for {
		<-sigChan
		// Loop to reap all zombie children that might have exited.
		for {
			var status syscall.WaitStatus
			// Wait for any child process (-1) without blocking (WNOHANG).
			pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
			if err != nil || pid <= 0 {
				// No more children to reap at this moment.
				break
			}
			logger.Debug("Reaped zombie process", "pid", pid)
		}
	}
}

// EnableCheckpointing enables checkpoint functionality for the container
func (c *Container) EnableCheckpointing(ctx context.Context, workDir string) error {
	if c == nil {
		return errors.New("container cannot be nil")
	}
	
	if c.checkpointEnabled {
		return nil // Already enabled
	}
	
	// Create checkpoint manager
	cm, err := NewCheckpointManager(ctx, workDir)
	if err != nil {
		return fmt.Errorf("failed to create checkpoint manager: %w", err)
	}
	
	c.checkpointManager = cm
	c.checkpointEnabled = true
	
	Logger(ctx).Info("Checkpoint functionality enabled", "container", c.Config.Runtime.Name, "workdir", workDir)
	return nil
}

// CreateCheckpoint creates a checkpoint of the current container
func (c *Container) CreateCheckpoint(ctx context.Context, opts *CheckpointOptions) (*CheckpointMetadata, error) {
	if c == nil {
		return nil, errors.New("container cannot be nil")
	}
	
	if !c.checkpointEnabled || c.checkpointManager == nil {
		return nil, errors.New("checkpointing is not enabled for this container")
	}
	
	if c.Process == nil || c.Process.Process == nil {
		return nil, errors.New("container is not running")
	}
	
	// Set default container name if not provided
	if opts == nil {
		opts = &CheckpointOptions{
			ContainerName: c.Config.Runtime.Name,
			EnableHooks:   true,
		}
	}
	
	if opts.ContainerName == "" {
		opts.ContainerName = c.Config.Runtime.Name
	}
	
	Logger(ctx).Info("Creating checkpoint", "container", opts.ContainerName, "pid", c.Process.Process.Pid)
	
	return c.checkpointManager.Checkpoint(ctx, c, opts)
}

// IsCheckpointEnabled returns whether checkpointing is enabled for this container
func (c *Container) IsCheckpointEnabled() bool {
	if c == nil {
		return false
	}
	return c.checkpointEnabled
}

// GetCheckpointManager returns the checkpoint manager for this container
func (c *Container) GetCheckpointManager() *CheckpointManager {
	if c == nil {
		return nil
	}
	return c.checkpointManager
}

func executeCommand(ctx context.Context, cfg *ProcessConfig) error {
	shellPath, err := exec.LookPath("sh")
	if err != nil {
		// If sh is not found, the container is likely misconfigured.
		return fmt.Errorf("could not find 'sh' in PATH: %w", err)
	}

	var args []string
	if cfg.Interactive {
		// Start an interactive shell - don't pass extra args for interactive mode
		args = []string{"sh"}
		Logger(ctx).Info("Starting interactive shell", "path", shellPath, "tty", cfg.TTY)
	} else {
		if cfg.Command == "" {
			return errors.New("no command specified")
		}
		// Run the specified command
		args = []string{"sh", "-c", cfg.Command}
		Logger(ctx).Info("Executing command", "path", shellPath, "args", args)
	}

	env := append(os.Environ(), cfg.Env...)

	if cfg.TTY {
		// Try PTY first, fallback to direct execution
		Logger(ctx).Debug("Attempting PTY execution")
		if err := executeWithTTY(ctx, shellPath, args, env); err != nil {
			Logger(ctx).Warn("PTY execution failed, falling back to direct execution", "error", err)
			cfg.TTY = false // Disable TTY for fallback
		} else {
			return nil
		}
	}
	
	// Direct execution without PTY
	if cfg.Interactive {
		// For interactive mode, replace the process entirely for proper terminal handling
		Logger(ctx).Info("Starting interactive shell with process replacement")
		return executeInteractiveShell(ctx, shellPath, args, env)
	} else {
		// Replace the current process with the new command.
		Logger(ctx).Info("Starting command with process replacement")
		return unix.Exec(shellPath, args, env)
	}
}

// executeWithTTY executes a command with a pseudo-TTY allocated
func executeWithTTY(ctx context.Context, path string, args []string, env []string) error {
    // Create the command - for interactive shells, don't pass additional args
    // For non-interactive commands, pass all args as they contain the "-c" and command
    var cmd *exec.Cmd
    if len(args) > 1 {
        // This is a command like ["sh", "-c", "command"], use all args
        cmd = exec.Command(path, args[1:]...)
    } else {
        // This is just ["sh"] for interactive mode, run shell without args
        cmd = exec.Command(path)
    }
    cmd.Env = append(env, "TERM=xterm-256color", "PS1=# ", "HOME=/root", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")

    // Start the command with a PTY
    ptmx, err := pty.Start(cmd)
    if err != nil {
        return fmt.Errorf("failed to start command with PTY: %w", err)
    }
    defer ptmx.Close()

    // Handle window size changes with proper cleanup
    var winchCleanup func()
    if isTerminal(int(os.Stdin.Fd())) {
        ch := make(chan os.Signal, 1)
        signal.Notify(ch, syscall.SIGWINCH)
        winchCtx, winchCancel := context.WithCancel(ctx)
        winchCleanup = func() {
            signal.Stop(ch)
            winchCancel()
            close(ch)
        }
        go func() {
            defer winchCancel()
            for {
                select {
                case <-winchCtx.Done():
                    return
                case <-ch:
                    if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
                        Logger(ctx).Debug("PTY resize failed", "error", err)
                    }
                }
            }
        }()
        ch <- syscall.SIGWINCH // Initial resize
    } else {
        // Set a default size when not a terminal
        if err := pty.Setsize(ptmx, &pty.Winsize{Rows: 24, Cols: 80}); err != nil {
            Logger(ctx).Debug("Failed to set default PTY size", "error", err)
        }
        winchCleanup = func() {} // No-op cleanup
    }
    defer winchCleanup()

    // Set terminal to raw mode
    if isTerminal(int(os.Stdin.Fd())) {
        oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
        if err != nil {
            Logger(ctx).Warn("Failed to set raw mode", "error", err)
        } else {
            defer term.Restore(int(os.Stdin.Fd()), oldState)
        }
    }

    Logger(ctx).Info("Interactive shell started, type 'exit' to quit")

    // Create context for I/O operations
    ioCtx, ioCancel := context.WithCancel(ctx)
    defer ioCancel()

    // Bidirectional I/O copying with proper cleanup
    var wg sync.WaitGroup
    errChan := make(chan error, 2)
    
    wg.Add(2)
    // Copy from stdin to PTY
    go func() {
        defer wg.Done()
        defer func() {
            // Signal EOF to the command by closing stdin
            // Note: PTY handles this automatically when the process exits
        }()
        
        for {
            select {
            case <-ioCtx.Done():
                return
            default:
                // Use a small buffer to make copying interruptible
                buf := make([]byte, 1024)
                n, err := os.Stdin.Read(buf)
                if err != nil {
                    if err != io.EOF {
                        errChan <- fmt.Errorf("stdin read error: %w", err)
                    }
                    return
                }
                if n > 0 {
                    if _, err := ptmx.Write(buf[:n]); err != nil {
                        errChan <- fmt.Errorf("PTY write error: %w", err)
                        return
                    }
                }
            }
        }
    }()
    
    // Copy from PTY to stdout
    go func() {
        defer wg.Done()
        for {
            select {
            case <-ioCtx.Done():
                return
            default:
                buf := make([]byte, 1024)
                n, err := ptmx.Read(buf)
                if err != nil {
                    if err != io.EOF {
                        errChan <- fmt.Errorf("PTY read error: %w", err)
                    }
                    return
                }
                if n > 0 {
                    if _, err := os.Stdout.Write(buf[:n]); err != nil {
                        errChan <- fmt.Errorf("stdout write error: %w", err)
                        return
                    }
                }
            }
        }
    }()

    // Wait for command completion or I/O error
    cmdDone := make(chan error, 1)
    go func() {
        cmdDone <- cmd.Wait()
    }()

    var cmdErr error
    select {
    case cmdErr = <-cmdDone:
        // Command finished, cancel I/O operations
        ioCancel()
    case ioErr := <-errChan:
        // I/O error occurred, terminate command
        Logger(ctx).Warn("I/O error in PTY session", "error", ioErr)
        cmd.Process.Kill()
        cmdErr = <-cmdDone
    case <-ctx.Done():
        // Context cancelled, terminate everything
        cmd.Process.Kill()
        cmdErr = ctx.Err()
    }

    // Wait for I/O goroutines to finish with timeout
    done := make(chan struct{})
    go func() {
        wg.Wait()
        close(done)
    }()
    
    select {
    case <-done:
        // I/O goroutines finished cleanly
    case <-time.After(5 * time.Second):
        // Timeout waiting for I/O cleanup
        Logger(ctx).Warn("Timeout waiting for I/O goroutines to finish")
    }

    return cmdErr
}

// executeInteractiveShell runs a simple interactive shell without PTY
func executeInteractiveShell(ctx context.Context, path string, args []string, env []string) error {
    // Use the provided path and args, or find a working shell as fallback
    var shellPath string
    var shellArgs []string
    
    if path != "" {
        // Try the provided path first
        if _, err := exec.LookPath(path); err == nil {
            shellPath = path
            shellArgs = args
        }
    }
    
    // Fallback to finding a working system shell
    if shellPath == "" {
        for _, shell := range []string{"/bin/bash", "/bin/sh"} {
            if p, err := exec.LookPath(shell); err == nil {
                shellPath = p
                shellArgs = []string{filepath.Base(shell)}
                break
            }
        }
    }
    
    if shellPath == "" {
        return fmt.Errorf("no suitable shell found")
    }

    Logger(ctx).Info("Executing interactive shell", "path", shellPath, "args", shellArgs)
    
    // Replace the current process with the shell
    return unix.Exec(shellPath, shellArgs, env)
}

// isTerminal checks if a file descriptor refers to a terminal
func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}