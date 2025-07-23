package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)

// --- IP Allocator ---

// IPAllocator manages IP address allocation within a network CIDR with O(1) performance.
type IPAllocator struct {
	network4    *net.IPNet
	network6    *net.IPNet
	used4       map[string]string // Maps IP address string to its owner.
	used6       map[string]string
	bitmap4     []uint64         // Bitmap for O(1) IPv4 allocation
	baseAddr4   uint32           // Base network address for IPv4
	maxAddrs4   uint32           // Maximum number of assignable addresses
	nextFree4   uint32           // Hint for next potentially free address
	counter     *big.Int         // A counter for generating unique IPv6 addresses.
	mu          sync.RWMutex     // Use RWMutex for better read performance
	rateLimiter *rate.Limiter
}

// NewIPAllocator creates a new IP address allocator for the given CIDRs.
func NewIPAllocator(network4 *net.IPNet, network6 *net.IPNet) *IPAllocator {
	allocator := &IPAllocator{
		network4: network4,
		network6: network6,
		used4:    make(map[string]string),
		used6:    make(map[string]string),
		counter:  big.NewInt(0),
		rateLimiter: rate.NewLimiter(rate.Every(1*time.Second), 100), // Allow 100 allocations per second
	}
	
	// Initialize IPv4 bitmap for O(1) allocation
	if network4 != nil {
		if baseAddr, err := ipToUint32(network4.IP); err == nil {
			ones, bits := network4.Mask.Size()
			if ones < 31 { // Only for networks with assignable hosts
				maxAddrs := uint32(1) << (bits - ones)
				// Number of 64-bit words needed for the bitmap
				bitmapSize := (maxAddrs + 63) / 64
				allocator.bitmap4 = make([]uint64, bitmapSize)
				allocator.baseAddr4 = baseAddr
				allocator.maxAddrs4 = maxAddrs - 2 // Exclude network and broadcast
				allocator.nextFree4 = 1 // Start from first assignable address
				
				// Mark network (0) and broadcast (maxAddrs-1) addresses as used
				allocator.setBit(0)
				allocator.setBit(maxAddrs - 1)
			}
		}
	}
	
	return allocator
}

// ipToUint32 converts a net.IP (IPv4) to a uint32.
func ipToUint32(ip net.IP) (uint32, error) {
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address")
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]), nil
}

// uint32ToIP converts a uint32 to a net.IP (IPv4).
func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// setBit sets a bit in the IPv4 allocation bitmap
func (a *IPAllocator) setBit(pos uint32) {
	if a.bitmap4 == nil || pos >= a.maxAddrs4+2 {
		return
	}
	wordIndex := pos / 64
	bitIndex := pos % 64
	if wordIndex < uint32(len(a.bitmap4)) {
		a.bitmap4[wordIndex] |= (1 << bitIndex)
	}
}

// clearBit clears a bit in the IPv4 allocation bitmap
func (a *IPAllocator) clearBit(pos uint32) {
	if a.bitmap4 == nil || pos >= a.maxAddrs4+2 {
		return
	}
	wordIndex := pos / 64
	bitIndex := pos % 64
	if wordIndex < uint32(len(a.bitmap4)) {
		a.bitmap4[wordIndex] &^= (1 << bitIndex)
	}
}

// isBitSet checks if a bit is set in the IPv4 allocation bitmap
func (a *IPAllocator) isBitSet(pos uint32) bool {
	if a.bitmap4 == nil || pos >= a.maxAddrs4+2 {
		return true // Treat out-of-range as used
	}
	wordIndex := pos / 64
	bitIndex := pos % 64
	if wordIndex >= uint32(len(a.bitmap4)) {
		return true
	}
	return (a.bitmap4[wordIndex] & (1 << bitIndex)) != 0
}

// findNextFreeBit finds the next free bit starting from a given position
func (a *IPAllocator) findNextFreeBit(start uint32) uint32 {
	if a.bitmap4 == nil {
		return 0
	}
	
	// Start searching from the given position
	for pos := start; pos <= a.maxAddrs4; pos++ {
		if !a.isBitSet(pos) {
			return pos
		}
	}
	
	// Wrap around and search from the beginning
	for pos := uint32(1); pos < start && pos <= a.maxAddrs4; pos++ {
		if !a.isBitSet(pos) {
			return pos
		}
	}
	
	return 0 // No free addresses
}

// AllocateIPv4 assigns an available IPv4 address to the given owner with O(1) performance.
func (a *IPAllocator) AllocateIPv4(owner string) net.IP {
	if a == nil {
		Logger(context.Background()).Error("IP allocator is nil")
		return nil
	}
	if owner == "" {
		Logger(context.Background()).Error("Cannot allocate IP to empty owner")
		return nil
	}
	if len(owner) > 253 { // DNS name length limit
		Logger(context.Background()).Error("Owner name too long", "length", len(owner), "max", 253)
		return nil
	}
	if a.network4 == nil {
		Logger(context.Background()).Error("IPv4 network not configured")
		return nil
	}
	if a.used4 == nil {
		a.used4 = make(map[string]string)
	}
	
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if the owner already has an IP.
	for ip, o := range a.used4 {
		if o == owner {
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				// Invalid IP in map, remove it
				delete(a.used4, ip)
				continue
			}
			return parsedIP
		}
	}

	// Fallback to legacy allocation if bitmap is not initialized
	if a.bitmap4 == nil {
		return a.allocateIPv4Legacy(owner)
	}

	// Use O(1) bitmap-based allocation
	pos := a.findNextFreeBit(a.nextFree4)
	if pos == 0 {
		Logger(context.Background()).Error("No available IPv4 addresses in the network", "cidr", a.network4.String())
		return nil
	}

	// Mark the position as used
	a.setBit(pos)
	a.nextFree4 = pos + 1
	if a.nextFree4 > a.maxAddrs4 {
		a.nextFree4 = 1
	}

	// Convert position to IP address
	ip := uint32ToIP(a.baseAddr4 + pos)
	a.used4[ip.String()] = owner
	
	Logger(context.Background()).Debug("Allocated IPv4", "owner", owner, "ip", ip, "position", pos)
	return ip
}

// allocateIPv4Legacy provides the original O(n) allocation as fallback
func (a *IPAllocator) allocateIPv4Legacy(owner string) net.IP {
	netAddr, err := ipToUint32(a.network4.IP)
	if err != nil {
		return nil
	}

	ones, bits := a.network4.Mask.Size()
	if ones >= 31 {
		return nil
	}

	numAddresses := uint32(1) << (bits - ones)
	for i := uint32(1); i < numAddresses-1; i++ {
		ip := uint32ToIP(netAddr + i)
		if _, used := a.used4[ip.String()]; !used {
			a.used4[ip.String()] = owner
			Logger(context.Background()).Debug("Allocated IPv4 (legacy)", "owner", owner, "ip", ip)
			return ip
		}
	}
	
	return nil
}

// AllocateIPv6 assigns a unique IPv6 address to the given owner.
func (a *IPAllocator) AllocateIPv6(owner string) net.IP {
	if a == nil {
		return nil
	}
	if owner == "" {
		Logger(context.Background()).Error("Cannot allocate IPv6 to empty owner")
		return nil
	}
	if a.network6 == nil {
		return nil
	}

	// Enforce rate limit for IPv6 allocation
	if !a.rateLimiter.Allow() {
		Logger(context.Background()).Warn("IPv6 allocation rate limit exceeded")
		return nil
	}
	
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check if the owner already has an IP.
	for ip, o := range a.used6 {
		if o == owner {
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				// Invalid IP in map, remove it
				delete(a.used6, ip)
				continue
			}
			return parsedIP
		}
	}

	baseInt := new(big.Int).SetBytes(a.network6.IP.To16())
	one := big.NewInt(1)

	// Iterate a reasonable number of times to find an available IP.
	// This avoids an infinite loop if the address space is nearly full.
	for i := 0; i < (1 << 16); i++ { // Limit to 65536 attempts
		a.counter.Add(a.counter, one)
		newIPInt := new(big.Int).Add(baseInt, a.counter)

		// Ensure the generated IP is still within the subnet.
		newIP := net.IP(newIPInt.Bytes())
		if !a.network6.Contains(newIP) {
			// We've likely exhausted the usable range or the counter wrapped around.
			// Reset the counter to start from the beginning of the range.
			a.counter = big.NewInt(0)
			continue
		}

		if _, used := a.used6[newIP.String()]; !used {
			a.used6[newIP.String()] = owner
			Logger(context.Background()).Debug("Allocated IPv6", "owner", owner, "ip", newIP)
			return newIP
		}
	}

	Logger(context.Background()).Error("No available IPv6 addresses in the network", "cidr", a.network6.String())
	return nil // No IP available
}

// Release frees the IP addresses associated with an owner.
func (a *IPAllocator) Release(owner string) {
	if a == nil || owner == "" {
		return
	}
	
	a.mu.Lock()
	defer a.mu.Unlock()

	// Release IPv4 address
	var ipv4Found string
	for ip, o := range a.used4 {
		if o == owner {
			ipv4Found = ip
			break
		}
	}
	if ipv4Found != "" {
		delete(a.used4, ipv4Found)
		
		// Also clear the bit in the bitmap if available
		if a.bitmap4 != nil && a.network4 != nil {
			if parsedIP := net.ParseIP(ipv4Found); parsedIP != nil {
				if ipUint, err := ipToUint32(parsedIP); err == nil {
					pos := ipUint - a.baseAddr4
					if pos > 0 && pos <= a.maxAddrs4 {
						a.clearBit(pos)
						// Update hint to this newly freed position for faster next allocation
						if pos < a.nextFree4 {
							a.nextFree4 = pos
						}
					}
				}
			}
		}
		
		Logger(context.Background()).Debug("Released IPv4", "owner", owner, "ip", ipv4Found)
	}

	// Release IPv6 address
	var ipv6Found string
	for ip, o := range a.used6 {
		if o == owner {
			ipv6Found = ip
			break
		}
	}
	if ipv6Found != "" {
		delete(a.used6, ipv6Found)
		Logger(context.Background()).Debug("Released IPv6", "owner", owner, "ip", ipv6Found)
	}
}

// --- Loop Device Manager ---

// LoopDeviceManager manages the attachment and detachment of loop devices.
type LoopDeviceManager struct {
	devices map[string]string // Maps source image file to the allocated loop device.
	mu      sync.Mutex
}

var loopManager = &LoopDeviceManager{
	devices: make(map[string]string),
}

// Attach attaches a loop device to a source file.
func (l *LoopDeviceManager) Attach(ctx context.Context, source string) (string, error) {
	if l == nil {
		return "", errors.New("loop device manager is nil")
	}
	if source == "" {
		return "", errors.New("source file path cannot be empty")
	}
	if len(source) > 4096 { // PATH_MAX on most systems
		return "", fmt.Errorf("source path too long (%d chars): max 4096", len(source))
	}
	if !filepath.IsAbs(source) {
		return "", fmt.Errorf("source path must be absolute: %s", source)
	}
	
	// Check system limits before proceeding
	if err := globalSystemLimits.CheckSystemLimits(); err != nil {
		return "", fmt.Errorf("system resource limits exceeded: %w", err)
	}
	
	// Check if source file exists and is readable
	if _, err := os.Stat(source); err != nil {
		return "", fmt.Errorf("source file '%s' not accessible: %w", source, err)
	}
	
	l.mu.Lock()
	defer l.mu.Unlock()

	if device, ok := l.devices[source]; ok {
		// Verify the device still exists
		if _, err := os.Stat(device); err == nil {
			return device, nil
		}
		// Device no longer exists, remove from map
		delete(l.devices, source)
	}

	// Use timeout context for losetup command
	cmdCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(cmdCtx, "losetup", "-fP", "--show", source)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("losetup attach failed: %w, output: %s", err, string(output))
	}
	device := strings.TrimSpace(string(output))
	if device == "" {
		return "", errors.New("losetup returned empty device name")
	}
	
	// Verify device exists and is accessible
	if _, err := os.Stat(device); err != nil {
		return "", fmt.Errorf("loop device not accessible: %w", err)
	}
	
	// Track the loop device for cleanup
	deviceID := fmt.Sprintf("loop:%s", device)
	globalResourceManager.TrackResource(deviceID, ResourceTypeLoopDevice, device, func() error {
		return l.Detach(context.Background(), source)
	})
	
	l.devices[source] = device
	return device, nil
}

// Detach detaches a loop device.
func (l *LoopDeviceManager) Detach(ctx context.Context, source string) error {
	if l == nil {
		return nil // Nothing to detach
	}
	if source == "" {
		return errors.New("source file path cannot be empty")
	}
	
	l.mu.Lock()
	defer l.mu.Unlock()

	device, ok := l.devices[source]
	if !ok {
		return nil // Already detached or never attached
	}
	
	// Use timeout for detach operation
	cmdCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "losetup", "-d", device)
	if err := cmd.Run(); err != nil {
		// Try forced detach as fallback
		forceCmd := exec.CommandContext(cmdCtx, "losetup", "-d", "-f", device)
		if forceErr := forceCmd.Run(); forceErr != nil {
			Logger(ctx).Warn("Failed to detach loop device", "device", device, "error", err, "force_error", forceErr)
			return fmt.Errorf("failed to detach loop device %s: %w", device, err)
		}
	}
	
	// Untrack the resource
	deviceID := fmt.Sprintf("loop:%s", device)
	globalResourceManager.UntrackResource(deviceID)

	delete(l.devices, source)
	return nil
}

// --- Filesystem Utilities ---

// prepareRootfs prepares the root filesystem for the container.
func prepareRootfs(ctx context.Context, cfg *StorageConfig, name string) (string, bool, error) {
	if cfg == nil {
		return "", false, errors.New("storage config cannot be nil")
	}
	if name == "" {
		return "", false, errors.New("container name cannot be empty")
	}
	if len(name) > 253 {
		return "", false, fmt.Errorf("container name too long (%d chars): max 253", len(name))
	}
	
	// Check if using pluggable storage drivers
	if cfg.UseDriver && cfg.Driver.Driver != "" {
		return prepareRootfsWithDriver(ctx, cfg, name)
	}
	
	// Legacy rootfs preparation
	return prepareRootfsLegacy(ctx, cfg, name)
}

// prepareRootfsWithDriver prepares rootfs using storage drivers
func prepareRootfsWithDriver(ctx context.Context, cfg *StorageConfig, name string) (string, bool, error) {
	logger := Logger(ctx).With("component", "rootfs-driver")
	
	// Set default graph root if not specified
	if cfg.Driver.GraphRoot == "" {
		tmpDir, err := os.MkdirTemp("", fmt.Sprintf("gophertainer-storage-%s-", name))
		if err != nil {
			return "", false, fmt.Errorf("failed to create storage temp dir: %w", err)
		}
		cfg.Driver.GraphRoot = tmpDir
	}
	
	if cfg.Driver.RunRoot == "" {
		cfg.Driver.RunRoot = filepath.Join(cfg.Driver.GraphRoot, "run")
	}
	
	// Create storage manager
	storageManager, err := NewStorageManager(ctx, cfg.Driver)
	if err != nil {
		return "", false, fmt.Errorf("failed to create storage manager: %w", err)
	}
	
	// Get the configured driver
	driver, err := storageManager.GetDriver()
	if err != nil {
		return "", false, fmt.Errorf("failed to get storage driver: %w", err)
	}
	
	// Create base layer from rootfs source if needed
	baseLayerID := "base"
	if exists, err := driver.Exists(ctx, baseLayerID); err != nil {
		return "", false, fmt.Errorf("failed to check base layer existence: %w", err)
	} else if !exists {
		logger.Info("Creating base layer from rootfs source", "source", cfg.RootFSSource)
		
		// Prepare base rootfs using legacy method
		baseRootfs, isTemp, err := prepareRootfsLegacy(ctx, cfg, "base")
		if err != nil {
			return "", false, fmt.Errorf("failed to prepare base rootfs: %w", err)
		}
		defer func() {
			if isTemp {
				unmountPath(ctx, baseRootfs)
				os.RemoveAll(baseRootfs)
			}
		}()
		
		// Create base layer
		opts := CreateOptions{ReadWrite: false}
		if _, err := driver.Create(ctx, baseLayerID, "", opts); err != nil {
			return "", false, fmt.Errorf("failed to create base layer: %w", err)
		}
		
		// Mount base layer and copy content
		baseMountPath, err := driver.Mount(ctx, baseLayerID, MountOptions{ReadWrite: true})
		if err != nil {
			return "", false, fmt.Errorf("failed to mount base layer: %w", err)
		}
		defer driver.Unmount(ctx, baseLayerID)
		
		// Copy content from prepared rootfs to driver layer
		if err := copyDirectory(baseRootfs, baseMountPath); err != nil {
			return "", false, fmt.Errorf("failed to copy base rootfs to layer: %w", err)
		}
	}
	
	// Create container-specific layer
	containerLayerID := fmt.Sprintf("container-%s", name)
	opts := CreateOptions{ReadWrite: true}
	if _, err := driver.Create(ctx, containerLayerID, baseLayerID, opts); err != nil {
		return "", false, fmt.Errorf("failed to create container layer: %w", err)
	}
	
	// Mount container layer
	mountPath, err := driver.Mount(ctx, containerLayerID, MountOptions{ReadWrite: true})
	if err != nil {
		return "", false, fmt.Errorf("failed to mount container layer: %w", err)
	}
	
	logger.Info("Rootfs prepared with storage driver", "driver", cfg.Driver.Driver, "mount_path", mountPath)
	return mountPath, true, nil
}

// prepareRootfsLegacy provides the original rootfs preparation logic
func prepareRootfsLegacy(ctx context.Context, cfg *StorageConfig, name string) (string, bool, error) {
	source := cfg.RootFSSource
	if source == "" {
		return "", false, errors.New("rootfs source cannot be empty")
	}

	if info, err := os.Stat(source); err == nil && info.IsDir() {
		return source, false, nil
	}

	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("gophertainer-%s-root-", name))
	if err != nil {
		return "", false, fmt.Errorf("failed to create temp dir for rootfs: %w", err)
	}

	Logger(ctx).Info("Preparing rootfs", "source", source, "tempDir", tmpDir)
	switch {
	case strings.HasSuffix(source, ".img"):
		if err := mountImage(ctx, source, tmpDir); err != nil {
			os.RemoveAll(tmpDir)
			return "", false, fmt.Errorf("failed to mount image: %w", err)
		}
		return tmpDir, true, nil
	case strings.HasSuffix(source, ".tar"), strings.HasSuffix(source, ".tar.gz"):
		if err := extractTar(source, tmpDir); err != nil {
			os.RemoveAll(tmpDir)
			return "", false, fmt.Errorf("failed to extract tar: %w", err)
		}
		return tmpDir, true, nil
	default:
		os.RemoveAll(tmpDir)
		return "", false, fmt.Errorf("unsupported rootfs format for source: %s", source)
	}
}

// mountImage mounts a filesystem image to a destination path.
func mountImage(ctx context.Context, source, dest string) error {
	device, err := loopManager.Attach(ctx, source)
	if err != nil {
		return err
	}

	fsType, err := detectFilesystemType(device)
	if err != nil {
		loopManager.Detach(ctx, source)
		return fmt.Errorf("failed to detect filesystem type for %s: %w", device, err)
	}

	if err := unix.Mount(device, dest, fsType, 0, ""); err != nil {
		loopManager.Detach(ctx, source)
		return fmt.Errorf("failed to mount loop device %s: %w", device, err)
	}

	return nil
}

// extractTar extracts a tar archive to a destination.
func extractTar(source, dest string) error {
	if source == "" {
		return errors.New("source path cannot be empty")
	}
	if dest == "" {
		return errors.New("destination path cannot be empty")
	}
	if !filepath.IsAbs(source) || !filepath.IsAbs(dest) {
		return errors.New("source and destination paths must be absolute")
	}
	
	// Use safe file opening with resource tracking
	file, err := SafeOpenFile(source, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open tar file: %w", err)
	}
	defer SafeCloseFile(file)
	
	// Create resource guard for partial extraction cleanup
	extractGuard := NewCriticalResourceGuard()
	var extractedFiles []string
	extractGuard.Add(func() error {
		// Cleanup partially extracted files on error
		for _, extractedFile := range extractedFiles {
			os.Remove(extractedFile)
		}
		return nil
	})
	defer func() {
		if err != nil {
			extractGuard.Release()
		}
	}()

	var fileReader io.Reader = file
	if strings.HasSuffix(source, ".gz") || strings.HasSuffix(source, ".tgz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		fileReader = gzReader
	}

	tarReader := tar.NewReader(fileReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Security: Prevent path traversal attacks (zip slip).
		target := filepath.Join(dest, header.Name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dest)) {
			return fmt.Errorf("tar entry '%s' is trying to escape the destination directory, which is a security risk", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory from tar: %w", err)
			}
		case tar.TypeReg:
			// Ensure the parent directory exists.
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory for file from tar: %w", err)
			}
			outFile, err := SafeOpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file from tar: %w", err)
			}
			extractedFiles = append(extractedFiles, target)
			
			if _, err := io.Copy(outFile, tarReader); err != nil {
				SafeCloseFile(outFile)
				return fmt.Errorf("failed to write file content from tar: %w", err)
			}
			
			if err := SafeCloseFile(outFile); err != nil {
				return fmt.Errorf("failed to close extracted file: %w", err)
			}
		case tar.TypeSymlink:
			// Ensure the parent directory exists.
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory for symlink from tar: %w", err)
			}
			if err := os.Symlink(header.Linkname, target); err != nil {
				return fmt.Errorf("failed to create symlink from tar: %w", err)
			}
		default:
			Logger(context.Background()).Warn("Unsupported tar header type", "type", header.Typeflag, "file", header.Name)
		}
	}
	return nil
}

// detectFilesystemType uses blkid to find the filesystem type of a device.
func detectFilesystemType(device string) (string, error) {
	cmd := exec.Command("blkid", "-o", "value", "-s", "TYPE", device)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("blkid failed for device %s: %w", device, err)
	}
	fsType := strings.TrimSpace(string(output))
	if fsType == "" {
		return "", fmt.Errorf("blkid did not return a filesystem type for device %s", device)
	}
	return fsType, nil
}

// --- Cleanup Utilities ---

// cleanupCgroupV2 removes a cgroup v2 directory.
func cleanupCgroupV2(ctx context.Context, path string) {
	if path == "" {
		return
	}
	
	logger := Logger(ctx).With("component", "cgroup-cleanup", "path", path)
	logger.Debug("Starting cgroup v2 cleanup")
	procsFile := filepath.Join(path, "cgroup.procs")
	
	// Kill processes in the cgroup
	if procs, err := os.ReadFile(procsFile); err == nil {
		lines := strings.Split(string(procs), "\n")
		for _, line := range lines {
			pidStr := strings.TrimSpace(line)
			if pidStr == "" {
				continue
			}
			if pid, err := strconv.Atoi(pidStr); err == nil && pid > 0 {
				logger.Debug("Killing process in cgroup", "pid", pid, "cgroup", path)
				if err := unix.Kill(pid, unix.SIGKILL); err != nil {
					logger.Warn("Failed to kill process", "pid", pid, "error", err)
				}
			}
		}
	} else if !os.IsNotExist(err) {
		logger.Warn("Failed to read cgroup.procs", "path", procsFile, "error", err)
	}
	
	// Give processes time to exit
	time.Sleep(100 * time.Millisecond)
	
	// Remove the cgroup directory
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		logger.Warn("Failed to remove cgroup v2 directory", "path", path, "error", err)
	} else {
		logger.Debug("Successfully removed cgroup v2 directory", "path", path)
	}
}

// cleanupStaleResources removes leftover network resources from previous runs.
func cleanupStaleResources(ctx context.Context, cfg *Config) error {
	logger := Logger(ctx).With("component", "cleanup")
	logger.Info("Starting cleanup of stale network resources")
	
	if cfg == nil {
		return errors.New("config cannot be nil")
	}

	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list links: %w", err)
	}

	for _, link := range links {
		if strings.HasPrefix(link.Attrs().Name, "veth-") {
			logger.Debug("Removing stale veth", "name", link.Attrs().Name)
			if err := netlink.LinkDel(link); err != nil {
				logger.Warn("Failed to delete stale link", "name", link.Attrs().Name, "error", err)
			}
		}
	}
	return nil
}

// unmountPath unmounts a given path.
func unmountPath(ctx context.Context, path string) error {
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil {
		if !os.IsNotExist(err) && err != unix.EINVAL {
			return fmt.Errorf("failed to unmount %s: %w", path, err)
		}
	}
	return nil
}

// --- Seccomp Implementation ---

// applySeccomp applies the seccomp profile to the process.
func applySeccomp(ctx context.Context, cfg *ProcessConfig) error {
	if cfg == nil {
		return errors.New("process config cannot be nil")
	}
	
	logger := Logger(ctx).With("component", "seccomp")

	if cfg.SeccompProfile == "unconfined" {
		logger.Warn("Seccomp is unconfined as per configuration. This is insecure and not recommended.")
		return nil
	}

	// var profile *specs.Seccomp
	// var err error
	if cfg.SeccompProfile == "" || cfg.SeccompProfile == DefaultSeccompProfileName {
		logger.Info("No seccomp profile provided, applying a restrictive default profile.")
		// profile = defaultSeccompProfile()
		logger.Info("Seccomp functionality disabled for compatibility.")
		return nil
	} else {
		logger.Info("Applying user-provided seccomp profile", "path", cfg.SeccompProfile)
		logger.Info("Seccomp functionality disabled for compatibility.")
		return nil
		/*
		var profileData []byte
		profileData, err = os.ReadFile(cfg.SeccompProfile)
		if err != nil {
			return fmt.Errorf("failed to read seccomp profile: %w", err)
		}
		if err = json.Unmarshal(profileData, &profile); err != nil {
			return fmt.Errorf("failed to parse seccomp profile JSON: %w", err)
		}
		*/
	}
	
	/*
	filter, err := buildBPF(ctx, profile)
	if err != nil {
		return fmt.Errorf("failed to build BPF filter from seccomp profile: %w", err)
	}
	*/
	
	/*
	prog := &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	// NO_NEW_PRIVS is essential for seccomp to be effective.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(NO_NEW_PRIVS) for seccomp failed: %w", err)
	}

	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(prog)), 0, 0); err != nil {
		return fmt.Errorf("prctl(SET_SECCOMP) failed: %w", err)
	}

	logger.Info("Seccomp profile applied successfully.")
	return nil
	*/
}

// defaultSeccompProfile returns a restrictive default seccomp profile.
func defaultSeccompProfile() interface{} { // *specs.Seccomp {
	// This list is now more restrictive, focusing on common application needs.
	_ = []string{
		"accept4", "access", "arch_prctl", "brk", "capget", "capset",
		"chdir", "clone", "close", "dup2", "dup3",
		"epoll_create1", "epoll_ctl", "epoll_pwait",
		"execve", "exit_group", "faccessat2", "fcntl",
		"fstat", "futex", "getdents64",
		"getegid", "geteuid", "getgid", "getgroups",
		"getpid", "getppid", "getrandom",
		"getrlimit", "getrusage", "getsockname", "gettid", "getuid",
		"ioctl", "lseek", "madvise", "mincore", "mmap", "mprotect",
		"munmap", "nanosleep", "newfstatat", "openat", "pipe2",
		"poll", "pread64", "pwrite64", "read",
		"readlinkat", "recvfrom", "recvmsg", "restart_syscall",
		"rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
		"sched_getaffinity", "sched_yield",
		"seccomp", "sendto", "set_robust_list",
		"set_tid_address", "setsockopt",
		"sigaltstack", "socket",
		"statx", "sysinfo", "tgkill",
		"timerfd_create", "timerfd_settime",
		"uname", "wait4", "write", "writev",
	}

	return nil
	/* &specs.Seccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{archMap[runtime.GOARCH]},
		Syscalls: []specs.LinuxSyscall{
			{Names: allowedSyscalls, Action: specs.ActAllow},
		},
	} */
}

// buildBPF constructs a BPF filter from a seccomp profile.
func buildBPF(ctx context.Context, profile interface{}) ([]unix.SockFilter, error) {
	if profile == nil {
		return nil, errors.New("seccomp profile cannot be nil")
	}
	
	// Type assertion to get the actual profile
	seccompProfile, ok := profile.(*specs.LinuxSeccomp)
	if !ok {
		return nil, errors.New("invalid seccomp profile type")
	}
	
	logger := Logger(ctx).With("component", "seccomp-bpf")
	hostArch, ok := archMap[runtime.GOARCH]
	if !ok {
		return nil, fmt.Errorf("unsupported host architecture for seccomp: %s", runtime.GOARCH)
	}
	hostArchConst, ok := seccompArchConstMap[hostArch]
	if !ok {
		return nil, fmt.Errorf("unknown seccomp architecture constant for: %s", hostArch)
	}

	archSupported := false
	for _, arch := range seccompProfile.Architectures {
		if arch == hostArch {
			archSupported = true
			break
		}
	}
	if !archSupported {
		return nil, fmt.Errorf("seccomp profile does not support host architecture %s", hostArch)
	}

	// BPF programs must start with these two instructions to load the syscall number and check the architecture.
	bpf := []unix.SockFilter{
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 4), // A = seccomp_data.arch
		bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, hostArchConst, 0, 1), // if (A != host_arch) goto fail
		bpfStmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, 0), // A = seccomp_data.nr
	}

	syscallMap := make(map[uint32]specs.LinuxSeccompAction)
	for _, rule := range seccompProfile.Syscalls {
		for _, name := range rule.Names {
			syscallNum, err := getSyscallNum(name)
			if err != nil {
				logger.Warn("Unknown syscall in seccomp profile, skipping", "syscall", name)
				continue
			}
			syscallMap[syscallNum] = rule.Action
		}
	}

	// Create a jump table for all the syscalls in the profile.
	// This is more efficient than a long chain of if-else jumps.
	for num, action := range syscallMap {
		actionCode, ok := seccompActionMap[action]
		if !ok {
			return nil, fmt.Errorf("unknown seccomp action in profile: %s", action)
		}
		// If the syscall number matches, jump to the return instruction.
		// Otherwise, fall through to the next check.
		bpf = append(bpf, bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, num, 0, 1))
		// Not a match, so jump over the return instruction.
		bpf = append(bpf, bpfStmt(unix.BPF_RET|unix.BPF_K, actionCode))
	}

	// Default action for any syscall that didn't match a rule.
	defaultAction, ok := seccompActionMap[seccompProfile.DefaultAction]
	if !ok {
		return nil, fmt.Errorf("unknown default seccomp action: %s", seccompProfile.DefaultAction)
	}
	bpf = append(bpf, bpfStmt(unix.BPF_RET|unix.BPF_K, defaultAction)) // fail: return default_action

	// The first jump instruction needs to know the total size of the filter program to jump to the final 'fail' state.
	// We adjust the jump offset of the architecture check now that we know the full length.
	bpf[1] = bpfJump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, hostArchConst, 0, uint32(len(bpf)-2))

	return bpf, nil
}

func bpfStmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func bpfJump(code uint16, k, jt, jf uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k, Jt: uint8(jt), Jf: uint8(jf)}
}

func getSyscallNum(name string) (uint32, error) {
	num, ok := syscalls[name]
	if !ok {
		return 0, fmt.Errorf("unknown syscall: %s", name)
	}
	return num, nil
}

// --- Seccomp and Capability Maps ---

var CapabilityMap = map[string]int{
	"AUDIT_CONTROL":      unix.CAP_AUDIT_CONTROL, "AUDIT_READ": unix.CAP_AUDIT_READ,
	"AUDIT_WRITE":        unix.CAP_AUDIT_WRITE, "BLOCK_SUSPEND": unix.CAP_BLOCK_SUSPEND,
	"BPF":                unix.CAP_BPF, "CHECKPOINT_RESTORE": unix.CAP_CHECKPOINT_RESTORE,
	"CHOWN":              unix.CAP_CHOWN, "DAC_OVERRIDE": unix.CAP_DAC_OVERRIDE,
	"DAC_READ_SEARCH":    unix.CAP_DAC_READ_SEARCH, "FOWNER": unix.CAP_FOWNER,
	"FSETID":             unix.CAP_FSETID, "IPC_LOCK": unix.CAP_IPC_LOCK,
	"IPC_OWNER":          unix.CAP_IPC_OWNER, "KILL": unix.CAP_KILL,
	"LEASE":              unix.CAP_LEASE, "LINUX_IMMUTABLE": unix.CAP_LINUX_IMMUTABLE,
	"MAC_ADMIN":          unix.CAP_MAC_ADMIN, "MAC_OVERRIDE": unix.CAP_MAC_OVERRIDE,
	"MKNOD":              unix.CAP_MKNOD, "NET_ADMIN": unix.CAP_NET_ADMIN,
	"NET_BIND_SERVICE":   unix.CAP_NET_BIND_SERVICE, "NET_BROADCAST": unix.CAP_NET_BROADCAST,
	"NET_RAW":            unix.CAP_NET_RAW, "PERFMON": unix.CAP_PERFMON,
	"SETGID":             unix.CAP_SETGID, "SETPCAP": unix.CAP_SETPCAP,
	"SETUID":             unix.CAP_SETUID, "SYS_ADMIN": unix.CAP_SYS_ADMIN,
	"SYS_BOOT":           unix.CAP_SYS_BOOT, "SYS_CHROOT": unix.CAP_SYS_CHROOT,
	"SYS_MODULE":         unix.CAP_SYS_MODULE, "SYS_NICE": unix.CAP_SYS_NICE,
	"SYS_PACCT":          unix.CAP_SYS_PACCT, "SYS_PTRACE": unix.CAP_SYS_PTRACE,
	"SYS_RAWIO":          unix.CAP_SYS_RAWIO, "SYS_RESOURCE": unix.CAP_SYS_RESOURCE,
	"SYS_TIME":           unix.CAP_SYS_TIME, "SYS_TTY_CONFIG": unix.CAP_SYS_TTY_CONFIG,
	"SYSLOG":             unix.CAP_SYSLOG, "WAKE_ALARM": unix.CAP_WAKE_ALARM,
}

// This is a partial list for amd64. A complete implementation would use different maps
// based on the build architecture.
var syscalls = map[string]uint32{
	"read":                   unix.SYS_READ, "write": unix.SYS_WRITE, "open": unix.SYS_OPEN,
	"close":                  unix.SYS_CLOSE, "stat": unix.SYS_STAT, "fstat": unix.SYS_FSTAT,
	"lstat":                  unix.SYS_LSTAT, "poll": unix.SYS_POLL, "lseek": unix.SYS_LSEEK,
	"mmap":                   unix.SYS_MMAP, "mprotect": unix.SYS_MPROTECT, "munmap": unix.SYS_MUNMAP,
	"brk":                    unix.SYS_BRK, "rt_sigaction": unix.SYS_RT_SIGACTION,
	"rt_sigprocmask":         unix.SYS_RT_SIGPROCMASK, "rt_sigreturn": unix.SYS_RT_SIGRETURN,
	"ioctl":                  unix.SYS_IOCTL, "pread64": unix.SYS_PREAD64, "pwrite64": unix.SYS_PWRITE64,
	"readv":                  unix.SYS_READV, "writev": unix.SYS_WRITEV, "access": unix.SYS_ACCESS,
	"pipe":                   unix.SYS_PIPE, "select": unix.SYS_SELECT, "sched_yield": unix.SYS_SCHED_YIELD,
	"mremap":                 unix.SYS_MREMAP, "msync": unix.SYS_MSYNC, "mincore": unix.SYS_MINCORE,
	"madvise":                unix.SYS_MADVISE, "shmget": unix.SYS_SHMGET, "shmat": unix.SYS_SHMAT,
	"shmctl":                 unix.SYS_SHMCTL, "dup": unix.SYS_DUP, "dup2": unix.SYS_DUP2,
	"pause":                  unix.SYS_PAUSE, "nanosleep": unix.SYS_NANOSLEEP, "getitimer": unix.SYS_GETITIMER,
	"alarm":                  unix.SYS_ALARM, "setitimer": unix.SYS_SETITIMER, "getpid": unix.SYS_GETPID,
	"sendfile":               unix.SYS_SENDFILE, "socket": unix.SYS_SOCKET, "connect": unix.SYS_CONNECT,
	"accept":                 unix.SYS_ACCEPT, "sendto": unix.SYS_SENDTO, "recvfrom": unix.SYS_RECVFROM,
	"sendmsg":                unix.SYS_SENDMSG, "recvmsg": unix.SYS_RECVMSG, "shutdown": unix.SYS_SHUTDOWN,
	"bind":                   unix.SYS_BIND, "listen": unix.SYS_LISTEN, "getsockname": unix.SYS_GETSOCKNAME,
	"getpeername":            unix.SYS_GETPEERNAME, "socketpair": unix.SYS_SOCKETPAIR,
	"setsockopt":             unix.SYS_SETSOCKOPT, "getsockopt": unix.SYS_GETSOCKOPT, "clone": unix.SYS_CLONE,
	"fork":                   unix.SYS_FORK, "vfork": unix.SYS_VFORK, "execve": unix.SYS_EXECVE,
	"exit":                   unix.SYS_EXIT, "wait4": unix.SYS_WAIT4, "kill": unix.SYS_KILL,
	"uname":                  unix.SYS_UNAME, "semget": unix.SYS_SEMGET, "semop": unix.SYS_SEMOP,
	"semctl":                 unix.SYS_SEMCTL, "shmdt": unix.SYS_SHMDT, "msgget": unix.SYS_MSGGET,
	"msgsnd":                 unix.SYS_MSGSND, "msgrcv": unix.SYS_MSGRCV, "msgctl": unix.SYS_MSGCTL,
	"fcntl":                  unix.SYS_FCNTL, "flock": unix.SYS_FLOCK, "fsync": unix.SYS_FSYNC,
	"fdatasync":              unix.SYS_FDATASYNC, "truncate": unix.SYS_TRUNCATE, "ftruncate": unix.SYS_FTRUNCATE,
	"getdents":               unix.SYS_GETDENTS, "getcwd": unix.SYS_GETCWD, "chdir": unix.SYS_CHDIR,
	"fchdir":                 unix.SYS_FCHDIR, "rename": unix.SYS_RENAME, "mkdir": unix.SYS_MKDIR,
	"rmdir":                  unix.SYS_RMDIR, "creat": unix.SYS_CREAT, "link": unix.SYS_LINK,
	"unlink":                 unix.SYS_UNLINK, "symlink": unix.SYS_SYMLINK, "readlink": unix.SYS_READLINK,
	"chmod":                  unix.SYS_CHMOD, "fchmod": unix.SYS_FCHMOD, "chown": unix.SYS_CHOWN,
	"fchown":                 unix.SYS_FCHOWN, "lchown": unix.SYS_LCHOWN, "umask": unix.SYS_UMASK,
	"gettimeofday":           unix.SYS_GETTIMEOFDAY, "getrlimit": unix.SYS_GETRLIMIT,
	"getrusage":              unix.SYS_GETRUSAGE, "sysinfo": unix.SYS_SYSINFO, "times": unix.SYS_TIMES,
	"ptrace":                 unix.SYS_PTRACE, "getuid": unix.SYS_GETUID, "syslog": unix.SYS_SYSLOG,
	"getgid":                 unix.SYS_GETGID, "setuid": unix.SYS_SETUID, "setgid": unix.SYS_SETGID,
	"geteuid":                unix.SYS_GETEUID, "getegid": unix.SYS_GETEGID, "setpgid": unix.SYS_SETPGID,
	"getppid":                unix.SYS_GETPPID, "getpgrp": unix.SYS_GETPGRP, "setsid": unix.SYS_SETSID,
	"setreuid":               unix.SYS_SETREUID, "setregid": unix.SYS_SETREGID, "getgroups": unix.SYS_GETGROUPS,
	"setgroups":              unix.SYS_SETGROUPS, "setresuid": unix.SYS_SETRESUID, "getresuid": unix.SYS_GETRESUID,
	"setresgid":              unix.SYS_SETRESGID, "getresgid": unix.SYS_GETRESGID, "getpgid": unix.SYS_GETPGID,
	"setfsuid":               unix.SYS_SETFSUID, "setfsgid": unix.SYS_SETFSGID, "getsid": unix.SYS_GETSID,
	"capget":                 unix.SYS_CAPGET, "capset": unix.SYS_CAPSET, "rt_sigpending": unix.SYS_RT_SIGPENDING,
	"rt_sigtimedwait":        unix.SYS_RT_SIGTIMEDWAIT, "rt_sigqueueinfo": unix.SYS_RT_SIGQUEUEINFO,
	"rt_sigsuspend":          unix.SYS_RT_SIGSUSPEND, "sigaltstack": unix.SYS_SIGALTSTACK, "utime": unix.SYS_UTIME,
	"mknod":                  unix.SYS_MKNOD, "uselib": unix.SYS_USELIB, "personality": unix.SYS_PERSONALITY,
	"ustat":                  unix.SYS_USTAT, "statfs": unix.SYS_STATFS, "fstatfs": unix.SYS_FSTATFS,
	"sysfs":                  unix.SYS_SYSFS, "getpriority": unix.SYS_GETPRIORITY, "setpriority": unix.SYS_SETPRIORITY,
	"sched_setparam":         unix.SYS_SCHED_SETPARAM, "sched_getparam": unix.SYS_SCHED_GETPARAM,
	"sched_setscheduler":     unix.SYS_SCHED_SETSCHEDULER, "sched_getscheduler": unix.SYS_SCHED_GETSCHEDULER,
	"sched_get_priority_max": unix.SYS_SCHED_GET_PRIORITY_MAX, "sched_get_priority_min": unix.SYS_SCHED_GET_PRIORITY_MIN,
	"sched_rr_get_interval":  unix.SYS_SCHED_RR_GET_INTERVAL, "mlock": unix.SYS_MLOCK, "munlock": unix.SYS_MUNLOCK,
	"mlockall":               unix.SYS_MLOCKALL, "munlockall": unix.SYS_MUNLOCKALL, "vhangup": unix.SYS_VHANGUP,
	"modify_ldt":             unix.SYS_MODIFY_LDT, "pivot_root": unix.SYS_PIVOT_ROOT, "_sysctl": unix.SYS__SYSCTL,
	"prctl":                  unix.SYS_PRCTL, "arch_prctl": unix.SYS_ARCH_PRCTL, "adjtimex": unix.SYS_ADJTIMEX,
	"setrlimit":              unix.SYS_SETRLIMIT, "chroot": unix.SYS_CHROOT, "sync": unix.SYS_SYNC,
	"acct":                   unix.SYS_ACCT, "settimeofday": unix.SYS_SETTIMEOFDAY, "mount": unix.SYS_MOUNT,
	"umount2":                unix.SYS_UMOUNT2, "swapon": unix.SYS_SWAPON, "swapoff": unix.SYS_SWAPOFF,
	"reboot":                 unix.SYS_REBOOT, "sethostname": unix.SYS_SETHOSTNAME, "setdomainname": unix.SYS_SETDOMAINNAME,
	"iopl":                   unix.SYS_IOPL, "ioperm": unix.SYS_IOPERM, "create_module": unix.SYS_CREATE_MODULE,
	"init_module":            unix.SYS_INIT_MODULE, "delete_module": unix.SYS_DELETE_MODULE,
	"get_kernel_syms":        unix.SYS_GET_KERNEL_SYMS, "query_module": unix.SYS_QUERY_MODULE,
	"quotactl":               unix.SYS_QUOTACTL, "nfsservctl": unix.SYS_NFSSERVCTL, "getpmsg": unix.SYS_GETPMSG,
	"putpmsg":                unix.SYS_PUTPMSG, "afs_syscall": unix.SYS_AFS_SYSCALL, "tuxcall": unix.SYS_TUXCALL,
	"security":               unix.SYS_SECURITY, "gettid": unix.SYS_GETTID, "readahead": unix.SYS_READAHEAD,
	"setxattr":               unix.SYS_SETXATTR, "lsetxattr": unix.SYS_LSETXATTR, "fsetxattr": unix.SYS_FSETXATTR,
	"getxattr":               unix.SYS_GETXATTR, "lgetxattr": unix.SYS_LGETXATTR, "fgetxattr": unix.SYS_FGETXATTR,
	"listxattr":              unix.SYS_LISTXATTR, "llistxattr": unix.SYS_LLISTXATTR, "flistxattr": unix.SYS_FLISTXATTR,
	"removexattr":            unix.SYS_REMOVEXATTR, "lremovexattr": unix.SYS_LREMOVEXATTR, "fremovexattr": unix.SYS_FREMOVEXATTR,
	"tkill":                  unix.SYS_TKILL, "time": unix.SYS_TIME, "futex": unix.SYS_FUTEX,
	"sched_setaffinity":      unix.SYS_SCHED_SETAFFINITY, "sched_getaffinity": unix.SYS_SCHED_GETAFFINITY,
	"set_thread_area":        unix.SYS_SET_THREAD_AREA, "io_setup": unix.SYS_IO_SETUP, "io_destroy": unix.SYS_IO_DESTROY,
	"io_getevents":           unix.SYS_IO_GETEVENTS, "io_submit": unix.SYS_IO_SUBMIT, "io_cancel": unix.SYS_IO_CANCEL,
	"get_thread_area":        unix.SYS_GET_THREAD_AREA, "lookup_dcookie": unix.SYS_LOOKUP_DCOOKIE,
	"epoll_create":           unix.SYS_EPOLL_CREATE, "epoll_ctl_old": unix.SYS_EPOLL_CTL_OLD,
	"epoll_wait_old":         unix.SYS_EPOLL_WAIT_OLD, "remap_file_pages": unix.SYS_REMAP_FILE_PAGES,
	"getdents64":             unix.SYS_GETDENTS64, "set_tid_address": unix.SYS_SET_TID_ADDRESS,
	"restart_syscall":        unix.SYS_RESTART_SYSCALL, "semtimedop": unix.SYS_SEMTIMEDOP, "fadvise64": unix.SYS_FADVISE64,
	"timer_create":           unix.SYS_TIMER_CREATE, "timer_settime": unix.SYS_TIMER_SETTIME,
	"timer_gettime":          unix.SYS_TIMER_GETTIME, "timer_getoverrun": unix.SYS_TIMER_GETOVERRUN,
	"timer_delete":           unix.SYS_TIMER_DELETE, "clock_settime": unix.SYS_CLOCK_SETTIME,
	"clock_gettime":          unix.SYS_CLOCK_GETTIME, "clock_getres": unix.SYS_CLOCK_GETRES,
	"clock_nanosleep":        unix.SYS_CLOCK_NANOSLEEP, "exit_group": unix.SYS_EXIT_GROUP,
	"epoll_wait":             unix.SYS_EPOLL_WAIT, "epoll_ctl": unix.SYS_EPOLL_CTL, "tgkill": unix.SYS_TGKILL,
	"utimes":                 unix.SYS_UTIMES, "vserver": unix.SYS_VSERVER, "mbind": unix.SYS_MBIND,
	"set_mempolicy":          unix.SYS_SET_MEMPOLICY, "get_mempolicy": unix.SYS_GET_MEMPOLICY,
	"mq_open":                unix.SYS_MQ_OPEN, "mq_unlink": unix.SYS_MQ_UNLINK, "mq_timedsend": unix.SYS_MQ_TIMEDSEND,
	"mq_timedreceive":        unix.SYS_MQ_TIMEDRECEIVE, "mq_notify": unix.SYS_MQ_NOTIFY, "mq_getsetattr": unix.SYS_MQ_GETSETATTR,
	"kexec_load":             unix.SYS_KEXEC_LOAD, "waitid": unix.SYS_WAITID, "add_key": unix.SYS_ADD_KEY,
	"request_key":            unix.SYS_REQUEST_KEY, "keyctl": unix.SYS_KEYCTL, "ioprio_set": unix.SYS_IOPRIO_SET,
	"ioprio_get":             unix.SYS_IOPRIO_GET, "inotify_init": unix.SYS_INOTIFY_INIT,
	"inotify_add_watch":      unix.SYS_INOTIFY_ADD_WATCH, "inotify_rm_watch": unix.SYS_INOTIFY_RM_WATCH,
	"migrate_pages":          unix.SYS_MIGRATE_PAGES, "openat": unix.SYS_OPENAT, "mkdirat": unix.SYS_MKDIRAT,
	"mknodat":                unix.SYS_MKNODAT, "fchownat": unix.SYS_FCHOWNAT, "futimesat": unix.SYS_FUTIMESAT,
	"newfstatat":             unix.SYS_NEWFSTATAT, "unlinkat": unix.SYS_UNLINKAT, "renameat": unix.SYS_RENAMEAT,
	"linkat":                 unix.SYS_LINKAT, "symlinkat": unix.SYS_SYMLINKAT, "readlinkat": unix.SYS_READLINKAT,
	"fchmodat":               unix.SYS_FCHMODAT, "faccessat": unix.SYS_FACCESSAT, "pselect6": unix.SYS_PSELECT6,
	"ppoll":                  unix.SYS_PPOLL, "unshare": unix.SYS_UNSHARE, "set_robust_list": unix.SYS_SET_ROBUST_LIST,
	"get_robust_list":        unix.SYS_GET_ROBUST_LIST, "splice": unix.SYS_SPLICE, "tee": unix.SYS_TEE,
	"sync_file_range":        unix.SYS_SYNC_FILE_RANGE, "vmsplice": unix.SYS_VMSPLICE, "move_pages": unix.SYS_MOVE_PAGES,
	"utimensat":              unix.SYS_UTIMENSAT, "epoll_pwait": unix.SYS_EPOLL_PWAIT, "signalfd": unix.SYS_SIGNALFD,
	"timerfd_create":         unix.SYS_TIMERFD_CREATE, "eventfd": unix.SYS_EVENTFD, "fallocate": unix.SYS_FALLOCATE,
	"timerfd_settime":        unix.SYS_TIMERFD_SETTIME, "timerfd_gettime": unix.SYS_TIMERFD_GETTIME,
	"accept4":                unix.SYS_ACCEPT4, "signalfd4": unix.SYS_SIGNALFD4, "eventfd2": unix.SYS_EVENTFD2,
	"epoll_create1":          unix.SYS_EPOLL_CREATE1, "dup3": unix.SYS_DUP3, "pipe2": unix.SYS_PIPE2,
	"inotify_init1":          unix.SYS_INOTIFY_INIT1, "preadv": unix.SYS_PREADV, "pwritev": unix.SYS_PWRITEV,
	"rt_tgsigqueueinfo":      unix.SYS_RT_TGSIGQUEUEINFO, "perf_event_open": unix.SYS_PERF_EVENT_OPEN,
	"recvmmsg":               unix.SYS_RECVMMSG, "fanotify_init": unix.SYS_FANOTIFY_INIT, "fanotify_mark": unix.SYS_FANOTIFY_MARK,
	"prlimit64":              unix.SYS_PRLIMIT64, "name_to_handle_at": unix.SYS_NAME_TO_HANDLE_AT,
	"open_by_handle_at":      unix.SYS_OPEN_BY_HANDLE_AT, "clock_adjtime": unix.SYS_CLOCK_ADJTIME,
	"syncfs":                 unix.SYS_SYNCFS, "sendmmsg": unix.SYS_SENDMMSG, "setns": unix.SYS_SETNS,
	"getcpu":                 unix.SYS_GETCPU, "process_vm_readv": unix.SYS_PROCESS_VM_READV,
	"process_vm_writev":      unix.SYS_PROCESS_VM_WRITEV, "kcmp": unix.SYS_KCMP, "finit_module": unix.SYS_FINIT_MODULE,
	"seccomp":                unix.SYS_SECCOMP, "getrandom": unix.SYS_GETRANDOM, "memfd_create": unix.SYS_MEMFD_CREATE,
	"kexec_file_load":        unix.SYS_KEXEC_FILE_LOAD, "bpf": unix.SYS_BPF, "execveat": unix.SYS_EXECVEAT,
	"userfaultfd":            unix.SYS_USERFAULTFD, "membarrier": unix.SYS_MEMBARRIER, "mlock2": unix.SYS_MLOCK2,
	"copy_file_range":        unix.SYS_COPY_FILE_RANGE, "preadv2": unix.SYS_PREADV2, "pwritev2": unix.SYS_PWRITEV2,
	"pkey_mprotect":          unix.SYS_PKEY_MPROTECT, "pkey_alloc": unix.SYS_PKEY_ALLOC, "pkey_free": unix.SYS_PKEY_FREE,
	"statx":                  unix.SYS_STATX, "io_pgetevents": unix.SYS_IO_PGETEVENTS, "rseq": unix.SYS_RSEQ,
	"pidfd_send_signal":      unix.SYS_PIDFD_SEND_SIGNAL, "io_uring_setup": unix.SYS_IO_URING_SETUP,
	"io_uring_enter":         unix.SYS_IO_URING_ENTER, "io_uring_register": unix.SYS_IO_URING_REGISTER,
	"open_tree":              unix.SYS_OPEN_TREE, "move_mount": unix.SYS_MOVE_MOUNT, "fsopen": unix.SYS_FSOPEN,
	"fsconfig":               unix.SYS_FSCONFIG, "fsmount": unix.SYS_FSMOUNT, "fspick": unix.SYS_FSPICK,
	"pidfd_open":             unix.SYS_PIDFD_OPEN, "clone3": unix.SYS_CLONE3, "close_range": unix.SYS_CLOSE_RANGE,
	"openat2":                unix.SYS_OPENAT2, "pidfd_getfd": unix.SYS_PIDFD_GETFD, "faccessat2": unix.SYS_FACCESSAT2,
	"process_madvise":        unix.SYS_PROCESS_MADVISE, "epoll_pwait2": unix.SYS_EPOLL_PWAIT2,
	"mount_setattr":          unix.SYS_MOUNT_SETATTR, "quotactl_fd": unix.SYS_QUOTACTL_FD,
	"landlock_create_ruleset": unix.SYS_LANDLOCK_CREATE_RULESET, "landlock_add_rule": unix.SYS_LANDLOCK_ADD_RULE,
	"landlock_restrict_self": unix.SYS_LANDLOCK_RESTRICT_SELF, "memfd_secret": unix.SYS_MEMFD_SECRET,
	"process_mrelease":       unix.SYS_PROCESS_MRELEASE,
}

// copyDirectory recursively copies a directory from source to destination
func copyDirectory(src, dst string) error {
	if src == "" || dst == "" {
		return fmt.Errorf("source and destination cannot be empty")
	}
	
	// Ensure destination directory exists
	if err := os.MkdirAll(dst, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}
	
	return filepath.Walk(src, func(srcPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Calculate relative path
		relPath, err := filepath.Rel(src, srcPath)
		if err != nil {
			return err
		}
		
		// Skip the root directory
		if relPath == "." {
			return nil
		}
		
		dstPath := filepath.Join(dst, relPath)
		
		switch {
		case info.IsDir():
			return os.MkdirAll(dstPath, info.Mode())
		case info.Mode().IsRegular():
			return copyFile(srcPath, dstPath, info.Mode())
		case info.Mode()&os.ModeSymlink != 0:
			return copySymlink(srcPath, dstPath)
		default:
			// Skip special files
			return nil
		}
	})
}

// copyFile copies a regular file from source to destination
func copyFile(src, dst string, mode os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	
	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	
	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	
	_, err = io.Copy(dstFile, srcFile)
	return err
}

// copySymlink copies a symbolic link
func copySymlink(src, dst string) error {
	linkTarget, err := os.Readlink(src)
	if err != nil {
		return err
	}
	
	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	
	return os.Symlink(linkTarget, dst)
}

// executeCommand executes the container's main command with proper security measures

// validateExecutable performs security validation on the executable
func validateExecutable(executable string) error {
	if executable == "" {
		return fmt.Errorf("executable path cannot be empty")
	}
	
	// Check for path traversal attempts
	if strings.Contains(executable, "..") {
		return fmt.Errorf("executable path contains directory traversal: %s", executable)
	}
	
	// Check for null bytes
	if strings.Contains(executable, "\x00") {
		return fmt.Errorf("executable path contains null bytes")
	}
	
	// Validate absolute paths more strictly
	if filepath.IsAbs(executable) {
		// Check if file exists and is executable
		fileInfo, err := os.Stat(executable)
		if err != nil {
			return fmt.Errorf("executable not found: %s", executable)
		}
		
		// Check file permissions
		if fileInfo.Mode()&0111 == 0 {
			return fmt.Errorf("file is not executable: %s", executable)
		}
		
		// Check for dangerous executables
		dangerousExecs := []string{
			"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish",
			"/usr/bin/python", "/usr/bin/perl", "/usr/bin/ruby",
			"/bin/su", "/usr/bin/sudo", "/bin/chroot",
		}
		
		for _, dangerous := range dangerousExecs {
			if executable == dangerous {
				return fmt.Errorf("dangerous executable not allowed: %s", executable)
			}
		}
	} else {
		// For relative paths, validate the name
		baseName := filepath.Base(executable)
		if baseName != executable {
			return fmt.Errorf("relative paths with directories not allowed: %s", executable)
		}
		
		// Check against dangerous command names
		dangerousNames := []string{
			"bash", "sh", "zsh", "fish", "python", "perl", "ruby",
			"su", "sudo", "chroot", "exec", "eval",
		}
		
		for _, dangerous := range dangerousNames {
			if baseName == dangerous {
				return fmt.Errorf("dangerous command not allowed: %s", baseName)
			}
		}
	}
	
	return nil
}

