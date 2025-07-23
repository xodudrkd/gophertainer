package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// SecurityHardeningManager provides comprehensive security protections
type SecurityHardeningManager struct {
	processLimiter    *ProcessLimiter
	memoryGuard       *MemoryExhaustionGuard
	fdLimiter         *FileDescriptorLimiter
	diskSpaceGuard    *DiskSpaceGuard
	networkLimiter    *NetworkResourceLimiter
	pathValidator     *PathValidator
	antiExploitGuard  *AntiExploitGuard
	mu                sync.RWMutex
	active            bool
}

// ProcessLimiter prevents fork bomb attacks
type ProcessLimiter struct {
	maxProcesses     int64
	currentProcesses int64 // atomic
	processStartTime map[int]time.Time
	mu               sync.RWMutex
	alertThreshold   int64
}

// MemoryExhaustionGuard prevents memory exhaustion attacks
type MemoryExhaustionGuard struct {
	maxMemoryMB      int64
	currentMemoryMB  int64 // atomic
	alertThreshold   int64
	emergencyCleanup []func()
	mu               sync.RWMutex
}

// FileDescriptorLimiter prevents FD exhaustion
type FileDescriptorLimiter struct {
	maxFDs         int64
	currentFDs     int64 // atomic
	fdTracker      map[uintptr]string
	mu             sync.RWMutex
	alertThreshold int64
}

// DiskSpaceGuard prevents disk space exhaustion
type DiskSpaceGuard struct {
	minFreeMB      int64
	alertThreshold int64
	monitorPaths   []string
	mu             sync.RWMutex
}

// NetworkResourceLimiter prevents network resource exhaustion
type NetworkResourceLimiter struct {
	maxConnections    int64
	currentConns      int64 // atomic
	maxInterfacesUser int64
	currentInterfaces int64 // atomic
	mu                sync.RWMutex
}

// PathValidator provides secure path validation and canonicalization
type PathValidator struct {
	allowedPrefixes  []string
	deniedPaths      []string
	maxPathLength    int
	maxSymlinkDepth  int
	mu               sync.RWMutex
}

// AntiExploitGuard provides protection against common exploits
type AntiExploitGuard struct {
	// TOCTOU (Time-of-Check-Time-of-Use) protection
	toctouCache map[string]TOCTOUEntry
	
	// Race condition detection
	raceDetector map[string]time.Time
	
	// Integer overflow protection
	maxIntegerValue int64
	
	mu sync.RWMutex
}

type TOCTOUEntry struct {
	checksum string
	stat     os.FileInfo
	checked  time.Time
}

var globalSecurityManager = &SecurityHardeningManager{
	processLimiter: &ProcessLimiter{
		maxProcesses:     100,
		processStartTime: make(map[int]time.Time),
		alertThreshold:   80,
	},
	memoryGuard: &MemoryExhaustionGuard{
		maxMemoryMB:    2048,
		alertThreshold: 1800,
	},
	fdLimiter: &FileDescriptorLimiter{
		maxFDs:         1024,
		fdTracker:      make(map[uintptr]string),
		alertThreshold: 900,
	},
	diskSpaceGuard: &DiskSpaceGuard{
		minFreeMB:      500,
		alertThreshold: 1000,
		monitorPaths:   []string{"/", "/tmp", "/var"},
	},
	networkLimiter: &NetworkResourceLimiter{
		maxConnections:    50,
		maxInterfacesUser: 10,
	},
	pathValidator: &PathValidator{
		allowedPrefixes: []string{"/tmp", "/var/tmp"},
		deniedPaths:     []string{"/proc", "/sys", "/dev"},
		maxPathLength:   4096,
		maxSymlinkDepth: 8,
	},
	antiExploitGuard: &AntiExploitGuard{
		toctouCache:     make(map[string]TOCTOUEntry),
		raceDetector:    make(map[string]time.Time),
		maxIntegerValue: 1<<31 - 1,
	},
}

// InitializeSecurityHardening sets up all security protections
func InitializeSecurityHardening(ctx context.Context, interactive bool) error {
	logger := Logger(ctx).With("component", "security-hardening")
	
	// Set process limits
	var rlimit syscall.Rlimit
	
	// Limit number of processes (fork bomb protection)
	if err := syscall.Getrlimit(unix.RLIMIT_NPROC, &rlimit); err == nil {
		rlimit.Cur = min(rlimit.Cur, 100) // Limit to 100 processes
		syscall.Setrlimit(unix.RLIMIT_NPROC, &rlimit)
	}
	
	// Limit file descriptors
	if err := syscall.Getrlimit(unix.RLIMIT_NOFILE, &rlimit); err == nil {
		rlimit.Cur = min(rlimit.Cur, 1024) // Limit to 1024 FDs
		syscall.Setrlimit(unix.RLIMIT_NOFILE, &rlimit)
	}
	
	// Limit memory (if possible)
	if err := syscall.Getrlimit(unix.RLIMIT_AS, &rlimit); err == nil {
		rlimit.Cur = min(rlimit.Cur, 2048*1024*1024) // Limit to 2GB
		syscall.Setrlimit(unix.RLIMIT_AS, &rlimit)
	}

	// Limit stack size
	if err := syscall.Getrlimit(unix.RLIMIT_STACK, &rlimit); err == nil {
		rlimit.Cur = min(rlimit.Cur, 8*1024*1024) // Limit to 8MB
		syscall.Setrlimit(unix.RLIMIT_STACK, &rlimit)
	}

	// Limit message queue size
	if err := syscall.Getrlimit(unix.RLIMIT_MSGQUEUE, &rlimit); err == nil {
		rlimit.Cur = min(rlimit.Cur, 16*1024*1024) // Limit to 16MB
		syscall.Setrlimit(unix.RLIMIT_MSGQUEUE, &rlimit)
	}

	// Prevent raising process priority
	if err := syscall.Getrlimit(unix.RLIMIT_NICE, &rlimit); err == nil {
		rlimit.Cur = min(rlimit.Cur, 40) // Prevent nice values below -20
		syscall.Setrlimit(unix.RLIMIT_NICE, &rlimit)
	}
	
	// Limit CPU time
	if err := syscall.Getrlimit(unix.RLIMIT_CPU, &rlimit); err == nil {
		rlimit.Cur = min(rlimit.Cur, 3600) // Limit to 1 hour CPU time
		syscall.Setrlimit(unix.RLIMIT_CPU, &rlimit)
	}
	
	// Start monitoring goroutines only in non-interactive mode
	if !interactive {
		// Stop any existing monitoring first, then start new monitoring
		globalSecurityManager.stopMonitoring()
		globalSecurityManager.startMonitoring(ctx)
	} else {
		// Stop all monitoring for interactive mode
		globalSecurityManager.stopMonitoring()
		logger.Info("Stopped security monitoring for interactive mode")
	}
	
	logger.Info("Security hardening initialized successfully")
	return nil
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

// startMonitoring starts all security monitoring goroutines
func (shm *SecurityHardeningManager) startMonitoring(ctx context.Context) {
	shm.mu.Lock()
	if shm.active {
		shm.mu.Unlock()
		return
	}
	shm.active = true
	shm.mu.Unlock()
	
	// Monitor resource usage
	go shm.monitorResourceUsage(ctx)
	
	// Clean up old entries
	go shm.cleanupOldEntries(ctx)
	
	// Monitor for suspicious activities
	go shm.monitorSuspiciousActivity(ctx)
}

// stopMonitoring stops all security monitoring goroutines
func (shm *SecurityHardeningManager) stopMonitoring() {
	shm.mu.Lock()
	shm.active = false
	shm.mu.Unlock()
}

// monitorResourceUsage continuously monitors system resource usage
func (shm *SecurityHardeningManager) monitorResourceUsage(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			shm.mu.RLock()
			active := shm.active
			shm.mu.RUnlock()
			if !active {
				return
			}
			shm.checkAllLimits(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// checkAllLimits checks all resource limits and triggers alerts if needed
func (shm *SecurityHardeningManager) checkAllLimits(ctx context.Context) {
	logger := Logger(ctx).With("component", "security-monitor")
	
	// Check process limits
	if current := atomic.LoadInt64(&shm.processLimiter.currentProcesses); current > shm.processLimiter.alertThreshold {
		logger.Warn("Process limit approaching", "current", current, "max", shm.processLimiter.maxProcesses)
	}
	
	// Check memory usage
	var meminfo syscall.Sysinfo_t
	if err := syscall.Sysinfo(&meminfo); err == nil {
		usedMB := (meminfo.Totalram - meminfo.Freeram) / (1024 * 1024)
		if usedMB > uint64(shm.memoryGuard.alertThreshold) {
			// Only log if monitoring is active (not in interactive mode)
			shm.mu.RLock()
			active := shm.active
			shm.mu.RUnlock()
			if active {
				logger.Warn("Memory usage high", "used_mb", usedMB, "threshold", shm.memoryGuard.alertThreshold)
			}
			shm.triggerMemoryCleanup()
		}
	}
	
	// Check file descriptor usage
	if current := atomic.LoadInt64(&shm.fdLimiter.currentFDs); current > shm.fdLimiter.alertThreshold {
		logger.Warn("File descriptor usage high", "current", current, "max", shm.fdLimiter.maxFDs)
	}
	
	// Check disk space
	shm.checkDiskSpace(ctx)
}

// triggerMemoryCleanup triggers emergency memory cleanup
func (shm *SecurityHardeningManager) triggerMemoryCleanup() {
	shm.memoryGuard.mu.RLock()
	cleanupFuncs := make([]func(), len(shm.memoryGuard.emergencyCleanup))
	copy(cleanupFuncs, shm.memoryGuard.emergencyCleanup)
	shm.memoryGuard.mu.RUnlock()
	
	for _, cleanup := range cleanupFuncs {
		go cleanup()
	}
	
	// Force garbage collection
	runtime.GC()
	runtime.GC()
}

// checkDiskSpace checks available disk space on monitored paths
func (shm *SecurityHardeningManager) checkDiskSpace(ctx context.Context) {
	logger := Logger(ctx).With("component", "disk-monitor")
	
	for _, path := range shm.diskSpaceGuard.monitorPaths {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(path, &stat); err == nil {
			freeMB := (stat.Bavail * uint64(stat.Bsize)) / (1024 * 1024)
			if int64(freeMB) < shm.diskSpaceGuard.minFreeMB {
				logger.Error("Disk space critically low", "path", path, "free_mb", freeMB, "min_required", shm.diskSpaceGuard.minFreeMB)
			} else if int64(freeMB) < shm.diskSpaceGuard.alertThreshold {
				logger.Warn("Disk space low", "path", path, "free_mb", freeMB, "threshold", shm.diskSpaceGuard.alertThreshold)
			}
		}
	}
}

// ValidateAndCanonicalizePath securely validates and canonicalizes a path
func (pv *PathValidator) ValidateAndCanonicalizePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path cannot be empty")
	}
	
	if len(path) > pv.maxPathLength {
		return "", fmt.Errorf("path too long: %d > %d", len(path), pv.maxPathLength)
	}
	
	// Resolve symlinks with depth limit
	resolved, err := pv.resolveSymlinksSecurely(path, 0)
	if err != nil {
		return "", fmt.Errorf("failed to resolve symlinks: %w", err)
	}
	
	// Clean the path
	clean := filepath.Clean(resolved)
	
	// Check against denied paths
	pv.mu.RLock()
	for _, denied := range pv.deniedPaths {
		if strings.HasPrefix(clean, denied) {
			pv.mu.RUnlock()
			return "", fmt.Errorf("path %s is denied (prefix %s)", clean, denied)
		}
	}
	pv.mu.RUnlock()
	
	return clean, nil
}

// resolveSymlinksSecurely resolves symlinks with depth limiting
func (pv *PathValidator) resolveSymlinksSecurely(path string, depth int) (string, error) {
	if depth > pv.maxSymlinkDepth {
		return "", fmt.Errorf("symlink depth exceeded: %d > %d", depth, pv.maxSymlinkDepth)
	}
	
	info, err := os.Lstat(path)
	if err != nil {
		return path, nil // Path doesn't exist, return as-is
	}
	
	if info.Mode()&os.ModeSymlink == 0 {
		return path, nil // Not a symlink
	}
	
	// Read symlink target
	target, err := os.Readlink(path)
	if err != nil {
		return "", fmt.Errorf("failed to read symlink: %w", err)
	}
	
	// Resolve relative paths
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	
	// Recursively resolve
	return pv.resolveSymlinksSecurely(target, depth+1)
}

// CheckTOCTOU performs Time-of-Check-Time-of-Use protection
func (aeg *AntiExploitGuard) CheckTOCTOU(path string, operation func() error, cleanup func()) error {
	aeg.mu.Lock()
	defer aeg.mu.Unlock()

	// Get file info at check time
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("TOCTOU check failed: %w", err)
	}

	// Calculate checksum
	checksum, err := aeg.calculateFileChecksum(path)
	if err != nil {
		return fmt.Errorf("TOCTOU checksum failed: %w", err)
	}

	// Store check information
	entry := TOCTOUEntry{
		checksum: checksum,
		stat:     info,
		checked:  time.Now(),
	}
	aeg.toctouCache[path] = entry

	// Perform operation
	if err := operation(); err != nil {
		if cleanup != nil {
			cleanup()
		}
		return err
	}

	// Verify file hasn't changed
	newInfo, err := os.Stat(path)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return fmt.Errorf("TOCTOU verification failed: %w", err)
	}

	if !info.ModTime().Equal(newInfo.ModTime()) || info.Size() != newInfo.Size() {
		if cleanup != nil {
			cleanup()
		}
		return fmt.Errorf("TOCTOU violation detected: file changed during operation")
	}

	return nil
}

// calculateFileChecksum calculates a simple checksum for TOCTOU protection
func (aeg *AntiExploitGuard) calculateFileChecksum(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	
	// Simple checksum based on file properties
	return fmt.Sprintf("%d_%d_%s", info.Size(), info.ModTime().Unix(), info.Mode().String()), nil
}

// DetectRaceCondition detects potential race conditions in file operations
func (aeg *AntiExploitGuard) DetectRaceCondition(key string) error {
	aeg.mu.Lock()
	defer aeg.mu.Unlock()
	
	now := time.Now()
	if lastAccess, exists := aeg.raceDetector[key]; exists {
		if now.Sub(lastAccess) < 100*time.Millisecond {
			return fmt.Errorf("potential race condition detected for key: %s", key)
		}
	}
	
	aeg.raceDetector[key] = now
	return nil
}

// CheckIntegerOverflow checks for potential integer overflow
func (aeg *AntiExploitGuard) CheckIntegerOverflow(a, b int64, operation string) error {
	switch operation {
	case "add":
		if a > 0 && b > aeg.maxIntegerValue-a {
			return fmt.Errorf("integer overflow detected in addition: %d + %d", a, b)
		}
	case "multiply":
		if a != 0 && b > aeg.maxIntegerValue/a {
			return fmt.Errorf("integer overflow detected in multiplication: %d * %d", a, b)
		}
	}
	return nil
}

// SecureFileCreate creates a file with secure permissions and validation
func SecureFileCreate(path string, perm os.FileMode) (*os.File, error) {
	// Validate path
	cleanPath, err := globalSecurityManager.pathValidator.ValidateAndCanonicalizePath(path)
	if err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}
	
	// Check for race conditions
	raceKey := fmt.Sprintf("create:%s", cleanPath)
	if err := globalSecurityManager.antiExploitGuard.DetectRaceCondition(raceKey); err != nil {
		return nil, fmt.Errorf("race condition detected: %w", err)
	}
	
	// Ensure secure permissions
	if perm&0077 != 0 {
		perm &= ^os.FileMode(0077) // Remove group/other permissions
	}
	
	// Create file atomically with O_EXCL to prevent race conditions
	fd, err := syscall.Open(cleanPath, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY, uint32(perm))
	if err != nil {
		return nil, fmt.Errorf("secure file creation failed: %w", err)
	}
	
	file := os.NewFile(uintptr(fd), cleanPath)
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("failed to create file object")
	}
	
	// Track file descriptor
	globalSecurityManager.fdLimiter.mu.Lock()
	globalSecurityManager.fdLimiter.fdTracker[uintptr(fd)] = cleanPath
	atomic.AddInt64(&globalSecurityManager.fdLimiter.currentFDs, 1)
	globalSecurityManager.fdLimiter.mu.Unlock()
	
	return file, nil
}

// SecureFileOpen opens a file with security checks
func SecureFileOpen(path string, flag int, perm os.FileMode) (*os.File, error) {
	// Validate path
	cleanPath, err := globalSecurityManager.pathValidator.ValidateAndCanonicalizePath(path)
	if err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}
	
	// Check FD limits
	if atomic.LoadInt64(&globalSecurityManager.fdLimiter.currentFDs) >= globalSecurityManager.fdLimiter.maxFDs {
		return nil, errors.New("file descriptor limit exceeded")
	}
	
	// Perform TOCTOU-safe operation
	var file *os.File
	err = globalSecurityManager.antiExploitGuard.CheckTOCTOU(cleanPath, func() error {
		var openErr error
		file, openErr = os.OpenFile(cleanPath, flag, perm)
		return openErr
	}, func() {
		if file != nil {
			file.Close()
		}
	})
	
	if err != nil {
		return nil, fmt.Errorf("secure file open failed: %w", err)
	}
	
	// Track file descriptor
	if file != nil {
		fd := file.Fd()
		globalSecurityManager.fdLimiter.mu.Lock()
		globalSecurityManager.fdLimiter.fdTracker[fd] = cleanPath
		atomic.AddInt64(&globalSecurityManager.fdLimiter.currentFDs, 1)
		globalSecurityManager.fdLimiter.mu.Unlock()
	}
	
	return file, nil
}

// SecureFileClose closes a file and updates tracking
func SecureFileClose(file *os.File) error {
	if file == nil {
		return nil
	}
	
	fd := file.Fd()
	
	// Remove from tracking
	globalSecurityManager.fdLimiter.mu.Lock()
	delete(globalSecurityManager.fdLimiter.fdTracker, fd)
	atomic.AddInt64(&globalSecurityManager.fdLimiter.currentFDs, -1)
	globalSecurityManager.fdLimiter.mu.Unlock()
	
	return file.Close()
}

// cleanupOldEntries periodically cleans up old cache entries
func (shm *SecurityHardeningManager) cleanupOldEntries(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			shm.mu.RLock()
			active := shm.active
			shm.mu.RUnlock()
			if !active {
				return
			}
			shm.performCleanup()
		case <-ctx.Done():
			return
		}
	}
}

// performCleanup cleans up old cache entries
func (shm *SecurityHardeningManager) performCleanup() {
	now := time.Now()
	
	// Clean TOCTOU cache
	shm.antiExploitGuard.mu.Lock()
	for path, entry := range shm.antiExploitGuard.toctouCache {
		if now.Sub(entry.checked) > 1*time.Hour {
			delete(shm.antiExploitGuard.toctouCache, path)
		}
	}
	shm.antiExploitGuard.mu.Unlock()
	
	// Clean race detector cache
	shm.antiExploitGuard.mu.Lock()
	for key, lastAccess := range shm.antiExploitGuard.raceDetector {
		if now.Sub(lastAccess) > 10*time.Minute {
			delete(shm.antiExploitGuard.raceDetector, key)
		}
	}
	shm.antiExploitGuard.mu.Unlock()
}

// monitorSuspiciousActivity monitors for suspicious activities
func (shm *SecurityHardeningManager) monitorSuspiciousActivity(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			shm.mu.RLock()
			active := shm.active
			shm.mu.RUnlock()
			if !active {
				return
			}
			shm.checkSuspiciousActivity(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// checkSuspiciousActivity checks for various suspicious activities
func (shm *SecurityHardeningManager) checkSuspiciousActivity(ctx context.Context) {
	logger := Logger(ctx).With("component", "security-detector")
	
	// Check for rapid process creation (possible fork bomb)
	shm.processLimiter.mu.RLock()
	recentProcesses := 0
	cutoff := time.Now().Add(-1 * time.Minute)
	for _, startTime := range shm.processLimiter.processStartTime {
		if startTime.After(cutoff) {
			recentProcesses++
		}
	}
	shm.processLimiter.mu.RUnlock()
	
	if recentProcesses > 20 {
		logger.Warn("Suspicious process creation rate detected", "processes_per_minute", recentProcesses)
	}
	
	// Check for suspicious file descriptor usage patterns
	shm.fdLimiter.mu.RLock()
	suspiciousPaths := make(map[string]int)
	for _, path := range shm.fdLimiter.fdTracker {
		suspiciousPaths[filepath.Dir(path)]++
	}
	shm.fdLimiter.mu.RUnlock()
	
	for dir, count := range suspiciousPaths {
		if count > 50 {
			logger.Warn("Suspicious file descriptor usage pattern", "directory", dir, "fd_count", count)
		}
	}
}

// GenerateSecureRandom generates cryptographically secure random data
func GenerateSecureRandom(length int) ([]byte, error) {
	if length <= 0 || length > 1024*1024 { // Max 1MB
		return nil, fmt.Errorf("invalid random data length: %d", length)
	}
	
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		return nil, fmt.Errorf("failed to generate secure random data: %w", err)
	}
	
	return data, nil
}

// SecureStringCompare performs constant-time string comparison to prevent timing attacks
func SecureStringCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	
	return result == 0
}

// Initialize security hardening on package import
func init() {
	// Set up basic security measures immediately
	runtime.GOMAXPROCS(runtime.NumCPU()) // Prevent CPU starvation
	
	// Register cleanup for global security manager
	runtime.SetFinalizer(globalSecurityManager, (*SecurityHardeningManager).cleanup)
}

// cleanup performs final cleanup of security resources
func (shm *SecurityHardeningManager) cleanup() {
	shm.mu.Lock()
	shm.active = false
	shm.mu.Unlock()
}


// applyChildSecurityHardening applies additional security hardening for child processes
func applyChildSecurityHardening() error {
	// Drop all capabilities except essential ones
	if err := dropDangerousCapabilities(); err != nil {
		return fmt.Errorf("failed to drop capabilities: %w", err)
	}
	
	// Set NO_NEW_PRIVS to prevent privilege escalation
	ret, _, errno := syscall.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0)
	if ret != 0 || errno != 0 {
		return fmt.Errorf("failed to set NO_NEW_PRIVS: %v", errno)
	}
	
	// Set strict umask
	syscall.Umask(0077) // Owner read/write only
	
	// Disable core dumps for security
	var rlimit syscall.Rlimit
	rlimit.Cur = 0
	rlimit.Max = 0
	if err := syscall.Setrlimit(unix.RLIMIT_CORE, &rlimit); err != nil {
		return fmt.Errorf("failed to disable core dumps: %w", err)
	}
	
	// Set process limits aggressively
	if err := syscall.Getrlimit(unix.RLIMIT_NPROC, &rlimit); err == nil {
		rlimit.Cur = min(rlimit.Cur, 50) // Very restrictive process limit
		syscall.Setrlimit(unix.RLIMIT_NPROC, &rlimit)
	}
	
	return nil
}

// dropDangerousCapabilities drops all capabilities except those needed for basic operation
func dropDangerousCapabilities() error {
	// Get current capabilities
	var header unix.CapUserHeader
	header.Version = unix.LINUX_CAPABILITY_VERSION_3
	header.Pid = 0

	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return fmt.Errorf("capget failed: %v", err)
	}

	// Clear all capabilities except basic ones needed for container operation
	// Keep only: CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_SETGID, CAP_SETUID
	basicCaps := uint32((1 << unix.CAP_CHOWN) | (1 << unix.CAP_DAC_OVERRIDE) |
		(1 << unix.CAP_FOWNER) | (1 << unix.CAP_SETGID) | (1 << unix.CAP_SETUID))

	data[0].Effective = basicCaps
	data[0].Permitted = basicCaps
	data[0].Inheritable = 0 // No inheritable capabilities
	data[1].Effective = 0
	data[1].Permitted = 0
	data[1].Inheritable = 0

	// Apply the new capability set
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fmt.Errorf("capset failed: %v", err)
	}

	return nil
}