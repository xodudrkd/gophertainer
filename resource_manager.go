package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	
	"golang.org/x/sys/unix"
)

// ResourceManager provides comprehensive resource tracking and cleanup
type ResourceManager struct {
	resources map[string]*TrackedResource
	mu        sync.RWMutex
	closed    int32 // atomic
}

// ResourceType defines the type of resource being tracked
type ResourceType int

const (
	ResourceTypeFile ResourceType = iota
	ResourceTypeMount
	ResourceTypeNetworkInterface
	ResourceTypeCgroup
	ResourceTypeLoopDevice
	ResourceTypePID
	ResourceTypeMemoryRegion
)

// TrackedResource represents a system resource that needs cleanup
type TrackedResource struct {
	ID       string
	Type     ResourceType
	Data     interface{} // Type-specific data
	CleanupF func() error
	Created  time.Time
	LastUsed time.Time
}

// SystemLimits tracks system resource usage
type SystemLimits struct {
	MaxOpenFiles     uint64
	MaxProcesses     uint64
	MaxMemoryMB      uint64
	MaxMountPoints   uint64
	MaxNetInterfaces uint64
	
	currentOpenFiles     int64 // atomic
	currentProcesses     int64 // atomic  
	currentMemoryMB      int64 // atomic
	currentMountPoints   int64 // atomic
	currentNetInterfaces int64 // atomic
}

var (
	globalResourceManager = &ResourceManager{
		resources: make(map[string]*TrackedResource),
	}
	
	globalSystemLimits = &SystemLimits{
		MaxOpenFiles:     8192,
		MaxProcesses:     1024,
		MaxMemoryMB:      4096,
		MaxMountPoints:   256,
		MaxNetInterfaces: 64,
	}
)

// TrackResource adds a resource for automatic cleanup
func (rm *ResourceManager) TrackResource(id string, rtype ResourceType, data interface{}, cleanup func() error) error {
	if atomic.LoadInt32(&rm.closed) != 0 {
		return errors.New("resource manager is closed")
	}
	
	if id == "" {
		return errors.New("resource ID cannot be empty")
	}
	
	if cleanup == nil {
		return errors.New("cleanup function cannot be nil")
	}
	
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	// Check for duplicate IDs
	if _, exists := rm.resources[id]; exists {
		return fmt.Errorf("resource with ID %s already tracked", id)
	}
	
	resource := &TrackedResource{
		ID:       id,
		Type:     rtype,
		Data:     data,
		CleanupF: cleanup,
		Created:  time.Now(),
		LastUsed: time.Now(),
	}
	
	rm.resources[id] = resource
	return nil
}

// UntrackResource removes a resource from tracking
func (rm *ResourceManager) UntrackResource(id string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	delete(rm.resources, id)
}

// CleanupResource cleans up a specific resource
func (rm *ResourceManager) CleanupResource(ctx context.Context, id string) error {
	rm.mu.RLock()
	resource, exists := rm.resources[id]
	rm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("resource %s not found", id)
	}
	
	// Create a timeout for cleanup
	cleanupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("cleanup panicked: %v", r)
			}
		}()
		done <- resource.CleanupF()
	}()
	
	select {
	case err := <-done:
		if err == nil {
			rm.UntrackResource(id)
		}
		return err
	case <-cleanupCtx.Done():
		return fmt.Errorf("cleanup timeout for resource %s", id)
	}
}

// CleanupAll cleans up all tracked resources with improved leak prevention
func (rm *ResourceManager) CleanupAll(ctx context.Context) []error {
	if !atomic.CompareAndSwapInt32(&rm.closed, 0, 1) {
		return []error{errors.New("resource manager already closed")}
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	resources := make([]*TrackedResource, 0, len(rm.resources))
	for _, resource := range rm.resources {
		resources = append(resources, resource)
	}

	var errors []error
	errorsMu := sync.Mutex{} // Protect errors slice

	cleanupCtx, cancel := context.WithTimeout(ctx, 90*time.Second) // Increased timeout
	defer cancel()

	// Cleanup resources in sequential order by type priority for better reliability
	typeOrder := []ResourceType{
		ResourceTypePID,
		ResourceTypeNetworkInterface,
		ResourceTypeMount,
		ResourceTypeLoopDevice,
		ResourceTypeCgroup,
		ResourceTypeFile,
		ResourceTypeMemoryRegion,
	}

	for _, rtype := range typeOrder {
		var wg sync.WaitGroup
		errChan := make(chan error, len(resources))

		// Process all resources of this type
		for _, resource := range resources {
			if resource.Type == rtype {
				wg.Add(1)
				go func(r *TrackedResource) {
					defer wg.Done()
					defer func() {
						if rec := recover(); rec != nil {
							errChan <- fmt.Errorf("cleanup panic for %s: %v", r.ID, rec)
						}
					}()

					// Create per-resource timeout
					resourceCtx, resourceCancel := context.WithTimeout(cleanupCtx, 30*time.Second)
					defer resourceCancel()

					done := make(chan error, 1)
					go func() {
						defer func() {
							if rec := recover(); rec != nil {
								done <- fmt.Errorf("resource cleanup panic: %v", rec)
							}
						}()
						done <- r.CleanupF()
					}()

					select {
					case err := <-done:
						if err != nil {
							errChan <- fmt.Errorf("cleanup failed for %s: %w", r.ID, err)
						}
					case <-resourceCtx.Done():
						errChan <- fmt.Errorf("cleanup timeout for resource %s", r.ID)
						// Resource may be leaked, but we continue with others
					}
				}(resource)
			}
		}

		// Wait for all resources of this type to complete with timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
			close(errChan)
		}()

		select {
		case <-done:
			// Collect errors for this type
			for err := range errChan {
				errorsMu.Lock()
				errors = append(errors, err)
				errorsMu.Unlock()
			}
		case <-cleanupCtx.Done():
			errorsMu.Lock()
			errors = append(errors, fmt.Errorf("cleanup timeout for resource type %d - some resources may be leaked", rtype))
			errorsMu.Unlock()

			// Try to drain error channel to prevent goroutine leaks
			go func() {
				for range errChan {
					// Drain remaining errors
				}
			}()
			break // Move to next type despite timeout
		}
	}

	// Clear all resources even if some cleanup failed to prevent memory leaks
	rm.resources = make(map[string]*TrackedResource)

	return errors
}

// CheckSystemLimits verifies we haven't exceeded system resource limits
func (sl *SystemLimits) CheckSystemLimits() error {
	var rlimit unix.Rlimit
	
	// Check file descriptor limit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rlimit); err == nil {
		current := atomic.LoadInt64(&sl.currentOpenFiles)
		if uint64(current) > sl.MaxOpenFiles || uint64(current) > rlimit.Cur-100 {
			return fmt.Errorf("approaching file descriptor limit: %d/%d", current, rlimit.Cur)
		}
	}
	
	// Check process limit
	if err := unix.Getrlimit(unix.RLIMIT_NPROC, &rlimit); err == nil {
		current := atomic.LoadInt64(&sl.currentProcesses)
		if uint64(current) > sl.MaxProcesses || uint64(current) > rlimit.Cur-10 {
			return fmt.Errorf("approaching process limit: %d/%d", current, rlimit.Cur)
		}
	}
	
	// Check memory usage
	var meminfo syscall.Sysinfo_t
	if err := syscall.Sysinfo(&meminfo); err == nil {
		totalMemMB := meminfo.Totalram / (1024 * 1024)
		current := atomic.LoadInt64(&sl.currentMemoryMB)
		if uint64(current) > sl.MaxMemoryMB || uint64(current) > totalMemMB*80/100 {
			return fmt.Errorf("approaching memory limit: %d MB/%d MB", current, totalMemMB)
		}
	}
	
	return nil
}

// TrackOpenFile tracks an open file descriptor
func (sl *SystemLimits) TrackOpenFile() error {
	if err := sl.CheckSystemLimits(); err != nil {
		return err
	}
	atomic.AddInt64(&sl.currentOpenFiles, 1)
	return nil
}

// UntrackOpenFile removes tracking for a file descriptor
func (sl *SystemLimits) UntrackOpenFile() {
	atomic.AddInt64(&sl.currentOpenFiles, -1)
}

// SafeOpenFile opens a file with resource tracking and leak prevention
func SafeOpenFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	if err := globalSystemLimits.TrackOpenFile(); err != nil {
		return nil, fmt.Errorf("cannot open file due to resource limits: %w", err)
	}
	
	file, err := os.OpenFile(path, flag, perm)
	if err != nil {
		globalSystemLimits.UntrackOpenFile()
		return nil, err
	}
	
	// Track the file for cleanup with improved error handling
	fileID := fmt.Sprintf("file:%s:%p", path, file)
	if err := globalResourceManager.TrackResource(fileID, ResourceTypeFile, file, func() error {
		defer globalSystemLimits.UntrackOpenFile()
		// Ensure file is closed even if Close() fails
		err := file.Close()
		if err != nil {
			// Force close using file descriptor if Close() fails
			syscall.Close(int(file.Fd()))
		}
		return err
	}); err != nil {
		// If tracking fails, cleanup immediately
		globalSystemLimits.UntrackOpenFile()
		file.Close()
		return nil, fmt.Errorf("failed to track file resource: %w", err)
	}
	
	return file, nil
}

// SafeCloseFile safely closes a file and removes tracking
func SafeCloseFile(file *os.File) error {
	if file == nil {
		return nil
	}
	
	fileID := fmt.Sprintf("file:%s:%p", file.Name(), file)
	return globalResourceManager.CleanupResource(context.Background(), fileID)
}

// AtomicFileOperation performs an atomic file operation with rollback
func AtomicFileOperation(targetPath string, operation func(tempPath string) error) error {
	if targetPath == "" {
		return errors.New("target path cannot be empty")
	}
	
	// Create temporary file
	tempPath := targetPath + ".tmp." + fmt.Sprintf("%d", time.Now().UnixNano())
	
	// Ensure cleanup of temp file on any failure
	defer func() {
		if _, err := os.Stat(tempPath); err == nil {
			os.Remove(tempPath)
		}
	}()
	
	// Perform the operation on the temporary file
	if err := operation(tempPath); err != nil {
		return fmt.Errorf("operation failed: %w", err)
	}
	
	// Atomically move temp file to target
	if err := os.Rename(tempPath, targetPath); err != nil {
		return fmt.Errorf("atomic commit failed: %w", err)
	}
	
	return nil
}

// MemoryPressureMonitor monitors system memory pressure
type MemoryPressureMonitor struct {
	threshold    uint64        // Memory pressure threshold percentage
	checkInterval time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
	callbacks    []func()
	mu           sync.RWMutex
}

// NewMemoryPressureMonitor creates a new memory pressure monitor
func NewMemoryPressureMonitor(threshold uint64) *MemoryPressureMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &MemoryPressureMonitor{
		threshold:     threshold,
		checkInterval: 5 * time.Second,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// AddCallback adds a callback to be called when memory pressure is detected
func (mpm *MemoryPressureMonitor) AddCallback(callback func()) {
	if callback == nil {
		return
	}
	
	mpm.mu.Lock()
	mpm.callbacks = append(mpm.callbacks, callback)
	mpm.mu.Unlock()
}

// Start begins monitoring memory pressure
func (mpm *MemoryPressureMonitor) Start() {
	go func() {
		ticker := time.NewTicker(mpm.checkInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				mpm.checkMemoryPressure()
			case <-mpm.ctx.Done():
				return
			}
		}
	}()
}

// Stop stops the memory pressure monitor
func (mpm *MemoryPressureMonitor) Stop() {
	mpm.cancel()
}

func (mpm *MemoryPressureMonitor) checkMemoryPressure() {
	var meminfo syscall.Sysinfo_t
	if err := syscall.Sysinfo(&meminfo); err != nil {
		return
	}
	
	// Calculate memory usage percentage
	usedMem := meminfo.Totalram - meminfo.Freeram - meminfo.Bufferram
	memUsagePercent := (usedMem * 100) / meminfo.Totalram
	
	if memUsagePercent > mpm.threshold {
		mpm.mu.RLock()
		callbacks := make([]func(), len(mpm.callbacks))
		copy(callbacks, mpm.callbacks)
		mpm.mu.RUnlock()
		
		// Execute callbacks in separate goroutines
		for _, callback := range callbacks {
			go func(cb func()) {
				defer func() {
					if r := recover(); r != nil {
						// Log panic but don't crash
					}
				}()
				cb()
			}(callback)
		}
	}
}

// FDLeakDetector detects file descriptor leaks
type FDLeakDetector struct {
	baseline map[string]bool
	mu       sync.RWMutex
}

// NewFDLeakDetector creates a new file descriptor leak detector
func NewFDLeakDetector() *FDLeakDetector {
	detector := &FDLeakDetector{
		baseline: make(map[string]bool),
	}
	detector.captureBaseline()
	return detector
}

func (fd *FDLeakDetector) captureBaseline() {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	
	// Read /proc/self/fd to get current file descriptors
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	
	fd.baseline = make(map[string]bool)
	for _, fdEntry := range fds {
		fd.baseline[fdEntry.Name()] = true
	}
}

// CheckForLeaks returns a list of potentially leaked file descriptors
func (fd *FDLeakDetector) CheckForLeaks() []string {
	fd.mu.RLock()
	defer fd.mu.RUnlock()
	
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil
	}
	
	var leaks []string
	for _, fdEntry := range fds {
		if !fd.baseline[fdEntry.Name()] {
			leaks = append(leaks, fdEntry.Name())
		}
	}
	
	return leaks
}

// CriticalResourceGuard provides a way to ensure critical resources are properly managed
type CriticalResourceGuard struct {
	resources []func() error
	mu        sync.Mutex
	released  bool
}

// NewCriticalResourceGuard creates a new resource guard
func NewCriticalResourceGuard() *CriticalResourceGuard {
	return &CriticalResourceGuard{}
}

// Add adds a cleanup function to the guard
func (crg *CriticalResourceGuard) Add(cleanup func() error) {
	if cleanup == nil {
		return
	}
	
	crg.mu.Lock()
	defer crg.mu.Unlock()
	
	if !crg.released {
		crg.resources = append(crg.resources, cleanup)
	}
}

// Release releases all guarded resources
func (crg *CriticalResourceGuard) Release() []error {
	crg.mu.Lock()
	defer crg.mu.Unlock()
	
	if crg.released {
		return nil
	}
	
	crg.released = true
	var errors []error
	
	// Release in reverse order (LIFO)
	for i := len(crg.resources) - 1; i >= 0; i-- {
		if err := crg.resources[i](); err != nil {
			errors = append(errors, err)
		}
	}
	
	crg.resources = nil
	return errors
}

// init initializes the global resource management system
func init() {
	// Start memory pressure monitoring
	memMonitor := NewMemoryPressureMonitor(80) // 80% threshold
	memMonitor.AddCallback(func() {
		// Force garbage collection on memory pressure
		runtime.GC()
		runtime.GC() // Double GC for better effect
	})
	memMonitor.Start()
	
	// Set finalizers for global resource managers
	runtime.SetFinalizer(globalResourceManager, (*ResourceManager).finalizer)
}

func (rm *ResourceManager) finalizer() {
	if atomic.LoadInt32(&rm.closed) == 0 {
		// Emergency cleanup if not properly closed
		rm.CleanupAll(context.Background())
	}
}