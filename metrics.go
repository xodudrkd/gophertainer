package main

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// MetricsCollector collects and manages runtime metrics
type MetricsCollector struct {
	// Container metrics
	containerCount     int64
	runningContainers  int64
	failedContainers   int64
	
	// Resource metrics
	allocatedIPv4      int64
	allocatedIPv6      int64
	openFiles          int64
	activeNetworks     int64
	
	// Performance metrics
	allocationLatency  time.Duration
	cleanupLatency     time.Duration
	networkSetupTime   time.Duration
	
	// System metrics
	memoryUsage        int64
	cpuUsage           float64
	goroutineCount     int64
	
	// Error metrics
	totalErrors        int64
	networkErrors      int64
	storageErrors      int64
	securityErrors     int64
	
	mu                 sync.RWMutex
	ctx                context.Context
	cancel             context.CancelFunc
	ticker             *time.Ticker
	observers          []MetricsObserver
}

// MetricsObserver interface for metrics notification
type MetricsObserver interface {
	OnMetricsUpdate(metrics *ContainerMetrics)
}

// ContainerMetrics represents collected metrics
type ContainerMetrics struct {
	Timestamp          time.Time     `json:"timestamp"`
	ContainerCount     int64         `json:"container_count"`
	RunningContainers  int64         `json:"running_containers"`
	FailedContainers   int64         `json:"failed_containers"`
	AllocatedIPv4      int64         `json:"allocated_ipv4"`
	AllocatedIPv6      int64         `json:"allocated_ipv6"`
	OpenFiles          int64         `json:"open_files"`
	ActiveNetworks     int64         `json:"active_networks"`
	AllocationLatency  time.Duration `json:"allocation_latency"`
	CleanupLatency     time.Duration `json:"cleanup_latency"`
	NetworkSetupTime   time.Duration `json:"network_setup_time"`
	MemoryUsage        int64         `json:"memory_usage"`
	CPUUsage           float64       `json:"cpu_usage"`
	GoroutineCount     int64         `json:"goroutine_count"`
	TotalErrors        int64         `json:"total_errors"`
	NetworkErrors      int64         `json:"network_errors"`
	StorageErrors      int64         `json:"storage_errors"`
	SecurityErrors     int64         `json:"security_errors"`
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	ctx, cancel := context.WithCancel(context.Background())
	return &MetricsCollector{
		ctx:       ctx,
		cancel:    cancel,
		ticker:    time.NewTicker(MetricsCollectionInterval),
		observers: make([]MetricsObserver, 0),
	}
}

// Start begins metrics collection
func (mc *MetricsCollector) Start(ctx context.Context) error {
	go mc.collectLoop()
	return nil
}

// Stop stops metrics collection
func (mc *MetricsCollector) Stop() error {
	mc.cancel()
	if mc.ticker != nil {
		mc.ticker.Stop()
	}
	return nil
}

// AddObserver adds a metrics observer
func (mc *MetricsCollector) AddObserver(observer MetricsObserver) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.observers = append(mc.observers, observer)
}

// RemoveObserver removes a metrics observer
func (mc *MetricsCollector) RemoveObserver(observer MetricsObserver) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	for i, obs := range mc.observers {
		if obs == observer {
			mc.observers = append(mc.observers[:i], mc.observers[i+1:]...)
			break
		}
	}
}

// collectLoop runs the metrics collection loop
func (mc *MetricsCollector) collectLoop() {
	for {
		select {
		case <-mc.ctx.Done():
			return
		case <-mc.ticker.C:
			mc.collectMetrics()
		}
	}
}

// collectMetrics collects current system metrics
func (mc *MetricsCollector) collectMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	metrics := &ContainerMetrics{
		Timestamp:          time.Now(),
		ContainerCount:     atomic.LoadInt64(&mc.containerCount),
		RunningContainers:  atomic.LoadInt64(&mc.runningContainers),
		FailedContainers:   atomic.LoadInt64(&mc.failedContainers),
		AllocatedIPv4:      atomic.LoadInt64(&mc.allocatedIPv4),
		AllocatedIPv6:      atomic.LoadInt64(&mc.allocatedIPv6),
		OpenFiles:          atomic.LoadInt64(&mc.openFiles),
		ActiveNetworks:     atomic.LoadInt64(&mc.activeNetworks),
		AllocationLatency:  mc.allocationLatency,
		CleanupLatency:     mc.cleanupLatency,
		NetworkSetupTime:   mc.networkSetupTime,
		MemoryUsage:        int64(memStats.Alloc),
		CPUUsage:           mc.cpuUsage,
		GoroutineCount:     int64(runtime.NumGoroutine()),
		TotalErrors:        atomic.LoadInt64(&mc.totalErrors),
		NetworkErrors:      atomic.LoadInt64(&mc.networkErrors),
		StorageErrors:      atomic.LoadInt64(&mc.storageErrors),
		SecurityErrors:     atomic.LoadInt64(&mc.securityErrors),
	}
	
	mc.notifyObservers(metrics)
}

// notifyObservers notifies all registered observers
func (mc *MetricsCollector) notifyObservers(metrics *ContainerMetrics) {
	mc.mu.RLock()
	observers := make([]MetricsObserver, len(mc.observers))
	copy(observers, mc.observers)
	mc.mu.RUnlock()
	
	for _, observer := range observers {
		go func(obs MetricsObserver) {
			defer func() {
				if r := recover(); r != nil {
					// Log panic but don't crash
				}
			}()
			obs.OnMetricsUpdate(metrics)
		}(observer)
	}
}

// Metric update methods

func (mc *MetricsCollector) IncrementContainerCount() {
	atomic.AddInt64(&mc.containerCount, 1)
}

func (mc *MetricsCollector) DecrementContainerCount() {
	atomic.AddInt64(&mc.containerCount, -1)
}

func (mc *MetricsCollector) IncrementRunningContainers() {
	atomic.AddInt64(&mc.runningContainers, 1)
}

func (mc *MetricsCollector) DecrementRunningContainers() {
	atomic.AddInt64(&mc.runningContainers, -1)
}

func (mc *MetricsCollector) IncrementFailedContainers() {
	atomic.AddInt64(&mc.failedContainers, 1)
}

func (mc *MetricsCollector) IncrementAllocatedIPv4() {
	atomic.AddInt64(&mc.allocatedIPv4, 1)
}

func (mc *MetricsCollector) DecrementAllocatedIPv4() {
	atomic.AddInt64(&mc.allocatedIPv4, -1)
}

func (mc *MetricsCollector) IncrementAllocatedIPv6() {
	atomic.AddInt64(&mc.allocatedIPv6, 1)
}

func (mc *MetricsCollector) DecrementAllocatedIPv6() {
	atomic.AddInt64(&mc.allocatedIPv6, -1)
}

func (mc *MetricsCollector) IncrementOpenFiles() {
	atomic.AddInt64(&mc.openFiles, 1)
}

func (mc *MetricsCollector) DecrementOpenFiles() {
	atomic.AddInt64(&mc.openFiles, -1)
}

func (mc *MetricsCollector) IncrementActiveNetworks() {
	atomic.AddInt64(&mc.activeNetworks, 1)
}

func (mc *MetricsCollector) DecrementActiveNetworks() {
	atomic.AddInt64(&mc.activeNetworks, -1)
}

func (mc *MetricsCollector) IncrementTotalErrors() {
	atomic.AddInt64(&mc.totalErrors, 1)
}

func (mc *MetricsCollector) IncrementNetworkErrors() {
	atomic.AddInt64(&mc.networkErrors, 1)
	atomic.AddInt64(&mc.totalErrors, 1)
}

func (mc *MetricsCollector) IncrementStorageErrors() {
	atomic.AddInt64(&mc.storageErrors, 1)
	atomic.AddInt64(&mc.totalErrors, 1)
}

func (mc *MetricsCollector) IncrementSecurityErrors() {
	atomic.AddInt64(&mc.securityErrors, 1)
	atomic.AddInt64(&mc.totalErrors, 1)
}

func (mc *MetricsCollector) RecordAllocationLatency(duration time.Duration) {
	mc.mu.Lock()
	mc.allocationLatency = duration
	mc.mu.Unlock()
}

func (mc *MetricsCollector) RecordCleanupLatency(duration time.Duration) {
	mc.mu.Lock()
	mc.cleanupLatency = duration
	mc.mu.Unlock()
}

func (mc *MetricsCollector) RecordNetworkSetupTime(duration time.Duration) {
	mc.mu.Lock()
	mc.networkSetupTime = duration
	mc.mu.Unlock()
}

// GetCurrentMetrics returns current metrics snapshot
func (mc *MetricsCollector) GetCurrentMetrics() *ContainerMetrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	
	return &ContainerMetrics{
		Timestamp:          time.Now(),
		ContainerCount:     atomic.LoadInt64(&mc.containerCount),
		RunningContainers:  atomic.LoadInt64(&mc.runningContainers),
		FailedContainers:   atomic.LoadInt64(&mc.failedContainers),
		AllocatedIPv4:      atomic.LoadInt64(&mc.allocatedIPv4),
		AllocatedIPv6:      atomic.LoadInt64(&mc.allocatedIPv6),
		OpenFiles:          atomic.LoadInt64(&mc.openFiles),
		ActiveNetworks:     atomic.LoadInt64(&mc.activeNetworks),
		AllocationLatency:  mc.allocationLatency,
		CleanupLatency:     mc.cleanupLatency,
		NetworkSetupTime:   mc.networkSetupTime,
		MemoryUsage:        int64(memStats.Alloc),
		CPUUsage:           mc.cpuUsage,
		GoroutineCount:     int64(runtime.NumGoroutine()),
		TotalErrors:        atomic.LoadInt64(&mc.totalErrors),
		NetworkErrors:      atomic.LoadInt64(&mc.networkErrors),
		StorageErrors:      atomic.LoadInt64(&mc.storageErrors),
		SecurityErrors:     atomic.LoadInt64(&mc.securityErrors),
	}
}