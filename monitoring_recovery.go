package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// SystemMonitor provides comprehensive system monitoring and health checks
type SystemMonitor struct {
	metrics           *SystemMetrics
	healthCheckers    []HealthChecker
	alertCallbacks    []AlertCallback
	recoveryActions   []RecoveryAction
	checkInterval     time.Duration
	criticalErrors    int64 // atomic
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	active            bool
}

// SystemMetrics tracks system-wide metrics
type SystemMetrics struct {
	// Performance metrics
	CPUUsage         float64
	MemoryUsage      int64
	DiskUsage        map[string]int64
	NetworkConnections int64
	
	// Resource counts
	OpenFileDescriptors int64
	RunningProcesses    int64
	ActiveContainers    int64
	
	// Error rates
	ErrorRate           float64
	CriticalErrors      int64
	RecoveryAttempts    int64
	
	// Timestamps
	LastUpdate          time.Time
	LastCriticalError   time.Time
	
	mu sync.RWMutex
}

// HealthChecker defines an interface for health checking components
type HealthChecker interface {
	Name() string
	CheckHealth(ctx context.Context) error
	Priority() HealthPriority
}

// HealthPriority defines the priority of health checks
type HealthPriority int

const (
	HealthPriorityCritical HealthPriority = iota
	HealthPriorityHigh
	HealthPriorityMedium
	HealthPriorityLow
)

// AlertCallback is called when alerts are triggered
type AlertCallback func(level AlertLevel, message string, metrics *SystemMetrics)

// AlertLevel defines the severity of alerts
type AlertLevel int

const (
	AlertLevelCritical AlertLevel = iota
	AlertLevelWarning
	AlertLevelInfo
)

// RecoveryAction defines an action to take during system recovery
type RecoveryAction struct {
	Name        string
	Priority    int
	Action      func(ctx context.Context) error
	Conditions  []string // Conditions that trigger this action
	MaxRetries  int
	RetryCount  int
	LastAttempt time.Time
}

// ErrorRecoveryManager handles automatic error recovery
type ErrorRecoveryManager struct {
	recoveryStrategies map[string]RecoveryStrategy
	failureHistory     map[string][]time.Time
	circuitBreakers    map[string]*CircuitBreaker
	bulkheads          map[string]*Bulkhead
	mu                 sync.RWMutex
}

// RecoveryStrategy defines how to recover from specific error types
type RecoveryStrategy struct {
	Name               string
	ErrorPatterns      []string
	RecoveryFunc       func(ctx context.Context, err error) error
	MaxRetries         int
	BackoffStrategy    BackoffStrategy
	CircuitBreakerName string
	BulkheadName      string
}

// BackoffStrategy defines how to backoff between retry attempts
type BackoffStrategy int

const (
	BackoffConstant BackoffStrategy = iota
	BackoffLinear
	BackoffExponential
	BackoffJittered
)

// CircuitBreaker prevents cascading failures
type CircuitBreaker struct {
	name            string
	failureThreshold int
	recoveryTimeout  time.Duration
	state           CircuitState
	failures        int64
	lastFailure     time.Time
	mu              sync.RWMutex
}

// CircuitState represents the state of a circuit breaker
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// Bulkhead isolates resources to prevent total system failure
type Bulkhead struct {
	name         string
	maxConcurrent int64
	current      int64 // atomic
	waitQueue    chan struct{}
	timeout      time.Duration
}

// StateConsistencyManager ensures system state remains consistent
type StateConsistencyManager struct {
	stateCheckers   map[string]StateChecker
	checkpoints     map[string]Checkpoint
	rollbackActions map[string]RollbackAction
	mu              sync.RWMutex
}

// StateChecker validates system state consistency
type StateChecker interface {
	Name() string
	CheckState(ctx context.Context) (StateResult, error)
	ExpectedState() interface{}
}

// StateResult contains the result of a state check
type StateResult struct {
	IsConsistent bool
	ActualState  interface{}
	Violations   []string
	Severity     StateSeverity
}

// StateSeverity indicates how severe a state inconsistency is
type StateSeverity int

const (
	StateSeverityInfo StateSeverity = iota
	StateSeverityWarning
	StateSeverityCritical
	StateSeverityFatal
)

// Checkpoint represents a system state checkpoint
type Checkpoint struct {
	ID        string
	Timestamp time.Time
	State     map[string]interface{}
	Metadata  map[string]string
}

// RollbackAction defines how to rollback system state
type RollbackAction struct {
	Name     string
	Priority int
	Action   func(ctx context.Context, checkpoint Checkpoint) error
}

var (
	globalSystemMonitor = &SystemMonitor{
		metrics:         &SystemMetrics{DiskUsage: make(map[string]int64)},
		healthCheckers:  make([]HealthChecker, 0),
		alertCallbacks:  make([]AlertCallback, 0),
		recoveryActions: make([]RecoveryAction, 0),
		checkInterval:   10 * time.Second,
	}
	
	globalErrorRecovery = &ErrorRecoveryManager{
		recoveryStrategies: make(map[string]RecoveryStrategy),
		failureHistory:     make(map[string][]time.Time),
		circuitBreakers:    make(map[string]*CircuitBreaker),
		bulkheads:          make(map[string]*Bulkhead),
	}
	
	globalStateManager = &StateConsistencyManager{
		stateCheckers:   make(map[string]StateChecker),
		checkpoints:     make(map[string]Checkpoint),
		rollbackActions: make(map[string]RollbackAction),
	}
)

// InitializeMonitoringAndRecovery starts the monitoring and recovery systems
func InitializeMonitoringAndRecovery(ctx context.Context) error {
	logger := Logger(ctx).With("component", "monitoring-recovery")
	
	// Initialize system monitor
	monitorCtx, monitorCancel := context.WithCancel(ctx)
	globalSystemMonitor.ctx = monitorCtx
	globalSystemMonitor.cancel = monitorCancel
	
	// Register default health checkers
	globalSystemMonitor.RegisterHealthChecker(&FileSystemHealthChecker{})
	globalSystemMonitor.RegisterHealthChecker(&MemoryHealthChecker{})
	globalSystemMonitor.RegisterHealthChecker(&ProcessHealthChecker{})
	globalSystemMonitor.RegisterHealthChecker(&NetworkHealthChecker{})
	
	// Register default alert callbacks
	globalSystemMonitor.RegisterAlertCallback(func(level AlertLevel, message string, metrics *SystemMetrics) {
		switch level {
		case AlertLevelCritical:
			logger.Error("Critical system alert", "message", message, "metrics", metrics)
		case AlertLevelWarning:
			logger.Warn("System warning", "message", message)
		case AlertLevelInfo:
			logger.Info("System info", "message", message)
		}
	})
	
	// Initialize recovery strategies
	initializeRecoveryStrategies()
	
	// Initialize circuit breakers and bulkheads
	initializeResiliencePatterns()
	
	// Start monitoring
	if err := globalSystemMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start system monitor: %w", err)
	}
	
	logger.Info("Monitoring and recovery system initialized successfully")
	return nil
}

// Start begins system monitoring
func (sm *SystemMonitor) Start() error {
	sm.mu.Lock()
	if sm.active {
		sm.mu.Unlock()
		return errors.New("system monitor is already active")
	}
	sm.active = true
	sm.mu.Unlock()
	
	// Start monitoring goroutines
	go sm.monitoringLoop()
	go sm.healthCheckLoop()
	go sm.recoveryLoop()
	
	return nil
}

// Stop stops system monitoring
func (sm *SystemMonitor) Stop() {
	sm.mu.Lock()
	if !sm.active {
		sm.mu.Unlock()
		return
	}
	sm.active = false
	sm.mu.Unlock()
	
	if sm.cancel != nil {
		sm.cancel()
	}
}

// monitoringLoop continuously monitors system metrics
func (sm *SystemMonitor) monitoringLoop() {
	ticker := time.NewTicker(sm.checkInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sm.updateMetrics()
			sm.checkThresholds()
		case <-sm.ctx.Done():
			return
		}
	}
}

// updateMetrics updates system metrics
func (sm *SystemMonitor) updateMetrics() {
	sm.metrics.mu.Lock()
	defer sm.metrics.mu.Unlock()
	
	// Update memory usage
	var meminfo syscall.Sysinfo_t
	if err := syscall.Sysinfo(&meminfo); err == nil {
		sm.metrics.MemoryUsage = int64(meminfo.Totalram - meminfo.Freeram)
	}
	
	// Update CPU usage (simplified)
	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err == nil {
		// Simple CPU usage calculation
		sm.metrics.CPUUsage = float64(rusage.Utime.Sec + rusage.Stime.Sec)
	}
	
	// Update file descriptor count
	if fds, err := os.ReadDir("/proc/self/fd"); err == nil {
		sm.metrics.OpenFileDescriptors = int64(len(fds))
	}
	
	// Update disk usage for monitored paths
	for _, path := range []string{"/", "/tmp", "/var"} {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(path, &stat); err == nil {
			usedBytes := (stat.Blocks - stat.Bavail) * uint64(stat.Bsize)
			sm.metrics.DiskUsage[path] = int64(usedBytes)
		}
	}
	
	sm.metrics.LastUpdate = time.Now()
}

// checkThresholds checks if any metrics exceed configured thresholds
func (sm *SystemMonitor) checkThresholds() {
	sm.metrics.mu.RLock()
	defer sm.metrics.mu.RUnlock()
	
	// Check memory usage (80% threshold)
	if sm.metrics.MemoryUsage > 0 {
		var meminfo syscall.Sysinfo_t
		if err := syscall.Sysinfo(&meminfo); err == nil {
			memUsagePercent := float64(sm.metrics.MemoryUsage) / float64(meminfo.Totalram) * 100
			if memUsagePercent > 80 {
				sm.triggerAlert(AlertLevelWarning, fmt.Sprintf("High memory usage: %.1f%%", memUsagePercent))
			}
			if memUsagePercent > 95 {
				sm.triggerAlert(AlertLevelCritical, fmt.Sprintf("Critical memory usage: %.1f%%", memUsagePercent))
				sm.triggerRecovery("memory_exhaustion")
			}
		}
	}
	
	// Check file descriptor usage
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil {
		fdUsagePercent := float64(sm.metrics.OpenFileDescriptors) / float64(rlimit.Cur) * 100
		if fdUsagePercent > 80 {
			sm.triggerAlert(AlertLevelWarning, fmt.Sprintf("High FD usage: %.1f%%", fdUsagePercent))
		}
		if fdUsagePercent > 95 {
			sm.triggerAlert(AlertLevelCritical, fmt.Sprintf("Critical FD usage: %.1f%%", fdUsagePercent))
			sm.triggerRecovery("fd_exhaustion")
		}
	}
	
	// Check disk usage
	for path, usedBytes := range sm.metrics.DiskUsage {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(path, &stat); err == nil {
			totalBytes := stat.Blocks * uint64(stat.Bsize)
			usagePercent := float64(usedBytes) / float64(totalBytes) * 100
			if usagePercent > 85 {
				sm.triggerAlert(AlertLevelWarning, fmt.Sprintf("High disk usage on %s: %.1f%%", path, usagePercent))
			}
			if usagePercent > 95 {
				sm.triggerAlert(AlertLevelCritical, fmt.Sprintf("Critical disk usage on %s: %.1f%%", path, usagePercent))
				sm.triggerRecovery("disk_exhaustion")
			}
		}
	}
}

// triggerAlert sends an alert to all registered callbacks
func (sm *SystemMonitor) triggerAlert(level AlertLevel, message string) {
	sm.mu.RLock()
	callbacks := make([]AlertCallback, len(sm.alertCallbacks))
	copy(callbacks, sm.alertCallbacks)
	sm.mu.RUnlock()
	
	for _, callback := range callbacks {
		go func(cb AlertCallback) {
			defer func() {
				if r := recover(); r != nil {
					// Log panic but don't crash
				}
			}()
			cb(level, message, sm.metrics)
		}(callback)
	}
}

// triggerRecovery triggers automatic recovery for a specific condition
func (sm *SystemMonitor) triggerRecovery(condition string) {
	atomic.AddInt64(&sm.criticalErrors, 1)
	
	sm.mu.RLock()
	actions := make([]RecoveryAction, 0)
	for _, action := range sm.recoveryActions {
		for _, cond := range action.Conditions {
			if cond == condition {
				actions = append(actions, action)
				break
			}
		}
	}
	sm.mu.RUnlock()
	
	// Execute recovery actions in priority order
	for _, action := range actions {
		go sm.executeRecoveryAction(action)
	}
}

// executeRecoveryAction executes a single recovery action
func (sm *SystemMonitor) executeRecoveryAction(action RecoveryAction) {
	ctx, cancel := context.WithTimeout(sm.ctx, 30*time.Second)
	defer cancel()
	
	if err := action.Action(ctx); err != nil {
		action.RetryCount++
		action.LastAttempt = time.Now()
		
		if action.RetryCount < action.MaxRetries {
			// Retry with exponential backoff
			delay := time.Duration(action.RetryCount*action.RetryCount) * time.Second
			time.Sleep(delay)
			go sm.executeRecoveryAction(action)
		}
	}
}

// RegisterHealthChecker registers a new health checker
func (sm *SystemMonitor) RegisterHealthChecker(checker HealthChecker) {
	sm.mu.Lock()
	sm.healthCheckers = append(sm.healthCheckers, checker)
	sm.mu.Unlock()
}

// RegisterAlertCallback registers a new alert callback
func (sm *SystemMonitor) RegisterAlertCallback(callback AlertCallback) {
	sm.mu.Lock()
	sm.alertCallbacks = append(sm.alertCallbacks, callback)
	sm.mu.Unlock()
}

// healthCheckLoop continuously runs health checks
func (sm *SystemMonitor) healthCheckLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sm.runHealthChecks()
		case <-sm.ctx.Done():
			return
		}
	}
}

// runHealthChecks runs all registered health checks
func (sm *SystemMonitor) runHealthChecks() {
	sm.mu.RLock()
	checkers := make([]HealthChecker, len(sm.healthCheckers))
	copy(checkers, sm.healthCheckers)
	sm.mu.RUnlock()
	
	for _, checker := range checkers {
		go func(hc HealthChecker) {
			ctx, cancel := context.WithTimeout(sm.ctx, 10*time.Second)
			defer cancel()
			
			if err := hc.CheckHealth(ctx); err != nil {
				level := AlertLevelWarning
				if hc.Priority() == HealthPriorityCritical {
					level = AlertLevelCritical
				}
				sm.triggerAlert(level, fmt.Sprintf("Health check failed for %s: %v", hc.Name(), err))
			}
		}(checker)
	}
}

// recoveryLoop handles periodic recovery operations
func (sm *SystemMonitor) recoveryLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sm.performMaintenanceRecovery()
		case <-sm.ctx.Done():
			return
		}
	}
}

// performMaintenanceRecovery performs routine maintenance recovery
func (sm *SystemMonitor) performMaintenanceRecovery() {
	// Force garbage collection if memory usage is high
	var meminfo syscall.Sysinfo_t
	if err := syscall.Sysinfo(&meminfo); err == nil {
		usedMem := meminfo.Totalram - meminfo.Freeram
		if float64(usedMem)/float64(meminfo.Totalram) > 0.7 {
			runtime.GC()
			debug.FreeOSMemory()
		}
	}
	
	// Clean up old metrics and logs
	sm.cleanupOldData()
}

// cleanupOldData cleans up old monitoring data
func (sm *SystemMonitor) cleanupOldData() {
	// Clean up old failure history
	globalErrorRecovery.mu.Lock()
	cutoff := time.Now().Add(-24 * time.Hour)
	for service, history := range globalErrorRecovery.failureHistory {
		filtered := make([]time.Time, 0)
		for _, failure := range history {
			if failure.After(cutoff) {
				filtered = append(filtered, failure)
			}
		}
		globalErrorRecovery.failureHistory[service] = filtered
	}
	globalErrorRecovery.mu.Unlock()
	
	// Clean up old checkpoints
	globalStateManager.mu.Lock()
	for id, checkpoint := range globalStateManager.checkpoints {
		if time.Since(checkpoint.Timestamp) > 1*time.Hour {
			delete(globalStateManager.checkpoints, id)
		}
	}
	globalStateManager.mu.Unlock()
}

// initializeRecoveryStrategies sets up default recovery strategies
func initializeRecoveryStrategies() {
	strategies := []RecoveryStrategy{
		{
			Name:          "memory_cleanup",
			ErrorPatterns: []string{"memory_exhaustion", "out of memory"},
			RecoveryFunc: func(ctx context.Context, err error) error {
				runtime.GC()
				debug.FreeOSMemory()
				return nil
			},
			MaxRetries:      3,
			BackoffStrategy: BackoffExponential,
		},
		{
			Name:          "fd_cleanup",
			ErrorPatterns: []string{"fd_exhaustion", "too many open files"},
			RecoveryFunc: func(ctx context.Context, err error) error {
				// Trigger resource cleanup
				return globalResourceManager.CleanupAll(ctx)[0] // Get first error if any
			},
			MaxRetries:      2,
			BackoffStrategy: BackoffLinear,
		},
		{
			Name:          "disk_cleanup",
			ErrorPatterns: []string{"disk_exhaustion", "no space left"},
			RecoveryFunc: func(ctx context.Context, err error) error {
				// Clean up temporary files
				return cleanupTemporaryFiles()
			},
			MaxRetries:      1,
			BackoffStrategy: BackoffConstant,
		},
	}
	
	globalErrorRecovery.mu.Lock()
	for _, strategy := range strategies {
		globalErrorRecovery.recoveryStrategies[strategy.Name] = strategy
	}
	globalErrorRecovery.mu.Unlock()
}

// initializeResiliencePatterns sets up circuit breakers and bulkheads
func initializeResiliencePatterns() {
	// Create circuit breakers
	circuitBreakers := []*CircuitBreaker{
		{
			name:            "network_operations",
			failureThreshold: 5,
			recoveryTimeout:  30 * time.Second,
			state:           CircuitClosed,
		},
		{
			name:            "file_operations",
			failureThreshold: 10,
			recoveryTimeout:  15 * time.Second,
			state:           CircuitClosed,
		},
	}
	
	globalErrorRecovery.mu.Lock()
	for _, cb := range circuitBreakers {
		globalErrorRecovery.circuitBreakers[cb.name] = cb
	}
	globalErrorRecovery.mu.Unlock()
	
	// Create bulkheads
	bulkheads := []*Bulkhead{
		{
			name:         "network_bulkhead",
			maxConcurrent: 10,
			waitQueue:    make(chan struct{}, 50),
			timeout:      30 * time.Second,
		},
		{
			name:         "file_bulkhead",
			maxConcurrent: 20,
			waitQueue:    make(chan struct{}, 100),
			timeout:      15 * time.Second,
		},
	}
	
	globalErrorRecovery.mu.Lock()
	for _, bh := range bulkheads {
		globalErrorRecovery.bulkheads[bh.name] = bh
	}
	globalErrorRecovery.mu.Unlock()
}

// cleanupTemporaryFiles cleans up temporary files to free disk space
func cleanupTemporaryFiles() error {
	tempDirs := []string{"/tmp", "/var/tmp"}
	
	for _, dir := range tempDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "gophertainer-") {
				path := fmt.Sprintf("%s/%s", dir, entry.Name())
				if info, err := entry.Info(); err == nil {
					// Remove files older than 1 hour
					if time.Since(info.ModTime()) > 1*time.Hour {
						os.RemoveAll(path)
					}
				}
			}
		}
	}
	
	return nil
}

// Health checker implementations

type FileSystemHealthChecker struct{}

func (f *FileSystemHealthChecker) Name() string { return "filesystem" }
func (f *FileSystemHealthChecker) Priority() HealthPriority { return HealthPriorityCritical }

func (f *FileSystemHealthChecker) CheckHealth(ctx context.Context) error {
	// Check if critical directories are accessible
	criticalPaths := []string{"/", "/tmp", "/proc", "/sys"}
	for _, path := range criticalPaths {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("critical path %s not accessible: %w", path, err)
		}
	}
	return nil
}

type MemoryHealthChecker struct{}

func (m *MemoryHealthChecker) Name() string { return "memory" }
func (m *MemoryHealthChecker) Priority() HealthPriority { return HealthPriorityHigh }

func (m *MemoryHealthChecker) CheckHealth(ctx context.Context) error {
	var meminfo syscall.Sysinfo_t
	if err := syscall.Sysinfo(&meminfo); err != nil {
		return fmt.Errorf("failed to get memory info: %w", err)
	}
	
	memUsage := float64(meminfo.Totalram-meminfo.Freeram) / float64(meminfo.Totalram) * 100
	if memUsage > 95 {
		return fmt.Errorf("critical memory usage: %.1f%%", memUsage)
	}
	
	return nil
}

type ProcessHealthChecker struct{}

func (p *ProcessHealthChecker) Name() string { return "process" }
func (p *ProcessHealthChecker) Priority() HealthPriority { return HealthPriorityMedium }

func (p *ProcessHealthChecker) CheckHealth(ctx context.Context) error {
	// Check if we can still create processes
	cmd := exec.CommandContext(ctx, "true")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot create processes: %w", err)
	}
	return nil
}

type NetworkHealthChecker struct{}

func (n *NetworkHealthChecker) Name() string { return "network" }
func (n *NetworkHealthChecker) Priority() HealthPriority { return HealthPriorityLow }

func (n *NetworkHealthChecker) CheckHealth(ctx context.Context) error {
	// Check if loopback interface is up
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get network interfaces: %w", err)
	}
	
	for _, iface := range interfaces {
		if iface.Name == "lo" && iface.Flags&net.FlagUp != 0 {
			return nil
		}
	}
	
	return errors.New("loopback interface not found or not up")
}
