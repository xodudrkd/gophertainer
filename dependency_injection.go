package main

import (
	"context"
	"log/slog"
	"sync"
)

// Dependencies holds all system dependencies for dependency injection
type Dependencies struct {
	Logger          *slog.Logger
	ResourceManager *ResourceManager
	SystemLimits    *SystemLimits
	SystemMonitor   *SystemMonitor
	SecurityManager *SecurityHardeningManager
	MetricsCollector *MetricsCollector
	ConfigValidator *Validator
}

// DependencyContainer manages dependency injection
type DependencyContainer struct {
	deps *Dependencies
	mu   sync.RWMutex
	once sync.Once
}

// NewDependencyContainer creates a new dependency container
func NewDependencyContainer() *DependencyContainer {
	return &DependencyContainer{}
}

// Initialize sets up all dependencies
func (dc *DependencyContainer) Initialize(ctx context.Context) error {
	var initErr error
	
	dc.once.Do(func() {
		dc.mu.Lock()
		defer dc.mu.Unlock()
		
		// Initialize logger
		logger := initLogger()
		
		// Initialize resource manager
		resourceManager := &ResourceManager{
			resources: make(map[string]*TrackedResource),
		}
		
		// Initialize system limits
		systemLimits := &SystemLimits{
			MaxOpenFiles:     DefaultMaxOpenFiles,
			MaxProcesses:     DefaultMaxProcesses,
			MaxMemoryMB:      DefaultMaxMemoryMB,
			MaxMountPoints:   DefaultMaxMountPoints,
			MaxNetInterfaces: DefaultMaxNetInterfaces,
		}
		
		// Initialize system monitor
		systemMonitor := globalSystemMonitor
		
		// Initialize security manager
		securityManager := globalSecurityManager
		
		// Initialize metrics collector
		metricsCollector := NewMetricsCollector()
		
		// Initialize config validator
		configValidator := NewValidator()
		
		dc.deps = &Dependencies{
			Logger:          logger,
			ResourceManager: resourceManager,
			SystemLimits:    systemLimits,
			SystemMonitor:   systemMonitor,
			SecurityManager: securityManager,
			MetricsCollector: metricsCollector,
			ConfigValidator: configValidator,
		}
		
		// Start background services
		if err := dc.startServices(ctx); err != nil {
			initErr = err
		}
	})
	
	return initErr
}

// GetDependencies returns the current dependencies
func (dc *DependencyContainer) GetDependencies() *Dependencies {
	dc.mu.RLock()
	defer dc.mu.RUnlock()
	return dc.deps
}

// Shutdown gracefully shuts down all services
func (dc *DependencyContainer) Shutdown(ctx context.Context) error {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	
	if dc.deps == nil {
		return nil
	}
	
	var shutdownErrors []error
	
	// Stop metrics collector
	if dc.deps.MetricsCollector != nil {
		if err := dc.deps.MetricsCollector.Stop(); err != nil {
			shutdownErrors = append(shutdownErrors, err)
		}
	}
	
	// Stop system monitor
	if dc.deps.SystemMonitor != nil {
		dc.deps.SystemMonitor.Stop()
	}
	
	// Cleanup resources
	if dc.deps.ResourceManager != nil {
		if errs := dc.deps.ResourceManager.CleanupAll(ctx); len(errs) > 0 {
			shutdownErrors = append(shutdownErrors, errs...)
		}
	}
	
	if len(shutdownErrors) > 0 {
		errorChain := NewErrorChain("dependency shutdown")
		for _, err := range shutdownErrors {
			errorChain.Add(err)
		}
		return errorChain
	}
	
	return nil
}

func (dc *DependencyContainer) startServices(ctx context.Context) error {
	if dc.deps.MetricsCollector != nil {
		if err := dc.deps.MetricsCollector.Start(ctx); err != nil {
			return NewContainerErrorWithCause(ErrInternalError, "failed to start metrics collector", err).
				WithComponent("dependency-injection")
		}
	}
	
	return nil
}

// Global dependency container
var globalDependencyContainer = NewDependencyContainer()

// GetDeps returns the global dependencies
func GetDeps() *Dependencies {
	return globalDependencyContainer.GetDependencies()
}

// InitializeDependencies initializes the global dependency container
func InitializeDependencies(ctx context.Context) error {
	return globalDependencyContainer.Initialize(ctx)
}

// ShutdownDependencies shuts down the global dependency container
func ShutdownDependencies(ctx context.Context) error {
	return globalDependencyContainer.Shutdown(ctx)
}