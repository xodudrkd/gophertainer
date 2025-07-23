package main

import "time"

// System resource limits
const (
	DefaultIPAllocatorRetries = 65536
	DefaultCleanupTimeout     = 30 * time.Second
	DefaultNetworkTimeout     = 60 * time.Second
	DefaultProcessTimeout     = 10 * time.Minute
	
	// File descriptor limits
	DefaultMaxOpenFiles     = 8192
	DefaultMaxProcesses     = 1024
	DefaultMaxMemoryMB      = 4096
	DefaultMaxMountPoints   = 256
	DefaultMaxNetInterfaces = 64
	
	// Memory pressure thresholds
	DefaultMemoryPressureThreshold = 80 // percentage
	MemoryPressureCheckInterval    = 5 * time.Second
	
	// Network configuration
	DefaultBridgeName = "gophertainer0"
	DefaultNetworkCIDR = "172.16.0.0/24"
	DefaultMTU = 1500
	VethNameLength = 8
	
	// Container limits
	DefaultContainerTimeout = 1 * time.Hour
	MaxContainersPerHost = 1000
	
	// Security hardening
	DefaultSeccompProfile = "default"
	MaxCapabilities = 64
	
	// OCI compliance
	OCISpecVersion = "1.0.2"
	OCIRuntimeName = "gophertainer"
	
	// Resource management
	ResourceCleanupBatchSize = 100
	ResourceCleanupInterval = 30 * time.Second
	
	// Monitoring intervals
	HealthCheckInterval = 30 * time.Second
	MetricsCollectionInterval = 10 * time.Second
	LogRotationInterval = 24 * time.Hour
	
	// Error retry configuration
	DefaultRetryAttempts = 3
	DefaultRetryBackoff = 1 * time.Second
	MaxRetryBackoff = 30 * time.Second
	
	// Storage limits
	MaxImageSize = 10 * 1024 * 1024 * 1024 // 10GB
	MaxVolumeSize = 100 * 1024 * 1024 * 1024 // 100GB
	TempDirCleanupAge = 24 * time.Hour
	
	// Buffer sizes for better performance
	DefaultBufferSize = 64 * 1024
	NetworkBufferSize = 32 * 1024
	LogBufferSize = 8 * 1024
)