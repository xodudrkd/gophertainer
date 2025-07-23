package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// Enhanced test suite with comprehensive coverage

func TestContainerStateManagement(t *testing.T) {
	container := &Container{
		Config: &Config{Runtime: RuntimeConfig{Name: "test"}},
		state:  StateCreated,
	}
	container.stateChange.L = &container.mu

	// Test state transitions
	container.setState(StateRunning)
	if container.getState() != StateRunning {
		t.Errorf("Expected state Running, got %v", container.getState())
	}

	container.setState(StateStopped)
	if container.getState() != StateStopped {
		t.Errorf("Expected state Stopped, got %v", container.getState())
	}
}

func TestConcurrentContainerOperations(t *testing.T) {
	container := &Container{
		Config:      &Config{Runtime: RuntimeConfig{Name: "test-concurrent"}},
		CleanupFunc: make([]CleanupFunc, 0),
		state:       StateCreated,
	}
	container.stateChange.L = &container.mu

	var wg sync.WaitGroup
	numGoroutines := 100

	// Test concurrent cleanup function addition
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			container.addCleanup(fmt.Sprintf("cleanup-%d", id), func() error {
				return nil
			})
		}(i)
	}

	// Test concurrent state changes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			container.setState(StateRunning)
			container.setState(StateCreated)
		}()
	}

	wg.Wait()

	// Verify no race conditions occurred
	if len(container.CleanupFunc) != numGoroutines {
		t.Errorf("Expected %d cleanup functions, got %d", numGoroutines, len(container.CleanupFunc))
	}
}

func TestIPAllocationPerformance(t *testing.T) {
	// Test O(1) IP allocation performance
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	allocator := NewIPAllocator(network, nil)

	start := time.Now()
	
	// Allocate many IPs to test performance
	for i := 0; i < 100; i++ {
		ip := allocator.AllocateIPv4(fmt.Sprintf("test-%d", i))
		if ip == nil {
			t.Errorf("Failed to allocate IP for test-%d", i)
		}
	}
	
	duration := time.Since(start)
	if duration > 100*time.Millisecond {
		t.Errorf("IP allocation took too long: %v", duration)
	}

	// Test release performance
	start = time.Now()
	for i := 0; i < 100; i++ {
		allocator.Release(fmt.Sprintf("test-%d", i))
	}
	
	duration = time.Since(start)
	if duration > 50*time.Millisecond {
		t.Errorf("IP release took too long: %v", duration)
	}
}

func TestBitmapIPAllocation(t *testing.T) {
	_, network, _ := net.ParseCIDR("10.0.0.0/28") // Small network for testing
	allocator := NewIPAllocator(network, nil)

	// Test that we can allocate all available IPs
	allocated := make([]net.IP, 0)
	for i := 0; i < 14; i++ { // /28 has 14 assignable addresses
		ip := allocator.AllocateIPv4(fmt.Sprintf("owner-%d", i))
		if ip == nil {
			t.Errorf("Failed to allocate IP %d", i)
		}
		allocated = append(allocated, ip)
	}

	// Test that we can't allocate more than available
	ip := allocator.AllocateIPv4("overflow")
	if ip != nil {
		t.Errorf("Should not be able to allocate more IPs, got %v", ip)
	}

	// Test release and reallocation
	allocator.Release("owner-5")
	newIP := allocator.AllocateIPv4("new-owner")
	if newIP == nil {
		t.Errorf("Should be able to allocate released IP")
	}
}

func TestErrorHandling(t *testing.T) {
	// Test structured error creation
	err := NewContainerError(ErrContainerCreation, "test error").
		WithContext("container_id", "test-123").
		WithContext("attempt", 1).
		WithComponent("test")

	if err.GetCode() != ErrContainerCreation {
		t.Errorf("Expected error code %v, got %v", ErrContainerCreation, err.GetCode())
	}

	if err.Context["container_id"] != "test-123" {
		t.Errorf("Expected context container_id=test-123, got %v", err.Context["container_id"])
	}

	// Test error chain
	chain := NewErrorChain("test operation")
	chain.Add(err)
	chain.Add(NewContainerError(ErrNetworkSetup, "network failed"))

	if !chain.HasErrors() {
		t.Errorf("Error chain should have errors")
	}

	if len(chain.Errors) != 2 {
		t.Errorf("Expected 2 errors in chain, got %d", len(chain.Errors))
	}
}

func TestResourceLeakPrevention(t *testing.T) {
	rm := &ResourceManager{
		resources: make(map[string]*TrackedResource),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Add some test resources
	for i := 0; i < 10; i++ {
		err := rm.TrackResource(
			fmt.Sprintf("test-resource-%d", i),
			ResourceTypeFile,
			fmt.Sprintf("data-%d", i),
			func() error {
				// Simulate cleanup
				time.Sleep(10 * time.Millisecond)
				return nil
			},
		)
		if err != nil {
			t.Errorf("Failed to track resource %d: %v", i, err)
		}
	}

	// Test cleanup with timeout
	start := time.Now()
	errors := rm.CleanupAll(ctx)
	duration := time.Since(start)

	if len(errors) > 0 {
		t.Errorf("Cleanup should not have errors, got: %v", errors)
	}

	if duration > 2*time.Second {
		t.Errorf("Cleanup took too long: %v", duration)
	}

	// Verify resources were cleaned up
	if len(rm.resources) != 0 {
		t.Errorf("Expected all resources to be cleaned up, got %d remaining", len(rm.resources))
	}
}

func TestConfigurationValidation(t *testing.T) {
	// Test valid configuration
	validConfig := &Config{
		Runtime: RuntimeConfig{
			Name: "valid-container",
		},
		Network: NetworkConfig{
			NetworkCIDR: "172.16.0.0/24",
			BridgeName:  "test0",
		},
		Storage: StorageConfig{
			RootFSSource: "/tmp", // Use existing path for test
		},
		Process: ProcessConfig{
			Command: "echo hello",
		},
		Cgroup: CgroupConfig{
			MemoryLimit: 256,
			CPULimit:    1.0,
		},
	}

	if err := validateConfig(validConfig); err != nil {
		t.Errorf("Valid config should pass validation: %v", err)
	}

	// Test invalid configurations
	invalidConfigs := []*Config{
		{Runtime: RuntimeConfig{Name: ""}}, // Empty name
		{Runtime: RuntimeConfig{Name: "invalid..name"}}, // Invalid characters
		{
			Runtime: RuntimeConfig{Name: "test"},
			Network: NetworkConfig{NetworkCIDR: "invalid-cidr"},
		}, // Invalid CIDR
		{
			Runtime: RuntimeConfig{Name: "test"},
			Cgroup:  CgroupConfig{MemoryLimit: -1},
		}, // Negative memory
	}

	for i, config := range invalidConfigs {
		if err := validateConfig(config); err == nil {
			t.Errorf("Invalid config %d should fail validation", i)
		}
	}
}

func TestMemoryPooling(t *testing.T) {
	// Test buffer pool
	buf1 := GetSmallBuffer()
	if len(buf1) != 0 {
		t.Errorf("Buffer should be empty, got length %d", len(buf1))
	}

	buf1 = append(buf1, []byte("test data")...)
	PutSmallBuffer(buf1)

	buf2 := GetSmallBuffer()
	if len(buf2) != 0 {
		t.Errorf("Reused buffer should be reset to empty, got length %d", len(buf2))
	}

	// Test string pool
	strings1 := GetStringSlice()
	strings1 = append(strings1, "test1", "test2")
	PutStringSlice(strings1)

	strings2 := GetStringSlice()
	if len(strings2) != 0 {
		t.Errorf("Reused string slice should be empty, got length %d", len(strings2))
	}
}

func TestMetricsCollection(t *testing.T) {
	collector := NewMetricsCollector()
	
	// Test metric updates
	collector.IncrementContainerCount()
	collector.IncrementRunningContainers()
	collector.IncrementAllocatedIPv4()

	metrics := collector.GetCurrentMetrics()
	
	if metrics.ContainerCount != 1 {
		t.Errorf("Expected container count 1, got %d", metrics.ContainerCount)
	}

	if metrics.RunningContainers != 1 {
		t.Errorf("Expected running containers 1, got %d", metrics.RunningContainers)
	}

	if metrics.AllocatedIPv4 != 1 {
		t.Errorf("Expected allocated IPv4 1, got %d", metrics.AllocatedIPv4)
	}

	// Test decrement operations
	collector.DecrementContainerCount()
	collector.DecrementRunningContainers()
	collector.DecrementAllocatedIPv4()

	metrics = collector.GetCurrentMetrics()
	
	if metrics.ContainerCount != 0 {
		t.Errorf("Expected container count 0, got %d", metrics.ContainerCount)
	}
}

func BenchmarkIPAllocationParallel(b *testing.B) {
	_, network, _ := net.ParseCIDR("10.0.0.0/16") // Large network
	allocator := NewIPAllocator(network, nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := allocator.AllocateIPv4(fmt.Sprintf("bench-%d", i))
			if ip != nil {
				allocator.Release(fmt.Sprintf("bench-%d", i))
			}
			i++
		}
	})
}

func BenchmarkBufferPool(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := GetSmallBuffer()
			buf = append(buf, []byte("benchmark data")...)
			PutSmallBuffer(buf)
		}
	})
}

func BenchmarkMetricsUpdate(b *testing.B) {
	collector := NewMetricsCollector()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			collector.IncrementContainerCount()
			collector.DecrementContainerCount()
		}
	})
}