package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestIPAllocator validates the functionality of the IPAllocator, including
// allocation, release, idempotency, and concurrency safety.
func TestIPAllocator(t *testing.T) {
	_, ipNet4, _ := net.ParseCIDR("10.0.0.0/24")
	_, ipNet6, _ := net.ParseCIDR("fd00::/64")
	allocator := NewIPAllocator(ipNet4, ipNet6)

	t.Run("IPv4 Allocation", func(t *testing.T) {
		ip1 := allocator.AllocateIPv4("container1")
		if ip1.String() != "10.0.0.1" {
			t.Errorf("Expected 10.0.0.1, got %s", ip1)
		}

		ip2 := allocator.AllocateIPv4("container2")
		if ip2.String() != "10.0.0.2" {
			t.Errorf("Expected 10.0.0.2, got %s", ip2)
		}

		// Test idempotency: the same owner should always get the same IP.
		ip1Again := allocator.AllocateIPv4("container1")
		if ip1Again.String() != ip1.String() {
			t.Errorf("Expected same IP for same owner, got %s", ip1Again)
		}
	})

	t.Run("IPv6 Allocation", func(t *testing.T) {
		ip1 := allocator.AllocateIPv6("container1")
		if ip1 == nil {
			t.Fatal("IPv6 allocation failed")
		}
		if ip1.String() != "fd00::1" {
			t.Errorf("Expected fd00::1, got %s", ip1)
		}

		ip2 := allocator.AllocateIPv6("container2")
		if ip1.String() == ip2.String() {
			t.Error("Got same IPv6 for different owners")
		}
	})

	t.Run("Release and Reuse", func(t *testing.T) {
		allocator.Release("container1")

		// The released IP (10.0.0.1) should now be available for a new owner.
		ip3 := allocator.AllocateIPv4("container3")
		if ip3.String() != "10.0.0.1" {
			t.Errorf("Expected released IP to be reused, got %s", ip3)
		}
	})

	t.Run("Concurrent Allocation", func(t *testing.T) {
		// Use a fresh allocator for the concurrency test.
		allocator2 := NewIPAllocator(ipNet4, ipNet6)
		var wg sync.WaitGroup
		ips := make(map[string]bool)
		mu := sync.Mutex{}

		// Allocate 10 IPs concurrently.
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				// Use a unique owner for each goroutine.
				owner := "concurrent-" + strconv.Itoa(id)
				ip := allocator2.AllocateIPv4(owner)
				mu.Lock()
				if ips[ip.String()] {
					t.Errorf("Duplicate IP allocated: %s", ip)
				}
				ips[ip.String()] = true
				mu.Unlock()
			}(i)
		}
		wg.Wait()

		if len(ips) != 10 {
			t.Errorf("Expected 10 unique IPs, got %d", len(ips))
		}
	})
}

// TestValidateConfig checks the config validation logic for various valid and invalid inputs.
func TestValidateConfig(t *testing.T) {
	// Create a dummy file for rootfs validation.
	tmpFile, err := os.CreateTemp("", "rootfs")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "Valid config",
			config: &Config{
				Runtime: RuntimeConfig{Name: "valid-name"},
				Network: NetworkConfig{NetworkCIDR: "172.16.0.0/24"},
				Cgroup:  CgroupConfig{MemoryLimit: 128},
				Storage: StorageConfig{RootFSSource: tmpFile.Name()},
				Process: ProcessConfig{Command: "ls"},
			},
			wantErr: false,
		},
		{
			name: "Invalid container name",
			config: &Config{
				Runtime: RuntimeConfig{Name: "invalid/name"},
				Network: NetworkConfig{NetworkCIDR: "172.16.0.0/24"},
				Storage: StorageConfig{RootFSSource: tmpFile.Name()},
			},
			wantErr: true,
		},
		{
			name: "Empty container name",
			config: &Config{
				Runtime: RuntimeConfig{Name: ""},
				Network: NetworkConfig{NetworkCIDR: "172.16.0.0/24"},
				Storage: StorageConfig{RootFSSource: tmpFile.Name()},
			},
			wantErr: true,
		},
		{
			name: "Invalid CIDR",
			config: &Config{
				Runtime: RuntimeConfig{Name: "test"},
				Network: NetworkConfig{NetworkCIDR: "invalid"},
				Storage: StorageConfig{RootFSSource: tmpFile.Name()},
				Process: ProcessConfig{Command: "ls"},
			},
			wantErr: true,
		},
		{
			name: "Memory limit too low",
			config: &Config{
				Runtime: RuntimeConfig{Name: "test"},
				Network: NetworkConfig{NetworkCIDR: "172.16.0.0/24"},
				Cgroup:  CgroupConfig{MemoryLimit: 2}, // Must be >= 4MB
				Storage: StorageConfig{RootFSSource: tmpFile.Name()},
				Process: ProcessConfig{Command: "ls"},
			},
			wantErr: true,
		},
		{
			name: "Invalid IPv6 CIDR",
			config: &Config{
				Runtime: RuntimeConfig{Name: "test"},
				Network: NetworkConfig{
					NetworkCIDR: "172.16.0.0/24",
					IPv6CIDR:    "invalid::",
				},
				Storage: StorageConfig{RootFSSource: tmpFile.Name()},
				Process: ProcessConfig{Command: "ls"},
			},
			wantErr: true,
		},
		{
			name: "Non-existent rootfs",
			config: &Config{
				Runtime: RuntimeConfig{Name: "test"},
				Network: NetworkConfig{NetworkCIDR: "172.16.0.0/24"},
				Storage: StorageConfig{RootFSSource: "/non/existent/path"},
				Process: ProcessConfig{Command: "ls"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestLoopDeviceManager verifies the attachment and detachment of loop devices.
func TestLoopDeviceManager(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Loop device tests require root privileges")
	}

	ctx := context.Background()

	// Create a dummy image file.
	tmpFile, err := os.CreateTemp("", "test*.img")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Make it 10MB so it's a valid block device target.
	if err := tmpFile.Truncate(10 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	t.Run("Attach and Detach", func(t *testing.T) {
		device, err := loopManager.Attach(ctx, tmpFile.Name())
		if err != nil {
			t.Fatalf("Attach failed: %v", err)
		}
		if device == "" {
			t.Error("Attach returned an empty device path")
		}

		// Test idempotency: attaching the same source should return the same device.
		device2, err := loopManager.Attach(ctx, tmpFile.Name())
		if err != nil {
			t.Fatalf("Second attach failed: %v", err)
		}
		if device != device2 {
			t.Errorf("Expected same device for same source, got %s and %s", device, device2)
		}

		// Detach the device.
		if err := loopManager.Detach(ctx, tmpFile.Name()); err != nil {
			t.Fatalf("Detach failed: %v", err)
		}

		// Verify it was detached by checking the internal map.
		loopManager.mu.Lock()
		_, ok := loopManager.devices[tmpFile.Name()]
		loopManager.mu.Unlock()
		if ok {
			t.Error("Device still present in map after detach")
		}
	})
}

// TestHookExecution checks that lifecycle hooks are executed correctly.
func TestHookExecution(t *testing.T) {
	ctx := context.Background()
	container := &Container{
		Config: &Config{
			Runtime: RuntimeConfig{
				Name: "test-hook-container",
				Hooks: map[string]HookConfig{
					"test-success": {
						Path:    "/bin/echo",
						Args:    []string{"hook successful"},
						Timeout: 1 * time.Second,
					},
				},
			},
		},
	}

	t.Run("Successful hook", func(t *testing.T) {
		err := container.runHook(ctx, "test-success")
		if err != nil {
			t.Errorf("Expected successful hook execution, but got error: %v", err)
		}
	})

	t.Run("Missing hook", func(t *testing.T) {
		// Running a non-existent hook should not return an error.
		err := container.runHook(ctx, "nonexistent-hook")
		if err != nil {
			t.Errorf("Expected no error for missing hook, but got: %v", err)
		}
	})

	t.Run("Timeout hook", func(t *testing.T) {
		// Add a hook that is guaranteed to time out.
		container.Config.Runtime.Hooks["slow-hook"] = HookConfig{
			Path:    "/bin/sleep",
			Args:    []string{"2"},
			Timeout: 100 * time.Millisecond,
		}

		err := container.runHook(ctx, "slow-hook")
		if err == nil {
			t.Error("Expected a timeout error, but got nil")
		} else if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Expected context.DeadlineExceeded error, but got: %v", err)
		}
	})
}

// TestContextLogging verifies that the logger can be stored in and retrieved from a context.
func TestContextLogging(t *testing.T) {
	logger := initLogger()
	ctx := WithLogger(context.Background(), logger)

	retrievedLogger := Logger(ctx)
	if retrievedLogger != logger {
		t.Error("Logger retrieved from context does not match the one that was stored")
	}

	// Test with a context that has no logger.
	emptyCtx := context.Background()
	defaultLogger := Logger(emptyCtx)
	if defaultLogger == nil {
		t.Error("Expected a default logger when none is in the context, but got nil")
	}
}

// TestVolumeValidation checks the security validation for volume mounts.
func TestVolumeValidation(t *testing.T) {
	// Create a dummy host path for a valid source.
	tmpDir, err := os.MkdirTemp("", "host-path")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a dummy rootfs directory.
	rootfs, err := os.MkdirTemp("", "rootfs")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(rootfs)

	tests := []struct {
		name    string
		volume  Volume
		wantErr bool
	}{
		{
			name:    "Valid volume mount",
			volume:  Volume{Source: tmpDir, Dest: "/container/path"},
			wantErr: false,
		},
		{
			name:    "Path escape attempt",
			volume:  Volume{Source: tmpDir, Dest: "../escape-attempt"},
			wantErr: true,
		},
		{
			name:    "Absolute path destination",
			volume:  Volume{Source: tmpDir, Dest: "/abs/path"},
			wantErr: false, // This is valid, it will be joined with rootfs.
		},
		{
			name:    "Deeply nested valid path",
			volume:  Volume{Source: tmpDir, Dest: "a/b/c/d"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The validation logic is inside mountVolumes. We call it with a single volume.
			err := mountVolumes(context.Background(), []Volume{tt.volume}, rootfs)

			// We only care about the validation error, not the mount error itself.
			// Since the test isn't in a separate mount namespace, the mount will likely
			// fail with a permission error, but the path validation happens first.
			if (err != nil) != tt.wantErr {
				t.Errorf("mountVolumes() error = %v, wantErr %v", err, tt.wantErr)
			}

			// If it was a valid path, we need to unmount it to clean up.
			if err == nil {
				dest := filepath.Join(rootfs, tt.volume.Dest)
				unix.Unmount(dest, 0)
			}
		})
	}
}

// --- Benchmark Tests ---

// BenchmarkIPAllocation measures the performance of allocating single IPv4 addresses.
func BenchmarkIPAllocation(b *testing.B) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/16")
	allocator := NewIPAllocator(ipNet, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use a unique owner for each allocation to avoid hitting the cache.
		allocator.AllocateIPv4(strconv.Itoa(i))
	}
}

// BenchmarkConcurrentIPAllocation measures the performance of allocating IPv4 addresses
// from multiple goroutines simultaneously.
func BenchmarkConcurrentIPAllocation(b *testing.B) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/16")
	allocator := NewIPAllocator(ipNet, nil)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Use a unique owner for each allocation.
			allocator.AllocateIPv4(strconv.Itoa(i))
			i++
		}
	})
}

