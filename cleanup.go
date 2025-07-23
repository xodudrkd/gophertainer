package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// Enhanced cleanup function with better concurrency safety
func (c *Container) cleanup(ctx context.Context) {
	if c == nil {
		return
	}
	
	// Use sync.Once to ensure cleanup only runs once
	c.once.Do(func() {
		c.setState(StateStopped)
		
		c.mu.Lock()
		cleanupFuncs := make([]CleanupFunc, len(c.CleanupFunc))
		copy(cleanupFuncs, c.CleanupFunc)
		c.mu.Unlock()

		logger := Logger(ctx)
		if len(cleanupFuncs) > 0 {
			logger.Info("Running cleanup functions...", "count", len(cleanupFuncs))
			
			// Run cleanup functions in parallel with timeout
			cleanupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			
			var wg sync.WaitGroup
			errorCh := make(chan error, len(cleanupFuncs))
			
			for i, cleanup := range cleanupFuncs {
				wg.Add(1)
				go func(idx int, cf CleanupFunc) {
					defer wg.Done()
					defer func() {
						if r := recover(); r != nil {
							logger.Error("Cleanup function panicked", "name", cf.Name, "index", idx, "panic", r)
							errorCh <- fmt.Errorf("cleanup %s panicked: %v", cf.Name, r)
						}
					}()
					
					if cf.Fn != nil {
						if err := cf.Fn(); err != nil {
							logger.Error("Cleanup function failed", "name", cf.Name, "error", err)
							errorCh <- fmt.Errorf("cleanup %s failed: %w", cf.Name, err)
						} else {
							logger.Debug("Cleanup function succeeded", "name", cf.Name)
						}
					}
				}(i, cleanup)
			}
			
			// Wait for all cleanup functions with timeout
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()
			
			select {
			case <-done:
				logger.Info("All cleanup functions completed")
			case <-cleanupCtx.Done():
				logger.Error("Cleanup timed out, some resources may not be cleaned up")
			}
			
			// Collect any errors
			close(errorCh)
			for err := range errorCh {
				logger.Warn("Cleanup error", "error", err)
			}
		} else {
			logger.Debug("No cleanup functions to run")
		}
	})
}

// setState safely updates the container state
func (c *Container) setState(state ContainerState) {
	if c == nil {
		return
	}
	
	c.mu.Lock()
	oldState := c.state
	c.state = state
	c.mu.Unlock()
	
	// Signal state change if we have a condition variable
	if c.stateChange.L != nil {
		c.stateChange.Broadcast()
	}
	
	Logger(context.Background()).Debug("Container state changed", "from", oldState, "to", state)
}

// getState safely reads the container state
func (c *Container) getState() ContainerState {
	if c == nil {
		return StateError
	}
	
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// waitForState waits for the container to reach a specific state
func (c *Container) waitForState(targetState ContainerState, timeout time.Duration) bool {
	if c == nil {
		return false
	}
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Initialize condition variable if not already done
	if c.stateChange.L == nil {
		c.stateChange.L = &c.mu
	}
	
	deadline := time.Now().Add(timeout)
	for c.state != targetState && time.Now().Before(deadline) {
		c.stateChange.Wait()
	}
	
	return c.state == targetState
}

// Enhanced resource cleanup utilities
func (c *Container) cleanupNetworkResources(ctx context.Context) error {
	logger := Logger(ctx)
	
	// Clean up network interfaces
	if c.Config != nil && !c.Config.Runtime.IsRootless {
		if err := cleanupStaleResources(ctx, c.Config); err != nil {
			logger.Warn("Failed to cleanup network resources", "error", err)
			return err
		}
	}
	
	return nil
}

func (c *Container) cleanupCgroupResources(ctx context.Context) error {
	logger := Logger(ctx)
	
	if c.Config != nil && c.Config.Cgroup.Name != "" {
		// Clean up cgroup v2
		cgroupPath := fmt.Sprintf("/sys/fs/cgroup/%s", c.Config.Cgroup.Name)
		cleanupCgroupV2(ctx, cgroupPath)
		
		// Clean up cgroup v1 paths
		subsystems := []string{"memory", "cpu", "pids"}
		for _, subsys := range subsystems {
			cgroupPath := fmt.Sprintf("/sys/fs/cgroup/%s/%s", subsys, c.Config.Cgroup.Name)
			if err := removePathIfExists(cgroupPath); err != nil {
				logger.Warn("Failed to remove cgroup v1 path", "path", cgroupPath, "error", err)
			}
		}
	}
	
	return nil
}

func (c *Container) cleanupLoopDevices(ctx context.Context) error {
	if c.Config != nil && c.Config.Storage.RootFSSource != "" {
		return loopManager.Detach(ctx, c.Config.Storage.RootFSSource)
	}
	return nil
}

// Helper function to safely remove paths
func removePathIfExists(path string) error {
	if path == "" {
		return nil
	}
	
	if _, err := os.Stat(path); err == nil {
		return os.RemoveAll(path)
	} else if os.IsNotExist(err) {
		return nil // Already removed
	} else {
		return err // Other error
	}
}