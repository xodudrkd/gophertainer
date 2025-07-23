package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// GracefulShutdown manages graceful shutdown of the container runtime
type GracefulShutdown struct {
	containers map[string]*Container
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	once       sync.Once
}

var globalShutdown = &GracefulShutdown{
	containers: make(map[string]*Container),
}

// RegisterContainer registers a container for graceful shutdown
func (gs *GracefulShutdown) RegisterContainer(name string, container *Container) {
	if gs == nil || container == nil || name == "" {
		return
	}
	
	gs.mu.Lock()
	defer gs.mu.Unlock()
	
	gs.containers[name] = container
	Logger(context.Background()).Debug("Registered container for graceful shutdown", "name", name)
}

// UnregisterContainer removes a container from graceful shutdown tracking
func (gs *GracefulShutdown) UnregisterContainer(name string) {
	if gs == nil || name == "" {
		return
	}
	
	gs.mu.Lock()
	defer gs.mu.Unlock()
	
	delete(gs.containers, name)
	Logger(context.Background()).Debug("Unregistered container from graceful shutdown", "name", name)
}

// InitGracefulShutdown sets up signal handlers for graceful shutdown
func InitGracefulShutdown(ctx context.Context) {
	globalShutdown.once.Do(func() {
		globalShutdown.ctx, globalShutdown.cancel = context.WithCancel(ctx)
		
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		
		go func() {
			defer signal.Stop(sigChan)
			
			select {
			case sig := <-sigChan:
				Logger(ctx).Info("Received shutdown signal, initiating graceful shutdown", "signal", sig)
				globalShutdown.Shutdown(30 * time.Second)
			case <-globalShutdown.ctx.Done():
				return
			}
		}()
		
		Logger(ctx).Info("Graceful shutdown handler initialized")
	})
}

// Shutdown performs graceful shutdown of all registered containers
func (gs *GracefulShutdown) Shutdown(timeout time.Duration) {
	if gs == nil {
		return
	}
	
	logger := Logger(gs.ctx)
	logger.Info("Starting graceful shutdown of all containers", "timeout", timeout)
	
	// Cancel the shutdown context to signal all components to stop
	gs.cancel()
	
	gs.mu.RLock()
	containers := make([]*Container, 0, len(gs.containers))
	names := make([]string, 0, len(gs.containers))
	for name, container := range gs.containers {
		containers = append(containers, container)
		names = append(names, name)
	}
	gs.mu.RUnlock()
	
	if len(containers) == 0 {
		logger.Info("No containers to shutdown")
		return
	}
	
	logger.Info("Shutting down containers", "count", len(containers), "names", names)
	
	// Create a timeout context for the shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	
	var wg sync.WaitGroup
	
	// Shutdown all containers in parallel
	for i, container := range containers {
		wg.Add(1)
		go func(idx int, c *Container, name string) {
			defer wg.Done()
			
			logger.Info("Shutting down container", "name", name)
			
			// Safely capture the process reference to avoid race conditions
			c.mu.RLock()
			var process *os.Process
			if c.Process != nil && c.Process.Process != nil {
				process = c.Process.Process
			}
			c.mu.RUnlock()
			
			// First try graceful shutdown
			if process != nil {
				// Send SIGTERM first
				if err := process.Signal(syscall.SIGTERM); err != nil {
					logger.Warn("Failed to send SIGTERM to container", "name", name, "error", err)
				} else {
					// Wait a bit for graceful shutdown
					time.Sleep(5 * time.Second)
					
					// Check if process is still running
					if err := process.Signal(syscall.Signal(0)); err == nil {
						// Process still running, send SIGKILL
						logger.Warn("Container did not respond to SIGTERM, sending SIGKILL", "name", name)
						process.Kill()
					}
				}
			}
			
			// Run cleanup
			c.cleanup(shutdownCtx)
			logger.Info("Container shutdown completed", "name", name)
			
		}(i, container, names[i])
	}
	
	// Wait for all shutdowns to complete or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		logger.Info("All containers shut down gracefully")
	case <-shutdownCtx.Done():
		logger.Error("Graceful shutdown timed out, some containers may not have shut down cleanly")
	}
	
	// Clear the containers map
	gs.mu.Lock()
	gs.containers = make(map[string]*Container)
	gs.mu.Unlock()
}

// Enhanced container signal handling with better concurrency
func (c *Container) enhancedHandleSignals(ctx context.Context) {
	if c == nil || c.Config == nil {
		Logger(context.Background()).Error("Invalid container or config in signal handler")
		return
	}
	
	logger := Logger(ctx).With("component", "signal-handler", "container", c.Config.Runtime.Name)
	sigChan := make(chan os.Signal, 1)
	
	// Build signal list with validation
	signals := make([]os.Signal, 0, len(c.Config.Process.SignalMap))
	for sig, forward := range c.Config.Process.SignalMap {
		if forward {
			signals = append(signals, sig)
		}
	}
	
	if len(signals) == 0 {
		logger.Debug("No signals configured for forwarding")
		return
	}
	
	signal.Notify(sigChan, signals...)
	defer signal.Stop(sigChan)
	
	// Use a separate goroutine for signal processing to avoid blocking
	signalProcessorCtx, signalCancel := context.WithCancel(ctx)
	defer signalCancel()
	
	go func() {
		defer signalCancel()
		
		for {
			select {
			case sig := <-sigChan:
				// Process signal in a separate goroutine to avoid blocking
				go c.processSignal(ctx, sig)
				
			case <-signalProcessorCtx.Done():
				return
			case <-c.ctx.Done():
				// Handle container context cancellation
				if c.Process != nil && c.Process.Process != nil {
					logger.Info("Container context cancelled, stopping process", "pid", c.Process.Process.Pid)
					if err := c.Process.Process.Signal(syscall.SIGTERM); err != nil {
						logger.Warn("Failed to send SIGTERM on context cancellation", "error", err)
						c.Process.Process.Kill()
					}
				}
				return
			}
		}
	}()
	
	// Wait for either signal processor to finish or container context to be done
	select {
	case <-signalProcessorCtx.Done():
	case <-c.ctx.Done():
		if errors.Is(c.ctx.Err(), context.DeadlineExceeded) {
			logger.Warn("Container timed out, forcing termination")
			if c.Process != nil && c.Process.Process != nil {
				c.Process.Process.Kill()
			}
		}
	}
}

// processSignal handles individual signal processing with retry logic
func (c *Container) processSignal(ctx context.Context, sig os.Signal) {
	if c == nil {
		return
	}
	
	logger := Logger(ctx).With("component", "signal-processor")
	
	if c.Process == nil || c.Process.Process == nil {
		logger.Warn("Cannot forward signal: process not available", "signal", sig)
		return
	}
	
	pid := c.Process.Process.Pid
	logger.Debug("Forwarding signal to container", "signal", sig, "pid", pid)
	
	// Retry signal sending with exponential backoff
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		if err := c.Process.Process.Signal(sig); err != nil {
			if i == maxRetries-1 {
				logger.Error("Failed to forward signal after retries", "signal", sig, "pid", pid, "error", err)
			} else {
				logger.Warn("Failed to forward signal, retrying", "signal", sig, "pid", pid, "retry", i+1, "error", err)
				time.Sleep(time.Duration(i+1) * 100 * time.Millisecond) // Exponential backoff
			}
		} else {
			logger.Debug("Successfully forwarded signal", "signal", sig, "pid", pid)
			return
		}
	}
}