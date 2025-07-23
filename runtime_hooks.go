package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// HookPhase represents different stages where hooks can be executed
type HookPhase string

const (
	// Container lifecycle hooks
	HookPhasePrestart    HookPhase = "prestart"     // Before container process starts
	HookPhaseCreateRuntime HookPhase = "createRuntime" // Runtime environment created
	HookPhaseCreateContainer HookPhase = "createContainer" // Container created
	HookPhaseStartContainer HookPhase = "startContainer" // Container process started
	HookPhasePoststart   HookPhase = "poststart"    // After container process starts
	HookPhasePoststop    HookPhase = "poststop"     // After container stops
	
	// Storage lifecycle hooks
	HookPhaseStoragePreMount  HookPhase = "storage.pre_mount"   // Before mounting storage
	HookPhaseStoragePostMount HookPhase = "storage.post_mount"  // After mounting storage
	HookPhaseStoragePreUnmount HookPhase = "storage.pre_unmount" // Before unmounting storage
	HookPhaseStoragePostUnmount HookPhase = "storage.post_unmount" // After unmounting storage
	
	// Network lifecycle hooks
	HookPhaseNetworkPreSetup    HookPhase = "network.pre_setup"     // Before network setup
	HookPhaseNetworkPostSetup   HookPhase = "network.post_setup"    // After network setup
	HookPhaseNetworkPreTeardown HookPhase = "network.pre_teardown"  // Before network teardown
	HookPhaseNetworkPostTeardown HookPhase = "network.post_teardown" // After network teardown
)

// HookResult represents the result of hook execution
type HookResult struct {
	Success   bool          `json:"success"`
	ExitCode  int           `json:"exit_code"`
	Output    string        `json:"output"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
}

// HookExecutor defines the interface for hook execution
type HookExecutor interface {
	Execute(ctx context.Context, hook Hook, state *HookContainerState) (*HookResult, error)
}

// Hook represents an individual hook with its configuration
type Hook struct {
	Name        string            `json:"name"`                  // Hook name/identifier
	Path        string            `json:"path"`                  // Executable path
	Args        []string          `json:"args,omitempty"`        // Command arguments
	Env         []string          `json:"env,omitempty"`         // Environment variables
	Timeout     time.Duration     `json:"timeout,omitempty"`     // Execution timeout
	Phase       HookPhase         `json:"phase"`                 // When to execute
	Priority    int               `json:"priority"`              // Execution order (lower = earlier)
	FailureMode HookFailureMode   `json:"failure_mode"`          // How to handle failures
	Conditions  []HookCondition   `json:"conditions,omitempty"`  // Execution conditions
	Metadata    map[string]string `json:"metadata,omitempty"`    // Additional metadata
	
	// Runtime state (not serialized)
	executor HookExecutor `json:"-"`
}

// HookFailureMode defines how to handle hook failures
type HookFailureMode string

const (
	HookFailureModeIgnore HookFailureMode = "ignore" // Continue execution
	HookFailureModeWarn   HookFailureMode = "warn"   // Log warning and continue
	HookFailureModeStop   HookFailureMode = "stop"   // Stop execution
	HookFailureModeFail   HookFailureMode = "fail"   // Fail the operation
)

// HookCondition defines when a hook should run
type HookCondition struct {
	Type  string `json:"type"`            // Condition type
	Key   string `json:"key"`             // Condition key
	Value string `json:"value"`           // Expected value
	Op    string `json:"op,omitempty"`    // Comparison operator
}

// HookManager manages container lifecycle hooks
type HookManager struct {
	hooks    map[HookPhase][]*Hook
	executor HookExecutor
	logger   *slog.Logger
	mu       sync.RWMutex
}

// NewHookManager creates a new hook manager
func NewHookManager(ctx context.Context) *HookManager {
	return &HookManager{
		hooks:    make(map[HookPhase][]*Hook),
		executor: &DefaultHookExecutor{},
		logger:   Logger(ctx).With("component", "hook-manager"),
	}
}

// RegisterHook registers a new hook
func (hm *HookManager) RegisterHook(hook *Hook) error {
	if hook == nil {
		return fmt.Errorf("hook cannot be nil")
	}
	
	if hook.Name == "" {
		return fmt.Errorf("hook name cannot be empty")
	}
	
	if hook.Path == "" {
		return fmt.Errorf("hook path cannot be empty")
	}
	
	if !filepath.IsAbs(hook.Path) {
		return fmt.Errorf("hook path must be absolute: %s", hook.Path)
	}
	
	if hook.Timeout == 0 {
		hook.Timeout = 30 * time.Second // Default timeout
	}
	
	if hook.FailureMode == "" {
		hook.FailureMode = HookFailureModeWarn
	}
	
	hook.executor = hm.executor
	
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	// Check for duplicate names within the same phase
	for _, existingHook := range hm.hooks[hook.Phase] {
		if existingHook.Name == hook.Name {
			return fmt.Errorf("hook with name %s already exists for phase %s", hook.Name, hook.Phase)
		}
	}
	
	hm.hooks[hook.Phase] = append(hm.hooks[hook.Phase], hook)
	
	// Sort hooks by priority
	sort.Slice(hm.hooks[hook.Phase], func(i, j int) bool {
		return hm.hooks[hook.Phase][i].Priority < hm.hooks[hook.Phase][j].Priority
	})
	
	hm.logger.Info("Registered hook", "name", hook.Name, "phase", hook.Phase, "priority", hook.Priority)
	return nil
}

// UnregisterHook removes a hook
func (hm *HookManager) UnregisterHook(phase HookPhase, name string) bool {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	hooks := hm.hooks[phase]
	for i, hook := range hooks {
		if hook.Name == name {
			// Remove hook by swapping with last element
			hooks[i] = hooks[len(hooks)-1]
			hm.hooks[phase] = hooks[:len(hooks)-1]
			
			// Re-sort after removal
			sort.Slice(hm.hooks[phase], func(i, j int) bool {
				return hm.hooks[phase][i].Priority < hm.hooks[phase][j].Priority
			})
			
			hm.logger.Info("Unregistered hook", "name", name, "phase", phase)
			return true
		}
	}
	return false
}

// ExecuteHooks executes all hooks for a given phase
func (hm *HookManager) ExecuteHooks(ctx context.Context, phase HookPhase, state *HookContainerState) error {
	hm.mu.RLock()
	hooks := make([]*Hook, len(hm.hooks[phase]))
	copy(hooks, hm.hooks[phase])
	hm.mu.RUnlock()
	
	if len(hooks) == 0 {
		return nil
	}
	
	hm.logger.Info("Executing hooks", "phase", phase, "count", len(hooks))
	
	var firstError error
	
	for _, hook := range hooks {
		// Check conditions
		if !hm.checkConditions(hook, state) {
			hm.logger.Debug("Skipping hook due to conditions", "name", hook.Name, "phase", phase)
			continue
		}
		
		hm.logger.Debug("Executing hook", "name", hook.Name, "phase", phase)
		
		result, err := hook.executor.Execute(ctx, *hook, state)
		if err != nil || (result != nil && !result.Success) {
			errMsg := fmt.Sprintf("hook %s failed", hook.Name)
			if err != nil {
				errMsg += fmt.Sprintf(": %v", err)
			}
			if result != nil && result.Error != "" {
				errMsg += fmt.Sprintf(" (%s)", result.Error)
			}
			
			hookErr := fmt.Errorf(errMsg)
			
			switch hook.FailureMode {
			case HookFailureModeIgnore:
				hm.logger.Debug("Ignoring hook failure", "name", hook.Name, "error", hookErr)
			case HookFailureModeWarn:
				hm.logger.Warn("Hook failed", "name", hook.Name, "error", hookErr)
			case HookFailureModeStop:
				hm.logger.Error("Hook failed, stopping execution", "name", hook.Name, "error", hookErr)
				return hookErr
			case HookFailureModeFail:
				if firstError == nil {
					firstError = hookErr
				}
				hm.logger.Error("Hook failed", "name", hook.Name, "error", hookErr)
			}
		} else {
			hm.logger.Debug("Hook executed successfully", "name", hook.Name, "phase", phase)
		}
	}
	
	if firstError != nil {
		return fmt.Errorf("hook execution failed: %w", firstError)
	}
	
	return nil
}

// checkConditions evaluates hook execution conditions
func (hm *HookManager) checkConditions(hook *Hook, state *HookContainerState) bool {
	if len(hook.Conditions) == 0 {
		return true // No conditions means always execute
	}
	
	for _, condition := range hook.Conditions {
		if !hm.evaluateCondition(condition, state) {
			return false
		}
	}
	
	return true
}

// evaluateCondition evaluates a single condition
func (hm *HookManager) evaluateCondition(condition HookCondition, state *HookContainerState) bool {
	var actualValue string
	
	switch condition.Type {
	case "env":
		actualValue = os.Getenv(condition.Key)
	case "config":
		// Access container config values
		if state != nil && state.Config != nil {
			switch condition.Key {
			case "runtime.name":
				actualValue = state.Config.Runtime.Name
			case "runtime.rootless":
				if state.Config.Runtime.IsRootless {
					actualValue = "true"
				} else {
					actualValue = "false"
				}
			case "storage.driver":
				if state.Config.Storage.RootFSSource != "" {
					actualValue = state.Config.Storage.RootFSSource
				}
			}
		}
	case "file":
		if _, err := os.Stat(condition.Key); err == nil {
			actualValue = "exists"
		} else {
			actualValue = "not_exists"
		}
	case "command":
		if _, err := exec.LookPath(condition.Key); err == nil {
			actualValue = "available"
		} else {
			actualValue = "not_available"
		}
	}
	
	switch condition.Op {
	case "eq", "":
		return actualValue == condition.Value
	case "ne":
		return actualValue != condition.Value
	case "contains":
		return strings.Contains(actualValue, condition.Value)
	case "startswith":
		return strings.HasPrefix(actualValue, condition.Value)
	case "endswith":
		return strings.HasSuffix(actualValue, condition.Value)
	}
	
	return false
}

// ListHooks returns all registered hooks for a phase
func (hm *HookManager) ListHooks(phase HookPhase) []*Hook {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	hooks := make([]*Hook, len(hm.hooks[phase]))
	copy(hooks, hm.hooks[phase])
	return hooks
}

// GetHookStats returns statistics about registered hooks
func (hm *HookManager) GetHookStats() map[HookPhase]int {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	stats := make(map[HookPhase]int)
	for phase, hooks := range hm.hooks {
		stats[phase] = len(hooks)
	}
	return stats
}

// DefaultHookExecutor is the default implementation of HookExecutor
type DefaultHookExecutor struct{}

// Execute executes a hook
func (e *DefaultHookExecutor) Execute(ctx context.Context, hook Hook, state *HookContainerState) (*HookResult, error) {
	startTime := time.Now()
	
	// Create timeout context
	hookCtx, cancel := context.WithTimeout(ctx, hook.Timeout)
	defer cancel()
	
	// Prepare command
	cmd := exec.CommandContext(hookCtx, hook.Path, hook.Args...)
	
	// Set environment
	cmd.Env = append(os.Environ(), hook.Env...)
	
	// Add container information to environment
	if state != nil && state.Config != nil {
		cmd.Env = append(cmd.Env,
			fmt.Sprintf("CONTAINER_NAME=%s", state.Config.Runtime.Name),
			fmt.Sprintf("HOOK_PHASE=%s", hook.Phase),
			fmt.Sprintf("HOOK_NAME=%s", hook.Name),
		)
		
		if state.Process != nil {
			cmd.Env = append(cmd.Env, fmt.Sprintf("CONTAINER_PID=%d", state.Process.Pid))
		}
	}
	
	// Execute command
	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime)
	
	result := &HookResult{
		Success:   err == nil,
		Output:    string(output),
		Duration:  duration,
		Timestamp: startTime,
	}
	
	if err != nil {
		result.Error = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
	}
	
	return result, nil
}

// HookRegistry manages hook registration from configuration files
type HookRegistry struct {
	manager    *HookManager
	configDirs []string
	logger     *slog.Logger
}

// NewHookRegistry creates a new hook registry
func NewHookRegistry(ctx context.Context, manager *HookManager, configDirs []string) *HookRegistry {
	return &HookRegistry{
		manager:    manager,
		configDirs: configDirs,
		logger:     Logger(ctx).With("component", "hook-registry"),
	}
}

// LoadHooks loads hooks from configuration directories
func (hr *HookRegistry) LoadHooks(ctx context.Context) error {
	for _, dir := range hr.configDirs {
		if err := hr.loadFromDirectory(ctx, dir); err != nil {
			hr.logger.Warn("Failed to load hooks from directory", "dir", dir, "error", err)
		}
	}
	return nil
}

// loadFromDirectory loads hooks from a specific directory
func (hr *HookRegistry) loadFromDirectory(ctx context.Context, dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil // Directory doesn't exist, skip
	}
	
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			return nil
		}
		
		if !strings.HasSuffix(path, ".json") {
			return nil
		}
		
		return hr.loadHookFile(path)
	})
}

// loadHookFile loads hooks from a JSON configuration file
func (hr *HookRegistry) loadHookFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read hook file %s: %w", path, err)
	}
	
	var config struct {
		Hooks []Hook `json:"hooks"`
	}
	
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse hook file %s: %w", path, err)
	}
	
	for i := range config.Hooks {
		hook := &config.Hooks[i]
		
		// Resolve relative paths
		if !filepath.IsAbs(hook.Path) {
			hook.Path = filepath.Join(filepath.Dir(path), hook.Path)
		}
		
		if err := hr.manager.RegisterHook(hook); err != nil {
			hr.logger.Warn("Failed to register hook", "name", hook.Name, "file", path, "error", err)
		} else {
			hr.logger.Info("Loaded hook", "name", hook.Name, "phase", hook.Phase, "file", path)
		}
	}
	
	return nil
}

// HookConfigGenerator generates example hook configurations
type HookConfigGenerator struct{}

// GenerateExampleConfig generates example hook configuration
func (g *HookConfigGenerator) GenerateExampleConfig() map[string]interface{} {
	return map[string]interface{}{
		"hooks": []Hook{
			{
				Name:        "setup-logging",
				Path:        "/usr/local/bin/setup-logging.sh",
				Phase:       HookPhasePrestart,
				Priority:    10,
				FailureMode: HookFailureModeWarn,
				Timeout:     30 * time.Second,
				Args:        []string{"--container", "${CONTAINER_NAME}"},
				Conditions: []HookCondition{
					{
						Type:  "env",
						Key:   "ENABLE_LOGGING",
						Value: "true",
					},
				},
			},
			{
				Name:        "network-setup",
				Path:        "/usr/local/bin/network-setup.sh",
				Phase:       HookPhaseNetworkPostSetup,
				Priority:    20,
				FailureMode: HookFailureModeFail,
				Timeout:     60 * time.Second,
				Conditions: []HookCondition{
					{
						Type:  "config",
						Key:   "runtime.rootless",
						Value: "false",
					},
				},
			},
			{
				Name:        "cleanup-resources",
				Path:        "/usr/local/bin/cleanup.sh",
				Phase:       HookPhasePoststop,
				Priority:    100,
				FailureMode: HookFailureModeIgnore,
				Timeout:     30 * time.Second,
			},
		},
	}
}

// SaveExampleConfig saves an example configuration to a file
func (g *HookConfigGenerator) SaveExampleConfig(path string) error {
	config := g.GenerateExampleConfig()
	
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(path, data, 0644)
}


// HookContainerState represents the container state passed to hooks
type HookContainerState struct {
	Config  *Config     `json:"config,omitempty"`
	Process *os.Process `json:"process,omitempty"`
	State   string      `json:"state,omitempty"`
}


// Add hook manager to Container struct (this would be added to the existing Container type)
type ContainerWithHooks struct {
	Container
	hookManager *HookManager
}


// Enhanced hook execution in container lifecycle
func (c *Container) executeLifecycleHook(ctx context.Context, phase HookPhase) error {
	// If hook manager is available, use it
	if hookManager := c.getHookManager(); hookManager != nil {
		state := &HookContainerState{
			Config: c.Config,
			State:  c.getState().String(),
		}
		
		if c.Process != nil {
			state.Process = c.Process.Process
		}
		
		return hookManager.ExecuteHooks(ctx, phase, state)
	}
	
	// Fallback to existing hook implementation
	return c.runHook(ctx, string(phase))
}

// getHookManager retrieves the hook manager (placeholder - would need Container modification)
func (c *Container) getHookManager() *HookManager {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hookManager
}