package main

import (
	"fmt"
	"strings"
)

// ErrorCode represents specific error types for better categorization
type ErrorCode string

const (
	// Container lifecycle errors
	ErrContainerCreation   ErrorCode = "container_creation_failed"
	ErrContainerStart      ErrorCode = "container_start_failed"
	ErrContainerStop       ErrorCode = "container_stop_failed"
	ErrContainerDestroy    ErrorCode = "container_destroy_failed"
	
	// Network errors
	ErrNetworkSetup        ErrorCode = "network_setup_failed"
	ErrIPAllocation        ErrorCode = "ip_allocation_failed"
	ErrBridgeCreation      ErrorCode = "bridge_creation_failed"
	ErrVethCreation        ErrorCode = "veth_creation_failed"
	
	// Storage errors
	ErrRootfsPreparation   ErrorCode = "rootfs_preparation_failed"
	ErrVolumeMount         ErrorCode = "volume_mount_failed"
	ErrImageLoad           ErrorCode = "image_load_failed"
	
	// Security errors
	ErrSeccompApplication  ErrorCode = "seccomp_application_failed"
	ErrCapabilitySet       ErrorCode = "capability_set_failed"
	ErrNamespaceCreation   ErrorCode = "namespace_creation_failed"
	
	// Resource management errors
	ErrCgroupSetup         ErrorCode = "cgroup_setup_failed"
	ErrResourceCleanup     ErrorCode = "resource_cleanup_failed"
	ErrResourceAllocation  ErrorCode = "resource_allocation_failed"
	
	// Configuration errors
	ErrConfigValidation    ErrorCode = "config_validation_failed"
	ErrConfigMarshal       ErrorCode = "config_marshal_failed"
	ErrConfigUnmarshal     ErrorCode = "config_unmarshal_failed"
	
	// OCI runtime errors
	ErrOCISpecValidation   ErrorCode = "oci_spec_validation_failed"
	ErrOCIRuntimeCreate    ErrorCode = "oci_runtime_create_failed"
	ErrOCIRuntimeStart     ErrorCode = "oci_runtime_start_failed"
	
	// System errors
	ErrSystemCall          ErrorCode = "system_call_failed"
	ErrPermissionDenied    ErrorCode = "permission_denied"
	ErrResourceExhausted   ErrorCode = "resource_exhausted"
	
	// Internal errors
	ErrInternalError       ErrorCode = "internal_error"
	ErrTimeout             ErrorCode = "timeout"
	ErrCancelled           ErrorCode = "cancelled"
)

// ContainerError represents a structured error with context
type ContainerError struct {
	Code      ErrorCode              `json:"code"`
	Message   string                 `json:"message"`
	Cause     error                  `json:"-"`
	Context   map[string]interface{} `json:"context,omitempty"`
	Retry     bool                   `json:"retry"`
	Component string                 `json:"component,omitempty"`
}

// Error implements the error interface
func (e *ContainerError) Error() string {
	var parts []string
	
	if e.Component != "" {
		parts = append(parts, fmt.Sprintf("[%s]", e.Component))
	}
	
	parts = append(parts, fmt.Sprintf("%s: %s", e.Code, e.Message))
	
	if len(e.Context) > 0 {
		var contextParts []string
		for k, v := range e.Context {
			contextParts = append(contextParts, fmt.Sprintf("%s=%v", k, v))
		}
		parts = append(parts, fmt.Sprintf("(%s)", strings.Join(contextParts, ", ")))
	}
	
	if e.Cause != nil {
		parts = append(parts, fmt.Sprintf("caused by: %v", e.Cause))
	}
	
	return strings.Join(parts, " ")
}

// Unwrap provides compatibility with errors.Is and errors.As
func (e *ContainerError) Unwrap() error {
	return e.Cause
}

// IsRetryable returns whether the error is retryable
func (e *ContainerError) IsRetryable() bool {
	return e.Retry
}

// GetCode returns the error code
func (e *ContainerError) GetCode() ErrorCode {
	return e.Code
}

// NewContainerError creates a new structured container error
func NewContainerError(code ErrorCode, message string) *ContainerError {
	return &ContainerError{
		Code:    code,
		Message: message,
		Context: make(map[string]interface{}),
	}
}

// NewContainerErrorWithCause creates a new container error with a cause
func NewContainerErrorWithCause(code ErrorCode, message string, cause error) *ContainerError {
	return &ContainerError{
		Code:    code,
		Message: message,
		Cause:   cause,
		Context: make(map[string]interface{}),
	}
}

// WithContext adds context information to the error
func (e *ContainerError) WithContext(key string, value interface{}) *ContainerError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithComponent sets the component that generated the error
func (e *ContainerError) WithComponent(component string) *ContainerError {
	e.Component = component
	return e
}

// WithRetryable marks the error as retryable or not
func (e *ContainerError) WithRetryable(retry bool) *ContainerError {
	e.Retry = retry
	return e
}

// ErrorChain represents a chain of errors for complex operations
type ErrorChain struct {
	Errors    []error `json:"errors"`
	Operation string  `json:"operation"`
}

// Error implements the error interface
func (ec *ErrorChain) Error() string {
	if len(ec.Errors) == 0 {
		return fmt.Sprintf("operation '%s' failed with no specific errors", ec.Operation)
	}
	
	if len(ec.Errors) == 1 {
		return fmt.Sprintf("operation '%s' failed: %v", ec.Operation, ec.Errors[0])
	}
	
	var messages []string
	for i, err := range ec.Errors {
		messages = append(messages, fmt.Sprintf("%d: %v", i+1, err))
	}
	
	return fmt.Sprintf("operation '%s' failed with %d errors:\n%s", 
		ec.Operation, len(ec.Errors), strings.Join(messages, "\n"))
}

// Add adds an error to the chain
func (ec *ErrorChain) Add(err error) {
	if err != nil {
		ec.Errors = append(ec.Errors, err)
	}
}

// HasErrors returns true if the chain contains any errors
func (ec *ErrorChain) HasErrors() bool {
	return len(ec.Errors) > 0
}

// FirstError returns the first error in the chain, or nil if empty
func (ec *ErrorChain) FirstError() error {
	if len(ec.Errors) == 0 {
		return nil
	}
	return ec.Errors[0]
}

// LastError returns the last error in the chain, or nil if empty
func (ec *ErrorChain) LastError() error {
	if len(ec.Errors) == 0 {
		return nil
	}
	return ec.Errors[len(ec.Errors)-1]
}

// ToError returns the ErrorChain as an error if it has errors, nil otherwise
func (ec *ErrorChain) ToError() error {
	if ec.HasErrors() {
		return ec
	}
	return nil
}

// NewErrorChain creates a new error chain for an operation
func NewErrorChain(operation string) *ErrorChain {
	return &ErrorChain{
		Operation: operation,
		Errors:    make([]error, 0),
	}
}

// Helper functions for common error patterns

// WrapSystemError wraps a system error with container error context
func WrapSystemError(syscall string, err error) *ContainerError {
	return NewContainerErrorWithCause(ErrSystemCall, 
		fmt.Sprintf("system call '%s' failed", syscall), err).
		WithContext("syscall", syscall).
		WithComponent("system")
}

// WrapConfigError wraps a configuration error
func WrapConfigError(field string, err error) *ContainerError {
	return NewContainerErrorWithCause(ErrConfigValidation,
		fmt.Sprintf("configuration validation failed for field '%s'", field), err).
		WithContext("field", field).
		WithComponent("config")
}

// WrapNetworkError wraps a network-related error
func WrapNetworkError(operation string, err error) *ContainerError {
	return NewContainerErrorWithCause(ErrNetworkSetup,
		fmt.Sprintf("network operation '%s' failed", operation), err).
		WithContext("operation", operation).
		WithComponent("network").
		WithRetryable(true)
}

// WrapStorageError wraps a storage-related error
func WrapStorageError(operation string, path string, err error) *ContainerError {
	return NewContainerErrorWithCause(ErrRootfsPreparation,
		fmt.Sprintf("storage operation '%s' failed", operation), err).
		WithContext("operation", operation).
		WithContext("path", path).
		WithComponent("storage")
}

// WrapSecurityError wraps a security-related error
func WrapSecurityError(operation string, err error) *ContainerError {
	return NewContainerErrorWithCause(ErrSeccompApplication,
		fmt.Sprintf("security operation '%s' failed", operation), err).
		WithContext("operation", operation).
		WithComponent("security")
}

// IsErrorCode checks if an error matches a specific error code
func IsErrorCode(err error, code ErrorCode) bool {
	if containerErr, ok := err.(*ContainerError); ok {
		return containerErr.Code == code
	}
	return false
}

// IsRetryableError checks if an error is retryable
func IsRetryableError(err error) bool {
	if containerErr, ok := err.(*ContainerError); ok {
		return containerErr.Retry
	}
	return false
}