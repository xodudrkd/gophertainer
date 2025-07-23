package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// PluginEventType represents different types of plugin events
type PluginEventType string

const (
	// Plugin lifecycle events
	PluginEventLoaded      PluginEventType = "plugin.loaded"
	PluginEventUnloaded    PluginEventType = "plugin.unloaded"
	PluginEventInitialized PluginEventType = "plugin.initialized"
	PluginEventStarted     PluginEventType = "plugin.started"
	PluginEventStopped     PluginEventType = "plugin.stopped"
	PluginEventError       PluginEventType = "plugin.error"
	
	// Container lifecycle events that plugins can listen to
	ContainerEventCreated  PluginEventType = "container.created"
	ContainerEventStarting PluginEventType = "container.starting"
	ContainerEventStarted  PluginEventType = "container.started"
	ContainerEventStopping PluginEventType = "container.stopping"
	ContainerEventStopped  PluginEventType = "container.stopped"
	ContainerEventDeleted  PluginEventType = "container.deleted"
	
	// Storage events
	StorageEventMounting   PluginEventType = "storage.mounting"
	StorageEventMounted    PluginEventType = "storage.mounted"
	StorageEventUnmounting PluginEventType = "storage.unmounting"
	StorageEventUnmounted  PluginEventType = "storage.unmounted"
	
	// Network events
	NetworkEventSetup      PluginEventType = "network.setup"
	NetworkEventTeardown   PluginEventType = "network.teardown"
)

// PluginEvent represents an event in the plugin system
type PluginEvent struct {
	ID         string                 `json:"id"`
	Type       PluginEventType        `json:"type"`
	PluginName string                 `json:"plugin_name,omitempty"`
	Source     string                 `json:"source"`
	Timestamp  time.Time              `json:"timestamp"`
	Data       map[string]interface{} `json:"data,omitempty"`
	Error      string                 `json:"error,omitempty"`
}

// PluginEventHandler defines the interface for handling plugin events
type PluginEventHandler interface {
	HandleEvent(ctx context.Context, event *PluginEvent) error
	GetHandledEvents() []PluginEventType
}

// PluginEventListener represents a registered event listener
type PluginEventListener struct {
	ID         string
	PluginName string
	Handler    PluginEventHandler
	EventTypes []PluginEventType
	Priority   int
	Created    time.Time
}

// PluginEventBus manages event distribution to plugins
type PluginEventBus struct {
	listeners    map[PluginEventType][]*PluginEventListener
	eventHistory []PluginEvent
	maxHistory   int
	logger       *slog.Logger
	mu           sync.RWMutex
}

// NewPluginEventBus creates a new plugin event bus
func NewPluginEventBus(ctx context.Context) *PluginEventBus {
	return &PluginEventBus{
		listeners:    make(map[PluginEventType][]*PluginEventListener),
		eventHistory: make([]PluginEvent, 0),
		maxHistory:   1000, // Keep last 1000 events
		logger:       Logger(ctx).With("component", "plugin-event-bus"),
	}
}

// Subscribe registers a plugin to listen for specific events
func (peb *PluginEventBus) Subscribe(pluginName string, handler PluginEventHandler, priority int) error {
	if handler == nil {
		return fmt.Errorf("event handler cannot be nil")
	}
	
	eventTypes := handler.GetHandledEvents()
	if len(eventTypes) == 0 {
		return fmt.Errorf("handler must specify at least one event type")
	}
	
	listener := &PluginEventListener{
		ID:         fmt.Sprintf("%s-%d", pluginName, time.Now().UnixNano()),
		PluginName: pluginName,
		Handler:    handler,
		EventTypes: eventTypes,
		Priority:   priority,
		Created:    time.Now(),
	}
	
	peb.mu.Lock()
	defer peb.mu.Unlock()
	
	// Register listener for each event type it handles
	for _, eventType := range eventTypes {
		peb.listeners[eventType] = append(peb.listeners[eventType], listener)
		
		// Sort by priority (lower numbers = higher priority)
		listeners := peb.listeners[eventType]
		for i := len(listeners) - 1; i > 0; i-- {
			if listeners[i].Priority < listeners[i-1].Priority {
				listeners[i], listeners[i-1] = listeners[i-1], listeners[i]
			} else {
				break
			}
		}
	}
	
	peb.logger.Info("Plugin subscribed to events", 
		"plugin", pluginName, 
		"events", eventTypes, 
		"priority", priority)
	
	return nil
}

// Unsubscribe removes a plugin's event subscriptions
func (peb *PluginEventBus) Unsubscribe(pluginName string) error {
	peb.mu.Lock()
	defer peb.mu.Unlock()
	
	removedCount := 0
	
	// Remove from all event type listeners
	for eventType, listeners := range peb.listeners {
		filteredListeners := make([]*PluginEventListener, 0, len(listeners))
		for _, listener := range listeners {
			if listener.PluginName != pluginName {
				filteredListeners = append(filteredListeners, listener)
			} else {
				removedCount++
			}
		}
		peb.listeners[eventType] = filteredListeners
	}
	
	peb.logger.Info("Plugin unsubscribed from events", "plugin", pluginName, "removed", removedCount)
	return nil
}

// Emit sends an event to all registered listeners
func (peb *PluginEventBus) Emit(event *PluginEvent) {
	if event == nil {
		return
	}
	
	// Generate ID if not set
	if event.ID == "" {
		event.ID = fmt.Sprintf("event-%d", time.Now().UnixNano())
	}
	
	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	
	// Set source if not set
	if event.Source == "" {
		event.Source = "plugin-manager"
	}
	
	peb.mu.RLock()
	listeners := make([]*PluginEventListener, len(peb.listeners[event.Type]))
	copy(listeners, peb.listeners[event.Type])
	peb.mu.RUnlock()
	
	if len(listeners) == 0 {
		peb.logger.Debug("No listeners for event", "type", event.Type)
		return
	}
	
	peb.logger.Debug("Emitting event", "type", event.Type, "listeners", len(listeners))
	
	// Add to history
	peb.addToHistory(*event)
	
	// Notify all listeners concurrently
	var wg sync.WaitGroup
	for _, listener := range listeners {
		wg.Add(1)
		go func(l *PluginEventListener) {
			defer wg.Done()
			peb.notifyListener(l, event)
		}(listener)
	}
	
	wg.Wait()
}

// notifyListener sends an event to a specific listener
func (peb *PluginEventBus) notifyListener(listener *PluginEventListener, event *PluginEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	start := time.Now()
	err := listener.Handler.HandleEvent(ctx, event)
	duration := time.Since(start)
	
	if err != nil {
		peb.logger.Warn("Event handler failed", 
			"plugin", listener.PluginName,
			"event_type", event.Type,
			"error", err,
			"duration", duration)
		
		// Emit error event
		errorEvent := &PluginEvent{
			Type:       PluginEventError,
			PluginName: listener.PluginName,
			Source:     "event-bus",
			Timestamp:  time.Now(),
			Error:      err.Error(),
			Data: map[string]interface{}{
				"original_event_type": event.Type,
				"original_event_id":   event.ID,
				"handler_duration":    duration.String(),
			},
		}
		
		// Emit error event asynchronously to avoid infinite loops
		go func() {
			peb.Emit(errorEvent)
		}()
	} else {
		peb.logger.Debug("Event handled successfully",
			"plugin", listener.PluginName,
			"event_type", event.Type,
			"duration", duration)
	}
}

// addToHistory adds an event to the event history
func (peb *PluginEventBus) addToHistory(event PluginEvent) {
	peb.mu.Lock()
	defer peb.mu.Unlock()
	
	peb.eventHistory = append(peb.eventHistory, event)
	
	// Trim history if it exceeds max size
	if len(peb.eventHistory) > peb.maxHistory {
		// Remove oldest events
		removeCount := len(peb.eventHistory) - peb.maxHistory
		peb.eventHistory = peb.eventHistory[removeCount:]
	}
}

// GetEventHistory returns recent events
func (peb *PluginEventBus) GetEventHistory(limit int) []PluginEvent {
	peb.mu.RLock()
	defer peb.mu.RUnlock()
	
	if limit <= 0 || limit > len(peb.eventHistory) {
		limit = len(peb.eventHistory)
	}
	
	// Return most recent events
	start := len(peb.eventHistory) - limit
	history := make([]PluginEvent, limit)
	copy(history, peb.eventHistory[start:])
	
	return history
}

// GetListeners returns information about registered listeners
func (peb *PluginEventBus) GetListeners() map[PluginEventType][]*PluginEventListener {
	peb.mu.RLock()
	defer peb.mu.RUnlock()
	
	result := make(map[PluginEventType][]*PluginEventListener)
	for eventType, listeners := range peb.listeners {
		result[eventType] = make([]*PluginEventListener, len(listeners))
		copy(result[eventType], listeners)
	}
	
	return result
}

// GetEventStats returns statistics about events
func (peb *PluginEventBus) GetEventStats() map[string]interface{} {
	peb.mu.RLock()
	defer peb.mu.RUnlock()
	
	stats := map[string]interface{}{
		"total_listeners":    peb.getTotalListenerCount(),
		"listeners_by_type":  peb.getListenerCountByType(),
		"event_history_size": len(peb.eventHistory),
		"max_history_size":   peb.maxHistory,
	}
	
	// Count events by type in history
	eventCounts := make(map[PluginEventType]int)
	for _, event := range peb.eventHistory {
		eventCounts[event.Type]++
	}
	stats["events_by_type"] = eventCounts
	
	return stats
}

// getTotalListenerCount returns the total number of listeners
func (peb *PluginEventBus) getTotalListenerCount() int {
	total := 0
	for _, listeners := range peb.listeners {
		total += len(listeners)
	}
	return total
}

// getListenerCountByType returns listener counts per event type
func (peb *PluginEventBus) getListenerCountByType() map[PluginEventType]int {
	counts := make(map[PluginEventType]int)
	for eventType, listeners := range peb.listeners {
		counts[eventType] = len(listeners)
	}
	return counts
}

// ClearHistory clears the event history
func (peb *PluginEventBus) ClearHistory() {
	peb.mu.Lock()
	defer peb.mu.Unlock()
	
	peb.eventHistory = make([]PluginEvent, 0)
	peb.logger.Info("Event history cleared")
}

// SetMaxHistory sets the maximum number of events to keep in history
func (peb *PluginEventBus) SetMaxHistory(maxHistory int) {
	if maxHistory < 0 {
		maxHistory = 0
	}
	
	peb.mu.Lock()
	defer peb.mu.Unlock()
	
	peb.maxHistory = maxHistory
	
	// Trim current history if needed
	if len(peb.eventHistory) > maxHistory {
		if maxHistory == 0 {
			peb.eventHistory = make([]PluginEvent, 0)
		} else {
			removeCount := len(peb.eventHistory) - maxHistory
			peb.eventHistory = peb.eventHistory[removeCount:]
		}
	}
	
	peb.logger.Info("Max event history size updated", "max_history", maxHistory)
}

// ContainerEventPlugin is an interface for plugins that want to handle container events
type ContainerEventPlugin interface {
	Plugin
	PluginEventHandler
}

// StorageEventPlugin is an interface for plugins that want to handle storage events
type StorageEventPlugin interface {
	Plugin
	PluginEventHandler
}

// NetworkEventPlugin is an interface for plugins that want to handle network events
type NetworkEventPlugin interface {
	Plugin
	PluginEventHandler
}

// DefaultEventHandler provides a basic implementation of PluginEventHandler
type DefaultEventHandler struct {
	eventTypes []PluginEventType
	handler    func(ctx context.Context, event *PluginEvent) error
}

// NewDefaultEventHandler creates a new default event handler
func NewDefaultEventHandler(eventTypes []PluginEventType, handler func(ctx context.Context, event *PluginEvent) error) *DefaultEventHandler {
	return &DefaultEventHandler{
		eventTypes: eventTypes,
		handler:    handler,
	}
}

// HandleEvent implements PluginEventHandler
func (deh *DefaultEventHandler) HandleEvent(ctx context.Context, event *PluginEvent) error {
	if deh.handler == nil {
		return nil
	}
	return deh.handler(ctx, event)
}

// GetHandledEvents implements PluginEventHandler
func (deh *DefaultEventHandler) GetHandledEvents() []PluginEventType {
	return deh.eventTypes
}

// Utility functions for creating common events

// NewContainerEvent creates a new container lifecycle event
func NewContainerEvent(eventType PluginEventType, containerName string, data map[string]interface{}) *PluginEvent {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["container_name"] = containerName
	
	return &PluginEvent{
		Type:      eventType,
		Source:    "container-runtime",
		Timestamp: time.Now(),
		Data:      data,
	}
}

// NewStorageEvent creates a new storage event
func NewStorageEvent(eventType PluginEventType, containerName string, mountPath string, data map[string]interface{}) *PluginEvent {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["container_name"] = containerName
	data["mount_path"] = mountPath
	
	return &PluginEvent{
		Type:      eventType,
		Source:    "storage-manager",
		Timestamp: time.Now(),
		Data:      data,
	}
}

// NewNetworkEvent creates a new network event
func NewNetworkEvent(eventType PluginEventType, containerName string, networkName string, data map[string]interface{}) *PluginEvent {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["container_name"] = containerName
	data["network_name"] = networkName
	
	return &PluginEvent{
		Type:      eventType,
		Source:    "network-manager",
		Timestamp: time.Now(),
		Data:      data,
	}
}