package codex

import (
	"strings"
	"time"
)

// AgentIdentityRecoveryHistoryEntry is a management-safe completed recovery
// attempt. It intentionally excludes runtime IDs, task IDs, and key material.
type AgentIdentityRecoveryHistoryEntry struct {
	ID         uint64     `json:"id"`
	Name       string     `json:"name,omitempty"`
	State      string     `json:"state"`
	Trigger    string     `json:"trigger,omitempty"`
	Attempt    int        `json:"attempt"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time  `json:"finished_at"`
	DurationMS int64      `json:"duration_ms"`
	ErrorCode  string     `json:"error_code,omitempty"`
	Error      string     `json:"error,omitempty"`
	Success    bool       `json:"success"`
}

// AgentIdentityRecoveryCoordinatorStats summarizes the bounded asynchronous
// recovery pool without exposing account credentials.
type AgentIdentityRecoveryCoordinatorStats struct {
	Concurrency   int `json:"concurrency"`
	Active        int `json:"active"`
	Queued        int `json:"queued"`
	QueueCapacity int `json:"queue_capacity"`
	HistoryCount  int `json:"history_count"`
	HistoryLimit  int `json:"history_limit"`
}

// ConfigureAgentIdentityRecovery applies runtime-safe recovery settings. A
// lower concurrency takes effect as current jobs finish; an increase is live.
func ConfigureAgentIdentityRecovery(concurrency, historyLimit int) AgentIdentityRecoveryCoordinatorStats {
	coordinator := defaultAgentIdentityRegistrationCoordinator
	if coordinator == nil {
		return AgentIdentityRecoveryCoordinatorStats{}
	}
	coordinator.setConcurrency(concurrency)
	coordinator.setHistoryLimit(historyLimit)
	return coordinator.stats()
}

// AgentIdentityRecoveryStats returns a point-in-time coordinator snapshot.
func AgentIdentityRecoveryStats() AgentIdentityRecoveryCoordinatorStats {
	if defaultAgentIdentityRegistrationCoordinator == nil {
		return AgentIdentityRecoveryCoordinatorStats{}
	}
	return defaultAgentIdentityRegistrationCoordinator.stats()
}

// AgentIdentityRecoveryHistory returns newest-first completed attempts.
func AgentIdentityRecoveryHistory(limit int) []AgentIdentityRecoveryHistoryEntry {
	if defaultAgentIdentityRegistrationCoordinator == nil {
		return []AgentIdentityRecoveryHistoryEntry{}
	}
	return defaultAgentIdentityRegistrationCoordinator.historySnapshot(limit)
}

func normalizeAgentIdentityRecoveryConcurrency(value int) int {
	if value <= 0 {
		return agentIdentityRegistrationWorkers
	}
	if value > agentIdentityRegistrationMaxWorkers {
		return agentIdentityRegistrationMaxWorkers
	}
	return value
}

func normalizeAgentIdentityRecoveryHistoryLimit(value int) int {
	if value <= 0 {
		return agentIdentityRegistrationHistorySize
	}
	if value > 10000 {
		return 10000
	}
	return value
}

func (c *agentIdentityRegistrationCoordinator) setConcurrency(value int) {
	if c == nil {
		return
	}
	c.limitMu.Lock()
	c.concurrency = normalizeAgentIdentityRecoveryConcurrency(value)
	c.limitCond.Broadcast()
	c.limitMu.Unlock()
}

func (c *agentIdentityRegistrationCoordinator) setHistoryLimit(value int) {
	if c == nil {
		return
	}
	limit := normalizeAgentIdentityRecoveryHistoryLimit(value)
	c.historyMu.Lock()
	c.historyLimit = limit
	if len(c.history) > limit {
		c.history = append([]AgentIdentityRecoveryHistoryEntry(nil), c.history[len(c.history)-limit:]...)
	}
	c.historyMu.Unlock()
}

func (c *agentIdentityRegistrationCoordinator) acquireRegistrationSlot() bool {
	if c == nil {
		return false
	}
	c.limitMu.Lock()
	c.waiting++
	for !c.closed && c.inFlight >= c.concurrency {
		c.limitCond.Wait()
	}
	c.waiting--
	if c.closed {
		c.limitMu.Unlock()
		return false
	}
	c.inFlight++
	c.limitMu.Unlock()
	return true
}

func (c *agentIdentityRegistrationCoordinator) releaseRegistrationSlot() {
	if c == nil {
		return
	}
	c.limitMu.Lock()
	if c.inFlight > 0 {
		c.inFlight--
	}
	c.limitCond.Broadcast()
	c.limitMu.Unlock()
}

func (c *agentIdentityRegistrationCoordinator) stats() AgentIdentityRecoveryCoordinatorStats {
	if c == nil {
		return AgentIdentityRecoveryCoordinatorStats{}
	}
	c.limitMu.Lock()
	concurrency := c.concurrency
	active := c.inFlight
	waiting := c.waiting
	c.limitMu.Unlock()
	c.historyMu.RLock()
	historyCount := len(c.history)
	historyLimit := c.historyLimit
	c.historyMu.RUnlock()
	return AgentIdentityRecoveryCoordinatorStats{
		Concurrency:   concurrency,
		Active:        active,
		Queued:        len(c.queue) + waiting,
		QueueCapacity: cap(c.queue),
		HistoryCount:  historyCount,
		HistoryLimit:  historyLimit,
	}
}

func (c *agentIdentityRegistrationCoordinator) recordAttempt(identity *AgentIdentity, status AgentIdentityRegistrationStatus, finishedAt time.Time) {
	if c == nil || identity == nil {
		return
	}
	entry := AgentIdentityRecoveryHistoryEntry{
		Name:       identity.registrationDisplayName(),
		State:      status.State,
		Trigger:    status.Trigger,
		Attempt:    status.Attempts,
		StartedAt:  cloneRegistrationTime(status.StartedAt),
		FinishedAt: finishedAt.UTC(),
		ErrorCode:  status.ErrorCode,
		Error:      status.Error,
		Success:    status.State == AgentIdentityRegistrationReady,
	}
	if status.StartedAt != nil {
		entry.DurationMS = finishedAt.Sub(*status.StartedAt).Milliseconds()
		if entry.DurationMS < 0 {
			entry.DurationMS = 0
		}
	}
	c.historyMu.Lock()
	c.historySequence++
	entry.ID = c.historySequence
	limit := normalizeAgentIdentityRecoveryHistoryLimit(c.historyLimit)
	if len(c.history) >= limit {
		copy(c.history, c.history[len(c.history)-limit+1:])
		c.history = c.history[:limit-1]
	}
	c.history = append(c.history, entry)
	c.historyMu.Unlock()
}

func (c *agentIdentityRegistrationCoordinator) historySnapshot(limit int) []AgentIdentityRecoveryHistoryEntry {
	if c == nil {
		return []AgentIdentityRecoveryHistoryEntry{}
	}
	c.historyMu.RLock()
	count := len(c.history)
	if limit <= 0 || limit > count {
		limit = count
	}
	result := make([]AgentIdentityRecoveryHistoryEntry, 0, limit)
	for index := count - 1; index >= 0 && len(result) < limit; index-- {
		entry := c.history[index]
		entry.StartedAt = cloneRegistrationTime(entry.StartedAt)
		result = append(result, entry)
	}
	c.historyMu.RUnlock()
	return result
}

func (a *AgentIdentity) SetRegistrationName(name string) {
	if a == nil {
		return
	}
	a.registrationMu.Lock()
	a.registrationName = strings.TrimSpace(name)
	a.registrationMu.Unlock()
}

func (a *AgentIdentity) registrationDisplayName() string {
	if a == nil {
		return ""
	}
	a.registrationMu.Lock()
	name := a.registrationName
	a.registrationMu.Unlock()
	return name
}
