package codex

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	AgentIdentityRegistrationReady          = "ready"
	AgentIdentityRegistrationQueued         = "queued"
	AgentIdentityRegistrationRegistering    = "registering"
	AgentIdentityRegistrationRetryWait      = "retry_wait"
	AgentIdentityRegistrationRuntimeDeleted = "runtime_deleted"
	AgentIdentityRegistrationFailed         = "failed"
)

const (
	agentIdentityRegistrationWorkers     = 4
	agentIdentityRegistrationQueueSize   = 2048
	agentIdentityRegistrationMaxAttempts = 5
	agentIdentityRegistrationBaseBackoff = time.Second
	agentIdentityRegistrationMaxBackoff  = 30 * time.Second
)

var (
	ErrAgentIdentityRegistrationPending = errors.New("agent identity task registration is pending")
	ErrAgentIdentityRuntimeDeleted      = errors.New("agent identity runtime has been deleted")
	ErrAgentIdentityCredentialsChanged  = errors.New("agent identity credentials changed during task registration")
)

// AgentIdentityRegistrationStatus is a sanitized snapshot suitable for the
// management API. It never contains runtime IDs, task IDs, or signing keys.
type AgentIdentityRegistrationStatus struct {
	State       string     `json:"state"`
	Attempts    int        `json:"attempts"`
	QueuedAt    *time.Time `json:"queued_at,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	NextRetryAt *time.Time `json:"next_retry_at,omitempty"`
	ErrorCode   string     `json:"error_code,omitempty"`
	Error       string     `json:"error,omitempty"`
	Active      bool       `json:"active"`
	CanRetry    bool       `json:"can_retry"`
}

type agentIdentityRegistrationError struct {
	code      string
	message   string
	retryable bool
	cause     error
}

func (e *agentIdentityRegistrationError) Error() string {
	if e == nil || e.message == "" {
		return "agent identity task registration failed"
	}
	return e.message
}

func (e *agentIdentityRegistrationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

type agentIdentityRegistrationCoordinator struct {
	queue       chan agentIdentityRegistrationJob
	stop        chan struct{}
	closeOnce   sync.Once
	wg          sync.WaitGroup
	maxAttempts int
	baseBackoff time.Duration
	maxBackoff  time.Duration
}

type agentIdentityRegistrationJob struct {
	identity   *AgentIdentity
	generation uint64
}

var defaultAgentIdentityRegistrationCoordinator = newAgentIdentityRegistrationCoordinator(
	agentIdentityRegistrationWorkers,
	agentIdentityRegistrationQueueSize,
	agentIdentityRegistrationMaxAttempts,
	agentIdentityRegistrationBaseBackoff,
	agentIdentityRegistrationMaxBackoff,
)

func newAgentIdentityRegistrationCoordinator(
	workers int,
	queueSize int,
	maxAttempts int,
	baseBackoff time.Duration,
	maxBackoff time.Duration,
) *agentIdentityRegistrationCoordinator {
	if workers < 1 {
		workers = 1
	}
	if queueSize < 1 {
		queueSize = 1
	}
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	if baseBackoff <= 0 {
		baseBackoff = time.Second
	}
	if maxBackoff < baseBackoff {
		maxBackoff = baseBackoff
	}
	c := &agentIdentityRegistrationCoordinator{
		queue:       make(chan agentIdentityRegistrationJob, queueSize),
		stop:        make(chan struct{}),
		maxAttempts: maxAttempts,
		baseBackoff: baseBackoff,
		maxBackoff:  maxBackoff,
	}
	for range workers {
		c.wg.Add(1)
		go c.worker()
	}
	return c
}

func (c *agentIdentityRegistrationCoordinator) close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() { close(c.stop) })
	c.wg.Wait()
}

func (c *agentIdentityRegistrationCoordinator) enqueue(identity *AgentIdentity, generation uint64) bool {
	if c == nil || identity == nil {
		return false
	}
	select {
	case <-c.stop:
		return false
	case c.queue <- agentIdentityRegistrationJob{identity: identity, generation: generation}:
		return true
	default:
		return false
	}
}

func (c *agentIdentityRegistrationCoordinator) worker() {
	defer c.wg.Done()
	for {
		select {
		case <-c.stop:
			return
		case job := <-c.queue:
			if job.identity != nil {
				job.identity.performTaskRegistration(c, job.generation)
			}
		}
	}
}

func (c *agentIdentityRegistrationCoordinator) backoff(attempt int) time.Duration {
	if c == nil {
		return time.Second
	}
	delay := c.baseBackoff
	for i := 1; i < attempt && delay < c.maxBackoff; i++ {
		if delay > c.maxBackoff/2 {
			delay = c.maxBackoff
			break
		}
		delay *= 2
	}
	if delay > c.maxBackoff {
		return c.maxBackoff
	}
	return delay
}

func initialAgentIdentityRegistrationStatus(hasTask bool) AgentIdentityRegistrationStatus {
	if hasTask {
		return AgentIdentityRegistrationStatus{State: AgentIdentityRegistrationReady}
	}
	now := time.Now().UTC()
	return AgentIdentityRegistrationStatus{
		State:    AgentIdentityRegistrationQueued,
		QueuedAt: &now,
		Active:   true,
	}
}

// SetRegistrationClient installs the proxy-aware client used by background
// registration. Callers may replace it when a request has a newer transport.
func (a *AgentIdentity) SetRegistrationClient(client *http.Client) {
	if a == nil || client == nil {
		return
	}
	a.registrationMu.Lock()
	a.registrationClient = client
	a.registrationMu.Unlock()
}

// StartTaskRegistration queues a missing task without blocking the caller.
func (a *AgentIdentity) StartTaskRegistration() (AgentIdentityRegistrationStatus, bool) {
	return a.queueTaskRegistration(nil, "", false)
}

// QueueTaskRegistration invalidates the rejected task and schedules one
// background registration. Concurrent calls collapse into the existing job.
func (a *AgentIdentity) QueueTaskRegistration(client *http.Client, staleTaskID string) (AgentIdentityRegistrationStatus, bool) {
	return a.queueTaskRegistration(client, staleTaskID, false)
}

// RetryTaskRegistration manually retries a failed registration. A deleted
// runtime is terminal and requires importing fresh credentials.
func (a *AgentIdentity) RetryTaskRegistration() (AgentIdentityRegistrationStatus, bool) {
	return a.queueTaskRegistration(nil, "", true)
}

func (a *AgentIdentity) queueTaskRegistration(client *http.Client, staleTaskID string, manual bool) (AgentIdentityRegistrationStatus, bool) {
	if a == nil {
		return AgentIdentityRegistrationStatus{State: AgentIdentityRegistrationFailed}, false
	}

	a.registrationMu.Lock()
	defer a.registrationMu.Unlock()
	if client != nil {
		a.registrationClient = client
	}

	a.mu.Lock()
	currentTaskID := a.taskID
	if staleTaskID != "" {
		if currentTaskID != "" && currentTaskID != staleTaskID {
			a.mu.Unlock()
			a.setRegistrationReadyLocked()
			return registrationStatusSnapshot(a.registrationStatus), false
		}
		if currentTaskID == staleTaskID {
			a.taskID = ""
			a.selectionAvailable.Store(false)
			currentTaskID = ""
		}
	}
	a.mu.Unlock()

	if currentTaskID != "" {
		a.setRegistrationReadyLocked()
		return registrationStatusSnapshot(a.registrationStatus), false
	}
	if a.registrationStatus.State == AgentIdentityRegistrationRuntimeDeleted {
		return registrationStatusSnapshot(a.registrationStatus), false
	}
	if manual && a.registrationStatus.State == AgentIdentityRegistrationFailed && !a.registrationStatus.CanRetry {
		return registrationStatusSnapshot(a.registrationStatus), false
	}
	if a.registrationEnqueued || a.registrationStatus.State == AgentIdentityRegistrationRegistering || a.registrationStatus.State == AgentIdentityRegistrationRetryWait {
		return registrationStatusSnapshot(a.registrationStatus), false
	}
	if a.registrationStatus.State == AgentIdentityRegistrationFailed && !manual {
		return registrationStatusSnapshot(a.registrationStatus), false
	}

	if a.registrationRetryTimer != nil {
		a.registrationRetryTimer.Stop()
		a.registrationRetryTimer = nil
	}
	now := time.Now().UTC()
	if manual || a.registrationStatus.QueuedAt == nil {
		a.registrationStatus.Attempts = 0
		a.registrationStatus.QueuedAt = &now
		a.registrationStatus.StartedAt = nil
		a.registrationStatus.FinishedAt = nil
	}
	a.registrationStatus.State = AgentIdentityRegistrationQueued
	a.registrationStatus.NextRetryAt = nil
	a.registrationStatus.ErrorCode = ""
	a.registrationStatus.Error = ""
	a.registrationStatus.Active = true
	a.registrationStatus.CanRetry = false
	a.selectionAvailable.Store(false)
	a.registrationEnqueued = true
	a.registrationGeneration++
	generation := a.registrationGeneration

	coordinator := a.registrationCoordinator
	if coordinator == nil {
		coordinator = defaultAgentIdentityRegistrationCoordinator
		a.registrationCoordinator = coordinator
	}
	if !coordinator.enqueue(a, generation) {
		a.registrationEnqueued = false
		a.setRegistrationFailedLocked("queue_full", "Task registration queue is full.", true)
		return registrationStatusSnapshot(a.registrationStatus), false
	}
	return registrationStatusSnapshot(a.registrationStatus), true
}

// RegistrationStatus returns a copy of the current management-safe state.
func (a *AgentIdentity) RegistrationStatus() AgentIdentityRegistrationStatus {
	if a == nil {
		return AgentIdentityRegistrationStatus{State: AgentIdentityRegistrationFailed}
	}
	a.registrationMu.Lock()
	defer a.registrationMu.Unlock()
	return registrationStatusSnapshot(a.registrationStatus)
}

// RuntimeSelectionAvailable lets the generic auth selector skip credentials
// while their task is missing or being repaired. The same runtime becomes
// selectable immediately after a successful background registration.
func (a *AgentIdentity) RuntimeSelectionAvailable() bool {
	if a == nil {
		return false
	}
	return a.selectionAvailable.Load()
}

// MarkRuntimeDeleted records a terminal upstream response and prevents further
// automatic registration attempts for these credentials.
func (a *AgentIdentity) MarkRuntimeDeleted() {
	if a == nil {
		return
	}
	a.registrationMu.Lock()
	persist := a.setRegistrationRuntimeDeletedLocked()
	a.registrationMu.Unlock()
	persistAgentIdentityRuntimeDeleted(persist)
}

func (a *AgentIdentity) setRegistrationRuntimeDeletedLocked() func(context.Context, string) error {
	if a.registrationStatus.State == AgentIdentityRegistrationRuntimeDeleted {
		return nil
	}
	if a.registrationRetryTimer != nil {
		a.registrationRetryTimer.Stop()
		a.registrationRetryTimer = nil
	}
	a.registrationGeneration++
	a.registrationEnqueued = false
	a.mu.Lock()
	a.taskID = ""
	a.mu.Unlock()
	a.selectionAvailable.Store(false)
	now := time.Now().UTC()
	a.registrationStatus.State = AgentIdentityRegistrationRuntimeDeleted
	a.registrationStatus.FinishedAt = &now
	a.registrationStatus.NextRetryAt = nil
	a.registrationStatus.ErrorCode = "runtime_deleted"
	a.registrationStatus.Error = "Agent runtime has been deleted. Import fresh credentials to recover this account."
	a.registrationStatus.Active = false
	a.registrationStatus.CanRetry = false
	return a.persist
}

func (a *AgentIdentity) performTaskRegistration(coordinator *agentIdentityRegistrationCoordinator, generation uint64) {
	a.registrationMu.Lock()
	if generation != a.registrationGeneration || !a.registrationEnqueued || a.registrationStatus.State != AgentIdentityRegistrationQueued {
		a.registrationMu.Unlock()
		return
	}
	a.registrationEnqueued = false
	a.registrationStatus.State = AgentIdentityRegistrationRegistering
	a.registrationStatus.Attempts++
	a.registrationStatus.Active = true
	a.registrationStatus.CanRetry = false
	now := time.Now().UTC()
	a.registrationStatus.StartedAt = &now
	a.registrationStatus.NextRetryAt = nil
	client := a.registrationClient
	a.registrationMu.Unlock()

	if client == nil {
		a.finishTaskRegistration(coordinator, generation, "", &agentIdentityRegistrationError{
			code:    "client_unavailable",
			message: "Task registration client is unavailable.",
		})
		return
	}

	taskID, err := registerAgentIdentityTask(context.Background(), client, a.key())
	a.finishTaskRegistration(coordinator, generation, taskID, err)
}

func (a *AgentIdentity) finishTaskRegistration(coordinator *agentIdentityRegistrationCoordinator, generation uint64, taskID string, err error) {
	a.registrationMu.Lock()
	var persistRuntimeDeleted func(context.Context, string) error
	defer func() {
		a.registrationMu.Unlock()
		persistAgentIdentityRuntimeDeleted(persistRuntimeDeleted)
	}()
	if generation != a.registrationGeneration || a.registrationStatus.State != AgentIdentityRegistrationRegistering {
		return
	}

	if err == nil && taskID != "" {
		persist := a.persist
		if persist != nil {
			if errPersist := persist(context.Background(), taskID); errPersist != nil {
				if errors.Is(errPersist, ErrAgentIdentityCredentialsChanged) {
					a.setRegistrationFailedLocked(
						"credentials_changed",
						"Credentials changed while task registration was in progress.",
						false,
					)
					return
				}
				log.WithError(errPersist).Warn("failed to persist agent identity task; continuing with in-memory task")
			}
		}

		a.mu.Lock()
		a.taskID = taskID
		a.mu.Unlock()
		a.selectionAvailable.Store(true)
		a.setRegistrationReadyLocked()
		return
	}

	registrationErr := normalizeAgentIdentityRegistrationError(err)
	if registrationErr.code == "runtime_deleted" {
		persistRuntimeDeleted = a.setRegistrationRuntimeDeletedLocked()
		return
	}

	if registrationErr.retryable && coordinator != nil && a.registrationStatus.Attempts < coordinator.maxAttempts {
		delay := coordinator.backoff(a.registrationStatus.Attempts)
		nextRetry := time.Now().UTC().Add(delay)
		a.registrationStatus.State = AgentIdentityRegistrationRetryWait
		a.registrationStatus.NextRetryAt = &nextRetry
		a.registrationStatus.ErrorCode = registrationErr.code
		a.registrationStatus.Error = registrationErr.message
		a.registrationStatus.Active = true
		a.registrationStatus.CanRetry = false
		a.registrationRetryTimer = time.AfterFunc(delay, func() {
			a.enqueueScheduledTaskRegistration(coordinator, generation)
		})
		return
	}

	a.setRegistrationFailedLocked(registrationErr.code, registrationErr.message, true)
}

func persistAgentIdentityRuntimeDeleted(persist func(context.Context, string) error) {
	if persist == nil {
		return
	}
	if err := persist(context.Background(), ""); err != nil && !errors.Is(err, ErrAgentIdentityCredentialsChanged) {
		log.WithError(err).Warn("failed to persist deleted agent identity runtime state")
	}
}

func (a *AgentIdentity) enqueueScheduledTaskRegistration(coordinator *agentIdentityRegistrationCoordinator, generation uint64) {
	a.registrationMu.Lock()
	defer a.registrationMu.Unlock()
	if generation != a.registrationGeneration || a.registrationStatus.State != AgentIdentityRegistrationRetryWait {
		return
	}
	a.registrationRetryTimer = nil
	a.registrationStatus.State = AgentIdentityRegistrationQueued
	a.registrationStatus.NextRetryAt = nil
	a.registrationStatus.Active = true
	a.registrationEnqueued = true
	if coordinator == nil || !coordinator.enqueue(a, generation) {
		a.registrationEnqueued = false
		a.setRegistrationFailedLocked("queue_full", "Task registration queue is full.", true)
	}
}

func (a *AgentIdentity) setRegistrationReadyLocked() {
	now := time.Now().UTC()
	a.registrationStatus.State = AgentIdentityRegistrationReady
	a.registrationStatus.FinishedAt = &now
	a.registrationStatus.NextRetryAt = nil
	a.registrationStatus.ErrorCode = ""
	a.registrationStatus.Error = ""
	a.registrationStatus.Active = false
	a.registrationStatus.CanRetry = false
	a.registrationEnqueued = false
	a.selectionAvailable.Store(true)
}

func (a *AgentIdentity) setRegistrationFailedLocked(code, message string, canRetry bool) {
	now := time.Now().UTC()
	a.registrationStatus.State = AgentIdentityRegistrationFailed
	a.registrationStatus.FinishedAt = &now
	a.registrationStatus.NextRetryAt = nil
	a.registrationStatus.ErrorCode = code
	a.registrationStatus.Error = message
	a.registrationStatus.Active = false
	a.registrationStatus.CanRetry = canRetry
	a.selectionAvailable.Store(false)
}

func registrationStatusSnapshot(status AgentIdentityRegistrationStatus) AgentIdentityRegistrationStatus {
	copyStatus := status
	copyStatus.QueuedAt = cloneRegistrationTime(status.QueuedAt)
	copyStatus.StartedAt = cloneRegistrationTime(status.StartedAt)
	copyStatus.FinishedAt = cloneRegistrationTime(status.FinishedAt)
	copyStatus.NextRetryAt = cloneRegistrationTime(status.NextRetryAt)
	return copyStatus
}

func cloneRegistrationTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func normalizeAgentIdentityRegistrationError(err error) *agentIdentityRegistrationError {
	if err == nil {
		return &agentIdentityRegistrationError{
			code:    "empty_task",
			message: "Task registration returned an empty task.",
		}
	}
	var registrationErr *agentIdentityRegistrationError
	if errors.As(err, &registrationErr) && registrationErr != nil {
		return registrationErr
	}
	return &agentIdentityRegistrationError{
		code:    "registration_failed",
		message: "Task registration failed.",
		cause:   err,
	}
}
