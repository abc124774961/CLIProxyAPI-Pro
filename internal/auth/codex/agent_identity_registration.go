package codex

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	AgentIdentityRegistrationReady              = "ready"
	AgentIdentityRegistrationCredentialsPending = "credentials_pending"
	AgentIdentityRegistrationQueued             = "queued"
	AgentIdentityRegistrationRegistering        = "registering"
	AgentIdentityRegistrationRetryWait          = "retry_wait"
	AgentIdentityRegistrationRuntimeDeleted     = "runtime_deleted"
	AgentIdentityRegistrationFailed             = "failed"
)

const (
	agentIdentityRegistrationWorkers     = 6
	agentIdentityRegistrationMaxWorkers  = 64
	agentIdentityRegistrationQueueSize   = 2048
	agentIdentityRegistrationMaxAttempts = 5
	agentIdentityRegistrationHistorySize = 2000
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
	Trigger     string     `json:"trigger,omitempty"`
	Active      bool       `json:"active"`
	CanRetry    bool       `json:"can_retry"`
}

// PendingAgentIdentity keeps an incomplete import visible to management while
// making it impossible for the generic selector to send traffic through it.
// Re-importing the same file with complete credentials replaces this runtime
// and automatically enters the normal task-registration flow.
type PendingAgentIdentity struct {
	status AgentIdentityRegistrationStatus
}

func NewPendingAgentIdentity() *PendingAgentIdentity {
	return &PendingAgentIdentity{status: AgentIdentityRegistrationStatus{
		State:     AgentIdentityRegistrationCredentialsPending,
		ErrorCode: "credentials_missing",
		Error:     "Agent Identity credentials are incomplete. Re-import a complete export to continue automatic recovery.",
		Active:    false,
		CanRetry:  false,
	}}
}

func (p *PendingAgentIdentity) RegistrationStatus() AgentIdentityRegistrationStatus {
	if p == nil {
		return AgentIdentityRegistrationStatus{
			State:     AgentIdentityRegistrationCredentialsPending,
			ErrorCode: "credentials_missing",
		}
	}
	return registrationStatusSnapshot(p.status)
}

func (*PendingAgentIdentity) SetRegistrationClient(*http.Client) {}

func (p *PendingAgentIdentity) RetryTaskRegistration() (AgentIdentityRegistrationStatus, bool) {
	return p.RegistrationStatus(), false
}

func (p *PendingAgentIdentity) RebuildTaskRegistration() (AgentIdentityRegistrationStatus, bool) {
	return p.RegistrationStatus(), false
}

func (*PendingAgentIdentity) RuntimeSelectionAvailable() bool { return false }

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

	limitMu     sync.Mutex
	limitCond   *sync.Cond
	concurrency int
	inFlight    int
	waiting     int
	closed      bool

	historyMu       sync.RWMutex
	history         []AgentIdentityRecoveryHistoryEntry
	historyLimit    int
	historySequence uint64
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
		queue:        make(chan agentIdentityRegistrationJob, queueSize),
		stop:         make(chan struct{}),
		maxAttempts:  maxAttempts,
		baseBackoff:  baseBackoff,
		maxBackoff:   maxBackoff,
		concurrency:  workers,
		historyLimit: agentIdentityRegistrationHistorySize,
	}
	c.limitCond = sync.NewCond(&c.limitMu)
	for range agentIdentityRegistrationMaxWorkers {
		c.wg.Add(1)
		go c.worker()
	}
	return c
}

func (c *agentIdentityRegistrationCoordinator) close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.limitMu.Lock()
		c.closed = true
		c.limitCond.Broadcast()
		c.limitMu.Unlock()
		close(c.stop)
	})
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
			if job.identity == nil {
				continue
			}
			if !c.acquireRegistrationSlot() {
				return
			}
			job.identity.performTaskRegistration(c, job.generation)
			c.releaseRegistrationSlot()
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
	return a.queueTaskRegistration(nil, "", false, false, "missing_task")
}

// QueueTaskRegistration invalidates the rejected task and schedules one
// background registration. Concurrent calls collapse into the existing job.
func (a *AgentIdentity) QueueTaskRegistration(client *http.Client, staleTaskID string) (AgentIdentityRegistrationStatus, bool) {
	return a.queueTaskRegistration(client, staleTaskID, false, false, "upstream_invalid_task")
}

// RetryTaskRegistration manually retries a retryable failed registration.
func (a *AgentIdentity) RetryTaskRegistration() (AgentIdentityRegistrationStatus, bool) {
	return a.queueTaskRegistration(nil, "", true, false, "manual_retry")
}

// RebuildTaskRegistration invalidates the current task and attempts to register
// a fresh task. It may recheck a previously deleted runtime, which is useful
// after credentials are replaced or an upstream deletion classification was stale.
func (a *AgentIdentity) RebuildTaskRegistration() (AgentIdentityRegistrationStatus, bool) {
	return a.queueTaskRegistration(nil, "", true, true, "manual_rebuild")
}

func (a *AgentIdentity) queueTaskRegistration(client *http.Client, staleTaskID string, manual, force bool, trigger string) (AgentIdentityRegistrationStatus, bool) {
	if a == nil {
		return AgentIdentityRegistrationStatus{State: AgentIdentityRegistrationFailed}, false
	}

	a.registrationMu.Lock()
	defer a.registrationMu.Unlock()
	if client != nil {
		a.registrationClient = client
	}
	if force && (a.registrationEnqueued || a.registrationStatus.State == AgentIdentityRegistrationRegistering || a.registrationStatus.State == AgentIdentityRegistrationRetryWait) {
		return registrationStatusSnapshot(a.registrationStatus), false
	}

	a.mu.Lock()
	currentTaskID := a.taskID
	if force {
		a.taskID = ""
		a.selectionAvailable.Store(false)
		currentTaskID = ""
	} else if staleTaskID != "" {
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
	if a.registrationStatus.State == AgentIdentityRegistrationRuntimeDeleted && !force {
		return registrationStatusSnapshot(a.registrationStatus), false
	}
	if manual && !force && a.registrationStatus.State == AgentIdentityRegistrationFailed && !a.registrationStatus.CanRetry {
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
	a.registrationStatus.Trigger = trigger
	a.registrationStatus.Active = true
	a.registrationStatus.CanRetry = false
	a.selectionAvailable.Store(false)
	a.registrationEnqueued = true
	a.registrationGeneration++
	a.beginRegistrationWaitLocked()
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

func (a *AgentIdentity) waitForTaskRegistration(ctx context.Context) error {
	if a == nil {
		return errors.New("agent identity is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		a.registrationMu.Lock()
		status := registrationStatusSnapshot(a.registrationStatus)
		done := a.registrationDone
		a.registrationMu.Unlock()

		switch status.State {
		case AgentIdentityRegistrationReady:
			if a.key().taskID == "" {
				return errors.New("agent identity recovery completed without a task")
			}
			return nil
		case AgentIdentityRegistrationRuntimeDeleted:
			return ErrAgentIdentityRuntimeDeleted
		case AgentIdentityRegistrationCredentialsPending:
			return ErrAgentIdentityCredentialsMissing
		case AgentIdentityRegistrationFailed:
			return registrationStatusError(status)
		}
		if done == nil {
			return ErrAgentIdentityRegistrationPending
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
}

func registrationStatusError(status AgentIdentityRegistrationStatus) error {
	message := strings.TrimSpace(status.Error)
	if message == "" {
		message = "Task registration failed."
	}
	code := strings.TrimSpace(status.ErrorCode)
	if code == "" {
		code = "registration_failed"
	}
	return &agentIdentityRegistrationError{
		code:      code,
		message:   message,
		retryable: status.CanRetry,
	}
}

func (a *AgentIdentity) beginRegistrationWaitLocked() {
	if a.registrationDone != nil {
		close(a.registrationDone)
	}
	a.registrationDone = make(chan struct{})
}

func (a *AgentIdentity) finishRegistrationWaitLocked() {
	if a.registrationDone == nil {
		return
	}
	close(a.registrationDone)
	a.registrationDone = nil
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
	alreadyDeleted := a.registrationStatus.State == AgentIdentityRegistrationRuntimeDeleted
	persist := a.setRegistrationRuntimeDeletedLocked()
	status := registrationStatusSnapshot(a.registrationStatus)
	coordinator := a.registrationCoordinator
	a.registrationMu.Unlock()
	persistAgentIdentityRuntimeDeleted(persist)
	if !alreadyDeleted && coordinator != nil {
		coordinator.recordAttempt(a, status, time.Now().UTC())
	}
}

func (a *AgentIdentity) setRegistrationRuntimeDeletedLocked() func(context.Context, string, string) error {
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
	a.registrationStatus.Trigger = "upstream_runtime_deleted"
	a.registrationStatus.Active = false
	a.registrationStatus.CanRetry = false
	a.finishRegistrationWaitLocked()
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
	persist := a.persist
	a.registrationMu.Unlock()

	if client == nil {
		a.finishTaskRegistration(coordinator, generation, "", &agentIdentityRegistrationError{
			code:    "client_unavailable",
			message: "Task registration client is unavailable.",
		})
		return
	}
	if persist != nil {
		if errPersist := persist(context.Background(), "", AgentIdentityRegistrationQueued); errPersist != nil {
			a.finishTaskRegistration(coordinator, generation, "", errPersist)
			return
		}
	}

	taskID, err := registerAgentIdentityTask(context.Background(), client, a.key())
	a.finishTaskRegistration(coordinator, generation, taskID, err)
}

func (a *AgentIdentity) finishTaskRegistration(coordinator *agentIdentityRegistrationCoordinator, generation uint64, taskID string, err error) {
	a.registrationMu.Lock()
	var persistRuntimeDeleted func(context.Context, string, string) error
	var recordAttempt bool
	var recordStatus AgentIdentityRegistrationStatus
	var recordFinishedAt time.Time
	defer func() {
		if recordAttempt {
			recordStatus = registrationStatusSnapshot(a.registrationStatus)
			recordFinishedAt = time.Now().UTC()
		}
		a.registrationMu.Unlock()
		persistAgentIdentityRuntimeDeleted(persistRuntimeDeleted)
		if recordAttempt && coordinator != nil {
			coordinator.recordAttempt(a, recordStatus, recordFinishedAt)
		}
	}()
	if generation != a.registrationGeneration || a.registrationStatus.State != AgentIdentityRegistrationRegistering {
		return
	}
	recordAttempt = true

	if err == nil && taskID != "" {
		persist := a.persist
		if persist != nil {
			if errPersist := persist(context.Background(), taskID, AgentIdentityRegistrationReady); errPersist != nil {
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
	if errors.Is(err, ErrAgentIdentityCredentialsChanged) {
		a.setRegistrationFailedLocked(
			"credentials_changed",
			"Credentials changed while task registration was in progress.",
			false,
		)
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

func persistAgentIdentityRuntimeDeleted(persist func(context.Context, string, string) error) {
	if persist == nil {
		return
	}
	if err := persist(context.Background(), "", AgentIdentityRegistrationRuntimeDeleted); err != nil && !errors.Is(err, ErrAgentIdentityCredentialsChanged) {
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
	a.finishRegistrationWaitLocked()
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
	a.finishRegistrationWaitLocked()
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
