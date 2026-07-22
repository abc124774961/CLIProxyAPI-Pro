package codex

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAgentIdentityRecoveryCoordinatorConcurrencyCanIncrease(t *testing.T) {
	coordinator := newAgentIdentityRegistrationCoordinator(1, 8, 2, time.Millisecond, time.Millisecond)
	defer coordinator.close()

	if !coordinator.acquireRegistrationSlot() {
		t.Fatal("failed to acquire initial registration slot")
	}
	acquired := make(chan bool, 1)
	go func() {
		acquired <- coordinator.acquireRegistrationSlot()
	}()

	select {
	case <-acquired:
		t.Fatal("second slot bypassed configured concurrency")
	case <-time.After(20 * time.Millisecond):
	}

	coordinator.setConcurrency(2)
	select {
	case ok := <-acquired:
		if !ok {
			t.Fatal("coordinator closed while increasing concurrency")
		}
	case <-time.After(time.Second):
		t.Fatal("increasing concurrency did not release a waiting registration")
	}

	stats := coordinator.stats()
	if stats.Concurrency != 2 || stats.Active != 2 {
		t.Fatalf("coordinator stats = %+v, want concurrency=2 active=2", stats)
	}
	coordinator.releaseRegistrationSlot()
	coordinator.releaseRegistrationSlot()
}

func TestAgentIdentityRecoveryHistoryIsBoundedAndNewestFirst(t *testing.T) {
	coordinator := newAgentIdentityRegistrationCoordinator(1, 8, 2, time.Millisecond, time.Millisecond)
	defer coordinator.close()
	coordinator.setHistoryLimit(2)

	runtime, _, _ := newTestAgentIdentity(t, "runtime-history", "task-history")
	runtime.SetRegistrationName("agent-history.json")
	for attempt := 1; attempt <= 3; attempt++ {
		started := time.Now().UTC().Add(-time.Duration(attempt) * time.Millisecond)
		coordinator.recordAttempt(runtime, AgentIdentityRegistrationStatus{
			State:     AgentIdentityRegistrationFailed,
			Trigger:   "manual_retry",
			Attempts:  attempt,
			StartedAt: &started,
			ErrorCode: "test_failure",
		}, time.Now().UTC())
	}

	history := coordinator.historySnapshot(10)
	if len(history) != 2 {
		t.Fatalf("history length = %d, want 2", len(history))
	}
	if history[0].Attempt != 3 || history[1].Attempt != 2 || history[0].ID <= history[1].ID {
		t.Fatalf("history order = %+v", history)
	}
	if history[0].Name != "agent-history.json" {
		t.Fatalf("history name = %q", history[0].Name)
	}
}

func TestAgentIdentityRebuildRechecksDeletedRuntime(t *testing.T) {
	runtime, _, _ := newTestAgentIdentity(t, "runtime-rebuild", "task-old")
	coordinator := newAgentIdentityRegistrationCoordinator(1, 8, 2, time.Millisecond, time.Millisecond)
	defer coordinator.close()
	runtime.registrationCoordinator = coordinator
	runtime.MarkRuntimeDeleted()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"task_id":"task-rebuilt"}`))
	}))
	defer server.Close()
	previousBaseURL := agentIdentityAuthAPIBaseURLForTest
	agentIdentityAuthAPIBaseURLForTest = server.URL
	defer func() { agentIdentityAuthAPIBaseURLForTest = previousBaseURL }()
	runtime.SetRegistrationClient(server.Client())

	status, queued := runtime.RebuildTaskRegistration()
	if !queued || status.Trigger != "manual_rebuild" {
		t.Fatalf("rebuild queued=%v status=%+v", queued, status)
	}
	status = waitForAgentIdentityRegistrationState(t, runtime, AgentIdentityRegistrationReady)
	if status.Trigger != "manual_rebuild" || !runtime.RuntimeSelectionAvailable() {
		t.Fatalf("rebuilt status=%+v available=%v", status, runtime.RuntimeSelectionAvailable())
	}
}

func TestAgentIdentityRuntimeMatchIncludesTask(t *testing.T) {
	left, _, encoded := newTestAgentIdentity(t, "runtime-match", "task-one")
	right, err := NewAgentIdentity(AgentIdentityCredentials{
		RuntimeID:  "runtime-match",
		PrivateKey: encoded,
		TaskID:     "task-one",
	})
	if err != nil {
		t.Fatalf("NewAgentIdentity: %v", err)
	}
	if !left.MatchesRuntime(right) {
		t.Fatal("identical runtimes did not match")
	}
	right.mu.Lock()
	right.taskID = "task-two"
	right.mu.Unlock()
	if left.MatchesRuntime(right) {
		t.Fatal("runtime with externally replaced task unexpectedly matched")
	}
}
