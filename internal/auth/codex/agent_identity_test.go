package codex

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

func newTestAgentIdentity(t *testing.T, runtimeID, taskID string) (*AgentIdentity, ed25519.PublicKey, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(der)
	runtime, err := NewAgentIdentity(AgentIdentityCredentials{
		RuntimeID:  runtimeID,
		PrivateKey: encoded,
		TaskID:     taskID,
	})
	if err != nil {
		t.Fatalf("NewAgentIdentity: %v", err)
	}
	return runtime, publicKey, encoded
}

func TestAgentIdentityAssertionSignature(t *testing.T) {
	runtime, publicKey, _ := newTestAgentIdentity(t, "runtime-test", "task-test")
	now := time.Date(2026, 7, 21, 3, 4, 5, 0, time.UTC)
	assertion, err := buildAgentAssertion(runtime.key(), now)
	if err != nil {
		t.Fatalf("buildAgentAssertion: %v", err)
	}
	if !strings.HasPrefix(assertion, "AgentAssertion ") {
		t.Fatalf("assertion scheme = %q", strings.SplitN(assertion, " ", 2)[0])
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(assertion, "AgentAssertion "))
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	var envelope map[string]string
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope["signature"])
	if err != nil {
		t.Fatalf("signature DecodeString: %v", err)
	}
	payload := envelope["agent_runtime_id"] + ":" + envelope["task_id"] + ":" + envelope["timestamp"]
	if !ed25519.Verify(publicKey, []byte(payload), signature) {
		t.Fatal("agent assertion signature did not verify")
	}
}

func TestAgentIdentityTaskRegistrationPlainAndEncrypted(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%v", encrypted), func(t *testing.T) {
			runtime, _, _ := newTestAgentIdentity(t, "runtime-register", "")
			key := runtime.key()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/agent/runtime-register/task/register" {
					t.Errorf("path = %q", r.URL.Path)
				}
				if !encrypted {
					_, _ = w.Write([]byte(`{"task_id":"task-plain"}`))
					return
				}
				digest := sha512.Sum512(key.privateKey.Seed())
				var curvePrivate [32]byte
				copy(curvePrivate[:], digest[:32])
				curvePrivate[0] &= 248
				curvePrivate[31] &= 127
				curvePrivate[31] |= 64
				publicBytes, deriveErr := curve25519.X25519(curvePrivate[:], curve25519.Basepoint)
				if deriveErr != nil {
					t.Errorf("X25519: %v", deriveErr)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				var curvePublic [32]byte
				copy(curvePublic[:], publicBytes)
				ciphertext, sealErr := box.SealAnonymous(nil, []byte("task-encrypted"), &curvePublic, rand.Reader)
				if sealErr != nil {
					t.Errorf("SealAnonymous: %v", sealErr)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"encrypted_task_id": base64.StdEncoding.EncodeToString(ciphertext)})
			}))
			defer server.Close()

			previousBaseURL := agentIdentityAuthAPIBaseURLForTest
			agentIdentityAuthAPIBaseURLForTest = server.URL
			defer func() { agentIdentityAuthAPIBaseURLForTest = previousBaseURL }()
			got, err := registerAgentIdentityTask(context.Background(), server.Client(), key)
			if err != nil {
				t.Fatalf("registerAgentIdentityTask: %v", err)
			}
			want := "task-plain"
			if encrypted {
				want = "task-encrypted"
			}
			if got != want {
				t.Fatalf("task ID = %q, want %q", got, want)
			}
		})
	}
}

func TestAgentIdentityConcurrentRegistrationIsSingleFlight(t *testing.T) {
	runtime, _, _ := newTestAgentIdentity(t, "runtime-concurrent", "")
	coordinator := newAgentIdentityRegistrationCoordinator(2, 32, 3, time.Millisecond, 5*time.Millisecond)
	defer coordinator.close()
	runtime.registrationCoordinator = coordinator
	var registrations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		registrations.Add(1)
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write([]byte(`{"task_id":"task-shared"}`))
	}))
	defer server.Close()
	previousBaseURL := agentIdentityAuthAPIBaseURLForTest
	agentIdentityAuthAPIBaseURLForTest = server.URL
	defer func() { agentIdentityAuthAPIBaseURLForTest = previousBaseURL }()

	var taskPersisted atomic.Int32
	var queuedPersisted atomic.Int32
	runtime.SetTaskPersister(func(_ context.Context, taskID, state string) error {
		if taskID != "" && state == AgentIdentityRegistrationReady {
			taskPersisted.Add(1)
		} else if taskID == "" && state == AgentIdentityRegistrationQueued {
			queuedPersisted.Add(1)
		}
		return nil
	})
	runtime.SetRegistrationClient(server.Client())
	var wg sync.WaitGroup
	statuses := make(chan AgentIdentityRegistrationStatus, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, _ := runtime.StartTaskRegistration()
			statuses <- status
		}()
	}
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status.State != AgentIdentityRegistrationQueued && status.State != AgentIdentityRegistrationRegistering {
			t.Fatalf("registration state = %q", status.State)
		}
	}
	waitForAgentIdentityRegistrationState(t, runtime, AgentIdentityRegistrationReady)
	if got := registrations.Load(); got != 1 {
		t.Fatalf("registrations = %d, want 1", got)
	}
	if got := taskPersisted.Load(); got != 1 {
		t.Fatalf("task persistence calls = %d, want 1", got)
	}
	if got := queuedPersisted.Load(); got != 1 {
		t.Fatalf("queued persistence calls = %d, want 1", got)
	}
	if _, taskID, err := runtime.Authorization(context.Background(), server.Client()); err != nil || taskID != "task-shared" {
		t.Fatalf("Authorization after registration task=%q err=%v", taskID, err)
	}
}

func TestAgentIdentityConcurrentRecoveryWaitsForSharedRegistration(t *testing.T) {
	runtime, _, _ := newTestAgentIdentity(t, "runtime-concurrent-recovery", "task-stale")
	coordinator := newAgentIdentityRegistrationCoordinator(1, 32, 1, time.Millisecond, time.Millisecond)
	defer coordinator.close()
	runtime.registrationCoordinator = coordinator

	var registrations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		registrations.Add(1)
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write([]byte(`{"task_id":"task-recovered"}`))
	}))
	defer server.Close()
	previousBaseURL := agentIdentityAuthAPIBaseURLForTest
	agentIdentityAuthAPIBaseURLForTest = server.URL
	defer func() { agentIdentityAuthAPIBaseURLForTest = previousBaseURL }()

	const callers = 20
	start := make(chan struct{})
	errorsFound := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			assertion, errRecover := runtime.RecoverAuthorization(context.Background(), server.Client(), "task-stale")
			if errRecover == nil && !strings.HasPrefix(assertion, "AgentAssertion ") {
				errRecover = fmt.Errorf("unexpected assertion scheme")
			}
			errorsFound <- errRecover
		}()
	}
	close(start)
	wg.Wait()
	close(errorsFound)
	for errRecover := range errorsFound {
		if errRecover != nil {
			t.Fatalf("RecoverAuthorization: %v", errRecover)
		}
	}
	if got := registrations.Load(); got != 1 {
		t.Fatalf("registrations = %d, want 1", got)
	}
	if taskID := runtime.key().taskID; taskID != "task-recovered" {
		t.Fatalf("recovered task = %q", taskID)
	}
}

func TestAgentIdentityAuthorizationCancellationDoesNotCancelSharedRecovery(t *testing.T) {
	runtime, _, _ := newTestAgentIdentity(t, "runtime-cancelled-waiter", "")
	coordinator := newAgentIdentityRegistrationCoordinator(1, 8, 1, time.Millisecond, time.Millisecond)
	defer coordinator.close()
	runtime.registrationCoordinator = coordinator

	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(requestStarted)
		<-releaseResponse
		_, _ = w.Write([]byte(`{"task_id":"task-after-cancel"}`))
	}))
	defer server.Close()
	previousBaseURL := agentIdentityAuthAPIBaseURLForTest
	agentIdentityAuthAPIBaseURLForTest = server.URL
	defer func() { agentIdentityAuthAPIBaseURLForTest = previousBaseURL }()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, _, errAuthorization := runtime.Authorization(ctx, server.Client())
		result <- errAuthorization
	}()
	<-requestStarted
	if errAuthorization := <-result; !errors.Is(errAuthorization, context.DeadlineExceeded) {
		close(releaseResponse)
		t.Fatalf("Authorization error = %v, want deadline exceeded", errAuthorization)
	}
	close(releaseResponse)
	waitForAgentIdentityRegistrationState(t, runtime, AgentIdentityRegistrationReady)
	if taskID := runtime.key().taskID; taskID != "task-after-cancel" {
		t.Fatalf("recovered task = %q", taskID)
	}
}

func TestAgentIdentityRecoveryFailureDoesNotReturnAssertion(t *testing.T) {
	runtime, _, _ := newTestAgentIdentity(t, "runtime-recovery-failure", "task-stale")
	coordinator := newAgentIdentityRegistrationCoordinator(1, 8, 1, time.Millisecond, time.Millisecond)
	defer coordinator.close()
	runtime.registrationCoordinator = coordinator

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"registration_rejected"}}`))
	}))
	defer server.Close()
	previousBaseURL := agentIdentityAuthAPIBaseURLForTest
	agentIdentityAuthAPIBaseURLForTest = server.URL
	defer func() { agentIdentityAuthAPIBaseURLForTest = previousBaseURL }()

	assertion, errRecover := runtime.RecoverAuthorization(context.Background(), server.Client(), "task-stale")
	if errRecover == nil || assertion != "" {
		t.Fatalf("assertion=%q error=%v, want failed recovery without assertion", assertion, errRecover)
	}
	status := runtime.RegistrationStatus()
	if status.State != AgentIdentityRegistrationFailed || status.Attempts != 1 {
		t.Fatalf("registration status = %+v", status)
	}
}

func TestAgentIdentityRegistrationRetriesTransientFailure(t *testing.T) {
	runtime, _, _ := newTestAgentIdentity(t, "runtime-retry", "")
	coordinator := newAgentIdentityRegistrationCoordinator(1, 8, 3, time.Millisecond, 2*time.Millisecond)
	defer coordinator.close()
	runtime.registrationCoordinator = coordinator

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"temporarily unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"task_id":"task-recovered"}`))
	}))
	defer server.Close()
	previousBaseURL := agentIdentityAuthAPIBaseURLForTest
	agentIdentityAuthAPIBaseURLForTest = server.URL
	defer func() { agentIdentityAuthAPIBaseURLForTest = previousBaseURL }()
	runtime.SetRegistrationClient(server.Client())

	if _, queued := runtime.StartTaskRegistration(); !queued {
		t.Fatal("missing task was not queued")
	}
	status := waitForAgentIdentityRegistrationState(t, runtime, AgentIdentityRegistrationReady)
	if status.Attempts != 2 || attempts.Load() != 2 {
		t.Fatalf("status attempts=%d HTTP attempts=%d, want 2", status.Attempts, attempts.Load())
	}
}

func TestAgentIdentityRegistrationStopsWhenRuntimeDeleted(t *testing.T) {
	runtime, _, _ := newTestAgentIdentity(t, "runtime-deleted", "")
	coordinator := newAgentIdentityRegistrationCoordinator(1, 8, 5, time.Millisecond, 2*time.Millisecond)
	defer coordinator.close()
	runtime.registrationCoordinator = coordinator

	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"biscuit_baker_service_agent_error_status","message":"Agent runtime has been deleted."}}`))
	}))
	defer server.Close()
	previousBaseURL := agentIdentityAuthAPIBaseURLForTest
	agentIdentityAuthAPIBaseURLForTest = server.URL
	defer func() { agentIdentityAuthAPIBaseURLForTest = previousBaseURL }()
	runtime.SetRegistrationClient(server.Client())

	if _, queued := runtime.StartTaskRegistration(); !queued {
		t.Fatal("missing task was not queued")
	}
	status := waitForAgentIdentityRegistrationState(t, runtime, AgentIdentityRegistrationRuntimeDeleted)
	if attempts.Load() != 1 || status.CanRetry || status.Active {
		t.Fatalf("attempts=%d status=%+v", attempts.Load(), status)
	}
	if _, queued := runtime.RetryTaskRegistration(); queued {
		t.Fatal("deleted runtime must not be manually requeued")
	}
}

func TestAgentIdentityRuntimeDeletedWinsOverInFlightRegistration(t *testing.T) {
	runtime, _, _ := newTestAgentIdentity(t, "runtime-deleted-in-flight", "")
	coordinator := newAgentIdentityRegistrationCoordinator(1, 8, 3, time.Millisecond, 2*time.Millisecond)
	runtime.registrationCoordinator = coordinator

	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(requestStarted)
		<-releaseResponse
		_, _ = w.Write([]byte(`{"task_id":"task-must-be-discarded"}`))
	}))
	defer server.Close()
	previousBaseURL := agentIdentityAuthAPIBaseURLForTest
	agentIdentityAuthAPIBaseURLForTest = server.URL
	defer func() { agentIdentityAuthAPIBaseURLForTest = previousBaseURL }()
	runtime.SetRegistrationClient(server.Client())

	var stalePersisted atomic.Int32
	var terminalPersisted atomic.Int32
	runtime.SetTaskPersister(func(_ context.Context, taskID, state string) error {
		if taskID == "" && state == AgentIdentityRegistrationRuntimeDeleted {
			terminalPersisted.Add(1)
		} else if taskID != "" {
			stalePersisted.Add(1)
		}
		return nil
	})
	if _, queued := runtime.StartTaskRegistration(); !queued {
		t.Fatal("missing task was not queued")
	}
	<-requestStarted
	runtime.MarkRuntimeDeleted()
	close(releaseResponse)
	coordinator.close()

	status := runtime.RegistrationStatus()
	if status.State != AgentIdentityRegistrationRuntimeDeleted {
		t.Fatalf("registration state = %q, want runtime_deleted", status.State)
	}
	if runtime.RuntimeSelectionAvailable() {
		t.Fatal("deleted runtime became selectable after stale registration completed")
	}
	if got := stalePersisted.Load(); got != 0 {
		t.Fatalf("stale persistence calls = %d, want 0", got)
	}
	if got := terminalPersisted.Load(); got != 1 {
		t.Fatalf("terminal persistence calls = %d, want 1", got)
	}
}

func TestAgentIdentityRegistrationFailsClosedWhenCredentialsChange(t *testing.T) {
	runtime, _, _ := newTestAgentIdentity(t, "runtime-credentials-changed", "")
	coordinator := newAgentIdentityRegistrationCoordinator(1, 8, 3, time.Millisecond, 2*time.Millisecond)
	defer coordinator.close()
	runtime.registrationCoordinator = coordinator

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"task_id":"task-stale"}`))
	}))
	defer server.Close()
	previousBaseURL := agentIdentityAuthAPIBaseURLForTest
	agentIdentityAuthAPIBaseURLForTest = server.URL
	defer func() { agentIdentityAuthAPIBaseURLForTest = previousBaseURL }()
	runtime.SetRegistrationClient(server.Client())
	runtime.SetTaskPersister(func(context.Context, string, string) error {
		return ErrAgentIdentityCredentialsChanged
	})

	if _, queued := runtime.StartTaskRegistration(); !queued {
		t.Fatal("missing task was not queued")
	}
	status := waitForAgentIdentityRegistrationState(t, runtime, AgentIdentityRegistrationFailed)
	if status.ErrorCode != "credentials_changed" || status.CanRetry {
		t.Fatalf("registration status = %+v", status)
	}
	if runtime.RuntimeSelectionAvailable() {
		t.Fatal("runtime became selectable after credentials changed")
	}
	if retryStatus, queued := runtime.RetryTaskRegistration(); queued || retryStatus.ErrorCode != "credentials_changed" {
		t.Fatalf("non-retryable registration queued=%v status=%+v", queued, retryStatus)
	}
}

func TestClassifyAgentIdentityRegistrationResponseRetriesRequestTimeout(t *testing.T) {
	err := normalizeAgentIdentityRegistrationError(classifyAgentIdentityRegistrationResponse(http.StatusRequestTimeout, nil))
	if !err.retryable || err.code != "http_408" {
		t.Fatalf("classification = %+v, want retryable http_408", err)
	}
}

func waitForAgentIdentityRegistrationState(t *testing.T, runtime *AgentIdentity, want string) AgentIdentityRegistrationStatus {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := runtime.RegistrationStatus()
		if status.State == want {
			return status
		}
		time.Sleep(time.Millisecond)
	}
	status := runtime.RegistrationStatus()
	t.Fatalf("registration state = %q, want %q", status.State, want)
	return status
}

func TestParseAgentIdentityMetadataVariants(t *testing.T) {
	_, _, encoded := newTestAgentIdentity(t, "unused", "unused")
	for name, metadata := range map[string]map[string]any{
		"flat": {
			"auth_mode":         "agentIdentity",
			"agent_runtime_id":  "runtime-flat",
			"agent_private_key": encoded,
			"task_id":           "task-flat",
		},
		"nested camel": {
			"authMode": "agentIdentity",
			"agentIdentity": map[string]any{
				"agentRuntimeId":  "runtime-nested",
				"agentPrivateKey": encoded,
				"taskId":          "task-nested",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			credentials, handled, err := ParseAgentIdentityMetadata(metadata)
			if err != nil || !handled {
				t.Fatalf("ParseAgentIdentityMetadata() handled=%v err=%v", handled, err)
			}
			if credentials.RuntimeID == "" || credentials.PrivateKey != encoded || credentials.TaskID == "" {
				t.Fatalf("unexpected credentials fields")
			}
		})
	}
}

func TestParseAgentIdentityMetadataMarksMissingCredentialsRecoverable(t *testing.T) {
	credentials, handled, err := ParseAgentIdentityMetadata(map[string]any{
		"auth_mode":  "agentIdentity",
		"account_id": "account-placeholder",
		"email":      "pending@example.com",
	})
	if !handled || !errors.Is(err, ErrAgentIdentityCredentialsMissing) {
		t.Fatalf("ParseAgentIdentityMetadata() handled=%v err=%v", handled, err)
	}
	if credentials.RuntimeID != "" || credentials.PrivateKey != "" {
		t.Fatalf("unexpected synthesized credentials: %+v", credentials)
	}
}

func TestAgentIdentitySensitiveBodyIsRedacted(t *testing.T) {
	runtime, _, encoded := newTestAgentIdentity(t, "runtime-secret", "task-secret")
	body := []byte("runtime-secret task-secret " + encoded + " AgentAssertion abc.def")
	redacted := string(runtime.RedactSensitiveBody(body))
	for _, secret := range []string{"runtime-secret", "task-secret", encoded, "abc.def"} {
		if strings.Contains(redacted, secret) {
			t.Fatalf("redacted body still contains sensitive value")
		}
	}
}

func TestIsAgentIdentityTaskInvalidResponseIsNarrow(t *testing.T) {
	if !IsAgentIdentityTaskInvalidResponse(http.StatusUnauthorized, []byte(`{"error":{"code":"task_expired"}}`)) {
		t.Fatal("task_expired should trigger task recovery")
	}
	if IsAgentIdentityTaskInvalidResponse(http.StatusUnauthorized, []byte(`{"error":{"code":"invalid_api_key"}}`)) {
		t.Fatal("unrelated 401 should not trigger task recovery")
	}
}

func TestIsAgentIdentityRuntimeDeletedResponseIsNarrow(t *testing.T) {
	if !IsAgentIdentityRuntimeDeletedResponse(http.StatusBadRequest, []byte(`{"error":{"message":"Agent runtime has been deleted."}}`)) {
		t.Fatal("deleted runtime message should be terminal")
	}
	if IsAgentIdentityRuntimeDeletedResponse(http.StatusServiceUnavailable, []byte(`{"error":{"code":"biscuit_baker_service_agent_error_status","message":"temporary service failure"}}`)) {
		t.Fatal("generic agent service status must not be classified as a deleted runtime")
	}
}
