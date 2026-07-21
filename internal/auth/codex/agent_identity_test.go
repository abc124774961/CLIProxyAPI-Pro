package codex

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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

	var persisted atomic.Int32
	runtime.SetTaskPersister(func(context.Context, string) error {
		persisted.Add(1)
		return nil
	})
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := runtime.Authorization(context.Background(), server.Client())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Authorization: %v", err)
		}
	}
	if got := registrations.Load(); got != 1 {
		t.Fatalf("registrations = %d, want 1", got)
	}
	if got := persisted.Load(); got != 1 {
		t.Fatalf("persistence calls = %d, want 1", got)
	}
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
