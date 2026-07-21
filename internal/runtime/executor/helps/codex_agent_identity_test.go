package helps

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type agentIdentityRoundTripFunc func(*http.Request) (*http.Response, error)

func (f agentIdentityRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func testAgentIdentityRuntime(t *testing.T, taskID string) *codexauth.AgentIdentity {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	runtime, err := codexauth.NewAgentIdentity(codexauth.AgentIdentityCredentials{
		RuntimeID:  "runtime-recovery",
		PrivateKey: base64.StdEncoding.EncodeToString(der),
		TaskID:     taskID,
	})
	if err != nil {
		t.Fatalf("NewAgentIdentity: %v", err)
	}
	return runtime
}

func TestDoCodexRequestWithAgentRecovery(t *testing.T) {
	runtime := testAgentIdentityRuntime(t, "task-stale")
	auth := &cliproxyauth.Auth{Runtime: runtime}
	var mu sync.Mutex
	var upstreamAuthorizations []string
	registrations := 0
	client := &http.Client{Transport: agentIdentityRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if req.URL.Host == "auth.openai.com" {
			registrations++
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"task_id":"task-new"}`)),
				Request:    req,
			}, nil
		}
		upstreamAuthorizations = append(upstreamAuthorizations, req.Header.Get("Authorization"))
		if len(upstreamAuthorizations) == 1 {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"task_expired"}}`)),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Request:    req,
		}, nil
	})}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://upstream.test/responses", strings.NewReader(`{"model":"gpt-test"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	authorization, staleTaskID, err := PrepareCodexAuthorization(context.Background(), auth, client, "")
	if err != nil {
		t.Fatalf("PrepareCodexAuthorization: %v", err)
	}
	req.Header.Set("Authorization", authorization)
	resp, err := DoCodexRequestWithAgentRecovery(context.Background(), auth, client, client, req, staleTaskID)
	if err != nil {
		t.Fatalf("DoCodexRequestWithAgentRecovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if registrations != 1 || len(upstreamAuthorizations) != 2 {
		t.Fatalf("registrations=%d upstream attempts=%d", registrations, len(upstreamAuthorizations))
	}
	if upstreamAuthorizations[0] == upstreamAuthorizations[1] {
		t.Fatal("retry should use a fresh assertion with the replacement task")
	}
	for _, value := range upstreamAuthorizations {
		if !strings.HasPrefix(value, "AgentAssertion ") {
			t.Fatalf("authorization scheme = %q", value)
		}
	}
}

func TestPrepareCodexAuthorizationKeepsBearerFlow(t *testing.T) {
	authorization, taskID, err := PrepareCodexAuthorization(context.Background(), &cliproxyauth.Auth{}, http.DefaultClient, "oauth-token")
	if err != nil || taskID != "" || authorization != "Bearer oauth-token" {
		t.Fatalf("authorization=%q task=%q err=%v", authorization, taskID, err)
	}
}
