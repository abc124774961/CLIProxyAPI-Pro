package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type managementTestAgentRegistrationRuntime struct {
	status  codexauth.AgentIdentityRegistrationStatus
	retries int
}

func (r *managementTestAgentRegistrationRuntime) SetRegistrationClient(*http.Client) {}

func (r *managementTestAgentRegistrationRuntime) RegistrationStatus() codexauth.AgentIdentityRegistrationStatus {
	return r.status
}

func (r *managementTestAgentRegistrationRuntime) RetryTaskRegistration() (codexauth.AgentIdentityRegistrationStatus, bool) {
	r.retries++
	r.status = codexauth.AgentIdentityRegistrationStatus{
		State:  codexauth.AgentIdentityRegistrationQueued,
		Active: true,
	}
	return r.status, true
}

func managementTestAgentIdentityKey(t *testing.T) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestWriteAuthFileExpandsAgentIdentityBundle(t *testing.T) {
	authDir := t.TempDir()
	key := managementTestAgentIdentityKey(t)
	payload, err := json.Marshal(map[string]any{
		"accounts": []map[string]any{
			{"name": "one", "credentials": map[string]any{
				"auth_mode": "agentIdentity", "agent_runtime_id": "runtime-one", "agent_private_key": key, "task_id": "task-one",
			}},
			{"name": "two", "credentials": map[string]any{
				"auth_mode": "agentIdentity", "agent_runtime_id": "runtime-two", "agent_private_key": key, "task_id": "task-two",
			}},
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	handler := &Handler{cfg: &config.Config{AuthDir: authDir}}
	if err := handler.writeAuthFile(context.Background(), "accounts-agentIdentity.json", payload); err != nil {
		t.Fatalf("writeAuthFile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(authDir, "accounts-agentIdentity.json")); !os.IsNotExist(err) {
		t.Fatalf("source bundle should not remain as an unknown auth file")
	}
	entries, err := os.ReadDir(authDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("auth files = %d, want 2", len(entries))
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "codex-agent-") {
			t.Fatalf("unexpected generated filename %q", entry.Name())
		}
		data, errRead := os.ReadFile(filepath.Join(authDir, entry.Name()))
		if errRead != nil {
			t.Fatalf("ReadFile: %v", errRead)
		}
		auths := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{
			Config:  handler.cfg,
			AuthDir: authDir,
		}, filepath.Join(authDir, entry.Name()), data)
		if len(auths) != 1 || auths[0].Runtime == nil {
			t.Fatalf("generated file %q is not a runnable auth", entry.Name())
		}
	}
}

func TestListAuthFilesIncludesAgentIdentityRegistration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authDir := t.TempDir()
	path := filepath.Join(authDir, "agent.json")
	if err := os.WriteFile(path, []byte(`{"type":"codex"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	runtime := &managementTestAgentRegistrationRuntime{status: codexauth.AgentIdentityRegistrationStatus{
		State:     codexauth.AgentIdentityRegistrationRuntimeDeleted,
		ErrorCode: "runtime_deleted",
		Error:     "Agent runtime has been deleted.",
	}}
	manager := coreauth.NewManager(nil, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "agent.json",
		FileName: "agent.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path": path,
		},
		Runtime: runtime,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)

	handler.ListAuthFiles(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"state":"runtime_deleted"`) ||
		strings.Contains(recorder.Body.String(), "runtime-secret") {
		t.Fatalf("unexpected response: %s", recorder.Body.String())
	}
}

func TestRegisterAgentIdentityTaskQueuesRetry(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runtime := &managementTestAgentRegistrationRuntime{status: codexauth.AgentIdentityRegistrationStatus{
		State:    codexauth.AgentIdentityRegistrationFailed,
		CanRetry: true,
	}}
	manager := coreauth.NewManager(nil, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "agent.json",
		FileName: "agent.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Runtime:  runtime,
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(
		http.MethodPost,
		"/v0/management/auth-files/agent-identity/register",
		bytes.NewBufferString(`{"name":"agent.json"}`),
	)
	ctx.Request.Header.Set("Content-Type", "application/json")

	handler.RegisterAgentIdentityTask(ctx)

	if recorder.Code != http.StatusAccepted || runtime.retries != 1 {
		t.Fatalf("status=%d retries=%d body=%s", recorder.Code, runtime.retries, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"state":"queued"`) {
		t.Fatalf("unexpected response: %s", recorder.Body.String())
	}
}

func TestListAgentIdentityRegistrationsReturnsLightweightProgress(t *testing.T) {
	gin.SetMode(gin.TestMode)
	runtime := &managementTestAgentRegistrationRuntime{status: codexauth.AgentIdentityRegistrationStatus{
		State:  codexauth.AgentIdentityRegistrationRegistering,
		Active: true,
	}}
	manager := coreauth.NewManager(nil, nil, nil)
	_, err := manager.Register(context.Background(), &coreauth.Auth{
		ID:       "agent.json",
		FileName: "agent.json",
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Runtime:  runtime,
		Metadata: map[string]any{"agent_private_key": "must-not-leak"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	handler := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/agent-identity/registrations", nil)

	handler.ListAgentIdentityRegistrations(ctx)

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"active":1`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "must-not-leak") {
		t.Fatalf("registration progress leaked auth metadata: %s", recorder.Body.String())
	}
}
