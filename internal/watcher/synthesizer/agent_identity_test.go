package synthesizer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func testAgentIdentityKey(t *testing.T) string {
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

func TestSynthesizeAgentIdentityAuthFile(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "codex-agent.json")
	metadata := map[string]any{
		"type":              "codex",
		"auth_mode":         "agentIdentity",
		"agent_runtime_id":  "runtime-test",
		"agent_private_key": testAgentIdentityKey(t),
		"task_id":           "task-test",
		"email":             "k12@example.com",
		"plan_type":         "k12",
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	ctx := &SynthesisContext{
		Config:      &config.Config{},
		AuthDir:     tempDir,
		Now:         time.Now(),
		IDGenerator: NewStableIDGenerator(),
	}
	auths := SynthesizeAuthFile(ctx, path, data)
	if len(auths) != 1 {
		t.Fatalf("auths = %d, want 1", len(auths))
	}
	if runtime, ok := auths[0].Runtime.(*agentIdentityRuntime); !ok || runtime.AgentIdentity == nil {
		t.Fatalf("runtime type = %T, want agent identity runtime", auths[0].Runtime)
	}
	if auths[0].AuthKind() != "oauth" {
		t.Fatalf("auth kind = %q, want oauth", auths[0].AuthKind())
	}
	if _, exists := auths[0].Metadata["access_token"]; exists {
		t.Fatal("agent identity auth unexpectedly has access_token")
	}
}

func TestPersistAgentIdentityTask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex-agent.json")
	metadata := map[string]any{
		"type":              "codex",
		"auth_mode":         "agentIdentity",
		"agent_runtime_id":  "runtime-persist",
		"agent_private_key": testAgentIdentityKey(t),
		"task_id":           "task-old",
	}
	data, _ := json.Marshal(metadata)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := persistAgentIdentityTask(context.Background(), path, "runtime-persist", "task-new"); err != nil {
		t.Fatalf("persistAgentIdentityTask: %v", err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(updated, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got["task_id"] != "task-new" {
		t.Fatalf("task_id = %v, want task-new", got["task_id"])
	}
}

func TestSynthesizeRejectsMalformedAgentIdentityKey(t *testing.T) {
	data := []byte(`{"type":"codex","auth_mode":"agentIdentity","agent_runtime_id":"runtime-bad","agent_private_key":"bad"}`)
	ctx := &SynthesisContext{Config: &config.Config{}, AuthDir: t.TempDir(), Now: time.Now()}
	if auths := SynthesizeAuthFile(ctx, filepath.Join(ctx.AuthDir, "bad.json"), data); len(auths) != 0 {
		t.Fatalf("auths = %d, want 0", len(auths))
	}
}
