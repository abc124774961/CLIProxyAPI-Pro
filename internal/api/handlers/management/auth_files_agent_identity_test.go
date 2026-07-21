package management

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
)

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
