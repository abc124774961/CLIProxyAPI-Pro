package synthesizer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

const agentIdentityRegistrationStateKey = "agent_identity_registration_state"

type agentIdentityRuntime struct {
	*codexauth.AgentIdentity
}

func (*agentIdentityRuntime) ShouldRefresh(time.Time, *coreauth.Auth) bool {
	return false
}

func attachAgentIdentityRuntime(auth *coreauth.Auth, path string, cfg *config.Config) error {
	if auth == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return nil
	}
	credentials, handled, err := codexauth.ParseAgentIdentityMetadata(auth.Metadata)
	if err != nil {
		return err
	}
	if !handled {
		return nil
	}
	runtime, err := codexauth.NewAgentIdentity(credentials)
	if err != nil {
		return err
	}
	runtimeDeleted := strings.EqualFold(
		strings.TrimSpace(metadataString(auth.Metadata, agentIdentityRegistrationStateKey)),
		codexauth.AgentIdentityRegistrationRuntimeDeleted,
	)
	if runtimeDeleted {
		runtime.MarkRuntimeDeleted()
	}
	runtime.SetTaskPersister(func(ctx context.Context, taskID string) error {
		return persistAgentIdentityTask(ctx, path, credentials.RuntimeID, credentials.PrivateKey, taskID)
	})
	runtime.SetRegistrationClient(newAgentIdentityRegistrationClient(cfg, auth))
	auth.Runtime = &agentIdentityRuntime{AgentIdentity: runtime}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes[coreauth.AttributeAuthKind] = coreauth.AuthKindOAuth
	if credentials.TaskID == "" && !runtimeDeleted {
		runtime.StartTaskRegistration()
	}
	return nil
}

func newAgentIdentityRegistrationClient(cfg *config.Config, auth *coreauth.Auth) *http.Client {
	proxyURL := ""
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}
	if proxyURL == "" {
		return &http.Client{}
	}
	transport, _, errBuild := proxyutil.BuildHTTPTransport(proxyURL)
	if errBuild != nil {
		log.WithError(errBuild).WithField("proxy", proxyutil.Redact(proxyURL)).Warn("failed to configure agent identity registration proxy")
		return &http.Client{}
	}
	return &http.Client{Transport: transport}
}

func persistAgentIdentityTask(ctx context.Context, path, runtimeID, privateKey, taskID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path = strings.TrimSpace(path)
	taskID = strings.TrimSpace(taskID)
	if path == "" {
		return errors.New("agent identity task persistence path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read agent identity auth file: %w", err)
	}
	metadata := make(map[string]any)
	if err := json.Unmarshal(data, &metadata); err != nil {
		return fmt.Errorf("parse agent identity auth file: %w", err)
	}
	credentials, handled, err := codexauth.ParseAgentIdentityMetadata(metadata)
	if err != nil || !handled ||
		credentials.RuntimeID != strings.TrimSpace(runtimeID) ||
		credentials.PrivateKey != strings.TrimSpace(privateKey) {
		return codexauth.ErrAgentIdentityCredentialsChanged
	}
	if taskID == "" {
		clearAgentIdentityTask(metadata)
		metadata[agentIdentityRegistrationStateKey] = codexauth.AgentIdentityRegistrationRuntimeDeleted
	} else {
		metadata["task_id"] = taskID
		delete(metadata, agentIdentityRegistrationStateKey)
	}
	updated, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize agent identity auth file: %w", err)
	}
	updated = append(updated, '\n')

	mode := os.FileMode(0o600)
	if info, errStat := os.Stat(path); errStat == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agent-task-*")
	if err != nil {
		return fmt.Errorf("create agent identity auth temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return fmt.Errorf("set agent identity auth temp mode: %w", err)
	}
	if _, err := tmp.Write(updated); err != nil {
		cleanup()
		return fmt.Errorf("write agent identity auth temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync agent identity auth temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close agent identity auth temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace agent identity auth file: %w", err)
	}
	return nil
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return value
}

func clearAgentIdentityTask(metadata map[string]any) {
	delete(metadata, "task_id")
	delete(metadata, "taskId")
	for _, key := range []string{"agent_identity", "agentIdentity"} {
		nested, ok := metadata[key].(map[string]any)
		if !ok {
			continue
		}
		delete(nested, "task_id")
		delete(nested, "taskId")
	}
}
