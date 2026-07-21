package synthesizer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type agentIdentityRuntime struct {
	*codexauth.AgentIdentity
}

func (*agentIdentityRuntime) ShouldRefresh(time.Time, *coreauth.Auth) bool {
	return false
}

func attachAgentIdentityRuntime(auth *coreauth.Auth, path string) error {
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
	runtime.SetTaskPersister(func(ctx context.Context, taskID string) error {
		return persistAgentIdentityTask(ctx, path, credentials.RuntimeID, taskID)
	})
	auth.Runtime = &agentIdentityRuntime{AgentIdentity: runtime}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes[coreauth.AttributeAuthKind] = coreauth.AuthKindOAuth
	return nil
}

func persistAgentIdentityTask(ctx context.Context, path, runtimeID, taskID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path = strings.TrimSpace(path)
	taskID = strings.TrimSpace(taskID)
	if path == "" || taskID == "" {
		return errors.New("agent identity task persistence path or task id is empty")
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
	if err != nil || !handled || credentials.RuntimeID != strings.TrimSpace(runtimeID) {
		return errors.New("agent identity auth file no longer matches runtime")
	}
	metadata["task_id"] = taskID
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
