package codex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// AgentIdentityImportFile is one canonical CPA auth file expanded from a K12
// accounts bundle.
type AgentIdentityImportFile struct {
	FileName string
	Metadata map[string]any
}

type agentIdentityBundle struct {
	Accounts []agentIdentityBundleAccount `json:"accounts"`
}

type agentIdentityBundleAccount struct {
	Name        string         `json:"name"`
	Platform    string         `json:"platform"`
	Type        string         `json:"type"`
	Priority    any            `json:"priority"`
	Credentials map[string]any `json:"credentials"`
	Extra       map[string]any `json:"extra"`
}

// ParseAgentIdentityBundle recognizes Sub2 K12 accounts bundles and expands
// them into stable, single-account CPA auth documents.
func ParseAgentIdentityBundle(data []byte) ([]AgentIdentityImportFile, bool, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, false, err
	}
	_, exists := envelope["accounts"]
	if !exists {
		return nil, false, nil
	}

	var bundle agentIdentityBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, true, errors.New("invalid agent identity accounts bundle")
	}
	if len(bundle.Accounts) == 0 {
		return nil, false, nil
	}

	// Sub2 OAuth exports use the same top-level accounts envelope. Claim the
	// payload only when at least one account actually contains agent identity
	// fields, then require the complete bundle to use that format.
	agentIdentityBundle := false
	for index, account := range bundle.Accounts {
		_, handled, err := ParseAgentIdentityMetadata(account.Credentials)
		if err != nil {
			return nil, true, fmt.Errorf("account %d has invalid agent identity credentials: %w", index+1, err)
		}
		if handled {
			agentIdentityBundle = true
			break
		}
	}
	if !agentIdentityBundle {
		return nil, false, nil
	}

	files := make([]AgentIdentityImportFile, 0, len(bundle.Accounts))
	seenRuntimeIDs := make(map[string]struct{}, len(bundle.Accounts))
	for index, account := range bundle.Accounts {
		credentials, handled, err := ParseAgentIdentityMetadata(account.Credentials)
		if err != nil {
			return nil, true, fmt.Errorf("account %d has invalid agent identity credentials: %w", index+1, err)
		}
		if !handled {
			return nil, true, fmt.Errorf("account %d is not an agent identity account", index+1)
		}
		if _, duplicate := seenRuntimeIDs[credentials.RuntimeID]; duplicate {
			return nil, true, fmt.Errorf("account %d duplicates an agent runtime id", index+1)
		}
		seenRuntimeIDs[credentials.RuntimeID] = struct{}{}

		metadata := cloneMetadata(account.Credentials)
		metadata["type"] = "codex"
		metadata["auth_mode"] = AuthModeAgentIdentity
		metadata["agent_runtime_id"] = credentials.RuntimeID
		metadata["agent_private_key"] = credentials.PrivateKey
		if credentials.TaskID != "" {
			metadata["task_id"] = credentials.TaskID
		}
		if name := strings.TrimSpace(account.Name); name != "" {
			metadata["name"] = name
		}
		if email := firstNonEmpty(firstString(metadata, "email"), firstString(account.Extra, "email")); email != "" {
			metadata["email"] = email
		}
		if account.Priority != nil {
			metadata["priority"] = account.Priority
		}
		if proxyURL := firstNonEmpty(
			firstString(metadata, "proxy_url", "proxyUrl"),
			firstString(account.Extra, "proxy_url", "proxyUrl"),
		); proxyURL != "" {
			metadata["proxy_url"] = proxyURL
		}

		digest := sha256.Sum256([]byte(credentials.RuntimeID))
		files = append(files, AgentIdentityImportFile{
			FileName: "codex-agent-" + hex.EncodeToString(digest[:8]) + ".json",
			Metadata: metadata,
		})
	}
	return files, true, nil
}

func cloneMetadata(source map[string]any) map[string]any {
	out := make(map[string]any, len(source)+6)
	for key, value := range source {
		out[key] = value
	}
	return out
}
