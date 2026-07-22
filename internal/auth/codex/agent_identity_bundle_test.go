package codex

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestParseAgentIdentityBundle(t *testing.T) {
	_, _, encoded := newTestAgentIdentity(t, "unused", "unused")
	payload, err := json.Marshal(map[string]any{
		"accounts": []map[string]any{
			{
				"name":     "k12-one",
				"platform": "openai",
				"priority": 2,
				"credentials": map[string]any{
					"auth_mode":         "agentIdentity",
					"agent_runtime_id":  "runtime-one",
					"agent_private_key": encoded,
					"task_id":           "task-one",
					"email":             "one@example.com",
					"plan_type":         "k12",
				},
			},
			{
				"name": "k12-two",
				"credentials": map[string]any{
					"authMode": "agentIdentity",
					"agentIdentity": map[string]any{
						"agentRuntimeId":  "runtime-two",
						"agentPrivateKey": encoded,
						"taskId":          "task-two",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	files, handled, err := ParseAgentIdentityBundle(payload)
	if err != nil || !handled {
		t.Fatalf("ParseAgentIdentityBundle() handled=%v err=%v", handled, err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %d, want 2", len(files))
	}
	if files[0].FileName == files[1].FileName {
		t.Fatal("stable filenames must differ across runtimes")
	}
	for _, file := range files {
		if file.Metadata["type"] != "codex" || file.Metadata["auth_mode"] != AuthModeAgentIdentity {
			t.Fatalf("canonical metadata is missing codex agent identity fields")
		}
		if _, ok := file.Metadata["access_token"]; ok {
			t.Fatal("agent identity import unexpectedly synthesized an access token")
		}
	}
}

func TestParseAgentIdentityBundleRejectsMalformedKey(t *testing.T) {
	payload := []byte(`{"accounts":[{"credentials":{"auth_mode":"agentIdentity","agent_runtime_id":"runtime-bad","agent_private_key":"not-a-key"}}]}`)
	files, handled, err := ParseAgentIdentityBundle(payload)
	if err == nil || !handled || len(files) != 0 {
		t.Fatalf("files=%d handled=%v err=%v", len(files), handled, err)
	}
}

func TestParseAgentIdentityBundleRemovesSyntheticIDToken(t *testing.T) {
	_, _, encoded := newTestAgentIdentity(t, "runtime-synthetic", "task-synthetic")
	header, err := json.Marshal(map[string]any{
		"alg":           "none",
		"typ":           "JWT",
		"cpa_synthetic": true,
	})
	if err != nil {
		t.Fatalf("Marshal header: %v", err)
	}
	payload, err := json.Marshal(map[string]any{"email": "synthetic@example.com"})
	if err != nil {
		t.Fatalf("Marshal payload: %v", err)
	}
	token := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".synthetic"
	bundle, err := json.Marshal(map[string]any{
		"accounts": []map[string]any{{
			"name": "synthetic",
			"credentials": map[string]any{
				"auth_mode":         "agentIdentity",
				"agent_runtime_id":  "runtime-synthetic",
				"agent_private_key": encoded,
				"task_id":           "task-synthetic",
				"id_token":          token,
			},
		}},
	})
	if err != nil {
		t.Fatalf("Marshal bundle: %v", err)
	}

	files, handled, err := ParseAgentIdentityBundle(bundle)
	if err != nil || !handled || len(files) != 1 {
		t.Fatalf("files=%d handled=%v err=%v", len(files), handled, err)
	}
	if _, exists := files[0].Metadata["id_token"]; exists {
		t.Fatal("synthetic id_token must not be persisted")
	}
	if files[0].Metadata["agent_runtime_id"] != "runtime-synthetic" ||
		files[0].Metadata["agent_private_key"] != encoded ||
		files[0].Metadata["task_id"] != "task-synthetic" {
		t.Fatal("agent identity credentials changed while sanitizing the bundle")
	}
}

func TestParseAgentIdentityBundleAcceptsPendingCredentials(t *testing.T) {
	payload := []byte(`{"accounts":[
		{"name":"pending-one@example.com","credentials":{"auth_mode":"agentIdentity","email":"pending-one@example.com"}},
		{"name":"pending-two@example.com","credentials":{"auth_mode":"agentIdentity","email":"pending-two@example.com"}}
	]}`)
	files, handled, err := ParseAgentIdentityBundle(payload)
	if err != nil || !handled || len(files) != 2 {
		t.Fatalf("files=%d handled=%v err=%v", len(files), handled, err)
	}
	if files[0].FileName == files[1].FileName {
		t.Fatal("pending imports must keep stable unique filenames")
	}
	for _, file := range files {
		if file.Metadata["agent_identity_registration_state"] != AgentIdentityRegistrationCredentialsPending {
			t.Fatalf("pending state = %v", file.Metadata["agent_identity_registration_state"])
		}
	}
}

func TestParseAgentIdentityBundleIgnoresSub2OAuthBundle(t *testing.T) {
	payload := []byte(`{"accounts":[{"type":"oauth","platform":"openai","credentials":{"access_token":"access","refresh_token":"refresh"}}]}`)
	files, handled, err := ParseAgentIdentityBundle(payload)
	if err != nil || handled || len(files) != 0 {
		t.Fatalf("files=%d handled=%v err=%v", len(files), handled, err)
	}
}

func TestParseAgentIdentityBundleKeepsSharedTeamMembersSeparate(t *testing.T) {
	_, _, encoded := newTestAgentIdentity(t, "unused", "unused")
	accounts := make([]map[string]any, 0, 499)
	for index := 0; index < 499; index++ {
		accounts = append(accounts, map[string]any{
			"name": fmt.Sprintf("member-%03d", index),
			"credentials": map[string]any{
				"auth_mode":          "agentIdentity",
				"account_id":         "shared-team",
				"chatgpt_account_id": "shared-team",
				"chatgpt_user_id":    fmt.Sprintf("user-%03d", index),
				"email":              fmt.Sprintf("member-%03d@example.com", index),
				"agent_runtime_id":   fmt.Sprintf("runtime-%03d", index),
				"agent_private_key":  encoded,
				"task_id":            fmt.Sprintf("task-%03d", index),
			},
		})
	}
	payload, err := json.Marshal(map[string]any{"accounts": accounts})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	files, handled, err := ParseAgentIdentityBundle(payload)
	if err != nil || !handled || len(files) != len(accounts) {
		t.Fatalf("files=%d handled=%v err=%v", len(files), handled, err)
	}
	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		if _, duplicate := seen[file.FileName]; duplicate {
			t.Fatalf("duplicate file name %q", file.FileName)
		}
		seen[file.FileName] = struct{}{}
	}
}
