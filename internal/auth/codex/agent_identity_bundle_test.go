package codex

import (
	"encoding/json"
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

func TestParseAgentIdentityBundleIgnoresSub2OAuthBundle(t *testing.T) {
	payload := []byte(`{"accounts":[{"type":"oauth","platform":"openai","credentials":{"access_token":"access","refresh_token":"refresh"}}]}`)
	files, handled, err := ParseAgentIdentityBundle(payload)
	if err != nil || handled || len(files) != 0 {
		t.Fatalf("files=%d handled=%v err=%v", len(files), handled, err)
	}
}
