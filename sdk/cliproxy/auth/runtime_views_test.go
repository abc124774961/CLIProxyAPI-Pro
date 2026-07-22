package auth

import (
	"context"
	"reflect"
	"testing"
)

func TestListRuntimeViewsReturnsOnlyRuntimeProjection(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	runtime := &struct{ name string }{name: "runtime"}
	_, err := manager.Register(context.Background(), &Auth{
		ID:       "agent.json",
		FileName: "agent.json",
		Provider: "codex",
		Runtime:  runtime,
		Metadata: map[string]any{"agent_private_key": "must-not-be-copied"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	views := manager.ListRuntimeViews()
	if len(views) != 1 {
		t.Fatalf("runtime views = %d, want 1", len(views))
	}
	if views[0].ID != "agent.json" || views[0].FileName != "agent.json" || views[0].Runtime != runtime {
		t.Fatalf("unexpected runtime view: %+v", views[0])
	}
	viewType := reflect.TypeOf(views[0])
	if viewType.NumField() != 3 {
		t.Fatalf("runtime view fields = %d, want only ID, FileName, Runtime", viewType.NumField())
	}
	if _, exists := viewType.FieldByName("Metadata"); exists {
		t.Fatal("runtime view must not expose or copy auth metadata")
	}
}
