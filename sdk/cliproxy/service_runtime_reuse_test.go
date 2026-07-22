package cliproxy

import "testing"

type reusableRuntimeStub struct {
	compatible bool
	starts     int
}

func (r *reusableRuntimeStub) CanReuseForAuthUpdate(any) bool {
	return r != nil && r.compatible
}

func (r *reusableRuntimeStub) StartBackgroundRecovery() {
	r.starts++
}

func TestReusableAuthRuntimeKeepsCompatibleLiveRuntime(t *testing.T) {
	existing := &reusableRuntimeStub{compatible: true}
	next := &reusableRuntimeStub{}
	if got := reusableAuthRuntime(existing, next); got != existing {
		t.Fatalf("runtime = %T %p, want existing %p", got, got, existing)
	}
	startAuthRuntimeRecovery(existing)
	if existing.starts != 1 {
		t.Fatalf("recovery starts = %d, want 1", existing.starts)
	}
}

func TestReusableAuthRuntimeHonorsIncompatibleReplacement(t *testing.T) {
	existing := &reusableRuntimeStub{compatible: false}
	next := &reusableRuntimeStub{}
	if got := reusableAuthRuntime(existing, next); got != next {
		t.Fatalf("runtime = %T %p, want replacement %p", got, got, next)
	}
}
