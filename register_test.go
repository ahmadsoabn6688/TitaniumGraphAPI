package gqlgate

import (
	"context"
	"testing"

	"gqlgate/register"
)

func TestRegistryDuplicatePanics(t *testing.T) {
	register.Reset()
	t.Cleanup(register.Reset)
	register.MutationHook("dup", func(ctx context.Context, ev *MutationEvent) error { return nil })
	defer func() {
		if recover() == nil {
			t.Error("registering the same hook name twice must panic at init time")
		}
	}()
	register.MutationHook("dup", func(ctx context.Context, ev *MutationEvent) error { return nil })
}

func TestRegistrySnapshotIsolated(t *testing.T) {
	register.Reset()
	t.Cleanup(register.Reset)
	register.MutationHook("a", func(ctx context.Context, ev *MutationEvent) error { return nil })
	hooks, _, _ := register.Registered()
	// Mutating the snapshot must not affect the registry.
	delete(hooks, "a")
	hooks2, _, _ := register.Registered()
	if _, ok := hooks2["a"]; !ok {
		t.Error("Registered() must return an isolated copy")
	}
}
