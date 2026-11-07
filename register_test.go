package gqlgate

import (
	"context"
	"strings"
	"testing"

	"github.com/graphql-go/graphql"

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

func TestRegistryObjectFields(t *testing.T) {
	register.Reset()
	t.Cleanup(register.Reset)
	resolve := func(context.Context, register.ObjectFieldParams) (any, error) { return "x", nil }
	register.ObjectField(register.ObjectFieldDef{Table: "users", Name: "badge", Type: graphql.String, Resolve: resolve})
	if got := register.RegisteredObjectFields(); len(got) != 1 || got[0].Name != "badge" {
		t.Fatalf("registered = %+v", got)
	}
	// buildHooks merges registered fields with WithObjectFields ones and
	// validates them together.
	extra := ObjectField{Table: "posts", Name: "score", Type: graphql.Int, Resolve: resolve}
	if _, err := buildHooks(baseConfig(), extra); err != nil {
		t.Fatal(err)
	}
	dup := ObjectField{Table: "users", Name: "badge", Type: graphql.String, Resolve: resolve}
	if _, err := buildHooks(baseConfig(), dup); err == nil || !strings.Contains(err.Error(), "registered twice") {
		t.Errorf("a duplicate object field must fail, got %v", err)
	}
	register.Reset()
	if len(register.RegisteredObjectFields()) != 0 {
		t.Error("Reset must clear object fields")
	}
}
