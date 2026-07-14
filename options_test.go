package gqlgate

import (
	"context"
	"strings"
	"testing"

	"github.com/graphql-go/graphql"

	"gqlgate/config"
	"gqlgate/register"
)

func baseConfig() *config.Config {
	return &config.Config{
		Roles: map[string]*config.Role{
			"admin":  {},
			"author": {},
		},
	}
}

func TestReloadCompatible(t *testing.T) {
	mk := func() *config.Config {
		c := &config.Config{}
		c.Database = config.Database{Host: "h", Port: 4000, User: "root", Schema: "appdb"}
		c.Server = config.Server{Host: "0.0.0.0", Port: 8080, Path: "/graphql"}
		return c
	}
	if err := reloadCompatible(mk(), mk()); err != nil {
		t.Errorf("identical configs must be reload-compatible, got %v", err)
	}
	soft := mk()
	soft.Server.Debug = true
	if err := reloadCompatible(mk(), soft); err != nil {
		t.Errorf("soft change must be reload-compatible, got %v", err)
	}
	dbChanged := mk()
	dbChanged.Database.Port = 4001
	if err := reloadCompatible(mk(), dbChanged); err == nil {
		t.Error("a DB connection change must be rejected for reload")
	}
	portChanged := mk()
	portChanged.Server.Port = 9090
	if err := reloadCompatible(mk(), portChanged); err == nil {
		t.Error("a listen-port change must be rejected for reload")
	}
}

func TestBuildHooksUnknownName(t *testing.T) {
	register.Reset()
	t.Cleanup(register.Reset)
	cfg := baseConfig()
	cfg.Hooks = config.HooksConfig{Tables: map[string]*config.TableHooks{
		"posts": {BeforeInsert: []string{"missing_hook"}},
	}}
	_, err := buildHooks(cfg)
	if err == nil || !strings.Contains(err.Error(), "missing_hook") {
		t.Fatalf("expected error naming the unregistered hook, got %v", err)
	}
}

func TestBuildHooksResolvesRegisteredNames(t *testing.T) {
	register.Reset()
	t.Cleanup(register.Reset)
	register.MutationHook("h", func(ctx context.Context, ev *MutationEvent) error { return nil })
	cfg := baseConfig()
	cfg.Hooks = config.HooksConfig{Tables: map[string]*config.TableHooks{
		"posts": {BeforeInsert: []string{"h"}, AfterInsert: []string{"h"}},
	}}
	hooks, err := buildHooks(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if hooks == nil {
		t.Fatal("expected non-nil hooks")
	}
}

func TestBuildHooksCustomFieldValidation(t *testing.T) {
	register.Reset()
	t.Cleanup(register.Reset)
	register.CustomField(register.CustomFieldDef{
		Name: "x", Operation: "subscription",
		Field: &graphql.Field{Type: graphql.String},
	})
	if _, err := buildHooks(baseConfig()); err == nil {
		t.Error("expected error for invalid Operation")
	}

	register.Reset()
	register.CustomField(register.CustomFieldDef{
		Name: "x", Operation: "query", AllowedRoles: []string{"ghost"},
		Field: &graphql.Field{Type: graphql.String},
	})
	if _, err := buildHooks(baseConfig()); err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Errorf("expected error naming the undefined role, got %v", err)
	}

	register.Reset()
	register.CustomField(register.CustomFieldDef{
		Name: "x", Operation: "query", AllowedRoles: []string{"admin"},
		Field: &graphql.Field{Type: graphql.String},
	})
	if _, err := buildHooks(baseConfig()); err != nil {
		t.Errorf("valid registered custom field rejected: %v", err)
	}
}
