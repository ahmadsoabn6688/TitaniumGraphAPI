package e2e

import (
	"strings"
	"testing"
)

// DB-free tests of the harness's own safety logic; these always run.

func TestNewDBNameIsHarnessOwned(t *testing.T) {
	for _, name := range []string{
		"TestSimple",
		"TestSub/case with spaces & symbols!",
		strings.Repeat("TestVeryLongName", 10),
		"",
	} {
		got := newDBName(name)
		if len(got) > 64 {
			t.Errorf("newDBName(%q) = %q exceeds 64 chars", name, got)
		}
		if !strings.HasPrefix(got, DBPrefix) || !dbNamePattern.MatchString(got) {
			t.Errorf("newDBName(%q) = %q does not match the harness pattern", name, got)
		}
	}
	if newDBName("TestX") == newDBName("TestX") {
		t.Error("newDBName must be unique per call")
	}
}

func TestDBNamePatternRejectsForeignDatabases(t *testing.T) {
	for _, name := range []string{"appdb", "mysql", "gqlgate_e2e", "gqlgate_e2e_appdb", "gqlgate_e2e_123_abcdef", "x_gqlgate_e2e_1700000000_abcdef"} {
		if dbNamePattern.MatchString(name) {
			t.Errorf("pattern must not match %q", name)
		}
	}
}

func TestFixtureRejectsDatabaseSwitching(t *testing.T) {
	for _, stmt := range []string{
		"USE appdb",
		"use appdb",
		"DROP DATABASE appdb",
		"drop schema if exists appdb",
		"CREATE DATABASE other",
		"  ALTER DATABASE appdb CHARACTER SET utf8mb4",
	} {
		if !forbiddenStmt.MatchString(stmt) {
			t.Errorf("forbidden statement accepted: %q", stmt)
		}
		// The whole script is refused, even when the bad statement is last.
		if _, err := splitScript("CREATE TABLE t (id INT);\n" + stmt + ";"); err == nil {
			t.Errorf("splitScript accepted %q", stmt)
		}
	}
	for _, stmt := range []string{"CREATE TABLE t (id INT)", "INSERT INTO users_database VALUES (1)", "CREATE VIEW v AS SELECT 1"} {
		if forbiddenStmt.MatchString(stmt) {
			t.Errorf("legitimate statement rejected: %q", stmt)
		}
	}
	stmts, err := splitScript(BlogFixture)
	if err != nil {
		t.Fatalf("BlogFixture: %v", err)
	}
	if len(stmts) < 9 {
		t.Errorf("BlogFixture split into %d statements, want >= 9", len(stmts))
	}
}

func TestResultGet(t *testing.T) {
	r := &Result{Data: map[string]any{
		"a": map[string]any{"nodes": []any{map[string]any{"id": float64(7)}, map[string]any{"id": "9"}}},
	}}
	if got := r.Int(t, "a.nodes.0.id"); got != 7 {
		t.Errorf("Int = %d", got)
	}
	if got := r.IDs(t, "a.nodes"); len(got) != 2 || got[1] != 9 {
		t.Errorf("IDs = %v", got)
	}
	for _, p := range []string{"a.nodes.5.id", "a.missing", "a.nodes.x"} {
		if r.Get(p) != nil {
			t.Errorf("Get(%q) should be nil", p)
		}
	}
}
