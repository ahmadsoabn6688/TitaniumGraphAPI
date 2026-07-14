package config

import (
	"os"
	"strings"
	"testing"
)

const minimalYAML = `
database:
  schema: appdb
jwt:
  algorithm: HS256
  secret: "0123456789abcdef0123456789abcdef"
roles:
  admin:
    tables:
      "*":
        select: true
`

func TestParseMinimal(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Port != 4000 || cfg.Server.Port != 8080 || cfg.Server.Path != "/graphql" {
		t.Errorf("defaults not applied: %+v", cfg)
	}
	if cfg.Server.MaxQueryDepth != 15 {
		t.Errorf("max_query_depth default = %d, want 15", cfg.Server.MaxQueryDepth)
	}
	perm := cfg.Roles["admin"].Tables["*"]
	if perm.Select == nil || !perm.Select.Allow || perm.Insert != nil {
		t.Errorf("boolean shorthand not decoded: %+v", perm)
	}
}

func TestParseOpPermObjectForm(t *testing.T) {
	yaml := strings.Replace(minimalYAML, "select: true", `select:
          allow: true
          columns: [id, name]
          filter: "tenant = :jwt.tenant"`, 1)
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	sel := cfg.Roles["admin"].Tables["*"].Select
	if !sel.Allow || len(sel.Columns) != 2 || sel.Filter == "" {
		t.Errorf("object form not decoded: %+v", sel)
	}
}

func TestUnknownKeysRejected(t *testing.T) {
	if _, err := Parse([]byte(minimalYAML + "\nunknown_key: 1")); err == nil {
		t.Error("unknown top-level keys must be rejected")
	}
}

func TestShortSecretRejected(t *testing.T) {
	yaml := strings.Replace(minimalYAML, `"0123456789abcdef0123456789abcdef"`, `"short"`, 1)
	if _, err := Parse([]byte(yaml)); err == nil {
		t.Error("secrets shorter than 32 bytes must be rejected for HS256")
	}
}

func TestMissingEnvVarRejected(t *testing.T) {
	os.Unsetenv("GQLGATE_TEST_NOT_SET")
	yaml := strings.Replace(minimalYAML, `"0123456789abcdef0123456789abcdef"`, "${GQLGATE_TEST_NOT_SET}", 1)
	if _, err := Parse([]byte(yaml)); err == nil {
		t.Error("unset env references must fail, not become empty strings")
	}
}

func TestEnvExpansion(t *testing.T) {
	t.Setenv("GQLGATE_TEST_SECRET", "0123456789abcdef0123456789abcdef")
	yaml := strings.Replace(minimalYAML, `"0123456789abcdef0123456789abcdef"`, "${GQLGATE_TEST_SECRET}", 1)
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWT.Secret != "0123456789abcdef0123456789abcdef" {
		t.Errorf("env not expanded: %q", cfg.JWT.Secret)
	}
}

func TestAnonymousRoleMustExist(t *testing.T) {
	yaml := strings.Replace(minimalYAML, "  secret:", "  anonymous_role: ghost\n  secret:", 1)
	if _, err := Parse([]byte(yaml)); err == nil {
		t.Error("anonymous_role referencing an undefined role must be rejected")
	}
}

func TestRoleLookupDefaults(t *testing.T) {
	yaml := strings.Replace(minimalYAML, "roles:", `  role_lookup:
    table: accounts
roles:`, 1)
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	rl := cfg.JWT.RoleLookup
	if !rl.Enabled() {
		t.Fatal("role_lookup with table set must be enabled")
	}
	if rl.Schema != "appdb" || rl.IDClaim != "sub" || rl.IDColumn != "id" || rl.RoleColumn != "role" {
		t.Errorf("defaults not applied: %+v", rl)
	}
	if rl.UsernameColumn == nil || *rl.UsernameColumn != "username" || rl.PasswordColumn == nil || *rl.PasswordColumn != "password" {
		t.Errorf("username/password column defaults not applied: %+v", rl)
	}
}

func TestRoleLookupOptOutColumns(t *testing.T) {
	yaml := strings.Replace(minimalYAML, "roles:", `  role_lookup:
    table: accounts
    username_column: ""
    password_column: ""
roles:`, 1)
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	rl := cfg.JWT.RoleLookup
	if *rl.UsernameColumn != "" || *rl.PasswordColumn != "" {
		t.Errorf("explicit empty columns must stay empty (opt-out): %+v", rl)
	}
}

func TestRoleLookupDisabledByDefault(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWT.RoleLookup.Enabled() {
		t.Error("role_lookup must be disabled when no table is set")
	}
}

// Environment-injected DB credentials (docker compose style) must take
// priority over whatever the YAML says.
func TestDatabaseEnvOverrides(t *testing.T) {
	t.Setenv("GQLGATE_DB_HOST", "tidb-prod")
	t.Setenv("GQLGATE_DB_PORT", "4001")
	t.Setenv("GQLGATE_DB_USER", "svc_gql")
	t.Setenv("GQLGATE_DB_PASSWORD", "s3cret")
	t.Setenv("GQLGATE_DB_SCHEMA", "proddb")
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Database
	if d.Host != "tidb-prod" || d.Port != 4001 || d.User != "svc_gql" || d.Password != "s3cret" || d.Schema != "proddb" {
		t.Errorf("env must override yaml, got %+v", d)
	}
}

func TestDatabaseEnvEmptyPasswordHonored(t *testing.T) {
	// A password env explicitly set to "" must override a yaml password
	// (fresh TiDB root has an empty password).
	yaml := strings.Replace(minimalYAML, "database:\n  schema: appdb",
		"database:\n  schema: appdb\n  password: fromyaml", 1)
	t.Setenv("GQLGATE_DB_PASSWORD", "")
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.Password != "" {
		t.Errorf("explicitly empty env password must win, got %q", cfg.Database.Password)
	}
}

func TestDSNForcedParams(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	dsn := cfg.Database.DSN()
	for _, want := range []string{"parseTime=true", "clientFoundRows=true"} {
		if !strings.Contains(dsn, want) {
			t.Errorf("DSN %q missing %s", dsn, want)
		}
	}
}
