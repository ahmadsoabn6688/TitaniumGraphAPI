package config

import (
	"strings"
	"testing"
)

func TestRoleSelectionDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWT.RoleHeader != DefaultRoleHeader {
		t.Errorf("role_header default = %q", cfg.JWT.RoleHeader)
	}
	if cfg.JWT.AllowedRolesConfigured() {
		t.Error("no allowed-roles source is configured by default")
	}
	// max_open_conns defaults to 10, so 4 root fields run at once.
	if cfg.Server.MaxParallelRootFields != 4 {
		t.Errorf("max_parallel_root_fields default = %d, want 4", cfg.Server.MaxParallelRootFields)
	}
}

func TestMaxParallelRootFields(t *testing.T) {
	withDB := func(dbYAML, server string) string {
		y := strings.Replace(minimalYAML, "database:\n  schema: appdb", "database:\n  schema: appdb\n"+dbYAML, 1)
		return y + "server:\n" + server
	}
	cfg, err := Parse([]byte(withDB("  max_open_conns: 3", "  port: 8080\n")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.MaxParallelRootFields != 1 {
		t.Errorf("3 connections: default = %d, want 1", cfg.Server.MaxParallelRootFields)
	}
	if _, err := Parse([]byte(withDB("  max_open_conns: 3", "  max_parallel_root_fields: 5\n"))); err == nil ||
		!strings.Contains(err.Error(), "exceeds database.max_open_conns") {
		t.Errorf("a cap above the pool must be rejected, got %v", err)
	}
	if _, err := Parse([]byte(withDB("", "  max_parallel_root_fields: -1\n"))); err == nil {
		t.Error("a negative cap must be rejected")
	}
	cfg, err = Parse([]byte(withDB("", "  max_parallel_root_fields: 1\n")))
	if err != nil || cfg.Server.MaxParallelRootFields != 1 {
		t.Errorf("explicit 1: %v %+v", err, cfg)
	}
}

func TestAllowedRolesValidation(t *testing.T) {
	jwt := func(extra string) string {
		return strings.Replace(minimalYAML, "  algorithm: HS256\n", "  algorithm: HS256\n"+extra, 1)
	}
	cfg, err := Parse([]byte(jwt("  allowed_roles_claim: roles\n  role_header: X-Role\n")))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.JWT.AllowedRolesConfigured() || cfg.JWT.AllowedRolesFromDB() || cfg.JWT.RoleHeader != "X-Role" {
		t.Errorf("claim source: %+v", cfg.JWT)
	}

	cfg, err = Parse([]byte(jwt("  role_lookup:\n    table: users\n    allowed_roles_table: {table: user_roles}\n")))
	if err != nil {
		t.Fatal(err)
	}
	at := cfg.JWT.RoleLookup.AllowedRolesTable
	if at.Schema != "appdb" || at.IDColumn != "user_id" || at.RoleColumn != "role" || !cfg.JWT.AllowedRolesFromDB() {
		t.Errorf("allowed_roles_table defaults: %+v", at)
	}

	for extra, want := range map[string]string{
		"  role_header: \"X Role\"\n":                       "not a valid HTTP header name",
		"  role_header: authorization\n":                    "cannot be authorization",
		"  role_lookup:\n    allowed_roles_column: roles\n": "need jwt.role_lookup.table",
		"  allowed_roles_claim: roles\n  role_lookup:\n    table: users\n    allowed_roles_column: roles\n": "at most one",
		"  role_lookup:\n    table: users\n    allowed_roles_table: {id_column: uid}\n":                     "allowed_roles_table.table is required",
	} {
		if _, err := Parse([]byte(jwt(extra))); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want error containing %q, got %v", extra, want, err)
		}
	}
}

func TestJSONTypes(t *testing.T) {
	base := minimalYAML + `
json_types:
  Profile:
    description: "A profile"
    fields:
      name: String
      age: {type: Int, description: "Years"}
      zip: {type: String, key: "zip-code"}
      address: Address
      tags: "[String]"
      contacts: "[Address]"
      extra: JSON
  Address:
    fields:
      city: String
      parent: Address
tables:
  people:
    columns:
      profile: {json_type: Profile}
      history: {name: past, json_type: "[Address]"}
`
	cfg, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.JSONTypes["Profile"]
	if p.Description != "A profile" || p.Fields["name"].Type != "String" || p.Fields["age"].Description != "Years" ||
		p.Fields["zip"].JSONKey("zip") != "zip-code" || p.Fields["name"].JSONKey("name") != "name" {
		t.Errorf("decoded: %+v", p)
	}
	if fc := cfg.Tables["people"].Columns["history"]; fc.Name != "past" || fc.JSONType != "[Address]" {
		t.Errorf("column config: %+v", fc)
	}

	for bad, want := range map[string]string{
		"      name: Strin\n":                      `"Strin" is neither`,
		"      name: \"String!\"\n":                "non-null (!) is not supported",
		"      name: \"[String\"\n":                "unbalanced",
		"      name: \"[[[[[String]]]]]\"\n":       "nest at most",
		"      name: {key: n}\n":                   "type is required",
		"      other: {type: String, key: name}\n": "both read the JSON key",
	} {
		y := strings.Replace(base, "      name: String\n", bad, 1)
		if bad == "      other: {type: String, key: name}\n" {
			y = strings.Replace(base, "      name: String\n", "      name: String\n"+bad, 1)
		}
		if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want error containing %q, got %v", bad, want, err)
		}
	}
	for bad, want := range map[string]string{
		"profile: {json_type: Nope}":   `"Nope" is neither`,
		"profile: {json_type: String}": "must be (a list of) a type declared",
	} {
		y := strings.Replace(base, "profile: {json_type: Profile}", bad, 1)
		if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want error containing %q, got %v", bad, want, err)
		}
	}
	y := strings.Replace(base, "  Address:\n", "  String:\n    fields: {a: Int}\n  Address:\n", 1)
	if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), "built-in scalar") {
		t.Errorf("a type named like a scalar must be rejected, got %v", err)
	}
	y = base + "    root_fields:\n      by_pk: {json_type: Profile}\n"
	if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), "columns only") {
		t.Errorf("json_type on a root field must be rejected, got %v", err)
	}
}
