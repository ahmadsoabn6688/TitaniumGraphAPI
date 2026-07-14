package rbac

import (
	"reflect"
	"testing"
)

func TestLookupClaim(t *testing.T) {
	claims := map[string]any{
		"sub":  "42",
		"role": "author",
		"app_metadata": map[string]any{
			"role":   "admin",
			"tenant": map[string]any{"id": float64(7)},
		},
		"https://myapp.com/claims": map[string]any{"role": "editor"},
	}

	tests := []struct {
		path string
		want any
		ok   bool
	}{
		{"sub", "42", true},
		{"role", "author", true},
		{"app_metadata.role", "admin", true},
		{"app_metadata.tenant.id", float64(7), true},
		{"https://myapp.com/claims.role", "editor", true},
		{"missing", nil, false},
		{"app_metadata.missing", nil, false},
		{"sub.deeper", nil, false},
	}
	for _, tc := range tests {
		got, ok := LookupClaim(claims, tc.path)
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("LookupClaim(%q) = (%v, %v), want (%v, %v)", tc.path, got, ok, tc.want, tc.ok)
		}
	}
}

func TestFilterSQL(t *testing.T) {
	f, err := CompileFilter("author_id = :jwt.sub AND tenant_id IN (:jwt.tenants)")
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"sub":     float64(1),
		"tenants": []any{"a", "b", "c"},
	}
	sqlStr, args, err := f.SQL(claims)
	if err != nil {
		t.Fatal(err)
	}
	wantSQL := "author_id = ? AND tenant_id IN (?, ?, ?)"
	if sqlStr != wantSQL {
		t.Errorf("sql = %q, want %q", sqlStr, wantSQL)
	}
	wantArgs := []any{float64(1), "a", "b", "c"}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Errorf("args = %v, want %v", args, wantArgs)
	}
}

func TestFilterSQLEmptyArray(t *testing.T) {
	f, _ := CompileFilter("tenant_id IN (:jwt.tenants)")
	sqlStr, args, err := f.SQL(map[string]any{"tenants": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	if sqlStr != "tenant_id IN (NULL)" || len(args) != 0 {
		t.Errorf("got %q with %d args; empty arrays must render as NULL and bind nothing", sqlStr, len(args))
	}
}

func TestFilterSQLMissingClaim(t *testing.T) {
	f, _ := CompileFilter("author_id = :jwt.sub")
	if _, _, err := f.SQL(map[string]any{}); err == nil {
		t.Error("missing claim must be an error, not an empty binding")
	}
}

func TestFilterRejectsObjects(t *testing.T) {
	f, _ := CompileFilter("meta = :jwt.meta")
	if _, _, err := f.SQL(map[string]any{"meta": map[string]any{"x": 1}}); err == nil {
		t.Error("object claims must not be bindable")
	}
}

func TestCompileFilterNoClaims(t *testing.T) {
	f, err := CompileFilter("published = 1")
	if err != nil {
		t.Fatal(err)
	}
	sqlStr, args, err := f.SQL(map[string]any{})
	if err != nil || sqlStr != "published = 1" || len(args) != 0 {
		t.Errorf("static filter should pass through, got %q %v %v", sqlStr, args, err)
	}
}
