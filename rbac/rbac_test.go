package rbac

import (
	"reflect"
	"testing"

	"gqlgate/config"
	"gqlgate/introspect"
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

func TestFilterValidationSQL(t *testing.T) {
	f, _ := CompileFilter("author_id = :jwt.sub AND tenant_id IN (:jwt.tenants)")
	if got := f.ValidationSQL(); got != "author_id = NULL AND tenant_id IN (NULL)" {
		t.Errorf("ValidationSQL = %q", got)
	}
}

func filterSurfaceTable() *introspect.Table {
	id := &introspect.Column{Name: "id", Ordinal: 0}
	title := &introspect.Column{Name: "title", Ordinal: 1}
	secret := &introspect.Column{Name: "secret", Ordinal: 2}
	return &introspect.Table{
		Name:      "posts",
		Columns:   []*introspect.Column{id, title, secret},
		ColumnMap: map[string]*introspect.Column{"id": id, "title": title, "secret": secret},
	}
}

func TestResolveFilterSurface(t *testing.T) {
	tbl := filterSurfaceTable()
	rels := []string{"author"}
	perm := &config.OpPerm{
		Allow:   true,
		Columns: []string{"id", "title"},
		FilterableColumns: &config.FilterableColumns{
			Names: []string{"title"}, Ops: map[string][]string{"title": {"_eq"}},
		},
		FilterOperators:     []string{"_eq", "_in"},
		FilterRelationships: &rels,
	}
	oa, err := resolveOp("r", tbl, "select", perm, true)
	if err != nil {
		t.Fatal(err)
	}
	if !oa.Explicit || oa.Filterable("id") || !oa.Filterable("title") || oa.Filterable("secret") {
		t.Errorf("filterable: explicit=%v id=%v title=%v secret=%v", oa.Explicit, oa.Filterable("id"), oa.Filterable("title"), oa.Filterable("secret"))
	}
	if !reflect.DeepEqual(oa.FilterColumns["title"], []string{"_eq"}) || !reflect.DeepEqual(oa.FilterOperators, []string{"_eq", "_in"}) || !reflect.DeepEqual(oa.FilterRelationships, rels) {
		t.Errorf("surface = %+v", oa)
	}

	// Default: every readable column is filterable.
	oa, _ = resolveOp("r", tbl, "select", &config.OpPerm{Allow: true, Columns: []string{"id"}}, true)
	if oa.FilterColumns != nil || !oa.Filterable("id") || oa.Filterable("title") {
		t.Errorf("default surface wrong: %+v", oa)
	}

	// A filterable column must be readable; explicit rules fail, wildcard rules skip.
	perm = &config.OpPerm{Allow: true, Columns: []string{"id"}, FilterableColumns: &config.FilterableColumns{Names: []string{"id", "secret"}}}
	if _, err := resolveOp("r", tbl, "select", perm, true); err == nil {
		t.Error("unreadable filterable column must fail an explicit rule")
	}
	oa, err = resolveOp("r", tbl, "select", perm, false)
	if err != nil || oa.Filterable("secret") || !oa.Filterable("id") {
		t.Errorf("wildcard rule should skip unreadable column: %v %+v", err, oa)
	}
}
