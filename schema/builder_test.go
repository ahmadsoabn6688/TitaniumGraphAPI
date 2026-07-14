package schema

import (
	"testing"

	"github.com/graphql-go/graphql"

	"gqlgate/config"
	"gqlgate/introspect"
)

// buildTestSchema builds a single-role schema over a one-table catalog.
// No DB is needed: resolvers are closures only invoked at query time.
func buildTestSchema(t *testing.T, selectCols []string) graphql.Schema {
	t.Helper()
	col := func(name string, ord int, pk bool) *introspect.Column {
		return &introspect.Column{Name: name, Ordinal: ord, DataType: "bigint", ColumnType: "bigint", IsPrimary: pk}
	}
	id := col("id", 0, true)
	balance := col("balance", 1, false)
	tbl := &introspect.Table{
		Name:       "acct",
		Columns:    []*introspect.Column{id, balance},
		ColumnMap:  map[string]*introspect.Column{"id": id, "balance": balance},
		PrimaryKey: []string{"id"},
	}
	catalog := &introspect.Catalog{
		SchemaName: "appdb",
		Tables:     map[string]*introspect.Table{"acct": tbl},
		TableOrder: []string{"acct"},
	}
	cfg := &config.Config{
		Roles: map[string]*config.Role{
			"viewer": {Tables: map[string]*config.TablePerm{
				"acct": {Select: &config.OpPerm{Allow: true, Columns: selectCols}},
			}},
		},
	}
	cfg.SchemaGen.DefaultPageSize = 25
	cfg.SchemaGen.MaxPageSize = 200

	schemas, err := BuildAll(Options{Catalog: catalog, Config: cfg})
	if err != nil {
		t.Fatalf("BuildAll: %v", err)
	}
	return schemas["viewer"]
}

func hasQueryField(s graphql.Schema, name string) bool {
	_, ok := s.QueryType().Fields()[name]
	return ok
}

// Fix: *_by_pk must not be generated when the role's select columns exclude
// the primary key, otherwise the PK becomes a probing oracle on a column the
// role may not read.
func TestByPkHiddenWhenPKNotReadable(t *testing.T) {
	s := buildTestSchema(t, []string{"balance"}) // id (the PK) is hidden
	if hasQueryField(s, "acct_by_pk") {
		t.Error("acct_by_pk must be absent when the PK column is not readable")
	}
	// The keyset connection also needs a readable PK, so it's absent too.
	if hasQueryField(s, "acct_connection") {
		t.Error("acct_connection must be absent when the PK is not readable")
	}
	// Aggregates don't need a PK and should still be generated.
	if !hasQueryField(s, "acct_aggregate") {
		t.Error("acct_aggregate should still be generated")
	}
}

func TestByPkPresentWhenPKReadable(t *testing.T) {
	s := buildTestSchema(t, []string{"id", "balance"})
	if !hasQueryField(s, "acct_by_pk") {
		t.Error("acct_by_pk should be generated when the PK is readable")
	}
	// And the hidden-PK argument path stays consistent: the by_pk arg exists.
	if f := s.QueryType().Fields()["acct_by_pk"]; f == nil || len(f.Args) != 1 {
		t.Errorf("acct_by_pk should take exactly one PK argument, got %+v", f)
	}
}

func TestConnectionFieldGating(t *testing.T) {
	// PK readable -> connection field + its parts exist.
	s := buildTestSchema(t, []string{"id", "balance"})
	if !hasQueryField(s, "acct_connection") {
		t.Fatal("acct_connection should be generated when the PK is readable")
	}
	conn, ok := s.Type("acct_connection").(*graphql.Object)
	if !ok {
		t.Fatal("acct_connection type missing")
	}
	for _, f := range []string{"nodes", "page_info", "total_count"} {
		if conn.Fields()[f] == nil {
			t.Errorf("connection type missing field %q", f)
		}
	}

	// PK hidden -> no connection (its cursor/order need a readable PK).
	s2 := buildTestSchema(t, []string{"balance"})
	if hasQueryField(s2, "acct_connection") {
		t.Error("acct_connection must be absent when the PK is not readable")
	}
}

// buildTestSchemaWithHooks builds the single-role ("viewer") schema with hooks.
func buildTestSchemaWithHooks(t *testing.T, hooks *Hooks) graphql.Schema {
	t.Helper()
	id := &introspect.Column{Name: "id", DataType: "bigint", ColumnType: "bigint", IsPrimary: true}
	tbl := &introspect.Table{
		Name: "acct", Columns: []*introspect.Column{id},
		ColumnMap: map[string]*introspect.Column{"id": id}, PrimaryKey: []string{"id"},
	}
	catalog := &introspect.Catalog{SchemaName: "appdb", Tables: map[string]*introspect.Table{"acct": tbl}, TableOrder: []string{"acct"}}
	cfg := &config.Config{Roles: map[string]*config.Role{
		"viewer": {Tables: map[string]*config.TablePerm{"acct": {Select: &config.OpPerm{Allow: true}}}},
	}}
	cfg.SchemaGen.DefaultPageSize = 25
	cfg.SchemaGen.MaxPageSize = 200
	schemas, err := BuildAll(Options{Catalog: catalog, Config: cfg, Hooks: hooks})
	if err != nil {
		t.Fatalf("BuildAll: %v", err)
	}
	return schemas["viewer"]
}

func customField(name string, allowed ...string) CustomField {
	return CustomField{
		Name: name, Operation: "query", AllowedRoles: allowed,
		Field: &graphql.Field{Type: graphql.String, Resolve: func(graphql.ResolveParams) (any, error) { return "ok", nil }},
	}
}

func TestCustomFieldVisibleToAllowedRole(t *testing.T) {
	hooks := NewHooks(nil, nil, []CustomField{customField("whoami", "viewer")})
	s := buildTestSchemaWithHooks(t, hooks)
	if !hasQueryField(s, "whoami") {
		t.Error("custom field allowed to viewer should be present")
	}
}

func TestCustomFieldHiddenFromOtherRole(t *testing.T) {
	hooks := NewHooks(nil, nil, []CustomField{customField("whoami", "someone_else")})
	s := buildTestSchemaWithHooks(t, hooks)
	if hasQueryField(s, "whoami") {
		t.Error("custom field not allowed to viewer must be absent from its schema")
	}
}

func TestCustomFieldCollisionRejected(t *testing.T) {
	// "acct_aggregate" collides with the generated aggregate query field.
	id := &introspect.Column{Name: "id", DataType: "bigint", ColumnType: "bigint", IsPrimary: true}
	tbl := &introspect.Table{Name: "acct", Columns: []*introspect.Column{id}, ColumnMap: map[string]*introspect.Column{"id": id}, PrimaryKey: []string{"id"}}
	catalog := &introspect.Catalog{SchemaName: "appdb", Tables: map[string]*introspect.Table{"acct": tbl}, TableOrder: []string{"acct"}}
	cfg := &config.Config{Roles: map[string]*config.Role{"viewer": {Tables: map[string]*config.TablePerm{"acct": {Select: &config.OpPerm{Allow: true}}}}}}
	cfg.SchemaGen.DefaultPageSize = 25
	cfg.SchemaGen.MaxPageSize = 200
	hooks := NewHooks(nil, nil, []CustomField{customField("acct_aggregate", "viewer")})
	if _, err := BuildAll(Options{Catalog: catalog, Config: cfg, Hooks: hooks}); err == nil {
		t.Error("custom field colliding with a generated field must be rejected")
	}
}
