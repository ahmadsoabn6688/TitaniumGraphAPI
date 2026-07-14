package schema

import (
	"testing"

	"github.com/graphql-go/graphql"

	"gqlgate/config"
	"gqlgate/introspect"
)

func TestScalarForVector(t *testing.T) {
	c := &introspect.Column{Name: "embedding", DataType: "vector", ColumnType: "vector(3)"}
	if got := scalarFor(c).Name(); got != "Vector" {
		t.Errorf("scalarFor(vector) = %q, want Vector", got)
	}
}

func TestIsNumeric(t *testing.T) {
	for _, dt := range []string{"int", "bigint", "decimal", "float", "double", "tinyint"} {
		if !isNumeric(&introspect.Column{DataType: dt}) {
			t.Errorf("%s should be numeric", dt)
		}
	}
	for _, dt := range []string{"varchar", "text", "datetime", "json", "vector"} {
		if isNumeric(&introspect.Column{DataType: dt}) {
			t.Errorf("%s should not be numeric", dt)
		}
	}
}

func TestVectorMetricMapping(t *testing.T) {
	for metric, fn := range vectorMetricSQL {
		if fn == "" {
			t.Errorf("metric %q has no distance function", metric)
		}
	}
	if vectorMetricSQL["COSINE"] != "VEC_COSINE_DISTANCE" {
		t.Error("COSINE must map to VEC_COSINE_DISTANCE")
	}
}

// buildDocsSchema builds a single-role schema for a docs table with a vector
// column and a numeric column, to check the TiDB-specific fields generate.
func buildDocsSchema(t *testing.T) graphql.Schema {
	t.Helper()
	col := func(name, dt, ct string, pk bool) *introspect.Column {
		return &introspect.Column{Name: name, DataType: dt, ColumnType: ct, IsPrimary: pk}
	}
	id := col("id", "bigint", "bigint", true)
	views := col("views", "int", "int", false)
	emb := col("embedding", "vector", "vector(3)", false)
	tbl := &introspect.Table{
		Name:       "docs",
		Columns:    []*introspect.Column{id, views, emb},
		ColumnMap:  map[string]*introspect.Column{"id": id, "views": views, "embedding": emb},
		PrimaryKey: []string{"id"},
	}
	catalog := &introspect.Catalog{SchemaName: "appdb", Tables: map[string]*introspect.Table{"docs": tbl}, TableOrder: []string{"docs"}}
	cfg := &config.Config{Roles: map[string]*config.Role{
		"viewer": {Tables: map[string]*config.TablePerm{"docs": {Select: &config.OpPerm{Allow: true}}}},
	}}
	cfg.SchemaGen.DefaultPageSize = 25
	cfg.SchemaGen.MaxPageSize = 200
	schemas, err := BuildAll(Options{Catalog: catalog, Config: cfg})
	if err != nil {
		t.Fatalf("BuildAll: %v", err)
	}
	return schemas["viewer"]
}

func TestTiDBFeatureFieldsGenerated(t *testing.T) {
	s := buildDocsSchema(t)
	for _, f := range []string{"docs_connection", "docs_aggregate", "docs_by_pk", "docs_nearest_by_embedding"} {
		if _, ok := s.QueryType().Fields()[f]; !ok {
			t.Errorf("expected query field %q", f)
		}
	}
	// The offset list field and standalone count are gone (cursor-only).
	for _, f := range []string{"docs", "docs_count"} {
		if _, ok := s.QueryType().Fields()[f]; ok {
			t.Errorf("field %q should no longer be generated", f)
		}
	}
	// The connection carries no order_by arg (keyset is PK-ordered).
	if conn := s.QueryType().Fields()["docs_connection"]; conn != nil {
		for _, a := range conn.Args {
			if a.Name() == "order_by" {
				t.Error("connection must not expose order_by (keyset is PK-ordered)")
			}
		}
	}
}
