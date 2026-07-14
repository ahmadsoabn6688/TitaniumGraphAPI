package schema

import (
	"testing"

	"gqlgate/introspect"
	"gqlgate/rbac"
)

// TestSetClauseValuesContract verifies the values setClause surfaces (used to
// populate the update lifecycle-hook event) are keyed by SQL column name and
// include RBAC presets — matching the insert path and the MutationEvent
// contract, not the raw GraphQL _set input.
func TestSetClauseValuesContract(t *testing.T) {
	authorID := &introspect.Column{Name: "author_id", DataType: "bigint", ColumnType: "bigint"}
	title := &introspect.Column{Name: "title", DataType: "varchar", ColumnType: "varchar(200)"}
	tbl := &introspect.Table{
		Name:      "posts",
		Columns:   []*introspect.Column{authorID, title},
		ColumnMap: map[string]*introspect.Column{"author_id": authorID, "title": title},
	}
	ti := &tableInfo{
		table:      tbl,
		fieldToCol: map[string]*introspect.Column{"author_id": authorID, "title": title},
		colToField: map[string]string{"author_id": "author_id", "title": "title"},
	}
	oa := &rbac.OpAccess{
		Columns:   []*introspect.Column{title},
		ColumnSet: map[string]bool{"title": true},
		Presets:   []rbac.Preset{{Column: authorID, ClaimPath: "sub"}},
	}
	id := &rbac.Identity{Claims: map[string]any{"sub": float64(7)}}

	_, _, byCol, err := setClause(ti, oa, map[string]any{"title": "hello"}, id)
	if err != nil {
		t.Fatal(err)
	}
	if byCol["title"] != "hello" {
		t.Errorf("byCol[title] = %v, want hello", byCol["title"])
	}
	// The preset (author_id from jwt.sub) must be present with its SQL name,
	// even though it never appeared in the client _set input.
	if byCol["author_id"] != float64(7) {
		t.Errorf("preset author_id = %v, want 7 (the sub claim)", byCol["author_id"])
	}
}
