package e2e

import (
	"database/sql"
	"slices"
	"strings"
	"testing"
)

// Regression tests for the filter surface's edge cases: relationship filters
// over join columns hidden from `where`, an explicitly empty operator list,
// and the index-friendly exact-case _starts_with on *_ci columns.

// joinColumnRoles hide FK join columns from `where` (while keeping them
// readable) and switch filtering off with an empty operator list.
const joinColumnRoles = `roles:
  admin:
    tables:
      "*":
        select: true
  fkhidden:
    tables:
      posts:
        select:
          allow: true
          columns: [id, author_id, title]
          filterable_columns: [id, title]
      users:
        select: true
      comments:
        select: true
  fkshown:
    tables:
      posts:
        select:
          allow: true
          columns: [id, author_id, title]
          filterable_columns: [id, author_id, title]
      users:
        select: true
  idhidden:
    tables:
      users:
        select:
          allow: true
          columns: [id, name]
          filterable_columns: [name]
      posts:
        select: true
  noops:
    tables:
      posts:
        select:
          allow: true
          filter_operators: []
      users:
        select: true
  anonymous:
    tables:
      posts:
        select: true
`

func TestFilterSurfaceHiddenJoinColumns(t *testing.T) {
	t.Parallel()
	env := New(t, WithRolesYAML(joinColumnRoles))
	const pq = `query($w: posts_bool_exp) { posts_connection(where: $w) { nodes { id } } }`
	const uq = `query($w: users_bool_exp) { users_connection(where: $w) { nodes { id } } }`
	w := func(m map[string]any) map[string]any { return map[string]any{"w": m} }
	authorID2 := map[string]any{"author": map[string]any{"id": map[string]any{"_eq": 2}}}

	// A role that may filter on author_id may also filter through author.
	fkshown := env.Token(t, "fkshown", 1)
	wantIDs(t, "fkshown author.id", ids(t, env, fkshown, pq, "posts_connection.nodes", w(authorID2)), 3)
	wantIDs(t, "fkshown author_id", ids(t, env, fkshown, pq, "posts_connection.nodes",
		w(map[string]any{"author_id": map[string]any{"_eq": 2}})), 3)
	admin := env.Token(t, "admin", 4)
	wantIDs(t, "admin author.id", ids(t, env, admin, pq, "posts_connection.nodes", w(authorID2)), 3)

	// author_id readable but not filterable: the relationship must not be a
	// way around that (author: {id: {_eq: 2}} is author_id = 2).
	fkhidden := env.Token(t, "fkhidden", 1)
	if got := inputFieldNames(t, env, fkhidden, "posts_bool_exp"); slices.Contains(got, "author") || slices.Contains(got, "author_id") {
		t.Errorf("fkhidden posts_bool_exp = %v", got)
	}
	env.GQL(t, fkhidden, pq, w(map[string]any{"author_id": map[string]any{"_eq": 2}})).MustFail(t, "author_id")
	env.GQL(t, fkhidden, `{ posts_connection(where: {author: {id: {_eq: 2}}}) { nodes { id } } }`, nil).MustFail(t, "author")
	env.GQL(t, fkhidden, pq, w(authorID2)).MustFail(t, "author")
	env.GQL(t, fkhidden, pq, w(map[string]any{"author": map[string]any{"id": map[string]any{"_in": []any{2}}}})).MustFail(t, "author")
	env.GQL(t, fkhidden, pq, w(map[string]any{"_not": map[string]any{"author": map[string]any{}}})).MustFail(t, "author")
	// Relationships joined on a filterable column keep working, and author_id
	// stays readable and navigable.
	wantIDs(t, "fkhidden comments", ids(t, env, fkhidden, pq, "posts_connection.nodes",
		w(map[string]any{"comments": map[string]any{"user_id": map[string]any{"_eq": 1}}})), 3, 4)
	r := env.MustGQL(t, fkhidden, `{ posts_by_pk(id: 3) { author_id author { name } } }`, nil)
	if r.Int(t, "posts_by_pk.author_id") != 2 || r.String(t, "posts_by_pk.author.name") != "Grace Hopper" {
		t.Errorf("fkhidden navigation: %s", r.Raw)
	}

	// Array relationships: users.id not filterable hides users.posts.
	idhidden := env.Token(t, "idhidden", 1)
	if got := inputFieldNames(t, env, idhidden, "users_bool_exp"); !slices.Equal(got, []string{"_and", "_not", "_or", "name"}) {
		t.Errorf("idhidden users_bool_exp = %v", got)
	}
	env.GQL(t, idhidden, uq, w(map[string]any{"posts": map[string]any{"author_id": map[string]any{"_eq": 1}}})).MustFail(t, "posts")
	env.GQL(t, idhidden, uq, w(map[string]any{"id": map[string]any{"_eq": 1}})).MustFail(t, "id")
	wantIDs(t, "admin users.posts", ids(t, env, admin, uq, "users_connection.nodes",
		w(map[string]any{"posts": map[string]any{"author_id": map[string]any{"_eq": 1}}})), 1)

	// filter_operators: [] switches column (and so relationship) filtering off.
	noops := env.Token(t, "noops", 1)
	if got := inputFieldNames(t, env, noops, "posts_bool_exp"); !slices.Equal(got, []string{"_and", "_not", "_or"}) {
		t.Errorf("noops posts_bool_exp = %v", got)
	}
	env.GQL(t, noops, pq, w(map[string]any{"title": map[string]any{"_regex": "^Notes"}})).MustFail(t, "title")
	env.GQL(t, noops, pq, w(map[string]any{"id": map[string]any{"_eq": 1}})).MustFail(t, "id")
	env.GQL(t, noops, pq, w(authorID2)).MustFail(t, "author")
	wantIDs(t, "noops unfiltered", ids(t, env, noops, pq, "posts_connection.nodes", nil), 1, 2, 3, 4)
	// ...but other tables keep the full surface.
	wantIDs(t, "noops users", ids(t, env, noops, uq, "users_connection.nodes",
		w(map[string]any{"name": map[string]any{"_regex": "^Ada"}})), 1)

	// Naming a relationship in filter_relationships while hiding its join
	// column is a config error: the reload is rejected and the previous
	// schema keeps serving.
	bad := strings.Replace(joinColumnRoles, "          filterable_columns: [id, title]\n",
		"          filterable_columns: [id, title]\n          filter_relationships: [author]\n", 1)
	if err := env.Reload(t, bad); err == nil || !strings.Contains(err.Error(), "author_id") {
		t.Errorf("reload with filter_relationships over a hidden join column: got %v", err)
	}
	wantIDs(t, "fkshown after rejected reload", ids(t, env, fkshown, pq, "posts_connection.nodes", w(authorID2)), 3)
}

// TestCIStartsWithIndex checks the SQL shape the gateway uses for the
// exact-case _starts_with on a *_ci column: TiDB must still plan an index
// range scan on the column's (ci) index, while the _bin predicate enforces
// the case.
func TestCIStartsWithIndex(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(
		"ALTER TABLE documents ADD COLUMN tag VARCHAR(20) COLLATE utf8mb4_general_ci NULL",
		"CREATE INDEX idx_documents_tag ON documents (tag)",
		"UPDATE documents SET tag = 'Alpha' WHERE id = 1",
		"UPDATE documents SET tag = 'alpine' WHERE id = 2",
	))
	// Same shape as schema.stringCond renders for {tag: {_starts_with: "Al"}}.
	const shape = "SELECT id FROM documents WHERE (`tag` LIKE ? ESCAPE '!' AND `tag` COLLATE utf8mb4_bin LIKE ? ESCAPE '!')"
	rows, err := env.DB.Query("EXPLAIN "+shape, "Al%", "Al%")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var plan []string
	for rows.Next() {
		vals := make([]sql.RawBytes, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		var line []string
		for _, v := range vals {
			line = append(line, string(v))
		}
		plan = append(plan, strings.Join(line, " | "))
	}
	if all := strings.Join(plan, "\n"); !strings.Contains(all, "IndexRangeScan") || !strings.Contains(all, "idx_documents_tag") {
		t.Errorf("_starts_with on a ci column should be an index range scan on idx_documents_tag:\n%s", all)
	}

	admin := env.Token(t, "admin", 4)
	const dq = `query($w: documents_bool_exp) { documents_connection(where: $w) { nodes { id } } }`
	doc := func(where map[string]any) []int64 {
		t.Helper()
		return ids(t, env, admin, dq, "documents_connection.nodes", map[string]any{"w": where})
	}
	tag := func(op, val string) map[string]any { return map[string]any{"tag": map[string]any{op: val}} }
	wantIDs(t, "ci _starts_with Al", doc(tag("_starts_with", "Al")), 1)
	wantIDs(t, "ci _starts_with al", doc(tag("_starts_with", "al")), 2)
	wantIDs(t, "ci _starts_with AL", doc(tag("_starts_with", "AL")))
	wantIDs(t, "ci _istarts_with AL", doc(tag("_istarts_with", "AL")), 1, 2)
	wantIDs(t, "ci _not _starts_with Al", doc(map[string]any{"_not": tag("_starts_with", "Al")}), 2)
}
