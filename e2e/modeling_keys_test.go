package e2e

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"gqlgate"
)

// End-to-end regressions for the modeling validation rules: declared
// relationships need columns of the same collation, declared keys refuse
// ENUM/SET columns, column renames cannot shadow the where operators, and a
// named view that has become invalid fails with an error naming it.

var declCollationSQL = []string{
	`CREATE TABLE pb (
	   code VARCHAR(10) COLLATE utf8mb4_general_ci NOT NULL PRIMARY KEY,
	   note VARCHAR(20) NOT NULL
	 )`,
	`INSERT INTO pb VALUES ('abc', 'public'), ('xyz', 'secret')`,
	`CREATE TABLE pc (
	   id INT NOT NULL PRIMARY KEY,
	   code VARCHAR(10) COLLATE utf8mb4_general_ci NOT NULL
	 )`,
	`INSERT INTO pc VALUES (1, 'ABC'), (2, 'nope'), (3, 'XYZ')`,
	`CREATE TABLE pa (
	   id INT NOT NULL PRIMARY KEY,
	   code VARCHAR(10) COLLATE utf8mb4_bin NOT NULL
	 )`,
	`INSERT INTO pa VALUES (1, 'ABC'), (2, 'abc')`,
	`CREATE TABLE pn (
	   id INT NOT NULL PRIMARY KEY,
	   ref VARCHAR(10) COLLATE utf8mb4_general_ci NULL UNIQUE
	 )`,
}

const declCollationTables = `tables:
  pc:
    relationships:
      b: {type: object, target: pb, mapping: {code: code}}
`

const declNullableUniqueTables = `tables:
  pc:
    relationships:
      n: {type: object, target: pn, mapping: {code: ref}}
`

// viewer cannot see pb's secret rows; limited cannot select pb at all.
const declCollationRoles = `roles:
  admin:
    tables:
      "*":
        select: true
  viewer:
    tables:
      pc:
        select: true
      pb:
        select:
          allow: true
          filter: "note <> 'secret'"
  limited:
    tables:
      pc:
        select: true
  anonymous:
    tables:
      pc:
        select: true
`

// navIDs returns the ids of nodes, and (sorted) those whose rel field is set.
func navIDs(t *testing.T, r *Result, path, rel string) (all, related []int64) {
	t.Helper()
	for _, n := range r.List(t, path) {
		m := n.(map[string]any)
		id := int64(m["id"].(float64))
		all = append(all, id)
		if m[rel] != nil {
			related = append(related, id)
		}
	}
	sort.Slice(related, func(i, j int) bool { return related[i] < related[j] })
	return all, related
}

func sameIDs(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestDeclaredRelationshipCollation: with matching collations the
// relationship field and its where filter agree for every role; a mapping
// between columns of different collations is refused.
func TestDeclaredRelationshipCollation(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(declCollationSQL...), WithExtraYAML(declCollationTables), WithRolesYAML(declCollationRoles))
	for _, role := range []string{"admin", "viewer"} {
		tok := env.Token(t, role, 1)
		r := env.MustGQL(t, tok, `{
			all: pc_connection { nodes { id b { code } } }
			has: pc_connection(where: {b: {}}) { nodes { id } }
			hasNot: pc_connection(where: {_not: {b: {}}}) { nodes { id } }
		}`, nil)
		_, related := navIDs(t, r, "all.nodes", "b")
		has := r.IDs(t, "has.nodes")
		if !sameIDs(related, has) {
			t.Errorf("%s: rows with a related b = %v, but where {b: {}} = %v", role, related, has)
		}
		if n := len(has) + len(r.IDs(t, "hasNot.nodes")); n != 3 {
			t.Errorf("%s: has + has-not = %d rows, want 3", role, n)
		}
		want := []int64{1, 3} // general_ci: 'ABC' = 'abc', 'XYZ' = 'xyz'
		if role == "viewer" {
			want = []int64{1} // pb's 'xyz' row is hidden from viewer
		}
		if env.QueryInt(t, "SELECT 'ABC' = _utf8mb4'abc' COLLATE utf8mb4_general_ci") == 1 && !sameIDs(has, want) {
			t.Errorf("%s: where {b: {}} = %v, want %v", role, has, want)
		}
	}
	// Negative: a role that cannot select pb has neither the field nor the
	// filter.
	limited := env.Token(t, "limited", 1)
	env.GQL(t, limited, `{ pc_connection(where: {b: {}}) { nodes { id } } }`, nil).MustFail(t, "b")
	env.GQL(t, limited, `{ pc_connection { nodes { id b { code } } } }`, nil).MustFail(t, "b")

	// utf8mb4_bin -> utf8mb4_general_ci is refused, naming both collations.
	err := env.ReloadExtra(t, declCollationTables+`  pa:
    relationships:
      b: {type: object, target: pb, mapping: {code: code}}
`)
	if err == nil || !strings.Contains(err.Error(), "utf8mb4_bin") || !strings.Contains(err.Error(), "utf8mb4_general_ci") {
		t.Errorf("bin vs general_ci mapping: reload error = %v", err)
	}
	// An object relationship onto a nullable UNIQUE column is refused, and
	// the error says which unique indexes count.
	err = env.ReloadExtra(t, declNullableUniqueTables)
	if err == nil || !strings.Contains(err.Error(), "NOT NULL and indexed in full") {
		t.Errorf("object onto nullable unique: reload error = %v", err)
	}
	// The previous schema keeps serving.
	env.MustGQL(t, env.Token(t, "admin", 1), `{ pc_connection { nodes { b { code } } } }`, nil)
}

var enumKeySQL = []string{
	`CREATE TABLE en (
	   e ENUM('zeta','alpha','mid') NOT NULL,
	   n INT NOT NULL
	 )`,
	`INSERT INTO en VALUES ('zeta', 1), ('alpha', 2), ('mid', 3)`,
	`CREATE VIEW en_text AS SELECT CAST(e AS CHAR(10)) AS e, n FROM en`,
	`CREATE TABLE en_ref (id INT NOT NULL PRIMARY KEY, e ENUM('zeta','alpha','mid') NOT NULL)`,
}

const enumKeyRoles = `roles:
  admin:
    tables:
      "*":
        select: true
      en_text:
        select: true
  reader:
    tables:
      en_text:
        select:
          allow: true
          columns: [n]
  anonymous:
    tables:
      en_ref:
        select: true
`

// TestEnumKeysRejected: an ENUM column cannot be a declared key or a
// declared join column (it sorts by member index, so a cursor seeking on its
// value skips rows); keying a view on the value cast to text pages through
// every row.
func TestEnumKeysRejected(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(enumKeySQL...), WithRolesYAML(enumKeyRoles),
		WithExtraYAML("tables:\n  en_text:\n    primary_key: [e]\n"))
	for _, tc := range []struct{ name, yaml, want string }{
		{"enum key", "tables:\n  en:\n    primary_key: [e]\n", "cannot be a key column"},
		{"enum join", "tables:\n  en_ref:\n    relationships:\n      x: {type: array, target: en, mapping: {e: e}}\n", "join-compatible"},
	} {
		if err := env.ReloadExtra(t, tc.yaml); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: reload error = %v, want %q", tc.name, err, tc.want)
		}
	}
	// The cast view pages through all three rows one at a time.
	admin := env.Token(t, "admin", 1)
	var seen []string
	after := ""
	for i := 0; i < 4; i++ {
		vars := map[string]any{}
		if after != "" {
			vars["after"] = after
		}
		r := env.MustGQL(t, admin, `query($after: String) { en_text_connection(first: 1, after: $after) {
			nodes { e } page_info { has_next_page end_cursor } } }`, vars)
		for _, n := range r.List(t, "en_text_connection.nodes") {
			seen = append(seen, n.(map[string]any)["e"].(string))
		}
		if r.Get("en_text_connection.page_info.has_next_page") != true {
			break
		}
		after = r.String(t, "en_text_connection.page_info.end_cursor")
	}
	if strings.Join(seen, ",") != "alpha,mid,zeta" {
		t.Errorf("paged keys = %v, want alpha,mid,zeta", seen)
	}
	// Negative: reader cannot read the key column, so it has no connection
	// (only the bounded list) and cannot filter on e.
	reader := env.Token(t, "reader", 1)
	env.GQL(t, reader, `{ en_text_connection { nodes { n } } }`, nil).MustFail(t, "en_text_connection")
	env.GQL(t, reader, `{ en_text_list(where: {e: {_eq: "zeta"}}) { n } }`, nil).MustFail(t, "e")
	if n := len(env.MustGQL(t, reader, `{ en_text_list { n } }`, nil).List(t, "en_text_list")); n != 3 {
		t.Errorf("reader list = %d rows, want 3", n)
	}
}

// TestColumnRenamedToOperator: a column renamed _and/_or/_not would replace
// the where operator, so the config is refused.
func TestColumnRenamedToOperator(t *testing.T) {
	t.Parallel()
	env := New(t)
	for _, op := range []string{"_and", "_or", "_not"} {
		err := env.ReloadExtra(t, "tables:\n  posts:\n    columns:\n      title: "+op+"\n")
		if err == nil || !strings.Contains(err.Error(), "logical operator") {
			t.Errorf("rename to %s: reload error = %v", op, err)
		}
	}
	// The logical operators still work, for admin and for author.
	for _, role := range []string{"admin", "author"} {
		r := env.MustGQL(t, env.Token(t, role, 1), `{ posts_connection(where: {_and: [{id: {_eq: 1}}], _not: {id: {_eq: 2}}}) { nodes { id } } }`, nil)
		wantIDs(t, role, r.IDs(t, "posts_connection.nodes"), 1)
	}
	// Negative: anonymous cannot filter on a column it cannot read.
	env.GQL(t, "", `{ posts_connection(where: {_and: [{body: {_eq: "x"}}]}) { nodes { id } } }`, nil).MustFail(t, "body")
}

// TestInvalidViewRejected: a named view whose base table was dropped is
// listed without columns; a reload (and a fresh start) fails with an error
// naming the view, and the previous schema keeps serving.
func TestInvalidViewRejected(t *testing.T) {
	t.Parallel()
	roles := `roles:
  admin:
    tables:
      "*":
        select: true
      vx:
        select: true
  reader:
    tables:
      posts:
        select: true
  anonymous:
    tables:
      posts:
        select: true
`
	env := New(t, WithRolesYAML(roles), WithSQL(
		`CREATE TABLE tmpx (id INT NOT NULL PRIMARY KEY, label VARCHAR(10))`,
		`INSERT INTO tmpx VALUES (1, 'one')`,
		`CREATE VIEW vx AS SELECT id, label FROM tmpx`,
	))
	admin := env.Token(t, "admin", 1)
	env.MustGQL(t, admin, `{ vx_list { label } }`, nil)
	// Negative: reader does not name vx, so it never sees it.
	env.GQL(t, env.Token(t, "reader", 1), `{ vx_list { label } }`, nil).MustFail(t, "vx_list")

	env.Exec(t, `DROP TABLE tmpx`)
	err := env.Reload(t, roles)
	if err == nil || !strings.Contains(err.Error(), `view "vx" has no columns`) {
		t.Fatalf("reload with invalid view: err = %v", err)
	}
	env.MustGQL(t, env.Token(t, "reader", 1), `{ posts_connection { nodes { id } } }`, nil)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	g, err := gqlgate.Open(ctx, env.Config)
	if err == nil {
		g.Close()
		t.Fatal("gqlgate.Open with an invalid view: want an error")
	}
	if !strings.Contains(err.Error(), `view "vx" has no columns`) {
		t.Errorf("gqlgate.Open error = %v", err)
	}
}
