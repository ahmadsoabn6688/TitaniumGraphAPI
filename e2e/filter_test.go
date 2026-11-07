package e2e

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"gqlgate"
	"gqlgate/config"
)

// End-to-end tests for the `where` surface: string operators, the
// configurable filter surface (filterable columns, operator allow-lists,
// custom operators) and filtering through relationships.
//
// Fixture recap (testdata/blog.sql): users 1 ada, 2 grace, 3 alan (inactive),
// 4 root (admin). Posts: 1 "Notes on the Analytical Engine" (ada), 2 "Draft:
// poetry and math" (ada, the only unpublished one), 3 "Compilers for humans"
// (grace), 4 "On computable numbers" (alan). Comments: 1 on post 1 by grace,
// 2 on post 1 by alan, 3 on post 3 by ada, 4 on post 4 by ada, 5 on post 4 by
// grace.

// ids runs a query that must succeed and returns the ids at path.
func ids(t *testing.T, env *Env, token, query, path string, vars map[string]any) []int64 {
	t.Helper()
	return env.MustGQL(t, token, query, vars).IDs(t, path)
}

func wantIDs(t *testing.T, label string, got []int64, want ...int64) {
	t.Helper()
	if want == nil {
		want = []int64{}
	}
	if got == nil {
		got = []int64{}
	}
	if !slices.Equal(got, want) {
		t.Errorf("%s: got ids %v, want %v", label, got, want)
	}
}

func inputFieldNames(t *testing.T, env *Env, token, typeName string) []string {
	t.Helper()
	r := env.MustGQL(t, token, `query($n: String!) { __type(name: $n) { inputFields { name } } }`, map[string]any{"n": typeName})
	var names []string
	for i := range r.List(t, "__type.inputFields") {
		names = append(names, r.String(t, "__type.inputFields."+strconv.Itoa(i)+".name"))
	}
	slices.Sort(names)
	return names
}

func TestStringOperators(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(
		"INSERT INTO posts (id, author_id, title, body, published) VALUES (5, 1, '50% off_sale!', 'promo', 1)",
		"ALTER TABLE documents ADD COLUMN tag VARCHAR(20) COLLATE utf8mb4_general_ci NULL",
		"UPDATE documents SET tag = 'Alpha' WHERE id = 1",
		"UPDATE documents SET tag = 'beta' WHERE id = 2",
	))
	admin := env.Token(t, "admin", 4)
	const q = `query($w: posts_bool_exp) { posts_connection(where: $w) { nodes { id } } }`
	post := func(token string, col, op string, val any) []int64 {
		t.Helper()
		return ids(t, env, token, q, "posts_connection.nodes", map[string]any{"w": map[string]any{col: map[string]any{op: val}}})
	}

	wantIDs(t, "_like is case-sensitive on a _bin column", post(admin, "title", "_like", "%engine%"))
	wantIDs(t, "_ilike", post(admin, "title", "_ilike", "%ENGINE%"), 1)
	wantIDs(t, "_nilike", post(admin, "title", "_nilike", "%DRAFT%"), 1, 3, 4, 5)
	wantIDs(t, "_iregex", post(admin, "title", "_iregex", "^(notes|on)"), 1, 4)
	wantIDs(t, "_niregex", post(admin, "title", "_niregex", "^(notes|on)"), 2, 3, 5)
	wantIDs(t, "_icontains", post(admin, "title", "_icontains", "COMPUT"), 4)
	wantIDs(t, "_contains", post(admin, "title", "_contains", "the A"), 1)
	wantIDs(t, "_contains is case-sensitive", post(admin, "title", "_contains", "the a"))
	wantIDs(t, "_starts_with", post(admin, "title", "_starts_with", "Notes"), 1)
	wantIDs(t, "_starts_with is case-sensitive", post(admin, "title", "_starts_with", "notes"))
	wantIDs(t, "_istarts_with", post(admin, "title", "_istarts_with", "notes"), 1)
	wantIDs(t, "_iends_with", post(admin, "title", "_iends_with", "NUMBERS"), 4)
	wantIDs(t, "_ends_with", post(admin, "title", "_ends_with", "sale!"), 5)

	// % and _ in the value are literals, not wildcards.
	wantIDs(t, "_contains %", post(admin, "title", "_contains", "%"), 5)
	wantIDs(t, "_contains %%", post(admin, "title", "_contains", "%%"))
	wantIDs(t, "_contains 0% o", post(admin, "title", "_contains", "0% o"), 5)
	wantIDs(t, "_starts_with _", post(admin, "title", "_starts_with", "_"))
	wantIDs(t, "_contains _", post(admin, "title", "_contains", "_"), 5)
	wantIDs(t, "_ends_with !", post(admin, "title", "_ends_with", "!"), 5)
	wantIDs(t, "_icontains F_S", post(admin, "title", "_icontains", "F_S"), 5)

	// On a _ci column the i-variants use the collation, and the
	// case-sensitive literal operators still compare exactly.
	const dq = `query($w: documents_bool_exp) { documents_connection(where: $w) { nodes { id } } }`
	doc := func(op, val string) []int64 {
		t.Helper()
		return ids(t, env, admin, dq, "documents_connection.nodes", map[string]any{"w": map[string]any{"tag": map[string]any{op: val}}})
	}
	wantIDs(t, "ci _starts_with exact", doc("_starts_with", "Alpha"), 1)
	wantIDs(t, "ci _starts_with wrong case", doc("_starts_with", "alpha"))
	wantIDs(t, "ci _istarts_with", doc("_istarts_with", "ALPHA"), 1)
	wantIDs(t, "ci _ilike", doc("_ilike", "%ETA"), 2)
	wantIDs(t, "ci _iregex", doc("_iregex", "^(alpha|BETA)$"), 1, 2)

	// The anonymous row filter still applies (post 2 is unpublished)...
	wantIDs(t, "anonymous _icontains", post("", "title", "_icontains", "draft"))
	wantIDs(t, "anonymous _istarts_with", post("", "title", "_istarts_with", "n"), 1)
	// ...the demo's anonymous filter surface withholds scan-heavy operators
	// and the body column...
	env.GQL(t, "", q, map[string]any{"w": map[string]any{"title": map[string]any{"_niregex": "^on"}}}).MustFail(t, "_niregex")
	env.GQL(t, "", q, map[string]any{"w": map[string]any{"body": map[string]any{"_icontains": "x"}}}).MustFail(t, "body")
	// ...and hidden columns cannot be probed with the new operators.
	env.GQL(t, "", `{ users_connection(where: {email: {_istarts_with: "ada"}}) { nodes { id } } }`, nil).MustFail(t, "email")
	env.GQL(t, "", `query($w: users_bool_exp) { users_connection(where: $w) { nodes { id } } }`,
		map[string]any{"w": map[string]any{"email": map[string]any{"_icontains": "@"}}}).MustFail(t, "email")

	// _contains keeps its JSON meaning on JSON columns.
	r0 := env.MustGQL(t, admin, `query($v: JSON) { users_connection(where: {metadata: {_contains: $v}}) { nodes { id } } }`,
		map[string]any{"v": map[string]any{"tier": "gold"}})
	wantIDs(t, "JSON _contains", r0.IDs(t, "users_connection.nodes"), 1)

	// String operators are not offered on non-string columns.
	env.GQL(t, admin, `{ posts_connection(where: {views: {_ilike: "4%"}}) { nodes { id } } }`, nil).MustFail(t, "_ilike")

	// They work in aggregates and mutations too.
	r := env.MustGQL(t, admin, `{ posts_aggregate(where: {title: {_istarts_with: "on "}}) { count } }`, nil)
	if n := r.Int(t, "posts_aggregate.count"); n != 1 {
		t.Errorf("aggregate count = %d, want 1", n)
	}
	r = env.MustGQL(t, admin, `mutation { update_posts(where: {title: {_contains: "%"}}, _set: {views: 50}) { affected_rows } }`, nil)
	if n := r.Int(t, "update_posts.affected_rows"); n != 1 {
		t.Errorf("update affected %d rows, want 1", n)
	}
	if v := env.QueryInt(t, "SELECT views FROM posts WHERE id = 5"); v != 50 {
		t.Errorf("post 5 views = %d", v)
	}
}

// filterRoles exercises the configurable filter surface.
const filterRoles = `roles:
  admin:
    tables:
      "*":
        select: true
        insert: true
        update: true
        delete: true
  reader:
    tables:
      posts:
        select:
          allow: true
          columns: [id, author_id, title, body, published, published_on]
          filterable_columns:
            id: all
            author_id: all
            title: [_eq, _istarts_with]
            published_on: all
          filter_relationships: [author]
      users:
        select:
          allow: true
          columns: [id, name, email]
          filter_operators: [_eq, _in]
      comments:
        select: true
  member:
    tables:
      users:
        select:
          allow: true
          columns: [id, name]
          filter: "id = :jwt.sub"
      posts:
        select: true
  postsonly:
    tables:
      posts:
        select: true
  leaky:
    tables:
      users:
        select:
          allow: true
          filter: "published = 1"
      posts:
        select: true
  anonymous:
    tables:
      posts:
        select: true
`

const customOpsTemplate = `
  custom_operators:
    - name: _year_eq
      argument: Int
      applies_to: [Date, DateTime]
      sql: "YEAR({column}) = {value}"
    - name: _len_gt
      argument: Int
      applies_to: [String]
      sql: "CHAR_LENGTH({column}) > {value}"
`

func TestFilterSurface(t *testing.T) {
	t.Parallel()
	tmpl := strings.Replace(DefaultConfigTemplate, "  max_page_size: 200\n", "  max_page_size: 200\n"+strings.TrimPrefix(customOpsTemplate, "\n"), 1)
	env := New(t, WithRolesYAML(filterRoles), WithConfigTemplate(tmpl))
	admin := env.Token(t, "admin", 4)
	reader := env.Token(t, "reader", 1)
	const q = `query($w: posts_bool_exp) { posts_connection(where: $w) { nodes { id } } }`
	w := func(m map[string]any) map[string]any { return map[string]any{"w": m} }
	op := func(col, op string, val any) map[string]any { return map[string]any{col: map[string]any{op: val}} }

	// The reader's where type only carries the configured surface.
	fields := inputFieldNames(t, env, reader, "posts_bool_exp")
	wantFields := []string{"_and", "_not", "_or", "author", "author_id", "id", "published_on", "title"}
	if !slices.Equal(fields, wantFields) {
		t.Errorf("reader posts_bool_exp = %v, want %v", fields, wantFields)
	}
	if got := inputFieldNames(t, env, reader, "posts_title_comparison_exp"); !slices.Equal(got, []string{"_eq", "_istarts_with"}) {
		t.Errorf("reader title operators = %v", got)
	}
	if got := inputFieldNames(t, env, reader, "users_name_comparison_exp"); !slices.Equal(got, []string{"_eq", "_in"}) {
		t.Errorf("reader users.name operators = %v", got)
	}
	// The admin keeps the full, shared comparison types.
	if got := inputFieldNames(t, env, admin, "String_comparison_exp"); !slices.Contains(got, "_like") || !slices.Contains(got, "_len_gt") {
		t.Errorf("admin String_comparison_exp = %v", got)
	}

	// Allowed: configured columns/operators and the author relationship.
	wantIDs(t, "reader _istarts_with", ids(t, env, reader, q, "posts_connection.nodes", w(op("title", "_istarts_with", "notes"))), 1)
	wantIDs(t, "reader author", ids(t, env, reader, q, "posts_connection.nodes",
		w(map[string]any{"author": op("name", "_eq", "Ada Lovelace")})), 1, 2)
	wantIDs(t, "reader custom op on Date", ids(t, env, reader, q, "posts_connection.nodes", w(op("published_on", "_year_eq", 2026))), 1, 3, 4)

	// Negative: operators, columns and relationships outside the surface,
	// whether inline or smuggled in through variables.
	env.GQL(t, reader, `{ posts_connection(where: {title: {_like: "%"}}) { nodes { id } } }`, nil).MustFail(t, "_like")
	env.GQL(t, reader, q, w(op("title", "_len_gt", 3))).MustFail(t, "_len_gt")
	env.GQL(t, reader, q, w(op("body", "_eq", "x"))).MustFail(t, "body")
	env.GQL(t, reader, q, w(op("published", "_eq", false))).MustFail(t, "published")
	env.GQL(t, reader, q, w(map[string]any{"comments": map[string]any{}})).MustFail(t, "comments")
	env.GQL(t, reader, q, w(map[string]any{"author": op("name", "_ilike", "%ada%")})).MustFail(t, "_ilike")
	// Non-filterable columns stay selectable.
	r := env.MustGQL(t, reader, `{ posts_by_pk(id: 2) { body published } }`, nil)
	if r.String(t, "posts_by_pk.body") != "Unpublished musings." {
		t.Errorf("reader cannot read body: %s", r.Raw)
	}

	// Custom operators for the unrestricted admin.
	wantIDs(t, "admin _len_gt", ids(t, env, admin, q, "posts_connection.nodes", w(op("title", "_len_gt", 25))), 1)
	wantIDs(t, "admin _year_eq on DateTime", ids(t, env, admin, `{ users_connection(where: {created_at: {_year_eq: 1999}}) { nodes { id } } }`, "users_connection.nodes", nil))
	wantIDs(t, "admin unrestricted", ids(t, env, admin, q, "posts_connection.nodes", w(op("body", "_icontains", "cobol"))), 3)

	// The target table's row filter applies inside relationship filters,
	// with its JWT claims bound: member (sub 2) only "sees" user 2.
	member := env.Token(t, "member", 2)
	wantIDs(t, "member author:{}", ids(t, env, member, q, "posts_connection.nodes", w(map[string]any{"author": map[string]any{}})), 3)
	wantIDs(t, "member _not author:{}", ids(t, env, member, q, "posts_connection.nodes",
		w(map[string]any{"_not": map[string]any{"author": map[string]any{}}})), 1, 2, 4)
	wantIDs(t, "admin author:{}", ids(t, env, admin, q, "posts_connection.nodes", w(map[string]any{"author": map[string]any{}})), 1, 2, 3, 4)

	// A role that cannot select the target gets no relationship filter.
	env.GQL(t, env.Token(t, "postsonly", 1), q, w(map[string]any{"author": map[string]any{}})).MustFail(t, "author")

	// A target row filter that does not resolve against its own table
	// ("published" is a posts column, not a users one) must never be embedded
	// in a correlated subquery, where it would silently bind to the outer
	// posts row. The gateway starts, but withholds the relationship.
	leaky := env.Token(t, "leaky", 1)
	if got := inputFieldNames(t, env, leaky, "posts_bool_exp"); slices.Contains(got, "author") {
		t.Errorf("leaky role must not get the author relationship filter: %v", got)
	}
	env.GQL(t, leaky, q, w(map[string]any{"author": map[string]any{}})).MustFail(t, "author")

	// A custom operator whose SQL does not run fails startup.
	bad := *env.Config
	bad.SchemaGen.CustomOperators = []config.CustomOperator{{Name: "_bad", Argument: "Int", SQL: "NO_SUCH_FN({column}) = {value}"}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if gate, err := gqlgate.Open(ctx, &bad); err == nil {
		gate.Close()
		t.Error("a custom operator with invalid SQL must fail startup")
	} else if !strings.Contains(err.Error(), "_bad") {
		t.Errorf("startup error should name the operator: %v", err)
	}

	// Hot reload rebuilds the surface: drop the reader's relationship filters.
	if err := env.Reload(t, strings.Replace(filterRoles, "filter_relationships: [author]", "filter_relationships: []", 1)); err != nil {
		t.Fatalf("reload: %v", err)
	}
	env.GQL(t, reader, q, w(map[string]any{"author": map[string]any{}})).MustFail(t, "author")
	wantIDs(t, "reader after reload", ids(t, env, reader, q, "posts_connection.nodes", w(op("title", "_istarts_with", "on"))), 4)
}

func TestRelationshipFilters(t *testing.T) {
	t.Parallel()
	env := New(t)
	admin := env.Token(t, "admin", 4)
	const pq = `query($w: posts_bool_exp) { posts_connection(where: $w) { nodes { id } total_count } }`
	const uq = `query($w: users_bool_exp) { users_connection(where: $w) { nodes { id } } }`
	const cq = `query($w: comments_bool_exp) { comments_connection(where: $w) { nodes { id } } }`
	posts := func(token string, where map[string]any) []int64 {
		t.Helper()
		return ids(t, env, token, pq, "posts_connection.nodes", map[string]any{"w": where})
	}
	users := func(token string, where map[string]any) []int64 {
		t.Helper()
		return ids(t, env, token, uq, "users_connection.nodes", map[string]any{"w": where})
	}
	m := func(kv ...any) map[string]any {
		out := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			out[kv[i].(string)] = kv[i+1]
		}
		return out
	}
	empty := map[string]any{}

	// Object relationship: the related row matches.
	wantIDs(t, "author name", posts(admin, m("author", m("name", m("_eq", "Ada Lovelace")))), 1, 2)
	// Array relationship: at least one related row matches; {} = has any; _not = has none.
	wantIDs(t, "has comments", posts(admin, m("comments", empty)), 1, 3, 4)
	wantIDs(t, "no comments", posts(admin, m("_not", m("comments", empty))), 2)
	wantIDs(t, "users with an unpublished post", users(admin, m("posts", m("published", m("_eq", false)))), 1)
	wantIDs(t, "users without posts", users(admin, m("_not", m("posts", empty))), 4)

	// An _and inside an array relationship is ONE EXISTS (the same comment
	// must satisfy both); two relationship predicates may match different rows.
	wantIDs(t, "same comment", posts(admin, m("comments", m("_and", []any{
		m("user_id", m("_eq", 2)), m("body", m("_icontains", "inspired"))}))))
	wantIDs(t, "different comments", posts(admin, m("_and", []any{
		m("comments", m("user_id", m("_eq", 2))), m("comments", m("body", m("_icontains", "inspired")))})), 1)
	wantIDs(t, "_or across relationships", posts(admin, m("_or", []any{
		m("author", m("is_active", m("_eq", false))), m("comments", m("body", m("_icontains", "cobol")))})), 3, 4)

	// Nesting: users whose posts received a comment from Grace.
	wantIDs(t, "nested", users(admin, m("posts", m("comments", m("user", m("name", m("_eq", "Grace Hopper")))))), 1, 3)
	wantIDs(t, "comments on inactive authors' posts", ids(t, env, admin, cq, "comments_connection.nodes",
		map[string]any{"w": m("post", m("author", m("is_active", m("_eq", false))))}), 4, 5)

	// Works in total_count, aggregates, nested relationship where args and pagination.
	r := env.MustGQL(t, admin, pq, map[string]any{"w": m("author", m("name", m("_eq", "Ada Lovelace")))})
	if n := r.Int(t, "posts_connection.total_count"); n != 2 {
		t.Errorf("total_count = %d, want 2", n)
	}
	r = env.MustGQL(t, admin, `{ posts_aggregate(where: {comments: {user: {name: {_eq: "Ada Lovelace"}}}}) { count sum { views } } }`, nil)
	if n := r.Int(t, "posts_aggregate.count"); n != 2 {
		t.Errorf("aggregate count = %d, want 2", n)
	}
	r = env.MustGQL(t, admin, `{ users_by_pk(id: 1) { posts(where: {comments: {}}) { id } } }`, nil)
	wantIDs(t, "nested relationship where arg", r.IDs(t, "users_by_pk.posts"), 1)
	r = env.MustGQL(t, admin, `{ users_connection(where: {posts: {}}) { nodes { id posts(where: {_not: {comments: {}}}) { id } } } }`, nil)
	wantIDs(t, "batched nested where", r.IDs(t, "users_connection.nodes.0.posts"), 2)
	r = env.MustGQL(t, admin, `{ posts_connection(first: 1, where: {comments: {}}) { nodes { id } page_info { end_cursor } } }`, nil)
	cursor := r.String(t, "posts_connection.page_info.end_cursor")
	r = env.MustGQL(t, admin, `query($a: String) { posts_connection(first: 5, after: $a, where: {comments: {}}) { nodes { id } } }`, map[string]any{"a": cursor})
	wantIDs(t, "second page", r.IDs(t, "posts_connection.nodes"), 3, 4)

	// The author role reads users through a column subset; is_active is in it.
	author := env.Token(t, "author", 1)
	wantIDs(t, "author role via is_active", posts(author, m("author", m("is_active", m("_eq", false)))), 4)

	// Negative RBAC for anonymous: the TARGET's row filter is applied inside
	// the subquery (post 2 is unpublished, so it cannot be matched)...
	wantIDs(t, "admin sees the draft through users.posts", users(admin, m("posts", m("title", m("_icontains", "draft")))), 1)
	wantIDs(t, "anonymous cannot match the hidden draft", users("", m("posts", m("title", m("_icontains", "draft")))))
	wantIDs(t, "anonymous: users with no VISIBLE posts", users("", m("_not", m("posts", empty))), 4)
	// ...and hidden target columns cannot be filtered on through a relationship.
	env.GQL(t, "", uq, map[string]any{"w": m("posts", m("published", m("_eq", false)))}).MustFail(t, "published")
	// The target's filter surface applies too (anonymous may not regex titles).
	env.GQL(t, "", uq, map[string]any{"w": m("posts", m("title", m("_iregex", "draft")))}).MustFail(t, "_iregex")
	env.GQL(t, "", pq, map[string]any{"w": m("author", m("email", m("_eq", "ada@example.com")))}).MustFail(t, "email")
	env.GQL(t, "", `{ users_connection(where: {posts: {published: {_eq: false}}}) { nodes { id } } }`, nil).MustFail(t, "published")
}

func TestRelationshipFilterMutations(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(
		`CREATE TABLE categories (
			id BIGINT PRIMARY KEY,
			parent_id BIGINT NULL,
			name VARCHAR(50) NOT NULL,
			CONSTRAINT fk_categories_parent FOREIGN KEY (parent_id) REFERENCES categories (id)
		)`,
		"INSERT INTO categories (id, parent_id, name) VALUES (1, NULL, 'root'), (2, 1, 'books'), (3, 2, 'scifi'), (4, 1, 'music')",
	))
	admin := env.Token(t, "admin", 4)

	// Self-referential relationships: "parent" (object) and "categories"
	// (array of children), each nesting level aliased.
	r := env.MustGQL(t, admin, `{ categories_connection(where: {parent: {parent: {name: {_eq: "root"}}}}) { nodes { id } } }`, nil)
	wantIDs(t, "grandchildren of root", r.IDs(t, "categories_connection.nodes"), 3)
	r = env.MustGQL(t, admin, `{ categories_connection(where: {categories: {categories: {}}}) { nodes { id } } }`, nil)
	wantIDs(t, "has grandchildren", r.IDs(t, "categories_connection.nodes"), 1)

	// UPDATE/DELETE whose where reads the same table through a relationship
	// (the MySQL error-1093 shape) works on TiDB.
	r = env.MustGQL(t, admin, `mutation { update_categories(where: {categories: {}}, _set: {name: "branch"}) { affected_rows } }`, nil)
	if n := r.Int(t, "update_categories.affected_rows"); n != 2 {
		t.Errorf("update affected %d, want 2 (categories 1 and 2 have children)", n)
	}
	r = env.MustGQL(t, admin, `mutation { delete_categories(where: {_not: {categories: {}}, parent: {id: {_eq: 1}}}) { affected_rows } }`, nil)
	if n := r.Int(t, "delete_categories.affected_rows"); n != 1 {
		t.Errorf("delete affected %d, want 1 (leaf 4 under root)", n)
	}
	if got := env.QueryString(t, "SELECT GROUP_CONCAT(id ORDER BY id) FROM categories"); got != "1,2,3" {
		t.Errorf("categories left = %s", got)
	}
	if got := env.QueryString(t, "SELECT GROUP_CONCAT(name ORDER BY id) FROM categories"); got != "branch,branch,scifi" {
		t.Errorf("category names = %s", got)
	}
	r = env.MustGQL(t, admin, `mutation { update_posts(where: {author: {posts: {id: {_eq: 2}}}}, _set: {views: 7}) { affected_rows } }`, nil)
	if n := r.Int(t, "update_posts.affected_rows"); n != 2 {
		t.Errorf("posts of the author of post 2: affected %d, want 2", n)
	}

	// The role's delete filter still applies on top of a relationship where:
	// grace (author 2) may delete her own comments and comments on her posts.
	grace := env.Token(t, "author", 2)
	r = env.MustGQL(t, grace, `mutation { delete_comments(where: {post: {author_id: {_eq: 1}}}) { affected_rows } }`, nil)
	if n := r.Int(t, "delete_comments.affected_rows"); n != 1 {
		t.Errorf("grace deleted %d comments on ada's posts, want only her own (1)", n)
	}
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM comments WHERE id IN (1, 2)"); n != 1 {
		t.Errorf("comments 1,2 remaining = %d, want 1 (alan's)", n)
	}
	r = env.MustGQL(t, grace, `mutation { delete_comments(where: {post: {title: {_starts_with: "Compilers"}}}) { affected_rows } }`, nil)
	if n := r.Int(t, "delete_comments.affected_rows"); n != 1 {
		t.Errorf("comments on grace's post deleted = %d, want 1", n)
	}
	// Anonymous has no mutations at all.
	env.GQL(t, "", `mutation { delete_comments(where: {post: {}}) { affected_rows } }`, nil).MustFail(t, "")
}

func TestRelationshipFilterNearest(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(
		`CREATE TABLE doc_tags (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			doc_id BIGINT NOT NULL,
			tag VARCHAR(20) NOT NULL,
			CONSTRAINT fk_doc_tags_doc FOREIGN KEY (doc_id) REFERENCES documents (id)
		)`,
		"INSERT INTO doc_tags (doc_id, tag) VALUES (1, 'red'), (3, 'red'), (2, 'blue')",
	))
	const q = `query($w: documents_bool_exp) {
		documents_nearest_by_embedding(to: "[1,2,3]", first: 5, where: $w) { node { id } }
	}`
	nearest := func(token string, where map[string]any) *Result {
		return env.GQL(t, token, q, map[string]any{"w": where})
	}
	r := nearest(env.Token(t, "admin", 4), map[string]any{"doc_tags": map[string]any{"tag": map[string]any{"_eq": "red"}}}).MustOK(t)
	var got []int64
	for i := range r.List(t, "documents_nearest_by_embedding") {
		got = append(got, r.Int(t, "documents_nearest_by_embedding."+strconv.Itoa(i)+".node.id"))
	}
	wantIDs(t, "nearest red", got, 1, 3)
	// Anonymous can read documents but not doc_tags: no such filter for it.
	nearest("", map[string]any{"doc_tags": map[string]any{}}).MustFail(t, "doc_tags")
}

// TestDemoConfigFilters opens the gateway with the roles and custom operators
// of the demo gqlgate.yaml (over the same blog schema the demo seeds), so the
// documented examples keep working.
func TestDemoConfigFilters(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "gqlgate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	demo, err := config.Parse(bytes.ReplaceAll(raw, []byte("${GQLGATE_JWT_SECRET}"), []byte(JWTSecret)))
	if err != nil {
		t.Fatalf("demo gqlgate.yaml: %v", err)
	}
	env := New(t, WithConfig(func(c *config.Config) {
		c.Roles = demo.Roles
		c.SchemaGen.CustomOperators = demo.SchemaGen.CustomOperators
	}))

	r := env.MustGQL(t, "", `{ posts_connection(where: {published_on: {_year_eq: 2026}, author: {name: {_eq: "Ada Lovelace"}}, title: {_istarts_with: "notes"}}) { nodes { id } } }`, nil)
	wantIDs(t, "anonymous demo filter", r.IDs(t, "posts_connection.nodes"), 1)
	env.GQL(t, "", `{ posts_connection(where: {title: {_ilike: "%a%"}}) { nodes { id } } }`, nil).MustFail(t, "_ilike")

	r = env.MustGQL(t, env.Token(t, "admin", 4), `{ users_connection(where: {posts: {comments: {user: {name: {_eq: "Grace Hopper"}}}}}) { nodes { id } } }`, nil)
	wantIDs(t, "admin demo relationship filter", r.IDs(t, "users_connection.nodes"), 1, 3)
}
