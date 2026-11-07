package e2e

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"gqlgate/config"
)

// End-to-end tests for native queries: parameterized read-only SQL exposed
// as root query fields, with per-role columns, row filters and argument
// presets, keyset connections and relationships into tables.

const nativeYAML = `native_queries:
  post_stats:
    sql: |
      SELECT p.id AS post_id, p.author_id, p.title, p.views, p.published,
             COUNT(c.id) AS comment_count   -- comments per post
      FROM posts p LEFT JOIN comments c ON c.post_id = p.id
      WHERE p.author_id = :author AND (:min_views IS NULL OR p.views >= :min_views)
      GROUP BY p.id, p.author_id, p.title, p.views, p.published
    arguments:
      author: BigInt!
      min_views: {type: Int, description: "Only posts with at least this many views"}
    columns:
      published: Boolean!
      comment_count: {type: BigInt!, name: commentCount, description: "Comments on the post"}
    key: [post_id]
    description: "Per-post statistics of one author."
    relationships:
      author: {type: object, target: users, mapping: {author_id: id}}
      comments: {type: array, target: comments, mapping: {post_id: post_id}}
  top_commenters:
    sql: |
      WITH counts AS (SELECT user_id, COUNT(*) AS n FROM comments GROUP BY user_id)
      SELECT u.id AS user_id, u.name, counts.n AS comment_count,
             RANK() OVER (ORDER BY counts.n DESC) AS rnk
      FROM counts JOIN users u ON u.id = counts.user_id
      WHERE counts.n >= :min_comments AND u.name <> 'x:y ?'
    arguments:
      min_comments: Int!
    root_fields:
      list: {name: topCommenters, description: "Commenters ranked by comment count"}
  titles_like:
    sql: "SELECT id, title FROM posts WHERE title LIKE :pattern"
    arguments:
      pattern: String!
    key: [id]
  logins:
    sql: "SELECT username AS login, CHAR_LENGTH(username) AS len FROM users"
    relationships:
      user: {type: object, target: users, mapping: {login: username}}
`

const nativeRoles = `roles:
  admin:
    tables:
      "*": {select: true}
    native_queries:
      post_stats: true
      top_commenters: true
      titles_like: true
      logins: true
  author:
    tables:
      users: {select: {allow: true, columns: [id, name]}}
      comments: {select: true}
    native_queries:
      post_stats:
        allow: true
        columns: [post_id, author_id, title, views, comment_count]
        presets: {author: ":jwt.sub"}
        filterable_columns: [views, title]
  anonymous:
    tables:
      users: {select: {allow: true, columns: [id, name]}}
    native_queries:
      top_commenters:
        allow: true
        columns: [user_id, name, rnk]
        filter: "rnk = 1"
`

func newNativeEnv(t *testing.T) *Env {
	t.Helper()
	return New(t, WithExtraYAML(nativeYAML), WithRolesYAML(nativeRoles))
}

func TestNativeQueryListAndArguments(t *testing.T) {
	t.Parallel()
	env := newNativeEnv(t)
	admin := env.Token(t, "admin", 4)

	r := env.MustGQL(t, admin, `{ post_stats(args: {author: 1}) { post_id title published commentCount } }`, nil)
	got := map[int64]int64{}
	for i := range r.List(t, "post_stats") {
		got[r.Int(t, "post_stats."+strconv.Itoa(i)+".post_id")] = r.Int(t, "post_stats."+strconv.Itoa(i)+".commentCount")
	}
	if !reflect.DeepEqual(got, map[int64]int64{1: 2, 2: 0}) {
		t.Errorf("post_stats(author: 1) = %v", got)
	}
	for i := range r.List(t, "post_stats") {
		p := "post_stats." + strconv.Itoa(i) + "."
		want := r.Int(t, p+"post_id") == 1 // post 1 is published, post 2 is not
		if r.Get(p+"published") != want {
			t.Errorf("published (declared Boolean!): %s", r.Raw)
		}
	}

	// Optional argument: omitted = NULL (no view floor), given = applied.
	r = env.MustGQL(t, admin, `{ post_stats(args: {author: 1, min_views: 100}) { post_id } }`, nil)
	if ids := r.List(t, "post_stats"); len(ids) != 1 || r.Int(t, "post_stats.0.post_id") != 1 {
		t.Errorf("min_views: %s", r.Raw)
	}

	// Variables work and are bound as parameters, never spliced into SQL.
	r = env.MustGQL(t, admin, `query($p: String!) { titles_like(args: {pattern: $p}) { id } }`,
		map[string]any{"p": "x' OR '1'='1"})
	if n := len(r.List(t, "titles_like")); n != 0 {
		t.Errorf("injection attempt matched %d rows: %s", n, r.Raw)
	}
	r = env.MustGQL(t, admin, `{ titles_like(args: {pattern: "%omp%"}) { id title } }`, nil)
	if ids := r.IDs(t, "titles_like"); !reflect.DeepEqual(ids, []int64{3, 4}) && !reflect.DeepEqual(ids, []int64{4, 3}) {
		t.Errorf("titles_like: %s", r.Raw)
	}

	// A required argument is required.
	env.GQL(t, admin, `{ post_stats { post_id } }`, nil).MustFail(t, "args")
	env.GQL(t, admin, `{ post_stats(args: {min_views: 1}) { post_id } }`, nil).MustFail(t, "author")

	// CTE + window function, renamed list field, limit and where.
	r = env.MustGQL(t, admin, `{ topCommenters(args: {min_comments: 1}, where: {rnk: {_eq: 1}}) { user_id comment_count rnk } }`, nil)
	if n := len(r.List(t, "topCommenters")); n != 2 {
		t.Errorf("topCommenters rank 1: %s", r.Raw)
	}
	r = env.MustGQL(t, admin, `{ topCommenters(args: {min_comments: 1}, limit: 1) { user_id } }`, nil)
	if n := len(r.List(t, "topCommenters")); n != 1 {
		t.Errorf("limit 1: %s", r.Raw)
	}
	env.GQL(t, admin, `{ topCommenters(args: {min_comments: 1}, limit: -1) { user_id } }`, nil).MustFail(t, "limit must be >= 0")
	if _, ok := env.MustGQL(t, admin, `{ __type(name: "Query") { fields { name } } }`, nil).Data["__type"]; !ok {
		t.Fatal("introspection failed")
	}
}

func TestNativeQueryPresetsAndRBAC(t *testing.T) {
	t.Parallel()
	env := newNativeEnv(t)
	grace := env.Token(t, "author", 2)

	// The author argument is preset from the token: grace sees her post only.
	r := env.MustGQL(t, grace, `{ post_stats { post_id title commentCount } }`, nil)
	if ids := r.List(t, "post_stats"); len(ids) != 1 || r.Int(t, "post_stats.0.post_id") != 3 {
		t.Errorf("author preset: %s", r.Raw)
	}
	// It cannot be passed, not even through variables.
	env.GQL(t, grace, `{ post_stats(args: {author: 1}) { post_id } }`, nil).MustFail(t, "author")
	env.GQL(t, grace, `query($a: post_stats_arguments) { post_stats(args: $a) { post_id } }`,
		map[string]any{"a": map[string]any{"author": 1}}).MustFail(t, "author")
	// The remaining optional argument still works.
	r = env.MustGQL(t, grace, `{ post_stats(args: {min_views: 1000}) { post_id } }`, nil)
	if n := len(r.List(t, "post_stats")); n != 0 {
		t.Errorf("min_views 1000: %s", r.Raw)
	}
	// The arguments type has no author field for this role.
	r = env.MustGQL(t, grace, `{ __type(name: "post_stats_arguments") { inputFields { name } } }`, nil)
	if f := r.List(t, "__type.inputFields"); len(f) != 1 || r.String(t, "__type.inputFields.0.name") != "min_views" {
		t.Errorf("post_stats_arguments for author: %s", r.Raw)
	}

	// Hidden column: neither selectable nor filterable; non-filterable
	// readable column not filterable either.
	env.GQL(t, grace, `{ post_stats { published } }`, nil).MustFail(t, "Cannot query field")
	env.GQL(t, grace, `{ post_stats(where: {published: {_eq: true}}) { post_id } }`, nil).MustFail(t, "published")
	env.GQL(t, grace, `{ post_stats(where: {commentCount: {_gt: 0}}) { post_id } }`, nil).MustFail(t, "commentCount")
	r = env.MustGQL(t, grace, `{ post_stats(where: {views: {_gt: 100}}) { post_id } }`, nil)
	if n := len(r.List(t, "post_stats")); n != 1 {
		t.Errorf("filter on views: %s", r.Raw)
	}

	// A token without the preset claim fails closed.
	nosub := env.SignClaims(t, map[string]any{"role": "author"})
	env.GQL(t, nosub, `{ post_stats { post_id } }`, nil).MustFail(t, "sub")

	// anonymous: not granted post_stats; top_commenters through its row
	// filter (rank 1 only) and without the comment_count column.
	env.GQL(t, "", `{ post_stats(args: {author: 1}) { post_id } }`, nil).MustFail(t, "Cannot query field")
	r = env.MustGQL(t, "", `{ topCommenters(args: {min_comments: 0}) { user_id name rnk } }`, nil)
	if n := len(r.List(t, "topCommenters")); n != 2 {
		t.Errorf("anonymous rank-1 filter: %s", r.Raw)
	}
	for i := range r.List(t, "topCommenters") {
		if r.Int(t, "topCommenters."+strconv.Itoa(i)+".rnk") != 1 {
			t.Errorf("anonymous saw a filtered row: %s", r.Raw)
		}
	}
	// The where cannot widen the row filter.
	r = env.MustGQL(t, "", `{ topCommenters(args: {min_comments: 0}, where: {rnk: {_gt: 1}}) { user_id } }`, nil)
	if n := len(r.List(t, "topCommenters")); n != 0 {
		t.Errorf("where widened the row filter: %s", r.Raw)
	}
	env.GQL(t, "", `{ topCommenters(args: {min_comments: 0}) { comment_count } }`, nil).MustFail(t, "Cannot query field")
	env.GQL(t, "", `{ topCommenters(args: {min_comments: 0}, where: {comment_count: {_gt: 1}}) { user_id } }`, nil).MustFail(t, "comment_count")
	// No key: no connection field.
	env.GQL(t, "", `{ top_commenters_connection(args: {min_comments: 0}) { nodes { user_id } } }`, nil).MustFail(t, "Cannot query field")
	// titles_like is admin-only.
	env.GQL(t, grace, `{ titles_like(args: {pattern: "%"}) { id } }`, nil).MustFail(t, "Cannot query field")
}

func TestNativeQueryConnection(t *testing.T) {
	t.Parallel()
	env := newNativeEnv(t)
	admin := env.Token(t, "admin", 4)

	q := `query($after: String, $a: BigInt!) { post_stats_connection(args: {author: $a}, first: 1, after: $after) {
	  nodes { post_id } page_info { has_next_page end_cursor } total_count } }`
	r := env.MustGQL(t, admin, q, map[string]any{"a": 1})
	if r.Int(t, "post_stats_connection.nodes.0.post_id") != 1 || r.Get("post_stats_connection.page_info.has_next_page") != true ||
		r.Int(t, "post_stats_connection.total_count") != 2 {
		t.Fatalf("page 1: %s", r.Raw)
	}
	cursor := r.String(t, "post_stats_connection.page_info.end_cursor")
	r = env.MustGQL(t, admin, q, map[string]any{"a": 1, "after": cursor})
	if r.Int(t, "post_stats_connection.nodes.0.post_id") != 2 || r.Get("post_stats_connection.page_info.has_next_page") != false {
		t.Fatalf("page 2: %s", r.Raw)
	}
	// The cursor is bound to the argument values.
	env.GQL(t, admin, q, map[string]any{"a": 2, "after": cursor}).MustFail(t, "cursor does not match")

	// The author's connection pages its own (preset) rows only.
	grace := env.Token(t, "author", 2)
	r = env.MustGQL(t, grace, `{ post_stats_connection { nodes { post_id } total_count } }`, nil)
	if r.Int(t, "post_stats_connection.total_count") != 1 || r.Int(t, "post_stats_connection.nodes.0.post_id") != 3 {
		t.Errorf("author connection: %s", r.Raw)
	}
	// Another user's cursor (other preset values) does not apply.
	ada := env.Token(t, "author", 1)
	r = env.MustGQL(t, ada, `{ post_stats_connection(first: 1) { page_info { end_cursor } } }`, nil)
	adaCursor := r.String(t, "post_stats_connection.page_info.end_cursor")
	env.GQL(t, grace, `query($c: String) { post_stats_connection(after: $c) { nodes { post_id } } }`,
		map[string]any{"c": adaCursor}).MustFail(t, "cursor does not match")
}

func TestNativeQueryRelationships(t *testing.T) {
	t.Parallel()
	env := newNativeEnv(t)
	admin := env.Token(t, "admin", 4)

	r := env.MustGQL(t, admin, `{ post_stats(args: {author: 1}, where: {post_id: {_eq: 1}}) {
	  post_id author { name } comments(order_by: [{id: asc}]) { id } comments_aggregate { count } } }`, nil)
	if r.String(t, "post_stats.0.author.name") != "Ada Lovelace" {
		t.Errorf("object relationship: %s", r.Raw)
	}
	if ids := r.IDs(t, "post_stats.0.comments"); !reflect.DeepEqual(ids, []int64{1, 2}) {
		t.Errorf("array relationship: %s", r.Raw)
	}
	if r.Int(t, "post_stats.0.comments_aggregate.count") != 2 {
		t.Errorf("nested aggregate: %s", r.Raw)
	}
	// Relationship filter (EXISTS correlated to the derived table).
	r = env.MustGQL(t, admin, `{ post_stats(args: {author: 1}, where: {comments: {user_id: {_eq: 3}}}) { post_id } }`, nil)
	if n := len(r.List(t, "post_stats")); n != 1 || r.Int(t, "post_stats.0.post_id") != 1 {
		t.Errorf("relationship filter: %s", r.Raw)
	}
	// A string join: the result column's collation is read from the
	// database and matches users.username, so the declared relationship and
	// its filter work.
	r = env.MustGQL(t, admin, `{ logins(where: {user: {email: {_eq: "grace@example.com"}}}) { login len user { name } } }`, nil)
	if n := len(r.List(t, "logins")); n != 1 || r.String(t, "logins.0.user.name") != "Grace Hopper" || r.Int(t, "logins.0.len") != 5 {
		t.Errorf("string-keyed relationship: %s", r.Raw)
	}
	r = env.MustGQL(t, admin, `{ post_stats(args: {author: 1}, where: {author: {name: {_eq: "nobody"}}}) { post_id } }`, nil)
	if n := len(r.List(t, "post_stats")); n != 0 {
		t.Errorf("object relationship filter: %s", r.Raw)
	}

	// The target's permissions apply: the author role reads users.id/name
	// only, so it cannot filter through author on a hidden column.
	grace := env.Token(t, "author", 2)
	r = env.MustGQL(t, grace, `{ post_stats { author { name } comments { id } } }`, nil)
	if r.String(t, "post_stats.0.author.name") != "Grace Hopper" {
		t.Errorf("author role relationship: %s", r.Raw)
	}
	env.GQL(t, grace, `{ post_stats { author { email } } }`, nil).MustFail(t, "Cannot query field")
	// filterable_columns lists views and title only, so author_id (the
	// join column) is not filterable and relationship filters are withheld.
	env.GQL(t, grace, `{ post_stats(where: {author: {name: {_eq: "x"}}}) { post_id } }`, nil).MustFail(t, "author")
}

func TestNativeQueryValidationAndReload(t *testing.T) {
	t.Parallel()
	env := newNativeEnv(t)
	admin := env.Token(t, "admin", 4)

	reject := func(extra, want string) {
		t.Helper()
		// extra is a native_queries: block; its entries join the working ones.
		err := env.ReloadExtra(t, nativeYAML+strings.TrimPrefix(extra, "native_queries:\n"))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("reload with %q: err = %v, want %q", extra, err, want)
		}
	}
	// Writes are rejected before they reach the database.
	reject("native_queries:\n  wipe:\n    sql: \"DELETE FROM posts\"\n", "only SELECT")
	reject("native_queries:\n  wipe:\n    sql: \"WITH x AS (SELECT 1) DELETE FROM posts\"\n", "DELETE is not allowed")
	reject("native_queries:\n  two:\n    sql: \"SELECT 1 AS a; DELETE FROM posts\"\n", "only one statement")
	reject("native_queries:\n  lock:\n    sql: \"SELECT id FROM posts FOR UPDATE\"\n", "UPDATE is not allowed")
	// Parameters must be declared; claims are presets, not SQL.
	reject("native_queries:\n  q:\n    sql: \"SELECT id FROM posts WHERE id = :id\"\n", "parameter :id is not declared")
	reject("native_queries:\n  q:\n    sql: \"SELECT id FROM posts WHERE author_id = :jwt.sub\"\n", "claims are not referenced")
	// Bad SQL fails at build time with a clear error.
	reject("native_queries:\n  q:\n    sql: \"SELECT nope FROM posts\"\n", "native_queries.q.sql: the statement does not run")
	reject("native_queries:\n  q:\n    sql: \"SELECT id, id FROM posts\"\n", "native_queries.q")
	reject("native_queries:\n  q:\n    sql: \"SELECT id FROM posts\"\n    key: [missing]\n", "native_queries.q.key")
	reject("native_queries:\n  q:\n    sql: \"SELECT id, body FROM posts\"\n    key: [body]\n", "cannot be a key column")
	reject("native_queries:\n  q:\n    sql: \"SELECT id FROM posts\"\n    relationships:\n      u: {type: object, target: users, mapping: {id: email}}\n", "join-compatible")
	reject("native_queries:\n  q:\n    sql: \"SELECT username COLLATE utf8mb4_general_ci AS login FROM users\"\n    relationships:\n      u: {type: object, target: users, mapping: {login: username}}\n", "collation")
	reject("native_queries:\n  posts_connection:\n    sql: \"SELECT id FROM posts\"\n", "collides")

	// After every rejected reload the previous schema still serves, and the
	// table was never written.
	env.MustGQL(t, admin, `{ post_stats(args: {author: 1}) { post_id } }`, nil)
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM posts"); n != 4 {
		t.Fatalf("posts count = %d", n)
	}

	if err := env.ReloadExtra(t, nativeYAML); err != nil {
		t.Fatal(err)
	}
	// A role filter naming a column the statement does not return fails the
	// reload.
	err := env.Reload(t, strings.Replace(nativeRoles, `filter: "rnk = 1"`, `filter: "no_such_col = 1"`, 1))
	if err == nil || !strings.Contains(err.Error(), "verifying the filter") {
		t.Fatalf("bad role filter: err = %v", err)
	}
	// A preset for an undeclared argument fails too.
	err = env.Reload(t, strings.Replace(nativeRoles, `presets: {author: ":jwt.sub"}`, `presets: {writer: ":jwt.sub"}`, 1))
	if err == nil || !strings.Contains(err.Error(), "not a declared argument") {
		t.Fatalf("bad preset: err = %v", err)
	}

	// A valid reload adds a query (and its grant).
	if err := env.Reload(t, nativeRoles); err != nil {
		t.Fatal(err)
	}
	if err := env.ReloadExtra(t, nativeYAML+`  user_names:
    sql: "SELECT id, name FROM users"
`); err != nil {
		t.Fatal(err)
	}
	if err := env.Reload(t, strings.Replace(nativeRoles, "      titles_like: true\n", "      titles_like: true\n      user_names: true\n", 1)); err != nil {
		t.Fatal(err)
	}
	r := env.MustGQL(t, admin, `{ user_names(limit: 2) { id name } }`, nil)
	if n := len(r.List(t, "user_names")); n != 2 {
		t.Errorf("user_names after reload: %s", r.Raw)
	}
}

// TestDemoConfigNativeQueries runs the native query examples of the demo
// gqlgate.yaml over the demo seed, as the three demo roles.
func TestDemoConfigNativeQueries(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "gqlgate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	demo, err := config.Parse([]byte(strings.ReplaceAll(string(raw), "${GQLGATE_JWT_SECRET}", JWTSecret)))
	if err != nil {
		t.Fatalf("demo gqlgate.yaml: %v", err)
	}
	if len(demo.NativeQueries) == 0 {
		t.Fatal("the demo config no longer shows native queries")
	}
	env := New(t, WithSQL(demoModelingSQL(t)), WithConfig(func(c *config.Config) {
		c.Roles = demo.Roles
		c.SchemaGen = demo.SchemaGen
		c.Tables = demo.Tables
		c.JSONTypes = demo.JSONTypes
		c.NativeQueries = demo.NativeQueries
	}))

	admin := env.Token(t, "admin", 4)
	r := env.MustGQL(t, admin, `{ author_activity(args: {since: "2026-02-01"}) { author_id name posts views view_rank author { email } } }`, nil)
	if n := len(r.List(t, "author_activity")); n != 2 { // Grace (Mar 2) and Alan (Feb 20)
		t.Fatalf("author_activity since Feb: %s", r.Raw)
	}
	r = env.MustGQL(t, admin, `{ author_activity_connection(first: 1) { nodes { author_id } page_info { has_next_page } total_count } }`, nil)
	if r.Int(t, "author_activity_connection.nodes.0.author_id") != 1 || r.Int(t, "author_activity_connection.total_count") != 3 {
		t.Errorf("author_activity_connection: %s", r.Raw)
	}

	// The inbox of the caller only: author 1 owns posts 1 and 2 (comments
	// 1 and 2 on post 1); the argument cannot be passed.
	ada := env.Token(t, "author", 1)
	r = env.MustGQL(t, ada, `{ comment_inbox_connection { nodes { comment_id post_title commenter { name } post { id } } } }`, nil)
	if n := len(r.List(t, "comment_inbox_connection.nodes")); n != 2 || r.String(t, "comment_inbox_connection.nodes.0.commenter.name") != "Grace Hopper" {
		t.Errorf("ada's inbox: %s", r.Raw)
	}
	env.GQL(t, ada, `{ comment_inbox(args: {author: 2}) { comment_id } }`, nil).MustFail(t, "args")

	// anonymous: top 3 by views, without the raw counts; no inbox.
	r = env.MustGQL(t, "", `{ author_activity { name posts view_rank } }`, nil)
	if n := len(r.List(t, "author_activity")); n != 3 {
		t.Errorf("anonymous author_activity: %s", r.Raw)
	}
	env.GQL(t, "", `{ author_activity { views } }`, nil).MustFail(t, "Cannot query field")
	env.GQL(t, "", `{ comment_inbox(args: {author: 1}) { comment_id } }`, nil).MustFail(t, "Cannot query field")
}

// scopedYAML is a native query whose Int argument is preset from the sub
// claim in the "(:x IS NULL OR col = :x)" style, where a NULL binding would
// mean "every author".
const scopedYAML = `native_queries:
  scoped_posts:
    sql: |
      SELECT /*+ USE_INDEX(posts, fk_posts_author) */ id, author_id
      FROM posts WHERE (:author IS NULL OR author_id = :author)
    arguments:
      author: Int!
    key: [id]
`

const scopedRoles = `roles:
  admin:
    native_queries:
      scoped_posts: true
  author:
    native_queries:
      scoped_posts:
        allow: true
        presets: {author: ":jwt.sub"}
  anonymous:
    tables:
      users: {select: {allow: true, columns: [id]}}
`

// A claim that does not fit the preset argument's type exactly (out of the
// Int range, fractional, boolean or null) fails the request; it is never
// bound as NULL or truncated to another user's id.
func TestNativeQueryPresetClaimCoercion(t *testing.T) {
	t.Parallel()
	env := New(t, WithExtraYAML(scopedYAML), WithRolesYAML(scopedRoles))

	// admin passes the argument; the optimizer hint reaches TiDB intact.
	r := env.MustGQL(t, env.Token(t, "admin", 4), `{ scoped_posts(args: {author: 1}) { id author_id } }`, nil)
	if ids := r.IDs(t, "scoped_posts"); !reflect.DeepEqual(ids, []int64{1, 2}) && !reflect.DeepEqual(ids, []int64{2, 1}) {
		t.Errorf("admin scoped_posts(author: 1): %s", r.Raw)
	}

	// author: the preset scopes the rows to the caller (string or numeric sub).
	for _, sub := range []any{"2", float64(2)} {
		r = env.MustGQL(t, env.Token(t, "author", sub), `{ scoped_posts { id author_id } }`, nil)
		if ids := r.IDs(t, "scoped_posts"); !reflect.DeepEqual(ids, []int64{3}) {
			t.Errorf("author sub=%#v: %s", sub, r.Raw)
		}
	}
	// The argument cannot be passed by this role.
	env.GQL(t, env.Token(t, "author", "2"), `{ scoped_posts(args: {author: 1}) { id } }`, nil).MustFail(t, "args")

	bad := []struct {
		sub  any
		want string
	}{
		{"3000000000", "range of Int"},
		{float64(3000000000), "range of Int"},
		{float64(1.9), "is not an integer"},
		{"1.9", "is not an integer"},
		{true, "is not an integer"},
		{nil, "null"},
	}
	for _, c := range bad {
		tok := env.SignClaims(t, map[string]any{"role": "author", "sub": c.sub})
		env.GQL(t, tok, `{ scoped_posts { id author_id } }`, nil).MustFail(t, c.want)
		env.GQL(t, tok, `{ scoped_posts_connection { nodes { id } } }`, nil).MustFail(t, c.want)
	}
}

// Literal presets that do not fit their argument and native root fields
// that a table's generated fields already have fail the build (startup and
// hot reload) instead of failing every request or hiding the table's field.
func TestNativeQueryBuildChecksOnReload(t *testing.T) {
	t.Parallel()
	env := New(t, WithExtraYAML(scopedYAML), WithRolesYAML(scopedRoles))
	grace := env.Token(t, "author", 2)

	err := env.Reload(t, strings.Replace(scopedRoles, `":jwt.sub"`, `"not-a-number"`, 1))
	if err == nil || !strings.Contains(err.Error(), `"not-a-number" is not an integer`) {
		t.Fatalf("bad literal preset: err = %v", err)
	}
	err = env.Reload(t, strings.Replace(scopedRoles, `":jwt.sub"`, `"3000000000"`, 1))
	if err == nil || !strings.Contains(err.Error(), "range of Int") {
		t.Fatalf("out-of-range literal preset: err = %v", err)
	}
	if err := env.Reload(t, scopedRoles); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"users_by_email", "users_list"} {
		err = env.ReloadExtra(t, scopedYAML+"  "+name+":\n    sql: \"SELECT id FROM users\"\n")
		if err == nil || !strings.Contains(err.Error(), `"`+name+`" for native query "`+name+`" collides with table users`) {
			t.Fatalf("native %s: err = %v", name, err)
		}
	}
	err = env.ReloadExtra(t, scopedYAML+"  q:\n    sql: \"SELECT id FROM users\"\n    root_fields: {list: {name: users_by_username}}\n")
	if err == nil || !strings.Contains(err.Error(), "collides with table users") {
		t.Fatalf("native root field users_by_username: err = %v", err)
	}

	// The previous schema still serves; a valid literal preset works.
	r := env.MustGQL(t, grace, `{ scoped_posts { id } }`, nil)
	if ids := r.IDs(t, "scoped_posts"); !reflect.DeepEqual(ids, []int64{3}) {
		t.Errorf("after rejected reloads: %s", r.Raw)
	}
	if err := env.ReloadExtra(t, scopedYAML); err != nil {
		t.Fatal(err)
	}
	if err := env.Reload(t, strings.Replace(scopedRoles, `":jwt.sub"`, `"1"`, 1)); err != nil {
		t.Fatal(err)
	}
	r = env.MustGQL(t, grace, `{ scoped_posts { id } }`, nil)
	if ids := r.IDs(t, "scoped_posts"); !reflect.DeepEqual(ids, []int64{1, 2}) && !reflect.DeepEqual(ids, []int64{2, 1}) {
		t.Errorf("literal preset 1: %s", r.Raw)
	}
}
