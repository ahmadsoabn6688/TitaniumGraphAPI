package e2e

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gqlgate/config"
)

// End-to-end tests for aggregates: per-column count / count_distinct /
// approx_count_distinct, the statistical functions, 64-bit count types, and
// nested <rel>_aggregate fields on array relationships.
//
// Fixture recap (testdata/blog.sql): posts 1 (ada, views 420, rating 4.9),
// 2 (ada, unpublished, views 3, rating NULL, published_on NULL), 3 (grace,
// 250, 4.5), 4 (alan, 999, 5.0). Comments: 1 on post 1 by grace, 2 on post 1
// by alan, 3 on post 3 by ada, 4 on post 4 by ada, 5 on post 4 by grace.

// float returns the number at path, failing the test if it is not one.
func float(t *testing.T, r *Result, path string) float64 {
	t.Helper()
	switch v := r.Get(path).(type) {
	case float64:
		return v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	t.Fatalf("%s: not a number in %s", path, r.Raw)
	return 0
}

func wantInt(t *testing.T, r *Result, path string, want int64) {
	t.Helper()
	if got := r.Int(t, path); got != want {
		t.Errorf("%s = %d, want %d", path, got, want)
	}
}

func wantNull(t *testing.T, r *Result, path string) {
	t.Helper()
	if v := r.Get(path); v != nil {
		t.Errorf("%s = %v, want null", path, v)
	}
}

// typeOfField returns the printed type of typeName.field via introspection
// (e.g. "BigInt!").
func typeOfField(t *testing.T, env *Env, token, typeName, field string) string {
	t.Helper()
	r := env.MustGQL(t, token, `query($n: String!) { __type(name: $n) { fields { name type { kind name ofType { name } } } } }`,
		map[string]any{"n": typeName})
	for i := range r.List(t, "__type.fields") {
		p := "__type.fields." + strconv.Itoa(i)
		if r.String(t, p+".name") != field {
			continue
		}
		if r.Get(p+".type.kind") == "NON_NULL" {
			return r.String(t, p+".type.ofType.name") + "!"
		}
		return r.String(t, p+".type.name")
	}
	t.Fatalf("%s.%s not found", typeName, field)
	return ""
}

func TestAggregateCountColumnsAndDistinct(t *testing.T) {
	t.Parallel()
	env := New(t)
	admin := env.Token(t, "admin", 4)

	r := env.MustGQL(t, admin, `{ posts_aggregate {
		count
		count_columns { rating published_on body }
		count_distinct { author_id published }
		approx_count_distinct { author_id }
	} }`, nil)
	wantInt(t, r, "posts_aggregate.count", 4)
	wantInt(t, r, "posts_aggregate.count_columns.rating", 3) // post 2 has no rating
	wantInt(t, r, "posts_aggregate.count_columns.published_on", 3)
	wantInt(t, r, "posts_aggregate.count_columns.body", 4)
	wantInt(t, r, "posts_aggregate.count_distinct.author_id", 3)
	wantInt(t, r, "posts_aggregate.count_distinct.published", 2)
	wantInt(t, r, "posts_aggregate.approx_count_distinct.author_id", 3)

	// where narrows the rows the counts run over.
	r = env.MustGQL(t, admin, `{ posts_aggregate(where: {author_id: {_eq: 1}}) {
		count count_columns { rating } count_distinct { author_id } } }`, nil)
	wantInt(t, r, "posts_aggregate.count", 2)
	wantInt(t, r, "posts_aggregate.count_columns.rating", 1)
	wantInt(t, r, "posts_aggregate.count_distinct.author_id", 1)

	// The role row filter applies (anonymous sees published posts only) ...
	r = env.MustGQL(t, "", `{ posts_aggregate { count count_columns { published_on } count_distinct { author_id title } } }`, nil)
	wantInt(t, r, "posts_aggregate.count", 3)
	wantInt(t, r, "posts_aggregate.count_columns.published_on", 3)
	wantInt(t, r, "posts_aggregate.count_distinct.author_id", 3)
	wantInt(t, r, "posts_aggregate.count_distinct.title", 3)

	// ... and hidden columns can be neither counted nor distinct-counted.
	env.GQL(t, "", `{ posts_aggregate { count_columns { published } } }`, nil).MustFail(t, "published")
	env.GQL(t, "", `{ posts_aggregate { count_distinct { views } } }`, nil).MustFail(t, "views")
	env.GQL(t, "", `{ posts_aggregate { approx_count_distinct { rating } } }`, nil).MustFail(t, "rating")
	author := env.Token(t, "author", 1)
	env.GQL(t, author, `{ users_aggregate { count_distinct { email } } }`, nil).MustFail(t, "email")
	env.GQL(t, author, `{ users_aggregate { count_columns { balance } } }`, nil).MustFail(t, "balance")
	r = env.MustGQL(t, author, `{ users_aggregate { count_distinct { is_active } } }`, nil)
	wantInt(t, r, "users_aggregate.count_distinct.is_active", 2)

	// Large values (TEXT, JSON) are not offered for distinct counts.
	env.GQL(t, admin, `{ posts_aggregate { count_distinct { body } } }`, nil).MustFail(t, "body")
	env.GQL(t, admin, `{ users_aggregate { approx_count_distinct { metadata } } }`, nil).MustFail(t, "metadata")
	r = env.MustGQL(t, admin, `{ users_aggregate { count_columns { metadata } } }`, nil)
	wantInt(t, r, "users_aggregate.count_columns.metadata", 2)
}

func TestAggregateStatistics(t *testing.T) {
	t.Parallel()
	env := New(t)
	admin := env.Token(t, "admin", 4)

	r := env.MustGQL(t, admin, `{ posts_aggregate {
		stddev { views rating } stddev_pop { views } stddev_samp { views }
		variance { views } var_pop { views } var_samp { views rating }
	} }`, nil)
	expect := func(path, sqlExpr string) {
		t.Helper()
		want, err := strconv.ParseFloat(env.QueryString(t, "SELECT "+sqlExpr+" FROM posts"), 64)
		if err != nil {
			t.Fatal(err)
		}
		if got := float(t, r, path); math.Abs(got-want) > 1e-6*math.Max(1, math.Abs(want)) {
			t.Errorf("%s = %v, want %v (%s)", path, got, want, sqlExpr)
		}
	}
	// stddev/variance are the SAMPLE statistics (as in Hasura/PostgreSQL).
	expect("posts_aggregate.stddev.views", "STDDEV_SAMP(views)")
	expect("posts_aggregate.stddev.rating", "STDDEV_SAMP(rating)")
	expect("posts_aggregate.stddev_pop.views", "STDDEV_POP(views)")
	expect("posts_aggregate.stddev_samp.views", "STDDEV_SAMP(views)")
	expect("posts_aggregate.variance.views", "VAR_SAMP(views)")
	expect("posts_aggregate.var_pop.views", "VAR_POP(views)")
	expect("posts_aggregate.var_samp.views", "VAR_SAMP(views)")
	expect("posts_aggregate.var_samp.rating", "VAR_SAMP(rating)")
	if pop, samp := float(t, r, "posts_aggregate.stddev_pop.views"), float(t, r, "posts_aggregate.stddev_samp.views"); pop >= samp {
		t.Errorf("population stddev %v should be below sample stddev %v", pop, samp)
	}

	// One row: the sample statistics are null, the population ones 0.
	r = env.MustGQL(t, admin, `{ posts_aggregate(where: {id: {_eq: 3}}) { stddev { views } var_pop { views } } }`, nil)
	wantNull(t, r, "posts_aggregate.stddev.views")
	if v := float(t, r, "posts_aggregate.var_pop.views"); v != 0 {
		t.Errorf("var_pop over one row = %v, want 0", v)
	}
	// No rows: null.
	r = env.MustGQL(t, admin, `{ posts_aggregate(where: {id: {_eq: 99}}) { count stddev_pop { views } count_distinct { title } } }`, nil)
	wantInt(t, r, "posts_aggregate.count", 0)
	wantNull(t, r, "posts_aggregate.stddev_pop.views")
	wantInt(t, r, "posts_aggregate.count_distinct.title", 0)

	// Statistics only on numeric columns, and only readable ones.
	env.GQL(t, admin, `{ posts_aggregate { stddev { title } } }`, nil).MustFail(t, "title")
	r = env.MustGQL(t, "", `{ posts_aggregate { var_samp { author_id } } }`, nil)
	if v := float(t, r, "posts_aggregate.var_samp.author_id"); v != 1 { // authors 1, 2, 3
		t.Errorf("anonymous var_samp(author_id) = %v, want 1", v)
	}
	env.GQL(t, "", `{ posts_aggregate { stddev { views } } }`, nil).MustFail(t, "views")
	env.GQL(t, "", `{ posts_aggregate { variance { rating } } }`, nil).MustFail(t, "rating")
}

func TestAggregate64Bit(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(
		"CREATE TABLE ledger (id BIGINT PRIMARY KEY, amount BIGINT NOT NULL, note VARCHAR(20) NULL)",
		"INSERT INTO ledger VALUES (1, 9223372036854775000, 'a'), (2, 9223372036854775000, 'b'), (3, 9007199254740993, NULL)",
	), WithConfig(func(c *config.Config) { c.SchemaGen.CountType = config.CountTypeBigInt }))
	admin := env.Token(t, "admin", 4)

	// With count_type: BigInt counts are 64-bit (wire format: a JSON number) ...
	for _, tc := range [][2]string{
		{"posts_aggregate_result", "count"},
		{"posts_connection", "total_count"},
		{"mutation_response", "affected_rows"},
		{"posts_count_distinct_fields", "author_id"},
		{"posts_count_columns_fields", "title"},
		{"posts_count_distinct_approx_fields", "title"},
	} {
		if got := typeOfField(t, env, admin, tc[0], tc[1]); got != "BigInt!" {
			t.Errorf("%s.%s = %s, want BigInt!", tc[0], tc[1], got)
		}
	}
	// ... and integer sums are exact Decimals: this one exceeds int64.
	r := env.MustGQL(t, admin, `{ ledger_aggregate { count sum { amount } count_columns { note } } }`, nil)
	wantInt(t, r, "ledger_aggregate.count", 3)
	wantInt(t, r, "ledger_aggregate.count_columns.note", 2)
	if got, want := r.String(t, "ledger_aggregate.sum.amount"), env.QueryString(t, "SELECT SUM(amount) FROM ledger"); got != want || got != "18455751272964290993" {
		t.Errorf("sum(amount) = %s, want exact %s", got, want)
	}

	// Mutations and connections keep working with 64-bit counts.
	r = env.MustGQL(t, admin, `mutation { update_ledger(where: {id: {_lte: 2}}, _set: {note: "z"}) { affected_rows } }`, nil)
	wantInt(t, r, "update_ledger.affected_rows", 2)
	r = env.MustGQL(t, admin, `{ ledger_connection(first: 1) { total_count } }`, nil)
	wantInt(t, r, "ledger_connection.total_count", 3)
}

// TestAggregateCountTypeDefault: a config without count_type (every config
// written before it existed) keeps the Int! count fields; Int can also be
// set explicitly. The new per-column counts are BigInt! either way.
func TestAggregateCountTypeDefault(t *testing.T) {
	t.Parallel()
	for name, opt := range map[string]Option{
		"default":  WithConfig(func(*config.Config) {}),
		"explicit": WithConfig(func(c *config.Config) { c.SchemaGen.CountType = config.CountTypeInt }),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := New(t, opt)
			if env.Config.SchemaGen.CountType != config.CountTypeInt {
				t.Fatalf("count_type resolved to %q", env.Config.SchemaGen.CountType)
			}
			admin := env.Token(t, "admin", 4)
			for _, tc := range [][3]string{
				{"posts_aggregate_result", "count", "Int!"},
				{"posts_connection", "total_count", "Int!"},
				{"mutation_response", "affected_rows", "Int!"},
				{"posts_count_distinct_fields", "author_id", "BigInt!"},
			} {
				if got := typeOfField(t, env, admin, tc[0], tc[1]); got != tc[2] {
					t.Errorf("%s.%s = %s, want %s", tc[0], tc[1], got, tc[2])
				}
			}
			r := env.MustGQL(t, admin, `{ posts_aggregate { count count_distinct { author_id } } }`, nil)
			wantInt(t, r, "posts_aggregate.count", 4)
			wantInt(t, r, "posts_aggregate.count_distinct.author_id", 3)
			// The anonymous role sees the same Int! type over its own rows.
			anon := env.MustGQL(t, "", `{ posts_aggregate { count } posts_connection { total_count } }`, nil)
			wantInt(t, anon, "posts_aggregate.count", 3)
			wantInt(t, anon, "posts_connection.total_count", 3)
		})
	}
}

// TestAggregateTableSuffixNames: tables <t> and <t>_approx (or <t>_count,
// <t>_stddev …) coexist; the aggregate type names stay distinct.
func TestAggregateTableSuffixNames(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(
		"CREATE TABLE events (id BIGINT PRIMARY KEY, kind VARCHAR(20) NOT NULL)",
		"CREATE TABLE events_approx (id BIGINT PRIMARY KEY, kind VARCHAR(20) NOT NULL)",
		"CREATE TABLE events_count (id BIGINT PRIMARY KEY, n INT NOT NULL)",
		"INSERT INTO events VALUES (1, 'a'), (2, 'a'), (3, 'b')",
		"INSERT INTO events_approx VALUES (1, 'x')",
	))
	admin := env.Token(t, "admin", 4)
	r := env.MustGQL(t, admin, `{
		events_aggregate { count_distinct { kind } approx_count_distinct { kind } }
		events_approx_aggregate { count_distinct { kind } approx_count_distinct { kind } }
	}`, nil)
	wantInt(t, r, "events_aggregate.count_distinct.kind", 2)
	wantInt(t, r, "events_aggregate.approx_count_distinct.kind", 2)
	wantInt(t, r, "events_approx_aggregate.count_distinct.kind", 1)
	if got := typeOfField(t, env, admin, "events_count_distinct_approx_fields", "kind"); got != "BigInt!" {
		t.Errorf("events_count_distinct_approx_fields.kind = %s", got)
	}
	if got := typeOfField(t, env, admin, "events_approx_count_distinct_fields", "kind"); got != "BigInt!" {
		t.Errorf("events_approx_count_distinct_fields.kind = %s", got)
	}
	// The anonymous role has no grant on these tables at all.
	env.GQL(t, "", `{ events_aggregate { count } }`, nil).MustFail(t, "events_aggregate")
}

func TestNestedAggregates(t *testing.T) {
	t.Parallel()
	env := New(t)
	admin := env.Token(t, "admin", 4)

	r := env.MustGQL(t, admin, `{ users_connection { nodes {
		id
		posts_aggregate { count sum { views } max { views } avg { rating } count_distinct { published } }
		comments_aggregate { count }
		published: posts_aggregate(where: {published: {_eq: true}}) { count }
		commented_by_grace: posts_aggregate(where: {comments: {user_id: {_eq: 2}}}) { count }
	} } }`, nil)
	if got := r.IDs(t, "users_connection.nodes"); len(got) != 4 {
		t.Fatalf("users = %v", got)
	}
	type row struct{ posts, sum, max, comments, published, byGrace int64 }
	want := []row{
		{2, 423, 420, 2, 1, 1}, // ada: posts 1, 2; comments 3, 4
		{1, 250, 250, 2, 1, 0}, // grace: post 3; comments 1, 5
		{1, 999, 999, 1, 1, 1}, // alan: post 4; comment 2
		{0, 0, 0, 0, 0, 0},     // root: nothing
	}
	for i, w := range want {
		p := "users_connection.nodes." + strconv.Itoa(i) + "."
		wantInt(t, r, p+"posts_aggregate.count", w.posts)
		wantInt(t, r, p+"comments_aggregate.count", w.comments)
		wantInt(t, r, p+"published.count", w.published)
		wantInt(t, r, p+"commented_by_grace.count", w.byGrace)
		if w.posts == 0 {
			wantNull(t, r, p+"posts_aggregate.sum.views")
			wantNull(t, r, p+"posts_aggregate.max.views")
			wantNull(t, r, p+"posts_aggregate.avg.rating")
			wantInt(t, r, p+"posts_aggregate.count_distinct.published", 0)
			continue
		}
		wantInt(t, r, p+"posts_aggregate.sum.views", w.sum)
		wantInt(t, r, p+"posts_aggregate.max.views", w.max)
	}
	if v := float(t, r, "users_connection.nodes.0.posts_aggregate.avg.rating"); v != 4.9 {
		t.Errorf("ada avg(rating) = %v, want 4.9 (NULL ignored)", v)
	}

	// Two levels deep, through by_pk and inside fragments.
	r = env.MustGQL(t, admin, `
		fragment C on comments_aggregate_result { count count_distinct { user_id } }
		{ users_by_pk(id: 1) { posts(order_by: [{id: asc}]) { id comments_aggregate { ...C } } } }`, nil)
	wantInt(t, r, "users_by_pk.posts.0.comments_aggregate.count", 2)
	wantInt(t, r, "users_by_pk.posts.0.comments_aggregate.count_distinct.user_id", 2)
	wantInt(t, r, "users_by_pk.posts.1.comments_aggregate.count", 0)

	// The child role row filter applies: anonymous only sees published posts.
	r = env.MustGQL(t, "", `{ users_connection { nodes { id posts_aggregate { count count_columns { body } } } } }`, nil)
	wantInt(t, r, "users_connection.nodes.0.posts_aggregate.count", 1)
	wantInt(t, r, "users_connection.nodes.0.posts_aggregate.count_columns.body", 1)

	// Negative RBAC: hidden child columns can be neither aggregated nor
	// filtered in the nested where, and only operators the role may use work.
	env.GQL(t, "", `{ users_connection { nodes { posts_aggregate { sum { views } } } } }`, nil).MustFail(t, "views")
	env.GQL(t, "", `{ users_connection { nodes { posts_aggregate { count_distinct { published } } } } }`, nil).MustFail(t, "published")
	env.GQL(t, "", `{ users_connection { nodes { posts_aggregate(where: {published: {_eq: false}}) { count } } } }`, nil).MustFail(t, "published")
	env.GQL(t, "", `query($w: posts_bool_exp) { users_connection { nodes { posts_aggregate(where: $w) { count } } } }`,
		map[string]any{"w": map[string]any{"body": map[string]any{"_icontains": "x"}}}).MustFail(t, "body")
	env.GQL(t, "", `{ users_connection { nodes { posts_aggregate(where: {title: {_regex: "."}}) { count } } } }`, nil).MustFail(t, "_regex")
	// Object relationships have no aggregate.
	env.GQL(t, admin, `{ posts_connection { nodes { author_aggregate { count } } } }`, nil).MustFail(t, "author_aggregate")
}

func TestNestedAggregateRolePermissions(t *testing.T) {
	t.Parallel()
	// reviewer: posts are limited to published ones without the views
	// column, comments to the reviewer's own, and the comments FK column is
	// hidden (so the list field cannot batch, but the aggregate still does).
	env := New(t, WithRolesYAML(DefaultRolesYAML+`
  reviewer:
    tables:
      users:
        select:
          allow: true
          columns: [id, name]
      posts:
        select:
          allow: true
          columns: [id, author_id, title, rating]
          filter: "published = 1"
      comments:
        select:
          allow: true
          columns: [id, user_id, body]
          filter: "user_id = :jwt.sub"
`))
	grace := env.Token(t, "reviewer", 2)
	r := env.MustGQL(t, grace, `{
		users_connection { nodes { id posts_aggregate { count max { rating } } comments_aggregate { count } } }
		posts_connection { nodes { id comments_aggregate { count } comments { id } } }
	}`, nil)
	// users: ada has only post 1 published; grace's comments are 1 and 5.
	wantInt(t, r, "users_connection.nodes.0.posts_aggregate.count", 1)
	if v := float(t, r, "users_connection.nodes.0.posts_aggregate.max.rating"); v != 4.9 {
		t.Errorf("ada max(rating) = %v, want 4.9", v)
	}
	wantInt(t, r, "users_connection.nodes.1.comments_aggregate.count", 2)
	wantInt(t, r, "users_connection.nodes.0.comments_aggregate.count", 0) // ada's comments are not grace's
	// posts 1, 3, 4 are visible; grace commented on 1 and 4.
	if got := r.IDs(t, "posts_connection.nodes"); len(got) != 3 {
		t.Fatalf("reviewer posts = %v", got)
	}
	for i, w := range []int64{1, 0, 1} {
		p := "posts_connection.nodes." + strconv.Itoa(i)
		wantInt(t, r, p+".comments_aggregate.count", w)
		if n := len(r.List(t, p+".comments")); int64(n) != w {
			t.Errorf("%s: list has %d comments, aggregate says %d", p, n, w)
		}
	}

	// The same request as admin counts everything.
	r = env.MustGQL(t, env.Token(t, "admin", 4), `{ posts_by_pk(id: 4) { comments_aggregate { count } } }`, nil)
	wantInt(t, r, "posts_by_pk.comments_aggregate.count", 2)

	// Negative RBAC for the reviewer.
	env.GQL(t, grace, `{ users_connection { nodes { posts_aggregate { sum { views } } } } }`, nil).MustFail(t, "views")
	env.GQL(t, grace, `{ posts_connection { nodes { comments_aggregate { count_distinct { post_id } } } } }`, nil).MustFail(t, "post_id")
	env.GQL(t, grace, `{ posts_connection { nodes { comments_aggregate(where: {post_id: {_eq: 1}}) { count } } } }`, nil).MustFail(t, "post_id")
	env.GQL(t, grace, `{ users_connection { nodes { posts_aggregate(where: {published: {_eq: false}}) { count } } } }`, nil).MustFail(t, "published")
}

func TestNestedAggregateCompositeKey(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(
		"CREATE TABLE shelves (aisle INT NOT NULL, slot INT NOT NULL, label VARCHAR(20) NOT NULL, PRIMARY KEY (aisle, slot))",
		"CREATE TABLE items (id BIGINT PRIMARY KEY, aisle INT NOT NULL, slot INT NOT NULL, qty INT NOT NULL, "+
			"CONSTRAINT fk_items_shelf FOREIGN KEY (aisle, slot) REFERENCES shelves (aisle, slot))",
		"INSERT INTO shelves VALUES (1, 1, 'a'), (1, 2, 'b'), (2, 1, 'c')",
		"INSERT INTO items VALUES (1, 1, 1, 5), (2, 1, 1, 7), (3, 1, 2, 1), (4, 2, 1, 10), (5, 2, 1, 10), (6, 2, 1, 4)",
	))
	r := env.MustGQL(t, env.Token(t, "admin", 4), `{ shelves_connection { nodes {
		label items_aggregate { count sum { qty } count_distinct { qty } var_pop { qty } } } } }`, nil)
	for i, w := range [][3]int64{{2, 12, 2}, {1, 1, 1}, {3, 24, 2}} {
		p := "shelves_connection.nodes." + strconv.Itoa(i) + ".items_aggregate."
		wantInt(t, r, p+"count", w[0])
		wantInt(t, r, p+"sum.qty", w[1])
		wantInt(t, r, p+"count_distinct.qty", w[2])
	}
	if v := float(t, r, "shelves_connection.nodes.0.items_aggregate.var_pop.qty"); v != 1 {
		t.Errorf("var_pop(qty) of shelf a = %v, want 1", v)
	}
}

// TestNestedAggregateBatching proves the nested aggregate runs one GROUP BY
// query per batch of parents, not one per parent, using TiDB's statement
// summary for this test's private database.
func TestNestedAggregateBatching(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(
		"INSERT INTO users (id, username, password, name, email) VALUES "+
			"(5, 'u5', 'x', 'U5', 'u5@x'), (6, 'u6', 'x', 'U6', 'u6@x'), (7, 'u7', 'x', 'U7', 'u7@x'), (8, 'u8', 'x', 'U8', 'u8@x')",
		"INSERT INTO posts (author_id, title, views) VALUES (5, 'p5', 1), (6, 'p6', 2), (7, 'p7', 3), (8, 'p8', 4), (8, 'p8b', 5)",
	))
	var enabled string
	if err := env.DB.QueryRow("SELECT @@tidb_enable_stmt_summary").Scan(&enabled); err != nil || (enabled != "1" && !strings.EqualFold(enabled, "ON")) {
		t.Skipf("statement summary unavailable (%q, %v)", enabled, err)
	}
	r := env.MustGQL(t, env.Token(t, "admin", 4), `{ users_connection { nodes { id posts_aggregate { count stddev_pop { views } } } } }`, nil)
	if n := len(r.List(t, "users_connection.nodes")); n != 8 {
		t.Fatalf("users = %d, want 8", n)
	}
	wantInt(t, r, "users_connection.nodes.7.posts_aggregate.count", 2)
	if v := float(t, r, "users_connection.nodes.7.posts_aggregate.stddev_pop.views"); v != 0.5 {
		t.Errorf("stddev_pop for user 8 = %v, want 0.5", v)
	}
	n := env.QueryInt(t, `SELECT COALESCE(SUM(EXEC_COUNT), 0) FROM information_schema.statements_summary
		WHERE LOWER(DIGEST_TEXT) LIKE '%stddev_pop%group by%' AND QUERY_SAMPLE_TEXT LIKE ?`, "%"+env.DBName+"%")
	if n != 1 {
		t.Errorf("nested aggregate ran %d GROUP BY queries for 8 parents, want 1", n)
	}
}

// TestDemoConfigAggregates runs the README aggregate examples against the
// roles and schema_gen settings of the demo gqlgate.yaml.
func TestDemoConfigAggregates(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "gqlgate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	demo, err := config.Parse(bytes.ReplaceAll(raw, []byte("${GQLGATE_JWT_SECRET}"), []byte(JWTSecret)))
	if err != nil {
		t.Fatalf("demo gqlgate.yaml: %v", err)
	}
	env := New(t, WithSQL(demoModelingSQL(t)), WithConfig(func(c *config.Config) {
		c.Roles = demo.Roles
		c.SchemaGen = demo.SchemaGen
		c.Tables = demo.Tables
	}))

	r := env.MustGQL(t, "", `{ users_connection { nodes {
		name
		posts_aggregate { count max { published_on } count_distinct { title } }
		comments_aggregate { count }
	} } }`, nil)
	wantInt(t, r, "users_connection.nodes.0.posts_aggregate.count", 1) // ada's draft is hidden
	if got := r.String(t, "users_connection.nodes.0.posts_aggregate.max.published_on"); got != "2026-01-15" {
		t.Errorf("ada max(published_on) = %s", got)
	}
	wantInt(t, r, "users_connection.nodes.1.comments_aggregate.count", 2)

	admin := env.Token(t, "admin", 4)
	r = env.MustGQL(t, admin, `{ posts_aggregate(where: {published: {_eq: true}}) {
		count avg { views } sum { views } min { views } max { published_on }
		count_columns { rating } count_distinct { author_id } approx_count_distinct { author_id }
		stddev { views } variance { views } stddev_pop { views } var_pop { views } stddev_samp { views } var_samp { views }
	} }`, nil)
	wantInt(t, r, "posts_aggregate.count", 3)
	wantInt(t, r, "posts_aggregate.sum.views", 420+250+999)
	r = env.MustGQL(t, admin, `{ users_connection { nodes {
		name
		posts_aggregate { count sum { views } max { published_on } }
		published: posts_aggregate(where: {published: {_eq: true}}) { count }
		commented: posts_aggregate(where: {comments: {user_id: {_eq: 2}}}) { count }
	} } }`, nil)
	wantInt(t, r, "users_connection.nodes.0.posts_aggregate.count", 2)
	wantInt(t, r, "users_connection.nodes.0.published.count", 1)
	wantInt(t, r, "users_connection.nodes.0.commented.count", 1)
	// The demo's anonymous filter surface also governs nested where.
	env.GQL(t, "", `{ users_connection { nodes { posts_aggregate(where: {title: {_ilike: "%a%"}}) { count } } } }`, nil).MustFail(t, "_ilike")
}
