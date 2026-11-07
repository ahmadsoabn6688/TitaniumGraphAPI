package e2e

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gqlgate/config"
)

// End-to-end tests for data modeling: views as read-only tables, declared
// (non-FK) relationships, logical keys and keyless tables, and custom GraphQL
// names, descriptions and deprecations from the tables: section.

// modelingSQL adds a view, a keyless table with a declared key and a keyless
// table without one to the blog fixture.
var modelingSQL = []string{
	`CREATE VIEW post_stats AS
	   SELECT p.id AS post_id, p.author_id, COUNT(c.id) AS comment_count
	   FROM posts p LEFT JOIN comments c ON c.post_id = p.id
	   GROUP BY p.id, p.author_id`,
	`CREATE VIEW secret_view AS SELECT id, username, password FROM users`,
	`CREATE TABLE tags (
	   post_ref BIGINT NOT NULL,
	   seq INT NOT NULL,
	   label VARCHAR(20) NOT NULL COMMENT 'Tag text'
	 ) COMMENT 'Post tags'`,
	`INSERT INTO tags VALUES (1, 1, 'math'), (1, 2, 'history'), (3, 1, 'go'), (4, 1, 'math')`,
	`CREATE TABLE event_log (
	   ts DATETIME NOT NULL,
	   level VARCHAR(10) NOT NULL,
	   message VARCHAR(100) NOT NULL,
	   user_id BIGINT NULL
	 ) COMMENT 'Append-only events'`,
	`INSERT INTO event_log VALUES
	   ('2026-01-01 10:00:00', 'error', 'disk full', 1),
	   ('2026-01-01 11:00:00', 'info', 'login', 1),
	   ('2026-01-02 09:00:00', 'error', 'timeout', 2),
	   ('2026-01-03 09:00:00', 'info', 'logout', NULL)`,
}

const modelingTablesYAML = `tables:
  post_stats:
    primary_key: [post_id]
    type_name: PostStats
    description: "Comment statistics per post."
    root_fields:
      connection: postStatsPage
      by_pk: {name: postStats, deprecated: "use posts.stats"}
      aggregate: postStatsAggregate
    columns:
      comment_count: {name: commentCount, description: "Number of comments"}
    relationships:
      post: {type: object, target: posts, mapping: {post_id: id}}
  posts:
    columns:
      body: {deprecated: "use title"}
    relationships:
      stats: {type: object, target: post_stats, mapping: {id: post_id}, deprecated: "experimental"}
      tag_list: {type: array, target: tags, mapping: {id: post_ref}, description: "Tags of the post"}
      writer: {foreign_key: fk_posts_author, description: "The author"}
  tags:
    primary_key: [post_ref, seq]
    columns:
      label: tagLabel
  users:
    relationships:
      events: {type: array, target: event_log, mapping: {id: user_id}}
`

// modelingRoles: admin reads everything (views must still be named); author
// sees its own stats only, tags without seq (so no cursor), and no events;
// reader has only the "*" wildcard, which never covers a view.
const modelingRoles = `roles:
  admin:
    tables:
      "*":
        select: true
        insert: true
        update: true
        delete: true
      post_stats:
        select: true
  author:
    tables:
      users:
        select:
          allow: true
          columns: [id, name]
      posts:
        select: true
      post_stats:
        select:
          allow: true
          filter: "author_id = :jwt.sub"
      tags:
        select:
          allow: true
          columns: [post_ref, label]
  reader:
    tables:
      "*":
        select: true
  anonymous:
    tables:
      posts:
        select:
          allow: true
          columns: [id, author_id, title]
          filter: "published = 1"
      tags:
        select: true
`

func newModelingEnv(t *testing.T) *Env {
	t.Helper()
	return New(t, WithSQL(modelingSQL...), WithExtraYAML(modelingTablesYAML), WithRolesYAML(modelingRoles),
		WithConfig(func(c *config.Config) { c.SchemaGen.DescriptionsFromComments = true }))
}

// TestViewsReadOnlyWithLogicalKey: a view is a query-only type with a cursor
// connection on its declared key, a by-key lookup and aggregates; it has no
// mutations, its row filter applies, and a role must name it to see it.
func TestViewsReadOnlyWithLogicalKey(t *testing.T) {
	t.Parallel()
	env := newModelingEnv(t)
	admin := env.Token(t, "admin", 4)

	r := env.MustGQL(t, admin, `{
		p1: postStatsPage(first: 2) { nodes { post_id commentCount post { title } } page_info { has_next_page end_cursor } total_count }
		one: postStats(post_id: 4) { commentCount }
		postStatsAggregate { count sum { commentCount } }
	}`, nil)
	ids := []int64{}
	for _, n := range r.List(t, "p1.nodes") {
		ids = append(ids, int64(n.(map[string]any)["post_id"].(float64)))
	}
	if !equalIDs(ids, []int64{1, 2}) {
		t.Fatalf("first page = %v: %s", ids, r.Raw)
	}
	wantInt(t, r, "p1.nodes.0.commentCount", 2)
	if got := r.String(t, "p1.nodes.0.post.title"); got != "Notes on the Analytical Engine" {
		t.Errorf("post via declared relationship = %q", got)
	}
	wantInt(t, r, "p1.total_count", 4)
	wantInt(t, r, "one.commentCount", 2)
	wantInt(t, r, "postStatsAggregate.count", 4)
	wantInt(t, r, "postStatsAggregate.sum.commentCount", 5)

	// Second page through the cursor on the declared key.
	cursor := r.String(t, "p1.page_info.end_cursor")
	r = env.MustGQL(t, admin, `query($c: String) { postStatsPage(first: 2, after: $c) { nodes { post_id } page_info { has_next_page } } }`,
		map[string]any{"c": cursor})
	if n := len(r.List(t, "postStatsPage.nodes")); n != 2 {
		t.Fatalf("second page = %s", r.Raw)
	}
	wantInt(t, r, "postStatsPage.nodes.0.post_id", 3)

	// No mutations on the view, even for a role with every write on "*".
	r = env.MustGQL(t, admin, `{ __type(name: "Mutation") { fields { name } } }`, nil)
	for _, f := range r.List(t, "__type.fields") {
		if name := f.(map[string]any)["name"].(string); strings.Contains(name, "post_stats") || strings.Contains(name, "PostStats") {
			t.Errorf("view has mutation field %s", name)
		}
	}

	// The view's row filter applies: author 1 sees only its own posts' stats.
	author := env.Token(t, "author", 1)
	r = env.MustGQL(t, author, `{ postStatsPage { nodes { post_id } } }`, nil)
	if n := len(r.List(t, "postStatsPage.nodes")); n != 2 {
		t.Errorf("author 1 stats rows = %d, want 2: %s", n, r.Raw)
	}
	r = env.MustGQL(t, author, `{ postStats(post_id: 3) { commentCount } }`, nil)
	wantNull(t, r, "postStats")

	// Negative: the "*" wildcard never exposes a view, nor do unnamed views
	// exist at all; anonymous was not granted the view.
	reader := env.Token(t, "reader", 2)
	env.GQL(t, reader, `{ postStatsPage { nodes { post_id } } }`, nil).MustFail(t, "postStatsPage")
	env.GQL(t, admin, `{ secret_view_list { password } }`, nil).MustFail(t, "secret_view_list")
	env.GQL(t, "", `{ postStatsPage { nodes { post_id } } }`, nil).MustFail(t, "postStatsPage")

	// Negative: granting a write on a view is rejected (hot reload keeps the
	// previous config serving).
	bad := strings.Replace(modelingRoles, "      post_stats:\n        select: true\n",
		"      post_stats:\n        select: true\n        insert: true\n", 1)
	if err := env.Reload(t, bad); err == nil || !strings.Contains(err.Error(), "view") {
		t.Fatalf("reload with a write on a view: err = %v", err)
	}
	env.MustGQL(t, admin, `{ postStats(post_id: 1) { commentCount } }`, nil)
}

// TestDeclaredRelationships: relationships declared by column mapping behave
// like FK ones (nested lists with args, nested aggregates, relationship
// filters, the target's row filter) and stay hidden from roles that cannot
// read the target or the join column.
func TestDeclaredRelationships(t *testing.T) {
	t.Parallel()
	env := newModelingEnv(t)
	admin := env.Token(t, "admin", 4)

	r := env.MustGQL(t, admin, `{ posts_connection { nodes {
		id
		stats { commentCount }
		tag_list(order_by: [{seq: desc}]) { tagLabel }
		tag_list_aggregate { count }
		writer { name }
	} } }`, nil)
	wantInt(t, r, "posts_connection.nodes.0.stats.commentCount", 2)
	wantInt(t, r, "posts_connection.nodes.1.stats.commentCount", 0)
	if got := r.String(t, "posts_connection.nodes.0.tag_list.0.tagLabel"); got != "history" {
		t.Errorf("first tag of post 1 (seq desc) = %q: %s", got, r.Raw)
	}
	wantInt(t, r, "posts_connection.nodes.0.tag_list_aggregate.count", 2)
	wantInt(t, r, "posts_connection.nodes.1.tag_list_aggregate.count", 0)
	if got := r.String(t, "posts_connection.nodes.2.writer.name"); got != "Grace Hopper" {
		t.Errorf("renamed FK relationship = %q", got)
	}
	// The renamed FK relationship no longer has its generated name.
	env.GQL(t, admin, `{ posts_connection { nodes { author { name } } } }`, nil).MustFail(t, "author")

	// Relationship filters through declared relationships (and their
	// renamed columns), in both directions.
	r = env.MustGQL(t, admin, `{ posts_connection(where: {stats: {commentCount: {_gt: 1}}}) { nodes { id } } }`, nil)
	if got := r.IDs(t, "posts_connection.nodes"); !equalIDs(got, []int64{1, 4}) {
		t.Errorf("posts with >1 comment = %v", got)
	}
	r = env.MustGQL(t, admin, `{ posts_connection(where: {tag_list: {tagLabel: {_eq: "math"}}}) { nodes { id } } }`, nil)
	if got := r.IDs(t, "posts_connection.nodes"); !equalIDs(got, []int64{1, 4}) {
		t.Errorf("posts tagged math = %v", got)
	}

	// Array relationship to a keyless table.
	r = env.MustGQL(t, admin, `{ users_connection { nodes { id events(where: {level: {_eq: "error"}}) { message } events_aggregate { count } } } }`, nil)
	if got := r.String(t, "users_connection.nodes.0.events.0.message"); got != "disk full" {
		t.Errorf("user 1 error events = %s", r.Raw)
	}
	wantInt(t, r, "users_connection.nodes.0.events_aggregate.count", 2)
	wantInt(t, r, "users_connection.nodes.2.events_aggregate.count", 0)

	// The target's row filter applies inside the declared relationship and
	// in filters through it: author 1 cannot see post 4's stats (author 3).
	author := env.Token(t, "author", 1)
	r = env.MustGQL(t, author, `{ posts_connection { nodes { id stats { commentCount } } } }`, nil)
	wantInt(t, r, "posts_connection.nodes.0.stats.commentCount", 2)
	wantNull(t, r, "posts_connection.nodes.3.stats")
	r = env.MustGQL(t, author, `{ posts_connection(where: {stats: {commentCount: {_gt: 1}}}) { nodes { id } } }`, nil)
	if got := r.IDs(t, "posts_connection.nodes"); !equalIDs(got, []int64{1}) {
		t.Errorf("author 1 filter through stats = %v, want [1]", got)
	}

	// Negative: author cannot read event_log, so users.events does not exist
	// for it, and anonymous cannot read post_stats, so posts.stats does not
	// exist (neither as a field nor in where).
	env.GQL(t, author, `{ users_connection { nodes { events { message } } } }`, nil).MustFail(t, "events")
	env.GQL(t, "", `{ posts_connection { nodes { stats { commentCount } } } }`, nil).MustFail(t, "stats")
	env.GQL(t, "", `{ posts_connection(where: {stats: {}}) { nodes { id } } }`, nil).MustFail(t, "stats")
	// Anonymous reads tags fully, including through the declared relationship
	// (only published posts).
	r = env.MustGQL(t, "", `{ posts_connection { nodes { id tag_list { tagLabel } } } }`, nil)
	if got := r.IDs(t, "posts_connection.nodes"); !equalIDs(got, []int64{1, 3, 4}) {
		t.Errorf("anonymous posts = %v", got)
	}
}

// TestKeylessTables: a table without a primary key gets a bounded list; with
// a declared key it gets a cursor connection and by-key lookup, but only for
// roles that can read the whole key.
func TestKeylessTables(t *testing.T) {
	t.Parallel()
	env := newModelingEnv(t)
	admin := env.Token(t, "admin", 4)

	r := env.MustGQL(t, admin, `{ event_log_list(limit: 10, where: {level: {_eq: "error"}}) { message } }`, nil)
	if n := len(r.List(t, "event_log_list")); n != 2 {
		t.Errorf("error events = %d: %s", n, r.Raw)
	}
	r = env.MustGQL(t, admin, `{ event_log_list(limit: 1) { message } }`, nil)
	if n := len(r.List(t, "event_log_list")); n != 1 {
		t.Errorf("limit 1 returned %d rows", n)
	}
	// No cursor field without a key, and no offset / order_by on the list.
	env.GQL(t, admin, `{ event_log_connection { nodes { message } } }`, nil).MustFail(t, "event_log_connection")
	env.GQL(t, admin, `{ event_log_list(offset: 1) { message } }`, nil).MustFail(t, "offset")
	env.GQL(t, admin, `{ event_log_list(order_by: [{ts: desc}]) { message } }`, nil).MustFail(t, "order_by")

	// Declared key: connection in key order + lookup by the composite key.
	r = env.MustGQL(t, admin, `{
		tags_connection(first: 3) { nodes { post_ref seq tagLabel } page_info { has_next_page } }
		tags_by_pk(post_ref: 1, seq: 2) { tagLabel }
	}`, nil)
	if got := r.String(t, "tags_connection.nodes.1.tagLabel"); got != "history" {
		t.Errorf("tags in key order: %s", r.Raw)
	}
	if got := r.String(t, "tags_by_pk.tagLabel"); got != "history" {
		t.Errorf("tags_by_pk = %q", got)
	}
	// Writes on a keyless table never use the logical key.
	env.GQL(t, admin, `mutation { update_tags_by_pk(post_ref: 1, seq: 2, _set: {tagLabel: "x"}) { seq } }`, nil).
		MustFail(t, "update_tags_by_pk")

	// Negative: author cannot read seq, so no cursor over (post_ref, seq) and
	// no by-key lookup — only the bounded list, without seq.
	author := env.Token(t, "author", 1)
	env.GQL(t, author, `{ tags_connection { nodes { tagLabel } } }`, nil).MustFail(t, "tags_connection")
	env.GQL(t, author, `{ tags_by_pk(post_ref: 1, seq: 1) { tagLabel } }`, nil).MustFail(t, "tags_by_pk")
	env.GQL(t, author, `{ tags_list { seq } }`, nil).MustFail(t, "seq")
	env.GQL(t, author, `{ tags_list(where: {seq: {_eq: 1}}) { tagLabel } }`, nil).MustFail(t, "seq")
	r = env.MustGQL(t, author, `{ tags_list(where: {post_ref: {_eq: 1}}) { tagLabel } }`, nil)
	if n := len(r.List(t, "tags_list")); n != 2 {
		t.Errorf("author tags of post 1 = %d", n)
	}
}

// TestCustomNamesAndDocs: renamed types, root fields and columns; config
// descriptions and deprecations; TiDB comments as descriptions (opt-in).
func TestCustomNamesAndDocs(t *testing.T) {
	t.Parallel()
	env := newModelingEnv(t)
	admin := env.Token(t, "admin", 4)

	r := env.MustGQL(t, admin, `{
		stats: __type(name: "PostStats") { description fields(includeDeprecated: true) { name description isDeprecated deprecationReason } }
		posts: __type(name: "posts") { fields(includeDeprecated: true) { name description isDeprecated deprecationReason } }
		tags: __type(name: "tags") { description fields { name description } }
		events: __type(name: "event_log") { description }
		users: __type(name: "users") { description }
		root: __type(name: "Query") { fields(includeDeprecated: true) { name isDeprecated deprecationReason } }
	}`, nil)
	if got := r.String(t, "stats.description"); got != "Comment statistics per post." {
		t.Errorf("view description = %q", got)
	}
	field := func(path, name string) map[string]any {
		for _, f := range r.List(t, path) {
			m := f.(map[string]any)
			if m["name"] == name {
				return m
			}
		}
		t.Fatalf("%s has no field %s: %s", path, name, r.Raw)
		return nil
	}
	if d := field("stats.fields", "commentCount")["description"]; d != "Number of comments" {
		t.Errorf("commentCount description = %v", d)
	}
	if f := field("posts.fields", "body"); f["isDeprecated"] != true || f["deprecationReason"] != "use title" {
		t.Errorf("posts.body deprecation = %v", f)
	}
	if f := field("posts.fields", "stats"); f["deprecationReason"] != "experimental" {
		t.Errorf("posts.stats deprecation = %v", f)
	}
	if f := field("posts.fields", "writer"); f["description"] != "The author" {
		t.Errorf("posts.writer description = %v", f)
	}
	if f := field("posts.fields", "tag_list"); f["description"] != "Tags of the post" {
		t.Errorf("posts.tag_list description = %v", f)
	}
	if f := field("root.fields", "postStats"); f["deprecationReason"] != "use posts.stats" {
		t.Errorf("postStats root deprecation = %v", f)
	}
	// Comments (descriptions_from_comments: true).
	if got := r.String(t, "tags.description"); got != "Post tags" {
		t.Errorf("tags description = %q", got)
	}
	if d := field("tags.fields", "tagLabel")["description"]; d != "Tag text" {
		t.Errorf("tagLabel description = %v", d)
	}
	if got := r.String(t, "events.description"); got != "Append-only events" {
		t.Errorf("event_log description = %q", got)
	}
	if got := r.String(t, "users.description"); !strings.HasPrefix(got, "Row of table") {
		t.Errorf("users (no comment) description = %q", got)
	}

	// The renamed column is the field name everywhere: output, where,
	// aggregates; the SQL name is gone.
	env.MustGQL(t, admin, `{ postStatsAggregate(where: {commentCount: {_gte: 0}}) { max { commentCount } } }`, nil)
	env.GQL(t, admin, `{ postStatsPage { nodes { comment_count } } }`, nil).MustFail(t, "comment_count")
	env.GQL(t, admin, `{ post_stats_connection { nodes { post_id } } }`, nil).MustFail(t, "post_stats_connection")
	// Deprecated fields still work.
	env.MustGQL(t, admin, `{ postStats(post_id: 1) { commentCount } posts_by_pk(id: 1) { body } }`, nil)
}

// TestModelingConfigErrors: a tables: entry that does not fit the schema,
// and a declared name colliding with a generated one, fail the build (a hot
// reload keeps the previous config serving).
func TestModelingConfigErrors(t *testing.T) {
	t.Parallel()
	env := New(t)
	admin := env.Token(t, "admin", 4)
	for _, tc := range []struct{ name, yaml, want string }{
		{"object onto non-unique", "tables:\n  posts:\n    relationships:\n      x: {type: object, target: comments, mapping: {id: post_id}}\n", "object relationship"},
		{"unknown column", "tables:\n  posts:\n    relationships:\n      x: {type: array, target: comments, mapping: {nope: post_id}}\n", "no column"},
		{"type mismatch", "tables:\n  posts:\n    relationships:\n      x: {type: array, target: comments, mapping: {title: post_id}}\n", "join-compatible"},
		{"name collision", "tables:\n  posts:\n    root_fields:\n      by_pk: users_by_pk\n", "collides"},
		{"column name collision", "tables:\n  posts:\n    columns:\n      body: title\n", "both map"},
		{"primary key on table with one", "tables:\n  posts:\n    primary_key: [title]\n", "already has a primary key"},
		{"relationship name vs FK name", "tables:\n  posts:\n    relationships:\n      comments: {type: array, target: comments, mapping: {id: post_id}}\n", "already used"},
	} {
		if err := env.ReloadExtra(t, tc.yaml); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: reload error = %v, want %q", tc.name, err, tc.want)
		}
	}
	// The previous config keeps serving, and a valid tables: block applies.
	env.MustGQL(t, admin, `{ posts_by_pk(id: 1) { title } }`, nil)
	if err := env.ReloadExtra(t, "tables:\n  posts:\n    root_fields:\n      by_pk: post\n"); err != nil {
		t.Fatalf("valid reload: %v", err)
	}
	env.MustGQL(t, admin, `{ post(id: 1) { title } }`, nil)
	env.GQL(t, admin, `{ posts_by_pk(id: 1) { title } }`, nil).MustFail(t, "posts_by_pk")
}

// demoModelingSQL is the part of the demo seed (example/seed.sql) that the
// blog fixture lacks: the post_stats view and the keyless post_tags table the
// demo gqlgate.yaml models.
func demoModelingSQL(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "example", "seed.sql"))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(raw), "\r\n", "\n")
	i := strings.Index(s, "CREATE VIEW post_stats")
	if i < 0 {
		t.Fatal("example/seed.sql has no post_stats view")
	}
	return s[i:]
}

// TestDemoConfigModeling runs the modeling examples of the demo gqlgate.yaml
// (view, logical keys, declared relationships, comments) over the demo seed.
func TestDemoConfigModeling(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "gqlgate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	demo, err := config.Parse([]byte(strings.ReplaceAll(string(raw), "${GQLGATE_JWT_SECRET}", JWTSecret)))
	if err != nil {
		t.Fatalf("demo gqlgate.yaml: %v", err)
	}
	env := New(t, WithSQL(demoModelingSQL(t)), WithConfig(func(c *config.Config) {
		c.Roles = demo.Roles
		c.SchemaGen = demo.SchemaGen
		c.Tables = demo.Tables
		c.JSONTypes = demo.JSONTypes
		c.NativeQueries = demo.NativeQueries
	}))
	r := env.MustGQL(t, "", `{
		posts_connection { nodes { id stats { commentCount } tags { tag } tags_aggregate { count } } }
		post_stats_connection { nodes { post_id commentCount post { title } } }
		post_tags_connection { nodes { post_id tag } }
		__type(name: "post_tags") { description }
	}`, nil)
	wantIDs(t, "anonymous posts", r.IDs(t, "posts_connection.nodes"), 1, 3, 4)
	wantInt(t, r, "posts_connection.nodes.0.stats.commentCount", 2)
	wantInt(t, r, "posts_connection.nodes.0.tags_aggregate.count", 2)
	if n := len(r.List(t, "post_stats_connection.nodes")); n != 3 {
		t.Errorf("anonymous sees stats of %d posts, want the 3 published", n)
	}
	if got := r.String(t, "__type.description"); got != "Free-form tags on posts" {
		t.Errorf("post_tags description = %q", got)
	}
	// Negative: anonymous may not read post_stats.author_id; author 1 sees
	// only its own posts' stats.
	env.GQL(t, "", `{ post_stats_connection { nodes { author_id } } }`, nil).MustFail(t, "author_id")
	r = env.MustGQL(t, env.Token(t, "author", 1), `{ post_stats_connection { nodes { post_id } } }`, nil)
	if n := len(r.List(t, "post_stats_connection.nodes")); n != 2 {
		t.Errorf("author 1 sees stats of %d posts, want 2", n)
	}

	// A tag on a draft (post 2) must not reveal the draft to anonymous —
	// neither listed nor confirmed by filtering on its post_id.
	env.Exec(t, "INSERT INTO post_tags (post_id, tag) VALUES (2, 'secret')")
	const draftTags = `{ post_tags_connection(where: {post_id: {_eq: 2}}) { nodes { tag } } }`
	if n := len(env.MustGQL(t, "", draftTags, nil).List(t, "post_tags_connection.nodes")); n != 0 {
		t.Errorf("anonymous sees %d tags of a draft", n)
	}
	r = env.MustGQL(t, "", `{ post_tags_connection { nodes { post_id } } }`, nil)
	for i := range r.List(t, "post_tags_connection.nodes") {
		if r.Int(t, "post_tags_connection.nodes."+strconv.Itoa(i)+".post_id") == 2 {
			t.Errorf("anonymous post_tags lists the draft: %s", r.Raw)
		}
	}
	if n := len(env.MustGQL(t, env.Token(t, "admin", 4), draftTags, nil).List(t, "post_tags_connection.nodes")); n != 1 {
		t.Errorf("admin sees %d tags of the draft, want 1", n)
	}
}
