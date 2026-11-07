package schema

import (
	"strings"
	"testing"

	"github.com/graphql-go/graphql"
	"gopkg.in/yaml.v3"

	"gqlgate/config"
	"gqlgate/introspect"
)

// modelCatalog is a small blog catalog: users <- posts (FK fk_posts_author),
// a self-referencing categories table, a keyless table and a view.
func modelCatalog() *introspect.Catalog {
	c := &introspect.Catalog{SchemaName: "appdb", Tables: map[string]*introspect.Table{}}
	add := func(name string, view bool, comment string, pk []string, cols ...*introspect.Column) *introspect.Table {
		t := &introspect.Table{Name: name, IsView: view, Comment: comment, ColumnMap: map[string]*introspect.Column{}, PrimaryKey: pk}
		for i, col := range cols {
			col.Ordinal = i
			t.Columns = append(t.Columns, col)
			t.ColumnMap[col.Name] = col
		}
		c.Tables[name] = t
		c.TableOrder = append(c.TableOrder, name)
		return t
	}
	big := func(name string, nullable bool) *introspect.Column {
		return &introspect.Column{Name: name, DataType: "bigint", ColumnType: "bigint", Nullable: nullable}
	}
	str := func(name string) *introspect.Column {
		return &introspect.Column{Name: name, DataType: "varchar", ColumnType: "varchar(50)", Collation: "utf8mb4_bin", Charset: "utf8mb4"}
	}
	users := add("users", false, "", []string{"id"}, big("id", false), str("name"), str("email"))
	users.ColumnMap["name"].Comment = "Display name"
	users.UniqueKeys = []*introspect.UniqueKey{{Name: "uq_email", Columns: []string{"email"}}}
	posts := add("posts", false, "Blog posts", []string{"id"}, big("id", false), big("author_id", false), str("title"))
	fk := &introspect.ForeignKey{ConstraintName: "fk_posts_author", Table: "posts", Columns: []string{"author_id"}, RefTable: "users", RefColumns: []string{"id"}}
	posts.ForeignKeys = []*introspect.ForeignKey{fk}
	users.IncomingFKs = []*introspect.ForeignKey{fk}
	cats := add("categories", false, "", []string{"id"}, big("id", false), big("parent_id", true))
	self := &introspect.ForeignKey{ConstraintName: "fk_cat_parent", Table: "categories", Columns: []string{"parent_id"}, RefTable: "categories", RefColumns: []string{"id"}}
	cats.ForeignKeys = []*introspect.ForeignKey{self}
	cats.IncomingFKs = []*introspect.ForeignKey{self}
	add("events", false, "", nil, big("user_id", true), str("message"), &introspect.Column{Name: "payload", DataType: "json", ColumnType: "json", Nullable: true})
	add("post_stats", true, "", nil, big("post_id", true), big("author_id", true), big("comment_count", true))
	return c
}

// modelConfig parses a tables: block plus one role.
func modelConfig(t *testing.T, tablesYAML, rolesYAML string) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	if tablesYAML != "" {
		if err := yaml.Unmarshal([]byte(tablesYAML), &cfg.Tables); err != nil {
			t.Fatalf("tables yaml: %v", err)
		}
	}
	if err := yaml.Unmarshal([]byte(rolesYAML), &cfg.Roles); err != nil {
		t.Fatalf("roles yaml: %v", err)
	}
	cfg.SchemaGen.DefaultPageSize = 25
	cfg.SchemaGen.MaxPageSize = 200
	return cfg
}

const adminRoles = `
admin:
  tables:
    "*": {select: true, insert: true, update: true, delete: true}
    post_stats: {select: true}
`

func buildModelSchema(t *testing.T, tablesYAML, rolesYAML string, mutate ...func(*config.Config)) (map[string]graphql.Schema, error) {
	t.Helper()
	cfg := modelConfig(t, tablesYAML, rolesYAML)
	for _, m := range mutate {
		m(cfg)
	}
	return BuildAll(Options{Catalog: modelCatalog(), Config: cfg})
}

func mustModelSchema(t *testing.T, tablesYAML, rolesYAML string, mutate ...func(*config.Config)) map[string]graphql.Schema {
	t.Helper()
	s, err := buildModelSchema(t, tablesYAML, rolesYAML, mutate...)
	if err != nil {
		t.Fatalf("BuildAll: %v", err)
	}
	return s
}

func objField(t *testing.T, s graphql.Schema, typeName, field string) *graphql.FieldDefinition {
	t.Helper()
	o, ok := s.Type(typeName).(*graphql.Object)
	if !ok {
		t.Fatalf("type %s missing", typeName)
	}
	return o.Fields()[field]
}

func TestModelDefaultsUnchanged(t *testing.T) {
	s := mustModelSchema(t, "", adminRoles)["admin"]
	for _, f := range []string{"users_by_pk", "users_connection", "users_aggregate", "posts_by_pk", "users_by_email"} {
		if !hasQueryField(s, f) {
			t.Errorf("default field %s missing", f)
		}
	}
	if f := objField(t, s, "posts", "author"); f == nil || f.Description != "Row of users referenced by author_id" {
		t.Errorf("FK relationship posts.author = %+v", f)
	}
	if f := objField(t, s, "users", "posts"); f == nil || f.Description != "Rows of posts whose author_id reference this row" {
		t.Errorf("FK relationship users.posts = %+v", f)
	}
	if objField(t, s, "users", "posts_aggregate") == nil {
		t.Error("users.posts_aggregate missing")
	}
	if d := s.Type("posts").Description(); d != "Row of table appdb.posts" {
		t.Errorf("comment used without descriptions_from_comments: %q", d)
	}
}

func TestCustomNames(t *testing.T) {
	tables := `
posts:
  type_name: Post
  description: "A blog post."
  root_fields:
    connection: allPosts
    by_pk: {name: post, description: "One post.", deprecated: "use allPosts"}
    insert_one: {name: createPost}
  columns:
    title: {name: headline, description: "The headline", deprecated: "use subject"}
  relationships:
    writer: {foreign_key: fk_posts_author, description: "Who wrote it", deprecated: "use author_id"}
users:
  columns:
    email: mail
  relationships:
    articles: {foreign_key: fk_posts_author}
`
	s := mustModelSchema(t, tables, adminRoles)["admin"]
	for _, f := range []string{"allPosts", "post", "posts_aggregate", "users_by_mail"} {
		if !hasQueryField(s, f) {
			t.Errorf("query field %s missing", f)
		}
	}
	for _, f := range []string{"posts_connection", "posts_by_pk", "users_by_email"} {
		if hasQueryField(s, f) {
			t.Errorf("query field %s should be renamed away", f)
		}
	}
	if s.MutationType().Fields()["createPost"] == nil || s.MutationType().Fields()["insert_posts"] == nil {
		t.Error("renamed/default mutation fields missing")
	}
	for _, typ := range []string{"Post", "Post_bool_exp", "Post_connection", "Post_aggregate_result", "Post_insert_input", "Post_mutation_response"} {
		if s.Type(typ) == nil {
			t.Errorf("type %s missing", typ)
		}
	}
	if s.Type("posts") != nil {
		t.Error("type posts should be renamed to Post")
	}
	if d := s.Type("Post").Description(); d != "A blog post." {
		t.Errorf("type description = %q", d)
	}
	f := objField(t, s, "Post", "headline")
	if f == nil || f.Description != "The headline" || f.DeprecationReason != "use subject" {
		t.Errorf("headline = %+v", f)
	}
	if objField(t, s, "Post", "title") != nil {
		t.Error("SQL column name must not be a field once renamed")
	}
	w := objField(t, s, "Post", "writer")
	if w == nil || w.Description != "Who wrote it" || w.DeprecationReason != "use author_id" {
		t.Errorf("writer = %+v", w)
	}
	if objField(t, s, "Post", "author") != nil {
		t.Error("renamed FK relationship keeps its generated name")
	}
	if objField(t, s, "users", "articles") == nil || objField(t, s, "users", "articles_aggregate") == nil {
		t.Error("renamed array relationship (or its aggregate) missing")
	}
	q := s.QueryType().Fields()["post"]
	if q.Description != "One post." || q.DeprecationReason != "use allPosts" {
		t.Errorf("root field docs = %q / %q", q.Description, q.DeprecationReason)
	}
	// The where input uses the GraphQL column names.
	be := s.Type("Post_bool_exp").(*graphql.InputObject)
	if be.Fields()["headline"] == nil || be.Fields()["title"] != nil || be.Fields()["writer"] == nil {
		t.Errorf("Post_bool_exp fields = %v", be.Fields())
	}
}

func TestCustomNameCollisions(t *testing.T) {
	for _, tc := range []struct{ name, tables, want string }{
		{"type name of another table", "posts:\n  type_name: users\n", "both map to GraphQL name"},
		{"type derived name", "posts:\n  type_name: users_bool\n", ""}, // users_bool_exp vs users_bool_bool_exp: fine
		{"type clash with derived", "posts:\n  type_name: users_connection\n", "collides"},
		{"root field of another table", "posts:\n  root_fields:\n    by_pk: users_aggregate\n", "collides"},
		{"mutation field", "posts:\n  root_fields:\n    delete: insert_users\n", "collides"},
		{"column rename onto another column", "posts:\n  columns:\n    title: author_id\n", "both map"},
		{"relationship onto a column", "posts:\n  relationships:\n    title: {foreign_key: fk_posts_author}\n", "field of column"},
		{"declared vs generated FK name", "posts:\n  relationships:\n    author: {type: object, target: users, mapping: {author_id: id}}\n", "already used"},
		{"reserved type", "posts:\n  type_name: page_info\n", "collides"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildModelSchema(t, tc.tables, adminRoles)
			if tc.want == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestModelValidation(t *testing.T) {
	for _, tc := range []struct{ name, tables, want string }{
		{"unknown table", "nope:\n  type_name: X\n", "not among the exposed"},
		{"unknown column", "posts:\n  columns:\n    nope: x\n", "no column"},
		{"pk on table with pk", "posts:\n  primary_key: [title]\n", "already has a primary key"},
		{"pk unknown column", "events:\n  primary_key: [nope]\n", "no column"},
		{"pk json column", "events:\n  primary_key: [payload]\n", "cannot be a key column"},
		{"view mutation root", "post_stats:\n  root_fields:\n    insert: x\n", "view"},
		{"unknown fk", "posts:\n  relationships:\n    w: {foreign_key: nope}\n", "no foreign-key relationship"},
		{"ambiguous self fk", "categories:\n  relationships:\n    p: {foreign_key: fk_cat_parent}\n", "ambiguous"},
		{"unknown target", "posts:\n  relationships:\n    x: {type: array, target: nope, mapping: {id: a}}\n", "not among the exposed"},
		{"unknown target column", "posts:\n  relationships:\n    x: {type: array, target: events, mapping: {author_id: nope}}\n", "no column"},
		{"incompatible types", "posts:\n  relationships:\n    x: {type: array, target: events, mapping: {title: user_id}}\n", "join-compatible"},
		{"json join", "events:\n  relationships:\n    x: {type: array, target: users, mapping: {payload: name}}\n", "join-compatible"},
		{"object onto non-unique", "users:\n  relationships:\n    ev: {type: object, target: events, mapping: {id: user_id}}\n", "object relationship"},
		// The error says which unique indexes count (nullable / prefix ones do not).
		{"object onto non-unique explains", "users:\n  relationships:\n    ev: {type: object, target: events, mapping: {id: user_id}}\n", "NOT NULL and indexed in full"},
		{"fk named twice", "posts:\n  relationships:\n    a1: {foreign_key: fk_posts_author}\n    a2: {foreign_key: posts.fk_posts_author}\n", "already named"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildModelSchema(t, tc.tables, adminRoles)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
	// Self-referencing FK disambiguated by type.
	if _, err := buildModelSchema(t, "categories:\n  relationships:\n    parent: {foreign_key: fk_cat_parent, type: object}\n    children: {foreign_key: fk_cat_parent, type: array}\n", adminRoles); err != nil {
		t.Errorf("typed self-referencing FK names: %v", err)
	}
}

func TestJoinCompatible(t *testing.T) {
	col := func(dt, ct string) *introspect.Column { return &introspect.Column{DataType: dt, ColumnType: ct} }
	for _, tc := range []struct {
		a, b *introspect.Column
		ok   bool
	}{
		{col("int", "int"), col("bigint", "bigint"), true},
		{col("varchar", "varchar(10)"), col("char", "char(3)"), true},
		{col("varchar", "varchar(10)"), col("int", "int"), false},
		{col("decimal", "decimal(10,2)"), col("decimal", "decimal(10,2)"), true},
		{col("decimal", "decimal(10,2)"), col("decimal", "decimal(12,4)"), false},
		{col("json", "json"), col("json", "json"), false},
		{col("text", "text"), col("varchar", "varchar(10)"), false},
		{col("tinyint", "tinyint(1)"), col("int", "int"), false},
		{col("datetime", "datetime"), col("timestamp", "timestamp"), true},
		// ENUM / SET / BIT never join (nor key) a declared relationship.
		{col("enum", "enum('a','b')"), col("enum", "enum('a','b')"), false},
		{col("set", "set('a','b')"), col("varchar", "varchar(10)"), false},
		{col("bit", "bit(8)"), col("bit", "bit(8)"), false},
		// Character columns must share charset and collation.
		{strCol("varchar(10)", "utf8mb4", "utf8mb4_bin"), strCol("varchar(10)", "utf8mb4", "utf8mb4_bin"), true},
		{strCol("varchar(10)", "utf8mb4", "utf8mb4_bin"), strCol("char(3)", "utf8mb4", "utf8mb4_bin"), true},
		{strCol("varchar(10)", "utf8mb4", "utf8mb4_bin"), strCol("varchar(10)", "utf8mb4", "utf8mb4_general_ci"), false},
		{strCol("varchar(10)", "utf8mb4", "utf8mb4_general_ci"), strCol("varchar(10)", "utf8mb4", "utf8mb4_unicode_ci"), false},
		{strCol("varchar(10)", "utf8", "utf8_bin"), strCol("varchar(10)", "utf8mb4", "utf8mb4_bin"), false},
		{strCol("varchar(10)", "utf8mb4", "utf8mb4_bin"), col("varchar", "varchar(10)"), false},
	} {
		if got := joinCompatible(tc.a, tc.b); got != tc.ok {
			t.Errorf("joinCompatible(%s %s, %s %s) = %v", tc.a.ColumnType, tc.a.Collation, tc.b.ColumnType, tc.b.Collation, got)
		}
	}
	why := joinMismatch(strCol("varchar(10)", "utf8mb4", "utf8mb4_bin"), strCol("varchar(10)", "utf8mb4", "utf8mb4_general_ci"))
	if !strings.Contains(why, "utf8mb4_bin") || !strings.Contains(why, "utf8mb4_general_ci") {
		t.Errorf("collation mismatch message %q should name both collations", why)
	}
}

func strCol(ct, charset, coll string) *introspect.Column {
	dt := ct
	if i := strings.IndexByte(ct, '('); i >= 0 {
		dt = ct[:i]
	}
	return &introspect.Column{DataType: dt, ColumnType: ct, Charset: charset, Collation: coll}
}

// TestKeyableColumn: declared keys exclude the types a keyset cursor cannot
// seek on in their sort order (ENUM/SET sort by member index, not value).
func TestKeyableColumn(t *testing.T) {
	for dt, ok := range map[string]bool{
		"int": true, "bigint": true, "varchar": true, "char": true, "datetime": true, "decimal": true, "binary": true,
		"enum": false, "set": false, "bit": false, "json": false, "vector": false, "text": false, "blob": false,
		"geometry": false, "point": false,
	} {
		if got := keyableColumn(&introspect.Column{DataType: dt}); got != ok {
			t.Errorf("keyableColumn(%s) = %v, want %v", dt, got, ok)
		}
	}
}

// TestDeclaredRelationshipFields: declared relationships become object /
// array fields with nested aggregates and where entries, honoring RBAC.
func TestDeclaredRelationshipFields(t *testing.T) {
	tables := `
post_stats:
  primary_key: [post_id]
  relationships:
    post: {type: object, target: posts, mapping: {post_id: id}}
posts:
  relationships:
    stats: {type: object, target: post_stats, mapping: {id: post_id}}
users:
  relationships:
    events: {type: array, target: events, mapping: {id: user_id}, description: "Their events"}
`
	roles := adminRoles + `
viewer:
  tables:
    posts: {select: true}
    users: {select: {allow: true, columns: [name]}}
    events: {select: true}
`
	all := mustModelSchema(t, tables, roles)
	s := all["admin"]
	if f := objField(t, s, "posts", "stats"); f == nil || f.Type.Name() != "post_stats" {
		t.Errorf("posts.stats = %+v", f)
	}
	if objField(t, s, "post_stats", "post") == nil {
		t.Error("post_stats.post missing")
	}
	ev := objField(t, s, "users", "events")
	if ev == nil || ev.Description != "Their events" || len(ev.Args) == 0 {
		t.Errorf("users.events = %+v", ev)
	}
	if objField(t, s, "users", "events_aggregate") == nil {
		t.Error("users.events_aggregate missing")
	}
	if s.Type("users_bool_exp").(*graphql.InputObject).Fields()["events"] == nil {
		t.Error("declared relationship missing from users_bool_exp")
	}

	v := all["viewer"]
	// Negative: viewer cannot read post_stats, so posts.stats is absent; it
	// cannot read users.id (the join column), so users.events is absent.
	if objField(t, v, "posts", "stats") != nil {
		t.Error("posts.stats visible without select on post_stats")
	}
	if objField(t, v, "users", "events") != nil || objField(t, v, "users", "events_aggregate") != nil {
		t.Error("users.events visible without the join column")
	}
	// The view is not granted to viewer at all.
	if v.Type("post_stats") != nil {
		t.Error("view type visible to a role that does not name it")
	}
}

// TestKeysAndListFields: the read key gates connection/by_pk; without a
// usable key a role gets <t>_list; logical keys never drive mutations.
func TestKeysAndListFields(t *testing.T) {
	roles := adminRoles + `
viewer:
  tables:
    events: {select: {allow: true, columns: [message]}}
    users: {select: {allow: true, columns: [name]}}
`
	all := mustModelSchema(t, "events:\n  primary_key: [user_id, message]\n", roles)
	s := all["admin"]
	if !hasQueryField(s, "events_connection") || !hasQueryField(s, "events_by_pk") {
		t.Error("declared key should give connection + by_pk")
	}
	if hasQueryField(s, "events_list") {
		t.Error("events_list must not exist when a cursor is available")
	}
	if args := s.QueryType().Fields()["events_by_pk"].Args; len(args) != 2 {
		t.Errorf("events_by_pk args = %d, want 2", len(args))
	}
	mf := s.MutationType().Fields()
	if mf["update_events_by_pk"] != nil || mf["delete_events_by_pk"] != nil || mf["insert_events_one"] != nil {
		t.Error("a logical key must not create by-pk mutations")
	}
	if mf["insert_events"] == nil {
		t.Error("bulk insert on a keyless table should remain")
	}

	v := all["viewer"]
	if hasQueryField(v, "events_connection") || hasQueryField(v, "events_by_pk") {
		t.Error("connection/by_pk need the whole key readable")
	}
	list := v.QueryType().Fields()["events_list"]
	if list == nil {
		t.Fatal("events_list missing for a role without a readable key")
	}
	names := map[string]bool{}
	for _, a := range list.Args {
		names[a.Name()] = true
	}
	if !names["limit"] || !names["where"] || names["offset"] || names["order_by"] || len(names) != 2 {
		t.Errorf("events_list args = %v (want limit, where only)", names)
	}
	// A hidden real PK also yields the list (never the PK).
	if !hasQueryField(v, "users_list") || hasQueryField(v, "users_connection") {
		t.Error("hidden PK: want users_list and no users_connection")
	}

	// Keyless without config: list, no connection.
	s2 := mustModelSchema(t, "", adminRoles)["admin"]
	if !hasQueryField(s2, "events_list") || hasQueryField(s2, "events_connection") || hasQueryField(s2, "post_stats_list") == false {
		t.Error("keyless table / view without a key should get <t>_list only")
	}
	if hasQueryField(s2, "users_list") {
		t.Error("tables with a readable PK get no list field")
	}
}

// TestListNameYields: a default <t>_list name that is already taken is left
// out (the newest generated field yields), while a configured one is checked
// like any fixed name.
func TestListNameYields(t *testing.T) {
	s := mustModelSchema(t, "users:\n  root_fields:\n    by_pk: events_list\n", adminRoles)["admin"]
	f := s.QueryType().Fields()["events_list"]
	if f == nil || len(f.Args) != 1 { // users' by_pk (one id argument)
		t.Errorf("events_list should be users' by_pk: %+v", f)
	}
	if _, err := buildModelSchema(t, "users:\n  root_fields:\n    by_pk: x\nevents:\n  root_fields:\n    list: x\n", adminRoles); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Errorf("explicit list name collision: err = %v", err)
	}
}

func TestDescriptionsFromComments(t *testing.T) {
	on := func(c *config.Config) { c.SchemaGen.DescriptionsFromComments = true }
	s := mustModelSchema(t, "users:\n  columns:\n    email: {description: \"From config\"}\n", adminRoles, on)["admin"]
	if d := s.Type("posts").Description(); d != "Blog posts" {
		t.Errorf("table comment not used: %q", d)
	}
	if f := objField(t, s, "users", "name"); f.Description != "Display name" {
		t.Errorf("column comment not used: %q", f.Description)
	}
	if f := objField(t, s, "users", "email"); f.Description != "From config" {
		t.Errorf("config description must win: %q", f.Description)
	}
	if f := objField(t, s, "users", "id"); f.Description != "Column id (bigint)" {
		t.Errorf("no comment: %q", f.Description)
	}
	off := mustModelSchema(t, "", adminRoles)["admin"]
	if f := objField(t, off, "users", "name"); f.Description != "Column name (varchar(50))" {
		t.Errorf("comment used while off: %q", f.Description)
	}
}
