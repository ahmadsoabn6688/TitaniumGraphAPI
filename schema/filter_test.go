package schema

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/graphql-go/graphql"

	"gqlgate/config"
	"gqlgate/introspect"
	"gqlgate/rbac"
)

// filterCatalog is a small blog schema with every relationship shape:
// posts.author_id -> users (object), users <- posts/comments (array), and the
// self-referential users.manager_id -> users.
func filterCatalog() *introspect.Catalog {
	col := func(name, dt string, pk bool) *introspect.Column {
		c := &introspect.Column{Name: name, DataType: dt, ColumnType: dt, IsPrimary: pk}
		if dt == "varchar" || dt == "text" {
			c.Charset, c.Collation = "utf8mb4", "utf8mb4_bin"
		}
		return c
	}
	mk := func(name string, cols ...*introspect.Column) *introspect.Table {
		t := &introspect.Table{Name: name, ColumnMap: map[string]*introspect.Column{}}
		for i, c := range cols {
			c.Ordinal = i
			t.Columns = append(t.Columns, c)
			t.ColumnMap[c.Name] = c
			if c.IsPrimary {
				t.PrimaryKey = append(t.PrimaryKey, c.Name)
			}
		}
		return t
	}
	email := col("email", "varchar", false)
	email.Collation = "utf8mb4_general_ci"
	users := mk("users", col("id", "bigint", true), col("name", "varchar", false), email,
		col("manager_id", "bigint", false), col("secret", "varchar", false), col("is_public", "tinyint", false))
	posts := mk("posts", col("id", "bigint", true), col("author_id", "bigint", false),
		col("title", "varchar", false), col("body", "text", false), col("published_on", "date", false))
	comments := mk("comments", col("id", "bigint", true), col("post_id", "bigint", false),
		col("user_id", "bigint", false), col("body", "text", false))

	fk := func(name, from string, cols []string, to string, refs []string) {
		f := &introspect.ForeignKey{ConstraintName: name, Table: from, Columns: cols, RefTable: to, RefColumns: refs}
		tables := map[string]*introspect.Table{"users": users, "posts": posts, "comments": comments}
		tables[from].ForeignKeys = append(tables[from].ForeignKeys, f)
		tables[to].IncomingFKs = append(tables[to].IncomingFKs, f)
	}
	fk("fk_comments_post", "comments", []string{"post_id"}, "posts", []string{"id"})
	fk("fk_comments_user", "comments", []string{"user_id"}, "users", []string{"id"})
	fk("fk_posts_author", "posts", []string{"author_id"}, "users", []string{"id"})
	fk("fk_users_manager", "users", []string{"manager_id"}, "users", []string{"id"})

	return &introspect.Catalog{
		SchemaName: "appdb",
		Tables:     map[string]*introspect.Table{"users": users, "posts": posts, "comments": comments},
		TableOrder: []string{"comments", "posts", "users"},
	}
}

// buildFilterRole builds one role over filterCatalog without a database and
// returns its builder (for SQL inspection) and schema.
func buildFilterRole(t *testing.T, role *config.Role, ops ...config.CustomOperator) (*builder, graphql.Schema) {
	t.Helper()
	b, s, err := tryBuildFilterRole(role, ops...)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return b, s
}

func tryBuildFilterRole(role *config.Role, ops ...config.CustomOperator) (*builder, graphql.Schema, error) {
	cfg := &config.Config{Roles: map[string]*config.Role{"r": role}}
	cfg.SchemaGen.DefaultPageSize = 25
	cfg.SchemaGen.MaxPageSize = 200
	cfg.SchemaGen.CustomOperators = ops
	opt := Options{Catalog: filterCatalog(), Config: cfg}
	shared, err := newBuildShared(opt)
	if err != nil {
		return nil, graphql.Schema{}, err
	}
	access, err := rbac.Resolve("r", role, opt.Catalog)
	if err != nil {
		return nil, graphql.Schema{}, err
	}
	return buildRoleBuilder(opt, shared, "r", access)
}

func selectAll() *config.Role {
	return &config.Role{Tables: map[string]*config.TablePerm{"*": {Select: &config.OpPerm{Allow: true}}}}
}

func inputFields(t *testing.T, s graphql.Schema, typeName string) []string {
	t.Helper()
	obj, ok := s.Type(typeName).(*graphql.InputObject)
	if !ok {
		t.Fatalf("input type %q missing", typeName)
	}
	var names []string
	for n := range obj.Fields() {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func fieldTypeName(t *testing.T, s graphql.Schema, typeName, field string) string {
	t.Helper()
	obj := s.Type(typeName).(*graphql.InputObject)
	f, ok := obj.Fields()[field]
	if !ok {
		t.Fatalf("%s.%s missing", typeName, field)
	}
	return f.Type.Name()
}

func has(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

var testID = &rbac.Identity{Role: "r", Claims: map[string]any{"sub": float64(7)}}

func TestLikeEscape(t *testing.T) {
	for in, want := range map[string]string{
		"plain":   "plain",
		"50%":     "50!%",
		"a_b":     "a!_b",
		"wow!":    "wow!!",
		"!%_":     "!!!%!_",
		`back\sl`: `back\sl`,
	} {
		if got := likeEscape(in); got != want {
			t.Errorf("likeEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStringOperatorSQL(t *testing.T) {
	bin := &introspect.Column{Name: "title", DataType: "varchar", Charset: "utf8mb4", Collation: "utf8mb4_bin"}
	ci := &introspect.Column{Name: "email", DataType: "varchar", Charset: "utf8mb4", Collation: "utf8mb4_general_ci"}
	tests := []struct {
		col      *introspect.Column
		op, val  string
		wantSQL  string
		wantArgs []any
	}{
		{bin, "_ilike", "%Ada%", "LOWER(c) LIKE LOWER(?)", []any{"%Ada%"}},
		{bin, "_nilike", "a_", "LOWER(c) NOT LIKE LOWER(?)", []any{"a_"}},
		{ci, "_ilike", "%ada%", "c LIKE ?", []any{"%ada%"}},
		{ci, "_nilike", "%ada%", "c NOT LIKE ?", []any{"%ada%"}},
		{bin, "_iregex", "^ad", "REGEXP_LIKE(c, ?, 'i')", []any{"^ad"}},
		{bin, "_niregex", "^ad", "NOT REGEXP_LIKE(c, ?, 'i')", []any{"^ad"}},
		{bin, "_contains", "50%_off", "c LIKE ? ESCAPE '!'", []any{"%50!%!_off%"}},
		{bin, "_starts_with", "Notes", "c LIKE ? ESCAPE '!'", []any{"Notes%"}},
		{bin, "_ends_with", "!", "c LIKE ? ESCAPE '!'", []any{"%!!"}},
		{bin, "_icontains", "TiDB", "LOWER(c) LIKE LOWER(?) ESCAPE '!'", []any{"%TiDB%"}},
		{bin, "_istarts_with", "no", "LOWER(c) LIKE LOWER(?) ESCAPE '!'", []any{"no%"}},
		{bin, "_iends_with", "_x", "LOWER(c) LIKE LOWER(?) ESCAPE '!'", []any{"%!_x"}},
		{ci, "_icontains", "ada", "c LIKE ? ESCAPE '!'", []any{"%ada%"}},
		// case-sensitive literal match on a _ci column forces the _bin collation
		{ci, "_starts_with", "Ada", "c COLLATE utf8mb4_bin LIKE ? ESCAPE '!'", []any{"Ada%"}},
		{ci, "_contains", "x", "c COLLATE utf8mb4_bin LIKE ? ESCAPE '!'", []any{"%x%"}},
	}
	for _, tc := range tests {
		c, handled, err := stringCond(tc.col, "c", tc.op, tc.val)
		if !handled || err != nil {
			t.Fatalf("%s %s: handled=%v err=%v", tc.col.Collation, tc.op, handled, err)
		}
		if c.sql != tc.wantSQL || !reflect.DeepEqual(c.args, tc.wantArgs) {
			t.Errorf("%s on %s: got %q %v, want %q %v", tc.op, tc.col.Collation, c.sql, c.args, tc.wantSQL, tc.wantArgs)
		}
	}
	if _, handled, _ := stringCond(bin, "c", "_eq", "x"); handled {
		t.Error("_eq must fall through to the generic operators")
	}
	if _, _, err := stringCond(bin, "c", "_ilike", nil); err == nil {
		t.Error("null pattern must be rejected")
	}
}

func TestStringOperatorsOnlyOnStrings(t *testing.T) {
	_, s := buildFilterRole(t, selectAll())
	str := inputFields(t, s, "String_comparison_exp")
	for _, op := range append([]string{"_eq", "_like", "_regex"}, stringOps...) {
		if !has(str, op) {
			t.Errorf("String_comparison_exp missing %s", op)
		}
	}
	big := inputFields(t, s, "BigInt_comparison_exp")
	for _, op := range stringOps {
		if has(big, op) {
			t.Errorf("BigInt_comparison_exp must not offer %s", op)
		}
	}
}

func TestRelationshipFilterSQL(t *testing.T) {
	b, s := buildFilterRole(t, selectAll())
	fields := inputFields(t, s, "posts_bool_exp")
	for _, f := range []string{"author", "comments", "id", "title", "_and", "_or", "_not"} {
		if !has(fields, f) {
			t.Errorf("posts_bool_exp missing %q (have %v)", f, fields)
		}
	}
	if got := fieldTypeName(t, s, "posts_bool_exp", "author"); got != "users_bool_exp" {
		t.Errorf("author filter type = %s, want users_bool_exp", got)
	}

	where := map[string]any{
		"author":   map[string]any{"name": map[string]any{"_eq": "Ada"}},
		"comments": map[string]any{},
		"_not":     map[string]any{"comments": map[string]any{"body": map[string]any{"_icontains": "spam"}}},
	}
	c, err := b.whereSQL(b.tinfos["posts"], where, testID)
	if err != nil {
		t.Fatal(err)
	}
	want := "NOT (EXISTS (SELECT 1 FROM `appdb`.`comments` AS `__gqlgate_r1` WHERE `__gqlgate_r1`.`post_id` = `appdb`.`posts`.`id` AND (LOWER(`__gqlgate_r1`.`body`) LIKE LOWER(?) ESCAPE '!'))) AND " +
		"EXISTS (SELECT 1 FROM `appdb`.`users` AS `__gqlgate_r2` WHERE `__gqlgate_r2`.`id` = `appdb`.`posts`.`author_id` AND (`__gqlgate_r2`.`name` = ?)) AND " +
		"EXISTS (SELECT 1 FROM `appdb`.`comments` AS `__gqlgate_r3` WHERE `__gqlgate_r3`.`post_id` = `appdb`.`posts`.`id`)"
	if c.sql != want {
		t.Errorf("sql =\n%s\nwant\n%s", c.sql, want)
	}
	if !reflect.DeepEqual(c.args, []any{"%spam%", "Ada"}) {
		t.Errorf("args = %v", c.args)
	}
}

func TestSelfReferentialRelationshipAliases(t *testing.T) {
	b, s := buildFilterRole(t, selectAll())
	fields := inputFields(t, s, "users_bool_exp")
	for _, f := range []string{"manager", "users", "posts", "comments"} {
		if !has(fields, f) {
			t.Errorf("users_bool_exp missing %q (have %v)", f, fields)
		}
	}
	c, err := b.whereSQL(b.tinfos["users"], map[string]any{
		"manager": map[string]any{"manager": map[string]any{"name": map[string]any{"_eq": "Boss"}}},
	}, testID)
	if err != nil {
		t.Fatal(err)
	}
	want := "EXISTS (SELECT 1 FROM `appdb`.`users` AS `__gqlgate_r1` WHERE `__gqlgate_r1`.`id` = `appdb`.`users`.`manager_id` AND (" +
		"EXISTS (SELECT 1 FROM `appdb`.`users` AS `__gqlgate_r2` WHERE `__gqlgate_r2`.`id` = `__gqlgate_r1`.`manager_id` AND (`__gqlgate_r2`.`name` = ?))))"
	if c.sql != want {
		t.Errorf("sql =\n%s\nwant\n%s", c.sql, want)
	}
	// Incoming self-relationship: "users" are the direct reports.
	c, err = b.whereSQL(b.tinfos["users"], map[string]any{"users": map[string]any{}}, testID)
	if err != nil {
		t.Fatal(err)
	}
	if want := "EXISTS (SELECT 1 FROM `appdb`.`users` AS `__gqlgate_r1` WHERE `__gqlgate_r1`.`manager_id` = `appdb`.`users`.`id`)"; c.sql != want {
		t.Errorf("reports sql = %s", c.sql)
	}
}

func TestRelationshipNamesUnchanged(t *testing.T) {
	_, s := buildFilterRole(t, selectAll())
	users := s.Type("users").(*graphql.Object).Fields()
	for _, f := range []string{"manager", "users", "posts", "comments"} {
		if users[f] == nil {
			t.Errorf("users object type missing relationship %q", f)
		}
	}
	posts := s.Type("posts").(*graphql.Object).Fields()
	if posts["author"] == nil || posts["comments"] == nil {
		t.Error("posts object type must keep author/comments relationships")
	}
}

func TestRelationshipFilterTargetRowFilter(t *testing.T) {
	role := selectAll()
	role.Tables["users"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, Filter: "is_public = 1 OR id = :jwt.sub"}}
	b, s := buildFilterRole(t, role)

	// Without a database the target's row filter cannot be verified, so
	// relationships into users are withheld (fail closed)...
	if has(inputFields(t, s, "posts_bool_exp"), "author") {
		t.Fatal("author must not be filterable when users' row filter is unverified")
	}
	if _, err := b.whereSQL(b.tinfos["posts"], map[string]any{"author": map[string]any{}}, testID); err == nil {
		t.Fatal("variables must not reach a withheld relationship")
	}

	// ...and once verified, the filter is embedded in a derived table.
	b.tinfos["users"].selectFilterOK = true
	if err := b.resolveFilterRels(b.tinfos["posts"]); err != nil {
		t.Fatal(err)
	}
	c, err := b.whereSQL(b.tinfos["posts"], map[string]any{"author": map[string]any{"name": map[string]any{"_eq": "Ada"}}}, testID)
	if err != nil {
		t.Fatal(err)
	}
	want := "EXISTS (SELECT 1 FROM (SELECT * FROM `appdb`.`users` WHERE is_public = 1 OR id = ?) AS `__gqlgate_r1` WHERE `__gqlgate_r1`.`id` = `appdb`.`posts`.`author_id` AND (`__gqlgate_r1`.`name` = ?))"
	if c.sql != want {
		t.Errorf("sql =\n%s\nwant\n%s", c.sql, want)
	}
	if !reflect.DeepEqual(c.args, []any{float64(7), "Ada"}) {
		t.Errorf("args = %v (role filter args must precede the predicate's)", c.args)
	}
	// A claim the filter needs but the token lacks is an error, never "no filter".
	if _, err := b.whereSQL(b.tinfos["posts"], map[string]any{"author": map[string]any{}}, &rbac.Identity{Claims: map[string]any{}}); err == nil {
		t.Error("missing claim in target filter must fail")
	}
}

func TestRelationshipFilterHiddenTargets(t *testing.T) {
	// No select on users: no author/manager relationship at all.
	role := &config.Role{Tables: map[string]*config.TablePerm{
		"posts":    {Select: &config.OpPerm{Allow: true}},
		"comments": {Select: &config.OpPerm{Allow: true}},
	}}
	b, s := buildFilterRole(t, role)
	if has(inputFields(t, s, "posts_bool_exp"), "author") {
		t.Error("author must not be offered when users is not selectable")
	}
	if _, err := b.whereSQL(b.tinfos["posts"], map[string]any{"author": map[string]any{}}, testID); err == nil {
		t.Error("author filter via variables must be rejected")
	}

	// users readable but secret hidden: can't be reached through the relationship.
	role.Tables["users"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, Columns: []string{"id", "name"}}}
	b, s = buildFilterRole(t, role)
	if !has(inputFields(t, s, "posts_bool_exp"), "author") {
		t.Fatal("author should be filterable")
	}
	if has(inputFields(t, s, "users_bool_exp"), "secret") {
		t.Error("hidden column must not be in users_bool_exp")
	}
	if _, err := b.whereSQL(b.tinfos["posts"], map[string]any{"author": map[string]any{"secret": map[string]any{"_eq": "x"}}}, testID); err == nil {
		t.Error("filtering on a hidden target column through a relationship must fail")
	}

	// Local join column not readable: relationship neither navigable nor filterable.
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, Columns: []string{"id", "title"}}}
	_, s = buildFilterRole(t, role)
	if has(inputFields(t, s, "posts_bool_exp"), "author") {
		t.Error("author must not be filterable when posts.author_id is hidden")
	}
}

func TestRelationshipFilterDepthLimit(t *testing.T) {
	b, _ := buildFilterRole(t, selectAll())
	expr := map[string]any{}
	cur := expr
	for i := 0; i < maxRelFilterDepth+1; i++ {
		next := map[string]any{}
		cur["manager"] = next
		cur = next
	}
	if _, err := b.whereSQL(b.tinfos["users"], expr, testID); err == nil || !strings.Contains(err.Error(), "nest") {
		t.Errorf("expected depth error, got %v", err)
	}
}

func TestFilterableColumnsAndOperators(t *testing.T) {
	role := selectAll()
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{
		Allow: true,
		FilterableColumns: &config.FilterableColumns{
			Names: []string{"id", "title"},
			Ops:   map[string][]string{"title": {"_eq", "_ilike"}},
		},
	}}
	b, s := buildFilterRole(t, role)
	fields := inputFields(t, s, "posts_bool_exp")
	if has(fields, "body") || has(fields, "author_id") {
		t.Errorf("non-filterable columns exposed: %v", fields)
	}
	if got := fieldTypeName(t, s, "posts_bool_exp", "title"); got != "posts_title_comparison_exp" {
		t.Errorf("restricted title type = %s", got)
	}
	if got := inputFields(t, s, "posts_title_comparison_exp"); !reflect.DeepEqual(got, []string{"_eq", "_ilike"}) {
		t.Errorf("title operators = %v", got)
	}
	if got := fieldTypeName(t, s, "posts_bool_exp", "id"); got != "BigInt_comparison_exp" {
		t.Errorf("unrestricted id type = %s, want the shared BigInt_comparison_exp", got)
	}
	// Relationships stay filterable (filter_relationships not set).
	if !has(fields, "author") {
		t.Error("author relationship should still be filterable")
	}
	// Defense in depth for values smuggled in through variables.
	ti := b.tinfos["posts"]
	if _, err := b.whereSQL(ti, map[string]any{"body": map[string]any{"_eq": "x"}}, testID); err == nil {
		t.Error("non-filterable column accepted")
	}
	if _, err := b.whereSQL(ti, map[string]any{"title": map[string]any{"_like": "%x"}}, testID); err == nil {
		t.Error("disallowed operator accepted")
	}
	if _, err := b.whereSQL(ti, map[string]any{"title": map[string]any{"_ilike": "%x"}}, testID); err != nil {
		t.Errorf("allowed operator rejected: %v", err)
	}
	// The body column is still selectable.
	if s.Type("posts").(*graphql.Object).Fields()["body"] == nil {
		t.Error("filterable_columns must not hide readable columns from output")
	}
}

func TestFilterOperatorsTableWide(t *testing.T) {
	role := selectAll()
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, FilterOperators: []string{"_eq", "_in", "_starts_with"}}}
	_, s := buildFilterRole(t, role)
	if got := inputFields(t, s, "posts_title_comparison_exp"); !reflect.DeepEqual(got, []string{"_eq", "_in", "_starts_with"}) {
		t.Errorf("title ops = %v", got)
	}
	if got := inputFields(t, s, "posts_id_comparison_exp"); !reflect.DeepEqual(got, []string{"_eq", "_in"}) {
		t.Errorf("id ops = %v", got)
	}
	// Other tables keep the shared, full types.
	if got := fieldTypeName(t, s, "users_bool_exp", "name"); got != "String_comparison_exp" {
		t.Errorf("users.name type = %s", got)
	}
}

func TestFilterRelationshipsAllowList(t *testing.T) {
	none := []string{}
	role := selectAll()
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, FilterRelationships: &none}}
	b, s := buildFilterRole(t, role)
	fields := inputFields(t, s, "posts_bool_exp")
	if has(fields, "author") || has(fields, "comments") {
		t.Errorf("filter_relationships: [] must hide every relationship: %v", fields)
	}
	if _, err := b.whereSQL(b.tinfos["posts"], map[string]any{"author": map[string]any{}}, testID); err == nil {
		t.Error("hidden relationship accepted")
	}
	// Navigation is unaffected.
	if s.Type("posts").(*graphql.Object).Fields()["author"] == nil {
		t.Error("filter_relationships must not remove the relationship field from output")
	}

	only := []string{"author"}
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, FilterRelationships: &only}}
	_, s = buildFilterRole(t, role)
	fields = inputFields(t, s, "posts_bool_exp")
	if !has(fields, "author") || has(fields, "comments") {
		t.Errorf("only author expected: %v", fields)
	}

	bad := []string{"writer"}
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, FilterRelationships: &bad}}
	if _, _, err := tryBuildFilterRole(role); err == nil || !strings.Contains(err.Error(), "writer") {
		t.Errorf("unknown relationship must fail the build, got %v", err)
	}
}

func TestFilterSurfaceValidation(t *testing.T) {
	cases := map[string]*config.OpPerm{
		"unknown table-wide op": {Allow: true, FilterOperators: []string{"_eqq"}},
		"unknown column op": {Allow: true, FilterableColumns: &config.FilterableColumns{
			Names: []string{"title"}, Ops: map[string][]string{"title": {"_bogus"}}}},
		"op not applicable": {Allow: true, FilterableColumns: &config.FilterableColumns{
			Names: []string{"id"}, Ops: map[string][]string{"id": {"_ilike"}}}},
		"hidden filterable column": {Allow: true, Columns: []string{"id"}, FilterableColumns: &config.FilterableColumns{
			Names: []string{"title"}}},
		"missing filterable column": {Allow: true, FilterableColumns: &config.FilterableColumns{Names: []string{"nope"}}},
	}
	for name, perm := range cases {
		role := selectAll()
		role.Tables["posts"] = &config.TablePerm{Select: perm}
		if _, _, err := tryBuildFilterRole(role); err == nil {
			t.Errorf("%s: expected a build error", name)
		}
	}

	// Wildcard rules skip what does not fit a table instead of failing.
	role := &config.Role{Tables: map[string]*config.TablePerm{"*": {Select: &config.OpPerm{
		Allow: true,
		FilterableColumns: &config.FilterableColumns{
			Names: []string{"id", "title"}, Ops: map[string][]string{"title": {"_eq", "_ilike"}, "id": {"_ilike", "_eq"}}},
	}}}}
	_, s := buildFilterRole(t, role)
	if got := inputFields(t, s, "users_bool_exp"); has(got, "title") || !has(got, "id") {
		t.Errorf("wildcard users fields = %v", got)
	}
	if got := inputFields(t, s, "posts_id_comparison_exp"); !reflect.DeepEqual(got, []string{"_eq"}) {
		t.Errorf("wildcard id ops = %v", got)
	}
}

func TestCustomOperators(t *testing.T) {
	ops := []config.CustomOperator{
		{Name: "_len_gt", Argument: "Int", AppliesTo: []string{"String"}, SQL: "CHAR_LENGTH({column}) > {value}"},
		{Name: "_between_len", Argument: "Int", AppliesTo: []string{"String"}, SQL: "CHAR_LENGTH({column}) BETWEEN {value} AND {value} * 2"},
		{Name: "_year_eq", Argument: "Int", AppliesTo: []string{"Date", "DateTime"}, SQL: "YEAR({column}) = {value}"},
	}
	b, s := buildFilterRole(t, selectAll(), ops...)
	str := inputFields(t, s, "String_comparison_exp")
	if !has(str, "_len_gt") || !has(str, "_between_len") || has(str, "_year_eq") {
		t.Errorf("String ops = %v", str)
	}
	if got := fieldTypeName(t, s, "String_comparison_exp", "_len_gt"); got != "Int" {
		t.Errorf("_len_gt arg type = %s, want Int", got)
	}
	if !has(inputFields(t, s, "Date_comparison_exp"), "_year_eq") {
		t.Error("Date_comparison_exp missing _year_eq")
	}
	c, err := b.whereSQL(b.tinfos["posts"], map[string]any{
		"title":  map[string]any{"_between_len": 3},
		"author": map[string]any{"name": map[string]any{"_len_gt": 2}},
	}, testID)
	if err != nil {
		t.Fatal(err)
	}
	want := "EXISTS (SELECT 1 FROM `appdb`.`users` AS `__gqlgate_r1` WHERE `__gqlgate_r1`.`id` = `appdb`.`posts`.`author_id` AND ((CHAR_LENGTH(`__gqlgate_r1`.`name`) > ?))) AND (CHAR_LENGTH(`title`) BETWEEN ? AND ? * 2)"
	if c.sql != want {
		t.Errorf("sql =\n%s\nwant\n%s", c.sql, want)
	}
	if !reflect.DeepEqual(c.args, []any{2, 3, 3}) {
		t.Errorf("args = %v", c.args)
	}

	// Custom operators obey allow-lists like built-ins.
	role := selectAll()
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, FilterOperators: []string{"_eq"}}}
	b, _ = buildFilterRole(t, role, ops...)
	if _, err := b.whereSQL(b.tinfos["posts"], map[string]any{"title": map[string]any{"_len_gt": 3}}, testID); err == nil {
		t.Error("custom operator outside the allow-list accepted")
	}

	// A custom operator may not shadow a built-in one.
	if _, _, err := tryBuildFilterRole(selectAll(), config.CustomOperator{Name: "_ilike", Argument: "String", SQL: "{column} = {value}"}); err == nil {
		t.Error("custom operator named like a built-in must be rejected")
	}
}

func TestSplitTemplateKeepsBracesInLiterals(t *testing.T) {
	got := splitTemplate("JSON_EXTRACT({column}, '$.{x}') = {value}")
	want := []string{"JSON_EXTRACT(", "{column}", ", '$.{", "x}') = ", "{value}", ""}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitTemplate = %q", got)
	}
}
