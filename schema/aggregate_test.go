package schema

import (
	"context"
	"database/sql/driver"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/graphql-go/graphql"

	"gqlgate/config"
	"gqlgate/introspect"
	"gqlgate/rbac"
)

func objectFields(t *testing.T, s graphql.Schema, typeName string) []string {
	t.Helper()
	obj, ok := s.Type(typeName).(*graphql.Object)
	if !ok {
		t.Fatalf("object type %q missing", typeName)
	}
	var names []string
	for n := range obj.Fields() {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func objectFieldType(t *testing.T, s graphql.Schema, typeName, field string) string {
	t.Helper()
	var fields graphql.FieldDefinitionMap
	switch ty := s.Type(typeName).(type) {
	case *graphql.Object:
		fields = ty.Fields()
	case *graphql.Interface: // mutation_response
		fields = ty.Fields()
	default:
		t.Fatalf("object type %q missing", typeName)
	}
	f, ok := fields[field]
	if !ok {
		t.Fatalf("%s.%s missing", typeName, field)
	}
	return f.Type.String()
}

// selectDeleteAll is selectAll plus delete, so mutation_response exists.
func selectDeleteAll() *config.Role {
	return &config.Role{Tables: map[string]*config.TablePerm{"*": {
		Select: &config.OpPerm{Allow: true}, Delete: &config.OpPerm{Allow: true}}}}
}

func TestAggregateResultShape(t *testing.T) {
	_, s := buildFilterRole(t, selectDeleteAll())

	got := objectFields(t, s, "posts_aggregate_result")
	want := []string{"approx_count_distinct", "avg", "count", "count_columns", "count_distinct", "max", "min",
		"stddev", "stddev_pop", "stddev_samp", "sum", "var_pop", "var_samp", "variance"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("posts_aggregate_result fields = %v, want %v", got, want)
	}
	// Without count_type the pre-existing count fields keep their Int! type
	// (backward compatibility); the new per-column counts are 64-bit.
	if ty := objectFieldType(t, s, "posts_aggregate_result", "count"); ty != "Int!" {
		t.Errorf("count type = %s, want Int!", ty)
	}
	if ty := objectFieldType(t, s, "posts_connection", "total_count"); ty != "Int!" {
		t.Errorf("total_count type = %s, want Int!", ty)
	}
	if ty := objectFieldType(t, s, "mutation_response", "affected_rows"); ty != "Int!" {
		t.Errorf("affected_rows type = %s, want Int!", ty)
	}
	if ty := objectFieldType(t, s, "posts_count_distinct_fields", "author_id"); ty != "BigInt!" {
		t.Errorf("count_distinct column type = %s, want BigInt!", ty)
	}
	if ty := objectFieldType(t, s, "posts_stddev_fields", "id"); ty != "Float" {
		t.Errorf("stddev column type = %s, want Float", ty)
	}
	// Existing buckets keep their types.
	if ty := objectFieldType(t, s, "posts_sum_fields", "id"); ty != "Decimal" {
		t.Errorf("sum column type = %s, want Decimal", ty)
	}
	if ty := objectFieldType(t, s, "posts_avg_fields", "id"); ty != "Float" {
		t.Errorf("avg column type = %s, want Float", ty)
	}

	// Column applicability: count_columns covers every column, the distinct
	// counts skip TEXT, the statistics only take numbers.
	if got := objectFields(t, s, "posts_count_columns_fields"); strings.Join(got, ",") != "author_id,body,id,published_on,title" {
		t.Errorf("count_columns fields = %v", got)
	}
	for _, typ := range []string{"posts_count_distinct_fields", "posts_count_distinct_approx_fields"} {
		if got := objectFields(t, s, typ); strings.Join(got, ",") != "author_id,id,published_on,title" {
			t.Errorf("%s fields = %v (TEXT must be excluded)", typ, got)
		}
	}
	for _, fn := range []string{"stddev", "stddev_pop", "stddev_samp", "variance", "var_pop", "var_samp"} {
		if got := objectFields(t, s, "posts_"+fn+"_fields"); strings.Join(got, ",") != "author_id,id" {
			t.Errorf("%s fields = %v, want numeric columns only", fn, got)
		}
	}
}

func TestCountTypes(t *testing.T) {
	cfg := &config.Config{Roles: map[string]*config.Role{"r": selectDeleteAll()}}
	cfg.SchemaGen.DefaultPageSize = 25
	cfg.SchemaGen.MaxPageSize = 200
	for countType, want := range map[string]string{
		config.CountTypeInt: "Int!", config.CountTypeBigInt: "BigInt!", "": "Int!",
	} {
		cfg.SchemaGen.CountType = countType
		schemas, err := BuildAll(Options{Catalog: filterCatalog(), Config: cfg})
		if err != nil {
			t.Fatal(err)
		}
		s := schemas["r"]
		for _, tc := range [][2]string{
			{"posts_aggregate_result", "count"},
			{"posts_connection", "total_count"},
			{"mutation_response", "affected_rows"},
		} {
			if ty := objectFieldType(t, s, tc[0], tc[1]); ty != want {
				t.Errorf("%s.%s = %s, want %s under count_type %q", tc[0], tc[1], ty, want, countType)
			}
		}
		// The new per-column counts stay 64-bit regardless.
		if ty := objectFieldType(t, s, "posts_count_distinct_fields", "id"); ty != "BigInt!" {
			t.Errorf("count_distinct column type = %s, want BigInt!", ty)
		}
	}
}

// A role that can read no numeric column of a table used to produce an empty
// <t>_sum_fields type, which graphql-go rejects; such buckets are now omitted.
func TestAggregateBucketsWithoutColumnsOmitted(t *testing.T) {
	role := selectAll()
	role.Tables["users"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, Columns: []string{"name", "email"}}}
	_, s := buildFilterRole(t, role)
	got := objectFields(t, s, "users_aggregate_result")
	if strings.Join(got, ",") != "approx_count_distinct,count,count_columns,count_distinct,max,min" {
		t.Errorf("users_aggregate_result fields = %v", got)
	}
	if s.Type("users_sum_fields") != nil || s.Type("users_stddev_fields") != nil {
		t.Error("empty numeric bucket types must not be generated")
	}
}

func TestAggPlanSQL(t *testing.T) {
	cat := filterCatalog()
	posts := cat.Tables["posts"]
	id, author, title := posts.ColumnMap["id"], posts.ColumnMap["author_id"], posts.ColumnMap["title"]
	req := aggRequest{count: true, cols: map[string][]*introspect.Column{
		"count_columns":         {title},
		"count_distinct":        {author},
		"approx_count_distinct": {author},
		"stddev":                {id},
		"stddev_pop":            {id},
		"stddev_samp":           {id},
		"variance":              {id},
		"var_pop":               {id},
		"var_samp":              {id},
		"sum":                   {id},
	}}
	exprs, plan := aggPlan(req)
	want := "COUNT(*), SUM(`id`), COUNT(`title`), COUNT(DISTINCT `author_id`), APPROX_COUNT_DISTINCT(`author_id`), " +
		"STDDEV_SAMP(`id`), STDDEV_POP(`id`), STDDEV_SAMP(`id`), VAR_SAMP(`id`), VAR_POP(`id`), VAR_SAMP(`id`)"
	if got := strings.Join(exprs, ", "); got != want {
		t.Errorf("aggPlan =\n %s\nwant\n %s", got, want)
	}
	if len(plan) != len(exprs) {
		t.Fatalf("plan has %d slots for %d expressions", len(plan), len(exprs))
	}

	// An empty request still counts, so the SELECT is never empty.
	if exprs, _ := aggPlan(aggRequest{}); strings.Join(exprs, ",") != "COUNT(*)" {
		t.Errorf("empty request = %v, want COUNT(*)", exprs)
	}

	// Over zero rows: counts are 0, everything else null.
	empty := emptyAggResult(req)
	if empty["count"] != int64(0) {
		t.Errorf("empty count = %#v", empty["count"])
	}
	if v := empty["count_distinct"].(map[string]any)["author_id"]; v != int64(0) {
		t.Errorf("empty count_distinct = %#v, want 0", v)
	}
	if _, set := empty["stddev"].(map[string]any)["id"]; set {
		t.Error("empty stddev must be null")
	}

	// Signatures distinguish selections (they key relationship loaders).
	a := aggRequest{cols: map[string][]*introspect.Column{"sum": {id}}}
	b := aggRequest{cols: map[string][]*introspect.Column{"avg": {id}}}
	if a.signature() == b.signature() {
		t.Error("different aggregate selections must not share a loader signature")
	}
}

func TestAggregateResultConversion(t *testing.T) {
	cat := filterCatalog()
	posts := cat.Tables["posts"]
	id, title := posts.ColumnMap["id"], posts.ColumnMap["title"]
	req := aggRequest{count: true, cols: map[string][]*introspect.Column{
		"count_distinct": {title}, "stddev_pop": {id}, "sum": {id},
	}}
	_, plan := aggPlan(req)
	b := &builder{opt: Options{Config: &config.Config{}}}
	out := emptyAggResult(req)
	// Text-protocol bytes and a count past 2^31 (must stay exact).
	vals := []any{[]byte("5000000000"), []byte("123456789012"), []byte("4000000001"), []byte("1.5")}
	if err := b.fillAggResult(out, plan, vals); err != nil {
		t.Fatal(err)
	}
	if out["count"] != int64(5000000000) {
		t.Errorf("count = %#v", out["count"])
	}
	if v := out["count_distinct"].(map[string]any)["title"]; v != int64(4000000001) {
		t.Errorf("count_distinct = %#v", v)
	}
	if v := out["stddev_pop"].(map[string]any)["id"]; v != 1.5 {
		t.Errorf("stddev_pop = %#v", v)
	}
	if v := out["sum"].(map[string]any)["id"]; v != "123456789012" {
		t.Errorf("sum = %#v", v)
	}
	if got := bigIntScalar.Serialize(out["count"]); got != int64(5000000000) {
		t.Errorf("BigInt serializes a large count as %#v", got)
	}
}

func TestNestedAggregateFields(t *testing.T) {
	_, s := buildFilterRole(t, selectAll())
	users := objectFields(t, s, "users")
	for _, f := range []string{"posts_aggregate", "comments_aggregate", "users_aggregate"} {
		if !has(users, f) {
			t.Errorf("users is missing %s: %v", f, users)
		}
	}
	if ty := objectFieldType(t, s, "users", "posts_aggregate"); ty != "posts_aggregate_result!" {
		t.Errorf("users.posts_aggregate type = %s", ty)
	}
	if args := s.Type("users").(*graphql.Object).Fields()["posts_aggregate"].Args; len(args) != 1 || args[0].Name() != "where" {
		t.Errorf("posts_aggregate must take only where, got %v", args)
	}
	// Object relationships get no aggregate.
	if has(objectFields(t, s, "posts"), "author_aggregate") {
		t.Error("object relationships must not get an aggregate field")
	}
	if !has(objectFields(t, s, "posts"), "comments_aggregate") {
		t.Error("posts.comments_aggregate missing")
	}

	// A child table the role cannot select gets no nested aggregate.
	role := selectAll()
	role.Tables["comments"] = &config.TablePerm{}
	_, s = buildFilterRole(t, role)
	if has(objectFields(t, s, "users"), "comments_aggregate") || has(objectFields(t, s, "posts"), "comments_aggregate") {
		t.Error("comments_aggregate must be absent when comments is not selectable")
	}
	// The nested result type follows the child's column permissions.
	role = selectAll()
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, Columns: []string{"id", "author_id", "title"}}}
	_, s = buildFilterRole(t, role)
	if has(objectFields(t, s, "posts_max_fields"), "body") {
		t.Error("hidden column body must not be aggregatable")
	}
}

func TestNestedAggregateNameCollision(t *testing.T) {
	cat := filterCatalog()
	users := cat.Tables["users"]
	c := &introspect.Column{Name: "posts_aggregate", DataType: "int", ColumnType: "int", Ordinal: len(users.Columns)}
	users.Columns = append(users.Columns, c)
	users.ColumnMap[c.Name] = c

	cfg := &config.Config{Roles: map[string]*config.Role{"r": selectAll()}}
	cfg.SchemaGen.DefaultPageSize = 25
	cfg.SchemaGen.MaxPageSize = 200
	schemas, err := BuildAll(Options{Catalog: cat, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	s := schemas["r"]
	if ty := objectFieldType(t, s, "users", "posts_aggregate"); ty != "Int!" {
		t.Errorf("the column posts_aggregate must keep its name, got type %s", ty)
	}
	if ty := objectFieldType(t, s, "users", "posts_aggregate_by_author_id"); ty != "posts_aggregate_result!" {
		t.Errorf("the nested aggregate must move aside, got %s", ty)
	}
}

func TestAggregateTypeNameCollision(t *testing.T) {
	err := checkNameCollisions(cat("posts", "posts_count_distinct_fields"))
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Errorf("a table named like a generated aggregate type must be rejected, got %v", err)
	}
	if err := checkNameCollisions(cat("posts", "posts_stats")); err != nil {
		t.Errorf("unexpected collision: %v", err)
	}
}

// TestNestedAggregateBatched runs a nested aggregate through graphql.Do
// against a fake database: all parents are served by ONE GROUP BY query that
// carries the child's role row filter and the client's where, and parents
// without child rows get count 0 / null.
func TestNestedAggregateBatched(t *testing.T) {
	role := selectAll()
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{Allow: true,
		Columns: []string{"id", "author_id", "title"}, Filter: "author_id <> :jwt.sub"}}
	answer := func(q string) ([]string, [][]driver.Value, error) {
		switch {
		case q == ciProbeSQL:
			return []string{"v"}, [][]driver.Value{{int64(1)}}, nil
		case strings.HasPrefix(q, "SELECT 1 FROM `appdb`."):
			return []string{"1"}, nil, nil
		case strings.Contains(q, "FROM `appdb`.`users`") && strings.Contains(q, "LIMIT ?"):
			cols := []string{"id", "name", "email", "manager_id", "secret", "is_public"}
			var rows [][]driver.Value
			for i := int64(1); i <= 3; i++ {
				rows = append(rows, []driver.Value{i, []byte("u"), []byte("e"), nil, []byte("s"), int64(1)})
			}
			return cols, rows, nil
		case strings.Contains(q, "GROUP BY"):
			return []string{"author_id", "c", "s", "d"}, [][]driver.Value{
				{int64(1), int64(2), []byte("3"), int64(2)},
				{int64(3), int64(5000000000), []byte("9"), int64(1)},
			}, nil
		}
		return nil, nil, errors.New("unexpected query: " + q)
	}
	db, log := newFakeDB(answer)
	_, s, err := tryBuildFilterRoleCfg(db, role, func(c *config.Config) { c.SchemaGen.CountType = config.CountTypeBigInt })
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithLoaders(rbac.WithIdentity(context.Background(), testID))
	res := graphql.Do(graphql.Params{Schema: s, Context: ctx, RequestString: `{
		users_connection { nodes { id posts_aggregate(where: {title: {_neq: "x"}}) {
			count sum { id } count_distinct { title } } } } }`})
	if len(res.Errors) > 0 {
		t.Fatalf("errors: %v", res.Errors)
	}

	var groupQueries []string
	for _, q := range log.all() {
		if strings.Contains(q, "GROUP BY") {
			groupQueries = append(groupQueries, q)
		}
	}
	if len(groupQueries) != 1 {
		t.Fatalf("want exactly one batched GROUP BY query, got %d: %v", len(groupQueries), groupQueries)
	}
	want := "SELECT `author_id`, COUNT(*), SUM(`id`), COUNT(DISTINCT `title`) FROM `appdb`.`posts` WHERE (`author_id` IN (?, ?, ?)) AND (`title` <> ?) AND (author_id <> ?) GROUP BY `author_id`"
	if groupQueries[0] != want {
		t.Errorf("batched SQL =\n %s\nwant\n %s", groupQueries[0], want)
	}

	nodes := res.Data.(map[string]any)["users_connection"].(map[string]any)["nodes"].([]any)
	agg := func(i int) map[string]any { return nodes[i].(map[string]any)["posts_aggregate"].(map[string]any) }
	if agg(0)["count"] != int64(2) || agg(0)["sum"].(map[string]any)["id"] != "3" {
		t.Errorf("user 1 aggregate = %v", agg(0))
	}
	// User 2 has no visible posts: count 0, sum null, count_distinct 0.
	if agg(1)["count"] != int64(0) || agg(1)["sum"].(map[string]any)["id"] != nil ||
		agg(1)["count_distinct"].(map[string]any)["title"] != int64(0) {
		t.Errorf("user 2 aggregate = %v", agg(1))
	}
	if agg(2)["count"] != int64(5000000000) {
		t.Errorf("user 3 count = %v (must not overflow)", agg(2)["count"])
	}

	// Negative RBAC: the hidden body column cannot be aggregated or filtered.
	for _, q := range []string{
		`{ users_connection { nodes { posts_aggregate { max { body } } } } }`,
		`{ users_connection { nodes { posts_aggregate { count_columns { body } } } } }`,
		`{ users_connection { nodes { posts_aggregate(where: {body: {_eq: "x"}}) { count } } } }`,
	} {
		res := graphql.Do(graphql.Params{Schema: s, Context: ctx, RequestString: q})
		if len(res.Errors) == 0 || !strings.Contains(res.Errors[0].Message, "body") {
			t.Errorf("%s: want a validation error on body, got %v", q, res.Errors)
		}
	}
}
