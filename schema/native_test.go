package schema

import (
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/graphql-go/graphql"
	"gopkg.in/yaml.v3"

	"gqlgate/config"
	"gqlgate/introspect"
	"gqlgate/rbac"
)

const nativePeopleYAML = `
people_by_domain:
  sql: |
    SELECT id, email, LOWER(email) AS lower_email -- trailing comment
    FROM people WHERE email LIKE :pattern AND (:min_id IS NULL OR id > :min_id)
  arguments:
    pattern: String!
    min_id: {type: BigInt, description: "Lower id bound"}
  columns:
    id: BigInt!
    email: String
    lower_email: {type: String, name: lowerEmail}
  key: [id]
  relationships:
    person: {type: object, target: people, mapping: {id: id}}
`

const nativePeopleRoles = `
full:
  tables:
    people: {select: true}
  native_queries:
    people_by_domain: true
limited:
  tables:
    people: {select: {allow: true, columns: [id]}}
  native_queries:
    people_by_domain:
      allow: true
      columns: [id, lower_email]
      filter: "id <> :jwt.banned"
      presets: {pattern: ":jwt.domain"}
      filterable_columns: [id]
none:
  tables:
    people: {select: true}
`

// nativeAnswer serves the people native query (and the people table) in
// the column order of the select list.
func nativeAnswer(q string) ([]string, [][]driver.Value, error) {
	rows := []map[string]driver.Value{
		{"id": int64(1), "email": []byte("ada@example.com"), "lower_email": []byte("ada@example.com")},
		{"id": int64(2), "email": []byte("Bob@example.com"), "lower_email": []byte("bob@example.com")},
	}
	switch {
	case q == ciProbeSQL:
		return []string{"v"}, [][]driver.Value{{int64(1)}}, nil
	case strings.HasPrefix(q, "SELECT 1 FROM"):
		return []string{"1"}, nil, nil
	case strings.HasPrefix(q, "SELECT * FROM (SELECT ") && strings.HasSuffix(q, "LIMIT 0"):
		// The native statement's own select list (aliases win).
		list := strings.TrimPrefix(q, "SELECT * FROM (SELECT ")
		list = list[:strings.LastIndex(list, "\n) AS ")]
		if loc := regexp.MustCompile(`\sFROM\s`).FindStringIndex(list); loc != nil {
			list = list[:loc[0]]
		}
		var cols []string
		for _, c := range strings.Split(list, ", ") {
			if i := strings.LastIndex(c, " AS "); i >= 0 {
				c = c[i+4:]
			}
			cols = append(cols, strings.Fields(c)[0])
		}
		return cols, nil, nil
	case strings.HasPrefix(q, "SELECT COUNT(*)"):
		return []string{"n"}, [][]driver.Value{{int64(len(rows))}}, nil
	case strings.HasPrefix(q, "SELECT "):
		list := strings.TrimPrefix(q[:strings.Index(q, " FROM ")], "SELECT ")
		var cols []string
		for _, c := range strings.Split(list, ", ") {
			cols = append(cols, strings.Trim(c, "`"))
		}
		var out [][]driver.Value
		for _, r := range rows {
			row := make([]driver.Value, len(cols))
			for i, c := range cols {
				row[i] = r[c]
			}
			out = append(out, row)
		}
		return cols, out, nil
	}
	return nil, nil, errors.New("unexpected query: " + q)
}

func nativeConfig(t *testing.T, nativeYAML, rolesYAML string) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	if err := yaml.Unmarshal([]byte(nativeYAML), &cfg.NativeQueries); err != nil {
		t.Fatalf("native yaml: %v", err)
	}
	if err := yaml.Unmarshal([]byte(rolesYAML), &cfg.Roles); err != nil {
		t.Fatalf("roles yaml: %v", err)
	}
	cfg.SchemaGen.DefaultPageSize = 25
	cfg.SchemaGen.MaxPageSize = 200
	return cfg
}

func buildNativeSchemas(t *testing.T, nativeYAML, rolesYAML string) (map[string]graphql.Schema, *fakeLog, error) {
	t.Helper()
	db, log := newFakeDB(nativeAnswer)
	s, err := BuildAll(Options{DB: db, Catalog: peopleCatalog(), Config: nativeConfig(t, nativeYAML, rolesYAML)})
	return s, log, err
}

func runNative(s graphql.Schema, role string, claims map[string]any, query string, vars map[string]any) *graphql.Result {
	ctx := WithLoaders(rbac.WithIdentity(context.Background(), &rbac.Identity{Role: role, Claims: claims}))
	return graphql.Do(graphql.Params{Schema: s, Context: ctx, RequestString: query, VariableValues: vars})
}

func TestNativeQuerySQLAndArguments(t *testing.T) {
	schemas, log, err := buildNativeSchemas(t, nativePeopleYAML, nativePeopleRoles)
	if err != nil {
		t.Fatal(err)
	}
	res := runNative(schemas["full"], "full", nil,
		`{ people_by_domain(args: {pattern: "%@example.com", min_id: 0}, where: {lowerEmail: {_eq: "x"}}, limit: 500) { id email lowerEmail person { email } } }`, nil)
	if len(res.Errors) > 0 {
		t.Fatal(res.Errors)
	}
	q, args := log.last("AS `__gqlgate_nq` WHERE")
	wantFrom := "SELECT `id`, `email`, `lower_email` FROM (SELECT id, email, LOWER(email) AS lower_email  \n" +
		"FROM people WHERE email LIKE ? AND (? IS NULL OR id > ?)\n) AS `__gqlgate_nq` WHERE (`lower_email` = ?) LIMIT ?"
	if q != wantFrom {
		t.Errorf("query =\n%q\nwant\n%q", q, wantFrom)
	}
	// Parameters bind in placeholder order (a name used twice twice), then
	// the where, then the limit clamped to max_page_size.
	if want := []any{"%@example.com", int64(0), int64(0), "x", int64(200)}; !reflect.DeepEqual(args, want) {
		t.Errorf("args = %#v, want %#v", args, want)
	}
	rows := res.Data.(map[string]any)["people_by_domain"].([]any)
	if len(rows) != 2 || rows[1].(map[string]any)["lowerEmail"] != "bob@example.com" {
		t.Errorf("rows = %v", rows)
	}

	// An omitted optional argument is NULL; a required one is required.
	res = runNative(schemas["full"], "full", nil, `{ people_by_domain(args: {pattern: "a"}) { id } }`, nil)
	if len(res.Errors) > 0 {
		t.Fatal(res.Errors)
	}
	if _, args = log.last("AS `__gqlgate_nq` WHERE"); !reflect.DeepEqual(args, []any{"a", nil, nil, int64(25)}) {
		t.Errorf("omitted optional: args = %#v", args)
	}
	if res = runNative(schemas["full"], "full", nil, `{ people_by_domain { id } }`, nil); len(res.Errors) == 0 {
		t.Error("missing required args accepted")
	}

	// Connection: keyset on the key, cursor bound to the argument values.
	res = runNative(schemas["full"], "full", nil,
		`{ people_by_domain_connection(args: {pattern: "a"}, first: 1) { nodes { id } page_info { has_next_page end_cursor } total_count } }`, nil)
	if len(res.Errors) > 0 {
		t.Fatal(res.Errors)
	}
	conn := res.Data.(map[string]any)["people_by_domain_connection"].(map[string]any)
	if conn["page_info"].(map[string]any)["has_next_page"] != true || conn["total_count"] != int64(2) && conn["total_count"] != 2 {
		t.Errorf("connection = %v", conn)
	}
	if q, _ := log.last("ORDER BY"); !strings.HasSuffix(q, " ORDER BY `id` ASC LIMIT ?") {
		t.Errorf("connection query = %q", q)
	}
	cursor := conn["page_info"].(map[string]any)["end_cursor"].(string)
	res = runNative(schemas["full"], "full", nil,
		`query($c: String) { people_by_domain_connection(args: {pattern: "b"}, after: $c) { nodes { id } } }`, map[string]any{"c": cursor})
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0].Message, "cursor does not match") {
		t.Errorf("cursor reused with other args: %v", res.Errors)
	}
	res = runNative(schemas["full"], "full", nil,
		`query($c: String) { people_by_domain_connection(args: {pattern: "a"}, after: $c) { nodes { id } } }`, map[string]any{"c": cursor})
	if len(res.Errors) > 0 {
		t.Fatal(res.Errors)
	}
	if q, args := log.last("ORDER BY"); !strings.Contains(q, "(`id` > ?)") || args[len(args)-2] != "1" {
		t.Errorf("keyset query = %q %v", q, args)
	}
}

func TestNativeQueryRolePresetsAndFilter(t *testing.T) {
	schemas, log, err := buildNativeSchemas(t, nativePeopleYAML, nativePeopleRoles)
	if err != nil {
		t.Fatal(err)
	}
	none := schemas["none"]
	if _, ok := none.QueryType().Fields()["people_by_domain"]; ok {
		t.Error("a role without a grant has the native query")
	}
	lim := schemas["limited"]
	args := lim.Type("people_by_domain_arguments").(*graphql.InputObject).Fields()
	if _, ok := args["pattern"]; ok || args["min_id"] == nil {
		t.Errorf("limited arguments = %v (the preset must be hidden)", args)
	}
	obj := lim.Type("people_by_domain").(*graphql.Object).Fields()
	if _, ok := obj["email"]; ok || obj["lowerEmail"] == nil {
		t.Errorf("limited columns = %v", obj)
	}
	be := lim.Type("people_by_domain_bool_exp").(*graphql.InputObject).Fields()
	if _, ok := be["lowerEmail"]; ok || be["id"] == nil {
		t.Errorf("limited filter surface = %v", be)
	}
	// args is optional: the only client argument is optional.
	claims := map[string]any{"domain": "%@corp", "banned": float64(7)}
	res := runNative(lim, "limited", claims, `{ people_by_domain { id lowerEmail } }`, nil)
	if len(res.Errors) > 0 {
		t.Fatal(res.Errors)
	}
	q, got := log.last("AS `__gqlgate_nq` WHERE")
	if !strings.Contains(q, "WHERE (id <> ?) LIMIT ?") {
		t.Errorf("role filter missing: %q", q)
	}
	if want := []any{"%@corp", nil, nil, float64(7), int64(25)}; !reflect.DeepEqual(got, want) {
		t.Errorf("args = %#v, want %#v", got, want)
	}
	// The preset cannot be passed, not even through variables.
	res = runNative(lim, "limited", claims, `query($a: people_by_domain_arguments) { people_by_domain(args: $a) { id } }`,
		map[string]any{"a": map[string]any{"pattern": "%"}})
	if len(res.Errors) == 0 {
		t.Error("preset argument accepted from variables")
	}
	// Hidden columns are not filterable through variables either.
	res = runNative(lim, "limited", claims, `query($w: people_by_domain_bool_exp) { people_by_domain(where: $w) { id } }`,
		map[string]any{"w": map[string]any{"email": map[string]any{"_eq": "x"}}})
	if len(res.Errors) == 0 {
		t.Error("hidden column filter accepted from variables")
	}
	// A null claim fails closed too: the preset never binds NULL.
	res = runNative(lim, "limited", map[string]any{"domain": nil, "banned": float64(1)}, `{ people_by_domain { id } }`, nil)
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0].Message, "null") {
		t.Errorf("null preset claim: %v", res.Errors)
	}
	// A missing claim fails closed.
	res = runNative(lim, "limited", map[string]any{"banned": float64(1)}, `{ people_by_domain { id } }`, nil)
	if len(res.Errors) == 0 || !strings.Contains(res.Errors[0].Message, "domain") {
		t.Errorf("missing preset claim: %v", res.Errors)
	}
	// The relationship needs the target's permission: limited reads
	// people.id, so person { id } works but person { email } does not exist.
	if _, ok := obj["person"]; !ok {
		t.Error("relationship missing for limited")
	}
}

func TestNativeQueryBuildErrors(t *testing.T) {
	cases := []struct {
		name, native, roles, want string
	}{
		{"collision with a table field", `
people_connection:
  sql: "SELECT 1 AS id"
  columns: {id: Int}
`, `full: {tables: {people: {select: true}}}`, "collides with table people"},
		{"unknown key", `
q:
  sql: "SELECT id FROM people"
  columns: {id: BigInt}
  key: [nope]
`, `full: {native_queries: {q: true}}`, "native_queries.q.key"},
		{"unknown column override", `
q:
  sql: "SELECT id FROM people"
  columns: {id: BigInt, nope: Int}
`, `full: {native_queries: {q: true}}`, `returns no column "nope"`},
		{"untyped column", `
q:
  sql: "SELECT id, email FROM people"
  columns: {id: BigInt}
`, `full: {native_queries: {q: true}}`, `no usable type for result column "email"`},
		{"undeclared grant", `
q:
  sql: "SELECT id FROM people"
  columns: {id: BigInt}
`, `full: {native_queries: {other: true}}`, "not declared under native_queries"},
		{"preset of an unknown argument", `
q:
  sql: "SELECT id FROM people"
  columns: {id: BigInt}
`, `full: {native_queries: {q: {allow: true, presets: {x: ":jwt.sub"}}}}`, "not a declared argument"},
		{"unknown readable column", `
q:
  sql: "SELECT id FROM people"
  columns: {id: BigInt}
`, `full: {native_queries: {q: {allow: true, columns: [nope]}}}`, `column "nope" does not exist`},
		{"relationship to a missing column", `
q:
  sql: "SELECT id FROM people"
  columns: {id: BigInt}
  relationships:
    p: {type: object, target: people, mapping: {id: nope}}
`, `full: {native_queries: {q: true}}`, "has no column"},
		{"non-unique object relationship", `
q:
  sql: "SELECT id FROM people"
  columns: {id: BigInt}
  relationships:
    p: {type: object, target: people, mapping: {id: email}}
`, `full: {native_queries: {q: true}}`, "join-compatible"},
		{"literal preset of the wrong type", `
q:
  sql: "SELECT id FROM people WHERE id > :min"
  arguments: {min: Int!}
  columns: {id: BigInt}
`, `full: {native_queries: {q: {allow: true, presets: {min: "not-a-number"}}}}`, `"not-a-number" is not an integer`},
		{"literal Int preset out of range", `
q:
  sql: "SELECT id FROM people WHERE id > :min"
  arguments: {min: Int}
  columns: {id: BigInt}
`, `full: {native_queries: {q: {allow: true, presets: {min: "3000000000"}}}}`, "range of Int"},
		{"literal Date preset", `
q:
  sql: "SELECT id FROM people WHERE :d IS NOT NULL"
  arguments: {d: Date}
  columns: {id: BigInt}
`, `full: {native_queries: {q: {allow: true, presets: {d: "2026-13-45"}}}}`, "does not fit type Date"},
		{"collision with a table's default list field", `
people_list:
  sql: "SELECT 1 AS id"
  columns: {id: Int}
`, `full: {tables: {people: {select: true}}}`, `"people_list" for native query "people_list" collides with table people`},
		{"root field collision with a table's default list field", `
q:
  sql: "SELECT 1 AS id"
  columns: {id: Int}
  root_fields: {list: {name: people_list}}
`, `full: {tables: {people: {select: true}}}`, `"people_list" for native query "q" collides with table people`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := buildNativeSchemas(t, c.native, c.roles)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// Without a database the columns come from the declarations.
func TestNativeQueryWithoutDB(t *testing.T) {
	cfg := nativeConfig(t, nativePeopleYAML, nativePeopleRoles)
	schemas, err := BuildAll(Options{Catalog: peopleCatalog(), Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	full := schemas["full"]
	f := full.QueryType().Fields()
	if f["people_by_domain"] == nil || f["people_by_domain_connection"] == nil {
		t.Errorf("fields = %v", f)
	}
	id := full.Type("people_by_domain").(*graphql.Object).Fields()["id"]
	if id.Type.String() != "BigInt!" {
		t.Errorf("id type = %s", id.Type)
	}
}

func TestColumnTypeFor(t *testing.T) {
	c := &introspect.Column{Name: "x", DataType: "tinyint", ColumnType: "tinyint"}
	columnTypeFor(c, "Boolean")
	if scalarFor(c).Name() != "Boolean" {
		t.Errorf("Boolean -> %s", scalarFor(c).Name())
	}
	c = &introspect.Column{Name: "s", DataType: "varchar", ColumnType: "varchar", Charset: "utf8mb4", Collation: "utf8mb4_general_ci"}
	columnTypeFor(c, "String")
	if c.Collation != "utf8mb4_general_ci" || c.DataType != "varchar" {
		t.Errorf("String keeps the collation: %+v", c)
	}
	columnTypeFor(c, "JSON")
	if c.Collation != "" || scalarFor(c).Name() != "JSON" {
		t.Errorf("JSON: %+v", c)
	}
	c = &introspect.Column{Name: "d", DataType: "decimal", ColumnType: "decimal(10,2)"}
	columnTypeFor(c, "Decimal")
	if c.ColumnType != "decimal(10,2)" {
		t.Errorf("Decimal keeps the precision: %+v", c)
	}
}

func TestPresetArgValue(t *testing.T) {
	arg := func(s *graphql.Scalar) *nativeArg { return &nativeArg{name: "a", scalar: s} }
	cases := []struct {
		a    *nativeArg
		in   any
		want any
		err  bool
	}{
		{arg(graphql.Int), float64(3), 3, false},
		{arg(graphql.Int), "42", 42, false},
		{arg(graphql.Int), "x", nil, true},
		{arg(bigIntScalar), "9007199254740993", int64(9007199254740993), false},
		{arg(bigIntScalar), float64(5), int64(5), false},
		{arg(graphql.Boolean), "true", true, false},
		{arg(graphql.String), "abc", "abc", false},
		{arg(graphql.Float), "1.5", 1.5, false},
		{arg(dateScalar), "2026-01-02", "2026-01-02", false},
		// A preset never binds NULL: a null claim is an error.
		{arg(graphql.String), nil, nil, true},
		{arg(graphql.Int), nil, nil, true},
		// Out of the 32-bit range of Int: an error, never NULL.
		{arg(graphql.Int), "3000000000", nil, true},
		{arg(graphql.Int), float64(3000000000), nil, true},
		{arg(graphql.Int), "-2147483648", -2147483648, false},
		{arg(bigIntScalar), "3000000000", int64(3000000000), false},
		{arg(bigIntScalar), float64(1 << 63), nil, true},
		// Fractional numbers are not truncated to an integer.
		{arg(graphql.Int), float64(1.9), nil, true},
		{arg(bigIntScalar), float64(1.9), nil, true},
		{arg(graphql.Int), "1.9", nil, true},
		// Booleans are not integers, numbers are not booleans.
		{arg(graphql.Int), true, nil, true},
		{arg(graphql.Boolean), float64(1), nil, true},
		{arg(graphql.Boolean), false, false, false},
		{arg(graphql.Float), "NaN", nil, true},
		{arg(graphql.Float), true, nil, true},
		{arg(graphql.Float), float64(2.5), 2.5, false},
		// Numeric claims bound to a String are written in full.
		{arg(graphql.String), float64(1000000), "1000000", false},
		{arg(graphql.String), true, "true", false},
		{arg(dateScalar), "not-a-date", nil, true},
		{arg(dateScalar), float64(1), nil, true},
		{arg(decimalScalar), true, nil, true},
		{arg(decimalScalar), "12.50", "12.50", false},
		{arg(graphql.String), []any{"a"}, nil, true},
	}
	for _, c := range cases {
		got, err := presetArgValue(c.a, c.in)
		if (err != nil) != c.err || !reflect.DeepEqual(got, c.want) {
			t.Errorf("presetArgValue(%s, %#v) = %#v, %v; want %#v (err %v)", c.a.scalar.Name(), c.in, got, err, c.want, c.err)
		}
	}
}

// A native query whose root field is a table's unique-key lookup fails the
// build instead of silently dropping the lookup.
func TestNativeQueryUniqueKeyCollision(t *testing.T) {
	cat := peopleCatalog()
	cat.Tables["people"].UniqueKeys = []*introspect.UniqueKey{{Name: "uk_email", Columns: []string{"email"}}}
	cfg := nativeConfig(t, `
people_by_email:
  sql: "SELECT 1 AS id"
  columns: {id: Int}
`, `full: {tables: {people: {select: true}}}`)
	_, err := BuildAll(Options{Catalog: cat, Config: cfg})
	if err == nil || !strings.Contains(err.Error(), `"people_by_email" for native query "people_by_email" collides with table people`) {
		t.Fatalf("err = %v", err)
	}
	// Without the native query the lookup exists.
	cfg.NativeQueries = nil
	s, err := BuildAll(Options{Catalog: cat, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	full := s["full"]
	if full.QueryType().Fields()["people_by_email"] == nil {
		t.Error("people_by_email lookup missing")
	}
}
