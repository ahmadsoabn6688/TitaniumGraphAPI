package schema

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/gqlerrors"

	"gqlgate/config"
	"gqlgate/introspect"
	"gqlgate/rbac"
)

// --- concurrent root fields --------------------------------------------------

// slowSchema has three query root fields that each take d and record how
// many of them run at once, plus a mutation root.
func slowSchema(t *testing.T, d time.Duration) (graphql.Schema, *int32) {
	t.Helper()
	var running, peak int32
	slow := func(p graphql.ResolveParams) (any, error) {
		n := atomic.AddInt32(&running, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if n <= old || atomic.CompareAndSwapInt32(&peak, old, n) {
				break
			}
		}
		time.Sleep(d)
		atomic.AddInt32(&running, -1)
		return "ok", nil
	}
	q := graphql.Fields{}
	for _, n := range []string{"a", "b", "c"} {
		q[n] = &graphql.Field{Type: graphql.String, Resolve: slow}
	}
	q["fails"] = &graphql.Field{Type: graphql.String, Resolve: func(graphql.ResolveParams) (any, error) {
		return nil, &CodedError{Code: CodeTimeout, Message: "boom"}
	}}
	q["panics"] = &graphql.Field{Type: graphql.String, Resolve: func(graphql.ResolveParams) (any, error) {
		panic("kaboom")
	}}
	q["deferred"] = &graphql.Field{Type: graphql.String, Resolve: func(graphql.ResolveParams) (any, error) {
		return func() (any, error) { return "later", nil }, nil
	}}
	concurrentRootFields(q)
	m := graphql.Fields{}
	for _, n := range []string{"m1", "m2", "m3"} {
		m[n] = &graphql.Field{Type: graphql.String, Resolve: slow}
	}
	s, err := graphql.NewSchema(graphql.SchemaConfig{
		Query:    graphql.NewObject(graphql.ObjectConfig{Name: "Query", Fields: q}),
		Mutation: graphql.NewObject(graphql.ObjectConfig{Name: "Mutation", Fields: m}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, &peak
}

func TestConcurrentRootFields(t *testing.T) {
	const d = 60 * time.Millisecond
	for _, tc := range []struct {
		limit    int
		query    string
		wantPeak int32
	}{
		{3, `{ a b c }`, 3},
		{2, `{ a b c }`, 2},
		{1, `{ a b c }`, 1},             // a limit of 1 runs serially
		{0, `{ a b c }`, 1},             // no limiter installed: serial
		{3, `{ a }`, 1},                 // one root field runs inline
		{3, `mutation { m1 m2 m3 }`, 1}, // mutations stay serial
		{3, `{ x: a ...F } fragment F on Query { y: a z: b }`, 3},
	} {
		s, peak := slowSchema(t, d)
		ctx := WithRootParallelism(context.Background(), tc.limit)
		res := graphql.Do(graphql.Params{Schema: s, RequestString: tc.query, Context: ctx})
		if len(res.Errors) > 0 {
			t.Fatalf("limit %d %s: %v", tc.limit, tc.query, res.Errors)
		}
		if *peak != tc.wantPeak {
			t.Errorf("limit %d %s: peak concurrency %d, want %d", tc.limit, tc.query, *peak, tc.wantPeak)
		}
		for k, v := range res.Data.(map[string]any) {
			if v != "ok" {
				t.Errorf("limit %d %s: %s = %v", tc.limit, tc.query, k, v)
			}
		}
	}
}

func TestConcurrentRootFieldsErrors(t *testing.T) {
	s, _ := slowSchema(t, time.Millisecond)
	ctx := WithRootParallelism(context.Background(), 4)
	res := graphql.Do(graphql.Params{Schema: s, RequestString: `{ a fails panics deferred }`, Context: ctx})
	data := res.Data.(map[string]any)
	if data["a"] != "ok" || data["deferred"] != "later" || data["fails"] != nil || data["panics"] != nil {
		t.Errorf("data = %v", data)
	}
	var sawCode, sawPanic bool
	for _, e := range res.Errors {
		if strings.Contains(e.Message, "boom") {
			// The code travels in the original error (the server restores it).
			var ce *CodedError
			if errors.As(originalErr(e), &ce) && ce.Code == CodeTimeout {
				sawCode = true
			}
		}
		if strings.Contains(e.Message, "internal error: kaboom") {
			sawPanic = true
		}
	}
	if !sawCode || !sawPanic {
		t.Errorf("errors = %v (code kept: %v, panic reported: %v)", res.Errors, sawCode, sawPanic)
	}
}

// originalErr unwraps a formatted graphql-go error to the resolver's error.
func originalErr(e gqlerrors.FormattedError) error {
	var err error = e.OriginalError()
	for i := 0; err != nil && i < 8; i++ {
		switch x := err.(type) {
		case *CodedError:
			return x
		case gqlerrors.FormattedError:
			err = x.OriginalError()
		case *gqlerrors.Error:
			err = x.OriginalError
		default:
			err = errors.Unwrap(err)
		}
	}
	return err
}

// TestConcurrentRootFieldsCustomFieldShared: a custom field's Field is shared
// by every role and every reload; building schemas must not wrap it (again).
func TestConcurrentRootFieldsCustomFieldShared(t *testing.T) {
	var calls int32
	resolve := func(graphql.ResolveParams) (any, error) {
		atomic.AddInt32(&calls, 1)
		return "pong", nil
	}
	field := &graphql.Field{Type: graphql.String, Resolve: resolve}
	hooks := NewHooks(nil, nil, []CustomField{{Name: "ping", Operation: "query", Field: field}})
	db, _ := newFakeDB(peopleAnswer)
	for i := 0; i < 3; i++ { // e.g. hot reloads
		schemas, err := peopleSchemas(t, db, hooks, nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx := WithRootParallelism(rbac.WithIdentity(context.Background(), &rbac.Identity{Role: "full"}), 1+i)
		res := graphql.Do(graphql.Params{Schema: schemas["full"], Context: ctx, RequestString: `{ a: ping b: ping c: ping }`})
		if len(res.Errors) > 0 || res.Data.(map[string]any)["c"] != "pong" {
			t.Fatalf("build %d: %v %v", i, res.Data, res.Errors)
		}
	}
	if fmt.Sprintf("%p", field.Resolve) != fmt.Sprintf("%p", resolve) {
		t.Error("the shared custom Field was modified")
	}
	if calls != 9 {
		t.Errorf("resolver ran %d times, want 9", calls)
	}
}

// TestConcurrentRootFieldsCancelled: a request whose context ends while a
// root field waits returns the context error instead of hanging.
func TestConcurrentRootFieldsCancelled(t *testing.T) {
	s, _ := slowSchema(t, 300*time.Millisecond)
	ctx, cancel := context.WithTimeout(WithRootParallelism(context.Background(), 2), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := graphql.Do(graphql.Params{Schema: s, RequestString: `{ a b c }`, Context: ctx})
	if time.Since(start) > 250*time.Millisecond {
		t.Errorf("cancelled request took %v", time.Since(start))
	}
	if len(res.Errors) == 0 {
		t.Error("want a context error")
	}
}

// --- shared catalog for object fields and typed JSON --------------------------

// peopleCatalog: people(id PK, email, profile JSON, contacts JSON).
func peopleCatalog() *introspect.Catalog {
	col := func(name, dt string, ord int) *introspect.Column {
		c := &introspect.Column{Name: name, DataType: dt, ColumnType: dt, Ordinal: ord, Nullable: name != "id"}
		if dt == "varchar" {
			c.Charset, c.Collation = "utf8mb4", "utf8mb4_bin"
		}
		return c
	}
	t := &introspect.Table{Name: "people", ColumnMap: map[string]*introspect.Column{}, PrimaryKey: []string{"id"}}
	for _, c := range []*introspect.Column{col("id", "bigint", 0), col("email", "varchar", 1),
		col("profile", "json", 2), col("contacts", "json", 3)} {
		if c.Name == "id" {
			c.IsPrimary = true
		}
		t.Columns = append(t.Columns, c)
		t.ColumnMap[c.Name] = c
	}
	return &introspect.Catalog{SchemaName: "appdb", Tables: map[string]*introspect.Table{"people": t}, TableOrder: []string{"people"}}
}

// peopleRows are the rows the fake database serves for people, by column.
var peopleRows = []map[string]driver.Value{
	{"id": int64(1), "email": []byte("ada@example.com"),
		"profile":  []byte(`{"name": "Ada", "age": 36, "zip-code": "N1", "tags": ["math", "poetry"], "address": {"city": "London", "parent": {"city": "UK"}}, "extra": {"any": [1, 2]}}`),
		"contacts": []byte(`[{"city": "Paris"}, null, {"city": "Turin"}]`)},
	{"id": int64(2), "email": []byte("bad@example.com"),
		"profile":  []byte(`{"name": 7, "age": 1.5, "tags": ["x", 3], "address": "nowhere"}`),
		"contacts": []byte(`{"city": "not a list"}`)},
	{"id": int64(3), "email": []byte("none@example.com"), "profile": []byte(`[1, 2]`), "contacts": nil},
}

// peopleAnswer serves people pages in the column order of the select list.
func peopleAnswer(q string) ([]string, [][]driver.Value, error) {
	switch {
	case q == ciProbeSQL:
		return []string{"v"}, [][]driver.Value{{int64(1)}}, nil
	case strings.HasPrefix(q, "SELECT 1 FROM"):
		return []string{"1"}, nil, nil
	case strings.Contains(q, "FROM `appdb`.`people`"):
		list := strings.TrimPrefix(q[:strings.Index(q, " FROM ")], "SELECT ")
		var cols []string
		for _, c := range strings.Split(list, ", ") {
			cols = append(cols, strings.Trim(c, "`"))
		}
		var rows [][]driver.Value
		for _, r := range peopleRows {
			row := make([]driver.Value, len(cols))
			for i, c := range cols {
				row[i] = r[c]
			}
			rows = append(rows, row)
		}
		return cols, rows, nil
	}
	return nil, nil, errors.New("unexpected query: " + q)
}

// peopleSchemas builds the schemas of two roles over people: "full" reads
// every column, "limited" only id.
func peopleSchemas(t *testing.T, db *sql.DB, hooks *Hooks, mutate func(*config.Config)) (map[string]graphql.Schema, error) {
	t.Helper()
	cfg := &config.Config{Roles: map[string]*config.Role{
		"full": {Tables: map[string]*config.TablePerm{"people": {Select: &config.OpPerm{Allow: true}}}},
		"limited": {Tables: map[string]*config.TablePerm{"people": {Select: &config.OpPerm{Allow: true,
			Columns: []string{"id"}}}}},
	}}
	cfg.SchemaGen.DefaultPageSize = 25
	cfg.SchemaGen.MaxPageSize = 200
	if mutate != nil {
		mutate(cfg)
	}
	return BuildAll(Options{DB: db, Catalog: peopleCatalog(), Config: cfg, Hooks: hooks})
}

func runAs(s graphql.Schema, role, query string) *graphql.Result {
	ctx := WithLoaders(rbac.WithIdentity(context.Background(), &rbac.Identity{Role: role, Claims: map[string]any{"sub": "u-" + role}}))
	return graphql.Do(graphql.Params{Schema: s, Context: ctx, RequestString: query})
}

func nodes(t *testing.T, res *graphql.Result) []any {
	t.Helper()
	data, _ := res.Data.(map[string]any)
	conn, _ := data["people_connection"].(map[string]any)
	n, ok := conn["nodes"].([]any)
	if !ok {
		t.Fatalf("no nodes in %v (errors %v)", res.Data, res.Errors)
	}
	return n
}

// --- object fields -------------------------------------------------------------

func TestObjectFields(t *testing.T) {
	db, _ := newFakeDB(peopleAnswer)
	var batchCalls, batchRows int32
	var mu sync.Mutex
	var seenRows []map[string]any
	defs := []ObjectField{
		{
			Table: "people", Name: "greeting", Requires: []string{"email"}, Type: graphql.String,
			Args: graphql.FieldConfigArgument{"prefix": &graphql.ArgumentConfig{Type: graphql.String}},
			ResolveBatch: func(_ context.Context, ps []ObjectFieldParams) ([]any, error) {
				atomic.AddInt32(&batchCalls, 1)
				atomic.AddInt32(&batchRows, int32(len(ps)))
				out := make([]any, len(ps))
				for i, p := range ps {
					mu.Lock()
					seenRows = append(seenRows, p.Row)
					mu.Unlock()
					prefix, _ := p.Args["prefix"].(string)
					out[i] = prefix + p.Row["email"].(string) + " as " + p.Role + " (" + p.Claims["sub"].(string) + ")"
				}
				return out, nil
			},
		},
		{
			Table: "people", Name: "id_label", Requires: []string{"id"}, Type: graphql.String,
			AllowedRoles: []string{"limited"},
			Resolve: func(_ context.Context, p ObjectFieldParams) (any, error) {
				if p.DB == nil {
					return nil, errors.New("no DB handle")
				}
				return fmt.Sprintf("person-%d", p.Row["id"]), nil
			},
		},
		{Table: "ghost_table", Name: "nothing", Type: graphql.String,
			Resolve: func(context.Context, ObjectFieldParams) (any, error) { return nil, nil }},
	}
	hooks := NewHooks(nil, nil, nil)
	hooks.SetObjectFields(defs)
	schemas, err := peopleSchemas(t, db, hooks, nil)
	if err != nil {
		t.Fatal(err)
	}

	res := runAs(schemas["full"], "full", `{ people_connection { nodes { id greeting(prefix: "hi ") g2: greeting } } }`)
	if len(res.Errors) > 0 {
		t.Fatal(res.Errors)
	}
	n := nodes(t, res)
	if got := n[0].(map[string]any)["greeting"]; got != "hi ada@example.com as full (u-full)" {
		t.Errorf("greeting = %v", got)
	}
	if got := n[2].(map[string]any)["g2"]; got != "none@example.com as full (u-full)" {
		t.Errorf("g2 = %v", got)
	}
	// One batch per distinct argument set, each covering every row.
	if batchCalls != 2 || batchRows != 6 {
		t.Errorf("batches = %d covering %d rows, want 2 covering 6", batchCalls, batchRows)
	}
	for _, r := range seenRows {
		if len(r) != 1 || r["email"] == nil {
			t.Errorf("the resolver must see exactly its required columns, got %v", r)
		}
	}

	// Negative RBAC: "limited" cannot read email, so greeting is not in its
	// schema; id_label is only for "limited".
	if res := runAs(schemas["limited"], "limited", `{ people_connection { nodes { greeting } } }`); len(res.Errors) == 0 ||
		!strings.Contains(res.Errors[0].Message, `Cannot query field "greeting"`) {
		t.Errorf("limited must not see greeting: %v", res.Errors)
	}
	if res := runAs(schemas["full"], "full", `{ people_connection { nodes { id_label } } }`); len(res.Errors) == 0 {
		t.Error("full is not in id_label's AllowedRoles")
	}
	res = runAs(schemas["limited"], "limited", `{ people_connection { nodes { id id_label } } }`)
	if len(res.Errors) > 0 {
		t.Fatal(res.Errors)
	}
	if got := nodes(t, res)[1].(map[string]any)["id_label"]; got != "person-2" {
		t.Errorf("id_label = %v", got)
	}
}

func TestObjectFieldErrors(t *testing.T) {
	db, _ := newFakeDB(peopleAnswer)
	build := func(defs ...ObjectField) error {
		hooks := NewHooks(nil, nil, nil)
		hooks.SetObjectFields(defs)
		_, err := peopleSchemas(t, db, hooks, nil)
		return err
	}
	str := graphql.String
	ok := func(context.Context, ObjectFieldParams) (any, error) { return "x", nil }
	for _, tc := range []struct {
		def  ObjectField
		want string
	}{
		{ObjectField{Table: "people", Name: "email", Type: str, Resolve: ok}, `collides with the field of column "email"`},
		{ObjectField{Table: "people", Name: "x", Requires: []string{"nope"}, Type: str, Resolve: ok}, `requires column "nope"`},
	} {
		if err := build(tc.def); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", tc.def.Name, tc.want, err)
		}
	}

	cfg := &config.Config{Roles: map[string]*config.Role{"r": {}}}
	for _, tc := range []struct {
		defs []ObjectField
		want string
	}{
		{[]ObjectField{{Table: "people", Name: "bad name", Type: str, Resolve: ok}}, "valid GraphQL Name"},
		{[]ObjectField{{Table: "people", Name: "x", Resolve: ok}}, "Type is required"},
		{[]ObjectField{{Table: "people", Name: "x", Type: str}}, "exactly one of Resolve and ResolveBatch"},
		{[]ObjectField{{Table: "people", Name: "x", Type: str, Resolve: ok,
			ResolveBatch: func(context.Context, []ObjectFieldParams) ([]any, error) { return nil, nil }}}, "exactly one"},
		{[]ObjectField{{Table: "people", Name: "x", Type: str, Resolve: ok, AllowedRoles: []string{"ghost"}}}, `role "ghost"`},
		{[]ObjectField{{Table: "people", Name: "x", Type: str, Resolve: ok}, {Table: "people", Name: "x", Type: str, Resolve: ok}}, "registered twice"},
	} {
		if err := ValidateObjectFields(cfg, tc.defs); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("want %q, got %v", tc.want, err)
		}
	}
}

func TestObjectFieldBatchFailures(t *testing.T) {
	db, _ := newFakeDB(peopleAnswer)
	hooks := NewHooks(nil, nil, nil)
	hooks.SetObjectFields([]ObjectField{
		{Table: "people", Name: "short", Type: graphql.String,
			ResolveBatch: func(_ context.Context, ps []ObjectFieldParams) ([]any, error) { return []any{"only one"}, nil }},
		{Table: "people", Name: "crash", Type: graphql.String,
			ResolveBatch: func(context.Context, []ObjectFieldParams) ([]any, error) { panic("hook bug") }},
	})
	schemas, err := peopleSchemas(t, db, hooks, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := runAs(schemas["full"], "full", `{ people_connection { nodes { id short crash } } }`)
	msgs := ""
	for _, e := range res.Errors {
		msgs += e.Message + "\n"
	}
	if !strings.Contains(msgs, "returned 1 results for 3 rows") || !strings.Contains(msgs, "internal error: hook bug") {
		t.Errorf("errors = %s", msgs)
	}
	// The rows themselves still resolve.
	if len(nodes(t, res)) != 3 {
		t.Errorf("nodes = %v", res.Data)
	}
}

// --- typed JSON columns ----------------------------------------------------------

func jsonTypesConfig(c *config.Config) {
	c.JSONTypes = map[string]*config.JSONType{
		"Profile": {Description: "A person's profile", Fields: map[string]*config.JSONField{
			"name":    {Type: "String"},
			"age":     {Type: "Int", Description: "Years"},
			"zip":     {Type: "String", Key: "zip-code"},
			"tags":    {Type: "[String]"},
			"address": {Type: "Address"},
			"extra":   {Type: "JSON"},
		}},
		"Address": {Fields: map[string]*config.JSONField{
			"city":   {Type: "String"},
			"parent": {Type: "Address"},
		}},
	}
	c.Tables = map[string]*config.TableConfig{"people": {Columns: map[string]*config.FieldConfig{
		"profile":  {JSONType: "Profile"},
		"contacts": {JSONType: "[Address]"},
	}}}
}

func TestTypedJSONColumns(t *testing.T) {
	db, _ := newFakeDB(peopleAnswer)
	schemas, err := peopleSchemas(t, db, nil, jsonTypesConfig)
	if err != nil {
		t.Fatal(err)
	}
	full := schemas["full"]
	if _, ok := full.Type("Profile").(*graphql.Object); !ok {
		t.Fatal("Profile type missing")
	}
	if typ := full.Type("people").(*graphql.Object).Fields()["contacts"].Type.String(); typ != "[Address]" {
		t.Errorf("contacts type = %s", typ)
	}
	// Writes and filters keep the JSON scalar.
	be := full.Type("people_bool_exp").(*graphql.InputObject).Fields()["profile"].Type.Name()
	if be != "JSON_comparison_exp" {
		t.Errorf("where profile type = %s", be)
	}

	res := runAs(full, "full", `{ people_connection { nodes {
		id profile { name age zip tags address { city parent { city } } extra } contacts { city } } } }`)
	n := nodes(t, res)
	p0 := n[0].(map[string]any)["profile"].(map[string]any)
	if p0["name"] != "Ada" || p0["age"] != 36 || p0["zip"] != "N1" ||
		p0["address"].(map[string]any)["parent"].(map[string]any)["city"] != "UK" ||
		len(p0["tags"].([]any)) != 2 || p0["extra"] == nil {
		t.Errorf("row 1 profile = %v", p0)
	}
	c0 := n[0].(map[string]any)["contacts"].([]any)
	if len(c0) != 3 || c0[1] != nil || c0[2].(map[string]any)["city"] != "Turin" {
		t.Errorf("row 1 contacts = %v", c0)
	}

	// Row 2 holds the wrong kinds: those fields are null with an error each;
	// the rest of the row (and the response) is intact.
	p1 := n[1].(map[string]any)["profile"].(map[string]any)
	for _, f := range []string{"name", "age", "tags", "address"} {
		if p1[f] != nil {
			t.Errorf("row 2 profile.%s = %v, want null", f, p1[f])
		}
	}
	if n[1].(map[string]any)["contacts"] != nil || n[1].(map[string]any)["id"] == nil {
		t.Errorf("row 2 = %v", n[1])
	}
	// Row 3's profile is an array, not an object.
	if n[2].(map[string]any)["profile"] != nil {
		t.Errorf("row 3 profile = %v", n[2])
	}
	want := []string{
		"Profile.name: the stored JSON holds a number where a String is declared",
		"Profile.age: the stored JSON holds a fractional number where an Int is declared",
		"Profile.tags[1]: the stored JSON holds a number where a String is declared",
		"Profile.address: the stored JSON holds a string where an object Address is declared",
		"people.contacts: the stored JSON holds an object where a list [Address] is declared",
		"people.profile: the stored JSON holds an array where an object Profile is declared",
	}
	msgs := ""
	for _, e := range res.Errors {
		msgs += e.Message + "\n"
	}
	for _, w := range want {
		if !strings.Contains(msgs, w) {
			t.Errorf("missing error %q in:\n%s", w, msgs)
		}
	}
	if len(res.Errors) != len(want) {
		t.Errorf("got %d errors, want %d:\n%s", len(res.Errors), len(want), msgs)
	}

	// Negative RBAC: "limited" cannot read profile, so neither the field nor
	// the declared types exist in its schema.
	limited := schemas["limited"]
	if limited.Type("Profile") != nil || limited.Type("Address") != nil {
		t.Error("the declared types must not appear for a role that cannot read the columns")
	}
	if res := runAs(limited, "limited", `{ people_connection { nodes { profile { name } } } }`); len(res.Errors) == 0 {
		t.Error("limited must not select profile")
	}
	if res := runAs(limited, "limited", `{ people_connection(where: {profile: {_is_null: false}}) { nodes { id } } }`); len(res.Errors) == 0 {
		t.Error("limited must not filter on profile")
	}
}

func TestTypedJSONBuildErrors(t *testing.T) {
	db, _ := newFakeDB(peopleAnswer)
	_, err := peopleSchemas(t, db, nil, func(c *config.Config) {
		jsonTypesConfig(c)
		c.Tables["people"].Columns["email"] = &config.FieldConfig{JSONType: "Profile"}
	})
	if err == nil || !strings.Contains(err.Error(), "json_type needs a JSON column") {
		t.Errorf("json_type on a varchar: %v", err)
	}
	_, err = peopleSchemas(t, db, nil, func(c *config.Config) {
		jsonTypesConfig(c)
		c.JSONTypes["people_connection"] = &config.JSONType{Fields: map[string]*config.JSONField{"a": {Type: "Int"}}}
	})
	if err == nil || !strings.Contains(err.Error(), "people_connection") {
		t.Errorf("a JSON type named like a generated type: %v", err)
	}
	// Without json_type the column stays the JSON scalar.
	schemas, err := peopleSchemas(t, db, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	full := schemas["full"]
	if typ := full.Type("people").(*graphql.Object).Fields()["profile"].Type.Name(); typ != "JSON" {
		t.Errorf("untyped profile = %s", typ)
	}
}

func TestCoerceJSON(t *testing.T) {
	ref := func(s string) config.JSONTypeRef {
		r, err := config.ParseJSONTypeRef(s)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, tc := range []struct {
		typ  string
		in   any
		want any
		err  bool
	}{
		{"Int", float64(3), 3, false},
		{"Int", float64(3e10), nil, true},
		{"Int", "3", nil, true},
		{"Float", float64(2.5), 2.5, false},
		{"Boolean", true, true, false},
		{"Boolean", float64(1), nil, true},
		{"String", "s", "s", false},
		{"JSON", []any{"x"}, []any{"x"}, false},
		{"[[Int]]", []any{[]any{float64(1)}, nil}, []any{[]any{1}, nil}, false},
		{"[[Int]]", []any{float64(1)}, nil, true},
		{"Thing", map[string]any{}, map[string]any{}, false},
		{"Thing", "x", nil, true},
		{"Int", nil, nil, false},
	} {
		got, err := coerceJSON(ref(tc.typ), tc.in, "f")
		if (err != nil) != tc.err {
			t.Errorf("%s %v: err = %v", tc.typ, tc.in, err)
			continue
		}
		if err != nil {
			var ce *CodedError
			if !errors.As(err, &ce) || ce.Code != CodeJSONShapeMismatch {
				t.Errorf("%s %v: want a json_shape_mismatch code, got %v", tc.typ, tc.in, err)
			}
			continue
		}
		if fmtAny(got) != fmtAny(tc.want) {
			t.Errorf("%s %v = %#v, want %#v", tc.typ, tc.in, got, tc.want)
		}
	}
}

func fmtAny(v any) string { return fmt.Sprintf("%#v", v) }
