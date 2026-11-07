package schema

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/graphql-go/graphql"

	"gqlgate/config"
	"gqlgate/introspect"
	"gqlgate/rbac"
)

func TestChunkKeys(t *testing.T) {
	keys := make([][]any, 2500)
	for i := range keys {
		keys[i] = []any{i}
	}
	var sizes []int
	for _, c := range chunkKeys(keys, 1) {
		sizes = append(sizes, len(c))
	}
	if !reflect.DeepEqual(sizes, []int{1000, 1000, 500}) {
		t.Errorf("single-column chunks = %v", sizes)
	}
	// Composite keys bound the parameters, not the tuples.
	if c := chunkKeys(keys[:600], 3); len(c) != 2 || len(c[0]) != 333 {
		t.Errorf("3-column chunks = %d groups, first %d", len(c), len(c[0]))
	}
	if len(chunkKeys(nil, 1)) != 0 {
		t.Error("no keys, no chunks")
	}
}

func insertTable(cols ...*introspect.Column) *introspect.Table {
	t := &introspect.Table{Name: "t", ColumnMap: map[string]*introspect.Column{}}
	for _, c := range cols {
		t.Columns = append(t.Columns, c)
		t.ColumnMap[c.Name] = c
		if c.IsPrimary {
			t.PrimaryKey = append(t.PrimaryKey, c.Name)
		}
	}
	return t
}

func TestInsertedKey(t *testing.T) {
	auto := &introspect.Column{Name: "id", IsPrimary: true, AutoIncrement: true, ColumnType: "bigint"}
	random := &introspect.Column{Name: "id", IsPrimary: true, AutoRandom: true, ColumnType: "bigint unsigned"}
	uuid := &introspect.Column{Name: "id", IsPrimary: true, HasDefault: true, ColumnType: "varchar(36)"}
	a := &introspect.Column{Name: "a", IsPrimary: true, ColumnType: "int"}
	b := &introspect.Column{Name: "b", IsPrimary: true, ColumnType: "int"}
	title := &introspect.Column{Name: "title", ColumnType: "varchar(10)"}

	tests := []struct {
		name   string
		table  *introspect.Table
		cols   []*introspect.Column
		vals   []any
		lastID int64
		want   []any
		ok     bool
	}{
		{"auto increment", insertTable(auto, title), []*introspect.Column{title}, []any{"x"}, 41, []any{int64(41)}, true},
		{"explicit value wins", insertTable(auto, title), []*introspect.Column{auto, title}, []any{7, "x"}, 7, []any{7}, true},
		{"zero means generate", insertTable(auto, title), []*introspect.Column{auto, title}, []any{0, "x"}, 9, []any{int64(9)}, true},
		{"auto random unsigned", insertTable(random, title), []*introspect.Column{title}, []any{"x"}, -5, []any{uint64(18446744073709551611)}, true},
		{"default expression", insertTable(uuid, title), []*introspect.Column{title}, []any{"x"}, 0, nil, false},
		{"supplied natural key", insertTable(uuid, title), []*introspect.Column{uuid, title}, []any{"k-1", "x"}, 0, []any{"k-1"}, true},
		{"composite", insertTable(a, b, title), []*introspect.Column{a, b}, []any{1, 2}, 0, []any{1, 2}, true},
		{"composite missing part", insertTable(a, b, title), []*introspect.Column{a}, []any{1}, 0, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := insertedKey(tc.table, tc.cols, tc.vals, tc.lastID)
			if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
				t.Errorf("insertedKey = %v %v, want %v %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestMovedKeys(t *testing.T) {
	keys := [][]any{{int64(1), []byte("a")}, {int64(2), []byte("b")}}
	if got := movedKeys([]string{"id", "code"}, keys, map[string]any{"title": "x"}); !reflect.DeepEqual(got, keys) {
		t.Errorf("unchanged key columns must keep the keys, got %v", got)
	}
	got := movedKeys([]string{"id", "code"}, keys, map[string]any{"code": "z"})
	want := [][]any{{int64(1), "z"}, {int64(2), "z"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("moved keys = %v, want %v", got, want)
	}
	if string(keys[0][1].([]byte)) != "a" {
		t.Error("movedKeys must not modify its input")
	}
}

// Rows read back for returning carry the raw driver values of their keys;
// they must line up with the keys the insert recorded (bound input values).
func TestOrderByKeys(t *testing.T) {
	keys := [][]any{{float64(3)}, {int64(1)}, {"2"}}
	rows := []map[string]any{{"n": 1}, {"n": 2}, {"n": 3}, {"n": 99}}
	raw := [][]any{{int64(1)}, {[]byte("2")}, {int64(3)}, {int64(99)}}
	var got []any
	for _, r := range orderByKeys(keys, rows, raw) {
		got = append(got, r["n"])
	}
	if !reflect.DeepEqual(got, []any{3, 1, 2, 99}) {
		t.Errorf("order = %v, want [3 1 2 99] (unmatched rows last, never dropped)", got)
	}
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if keyText([]any{ts, nil}) != keyText([]any{ts, nil}) || keyText([]any{"a", "b"}) == keyText([]any{"ab"}) {
		t.Error("keyText must be stable and keep tuple parts apart")
	}
}

func TestClassifyDBError(t *testing.T) {
	tests := []struct {
		num  uint16
		code string
	}{
		{1062, CodeConstraintViolation}, {1451, CodeForeignKeyViolation}, {1452, CodeForeignKeyViolation},
		{1048, CodeNotNullViolation}, {1364, CodeNotNullViolation}, {1406, CodeDataTooLong},
		{1264, CodeDataException}, {1366, CodeDataException}, {3819, CodeCheckViolation},
		{1205, CodeConflict}, {1213, CodeConflict}, {8002, CodeConflict}, {9007, CodeConflict},
		{1146, CodeDatabaseError},
	}
	for _, tc := range tests {
		err := &mysql.MySQLError{Number: tc.num, Message: "Duplicate entry 'secret@x' for key 'users.email' SELECT ..."}
		code, msg, num := classifyDBError(err)
		if code != tc.code || num != tc.num {
			t.Errorf("%d: code %q num %d, want %q", tc.num, code, num, tc.code)
		}
		if strings.Contains(msg, "secret") || strings.Contains(msg, "SELECT") {
			t.Errorf("%d: safe message leaks the database message: %q", tc.num, msg)
		}
	}
	if code, _, _ := classifyDBError(context.DeadlineExceeded); code != CodeTimeout {
		t.Errorf("deadline exceeded = %q, want timeout", code)
	}
	if code, _, _ := classifyDBError(errors.New("bad connection")); code != CodeDatabaseError {
		t.Errorf("plain error = %q, want database_error", code)
	}
}

func TestDBErrMasksUnlessDebug(t *testing.T) {
	raw := &mysql.MySQLError{Number: 1062, Message: "Duplicate entry 'ada@example.com' for key 'users.email'"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	b := &builder{opt: Options{Config: &config.Config{}, Logger: logger}}
	var ce *CodedError
	if err := b.dbErr(raw); !errors.As(err, &ce) || ce.Code != CodeConstraintViolation || strings.Contains(ce.Message, "ada@") {
		t.Errorf("masked error = %#v", err)
	}
	if ext := ce.Extensions(); ext["code"] != CodeConstraintViolation || ext["db_error_number"] != nil {
		t.Errorf("masked extensions = %v (the error number is debug-only)", ext)
	}

	dbg := &builder{opt: Options{Config: &config.Config{Server: config.Server{Debug: true}}}}
	if err := dbg.dbErr(raw); !errors.As(err, &ce) || !strings.Contains(ce.Message, "ada@") || ce.Extensions()["db_error_number"] != 1062 {
		t.Errorf("debug error = %#v, want the raw message with the code", err)
	}
	// Already-coded errors pass through unchanged (a limit hit while scanning).
	limit := ResponseTooLarge(5)
	if err := b.dbErr(limit); err != limit {
		t.Errorf("coded error rewrapped: %v", err)
	}
}

func TestResponseRowBudget(t *testing.T) {
	if err := countRows(context.Background(), 1_000_000); err != nil {
		t.Errorf("no tracker = unlimited, got %v", err)
	}
	ctx := WithResponseLimit(context.Background(), 0)
	if err := countRows(ctx, 1_000_000); err != nil || ResponseLimitExceeded(ctx) {
		t.Errorf("0 = unlimited, got %v", err)
	}
	ctx = WithResponseLimit(context.Background(), 3)
	for i := 0; i < 3; i++ {
		if err := countRows(ctx, 1); err != nil {
			t.Fatalf("row %d within the budget failed: %v", i+1, err)
		}
	}
	err := countRows(ctx, 1)
	var ce *CodedError
	if !errors.As(err, &ce) || ce.Code != CodeResponseTooLarge || !ResponseLimitExceeded(ctx) {
		t.Errorf("row 4 = %v, want response_too_large", err)
	}
	if MutationCommitted(ctx) {
		t.Error("nothing committed yet")
	}
	noteCommit(ctx)
	if !MutationCommitted(ctx) {
		t.Error("commit not recorded")
	}
}

// uniqueCatalog is filterCatalog with a unique key on users.email, a
// composite one on posts (author_id, title), and comments keyed by "pk".
func uniqueKeyCatalog() *introspect.Catalog {
	c := filterCatalog()
	c.Tables["users"].UniqueKeys = []*introspect.UniqueKey{{Name: "uq_email", Columns: []string{"email"}}}
	c.Tables["posts"].UniqueKeys = []*introspect.UniqueKey{{Name: "uq_author_title", Columns: []string{"author_id", "title"}}}
	pk := &introspect.Column{Name: "pk", DataType: "bigint", ColumnType: "bigint", Ordinal: 4}
	cm := c.Tables["comments"]
	cm.Columns = append(cm.Columns, pk)
	cm.ColumnMap["pk"] = pk
	cm.UniqueKeys = []*introspect.UniqueKey{{Name: "uq_pk", Columns: []string{"pk"}}}
	return c
}

func buildUniqueRole(t *testing.T, role *config.Role, hooks *Hooks) (graphql.Schema, error) {
	t.Helper()
	cfg := &config.Config{Roles: map[string]*config.Role{"r": role}}
	cfg.SchemaGen.DefaultPageSize = 25
	cfg.SchemaGen.MaxPageSize = 200
	schemas, err := BuildAll(Options{Catalog: uniqueKeyCatalog(), Config: cfg, Hooks: hooks})
	if err != nil {
		return graphql.Schema{}, err
	}
	return schemas["r"], nil
}

func hasMutationField(s graphql.Schema, name string) bool {
	if s.MutationType() == nil {
		return false
	}
	_, ok := s.MutationType().Fields()[name]
	return ok
}

func TestUniqueKeyFields(t *testing.T) {
	all := &config.OpPerm{Allow: true}
	s, err := buildUniqueRole(t, &config.Role{Tables: map[string]*config.TablePerm{"*": {Select: all, Update: all, Delete: all}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"users_by_email", "posts_by_author_id_and_title"} {
		if !hasQueryField(s, f) {
			t.Errorf("query field %s missing", f)
		}
	}
	for _, f := range []string{"update_users_by_email", "delete_users_by_email", "update_posts_by_author_id_and_title", "delete_posts_by_author_id_and_title"} {
		if !hasMutationField(s, f) {
			t.Errorf("mutation field %s missing", f)
		}
	}
	if f := s.QueryType().Fields()["posts_by_author_id_and_title"]; f == nil || len(f.Args) != 2 {
		t.Errorf("composite lookup must take both key columns, got %+v", f)
	}
	// comments.pk would be comments_by_pk, which the primary-key lookup
	// already is: the unique-key field is left out, the PK one stays.
	if f := s.QueryType().Fields()["comments_by_pk"]; f == nil || len(f.Args) != 1 || f.Args[0].Name() != "id" {
		t.Errorf("comments_by_pk must stay the primary-key lookup, got %+v", f)
	}

	// Negative RBAC: a key column the role cannot read, or may not filter
	// on with _eq, gives no lookup (it would probe a hidden column).
	hidden := &config.Role{Tables: map[string]*config.TablePerm{
		"users": {Select: &config.OpPerm{Allow: true, Columns: []string{"id", "name"}}, Update: all, Delete: all},
		"posts": {Select: &config.OpPerm{Allow: true, FilterableColumns: &config.FilterableColumns{
			Names: []string{"id", "author_id", "title"}, Ops: map[string][]string{"title": {"_ilike"}}}}, Update: all},
	}}
	s, err = buildUniqueRole(t, hidden, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"users_by_email", "posts_by_author_id_and_title"} {
		if hasQueryField(s, f) {
			t.Errorf("%s must not exist when a key column is hidden or not _eq-filterable", f)
		}
	}
	for _, f := range []string{"update_users_by_email", "delete_users_by_email", "update_posts_by_author_id_and_title"} {
		if hasMutationField(s, f) {
			t.Errorf("%s must not exist when a key column is hidden or not _eq-filterable", f)
		}
	}

	// Select only: lookups, no point mutations.
	s, err = buildUniqueRole(t, &config.Role{Tables: map[string]*config.TablePerm{"*": {Select: all}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasQueryField(s, "users_by_email") || hasMutationField(s, "update_users_by_email") || hasMutationField(s, "delete_users_by_email") {
		t.Error("a select-only role gets the lookup and no point mutations")
	}
}

// A custom field that already uses a unique-key field's name keeps it rather
// than failing the build (the generated field is the newcomer).
func TestCustomFieldReplacesUniqueKeyField(t *testing.T) {
	custom := &graphql.Field{Type: graphql.String, Resolve: func(graphql.ResolveParams) (any, error) { return "custom", nil }}
	hooks := NewHooks(nil, nil, []CustomField{{Name: "users_by_email", Operation: "query", Field: custom}})
	s, err := buildUniqueRole(t, &config.Role{Tables: map[string]*config.TablePerm{"*": {Select: &config.OpPerm{Allow: true}}}}, hooks)
	if err != nil {
		t.Fatal(err)
	}
	if f := s.QueryType().Fields()["users_by_email"]; f == nil || f.Type != graphql.String {
		t.Errorf("custom field did not take the name: %+v", f)
	}
	// Fixed generated names still refuse a custom field.
	hooks = NewHooks(nil, nil, []CustomField{{Name: "users_by_pk", Operation: "query", Field: custom}})
	if _, err := buildUniqueRole(t, &config.Role{Tables: map[string]*config.TablePerm{"*": {Select: &config.OpPerm{Allow: true}}}}, hooks); err == nil {
		t.Error("a custom field colliding with users_by_pk must fail")
	}
}

func TestMutationResponseTypes(t *testing.T) {
	all := &config.OpPerm{Allow: true}
	s, err := buildUniqueRole(t, &config.Role{Tables: map[string]*config.TablePerm{
		"posts":    {Select: all, Insert: all, Update: all, Delete: all},
		"comments": {Insert: all}, // insert only: nothing to return through
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	iface, ok := s.Type("mutation_response").(*graphql.Interface)
	if !ok {
		t.Fatalf("mutation_response must stay as an interface, got %T", s.Type("mutation_response"))
	}
	if _, ok := iface.Fields()["affected_rows"]; !ok {
		t.Error("mutation_response.affected_rows missing")
	}
	if got := objectFields(t, s, "posts_mutation_response"); !reflect.DeepEqual(got, []string{"affected_rows", "returning"}) {
		t.Errorf("posts_mutation_response fields = %v", got)
	}
	if ty := objectFieldType(t, s, "posts_mutation_response", "returning"); ty != "[posts!]!" {
		t.Errorf("returning type = %s", ty)
	}
	if got := objectFields(t, s, "comments_mutation_response"); !reflect.DeepEqual(got, []string{"affected_rows"}) {
		t.Errorf("insert-only comments_mutation_response fields = %v, want only affected_rows", got)
	}
	for _, f := range []string{"insert_posts", "update_posts", "delete_posts"} {
		if got := s.MutationType().Fields()[f].Type.String(); got != "posts_mutation_response!" {
			t.Errorf("%s returns %s", f, got)
		}
	}
	impl := false
	for _, i := range s.Type("posts_mutation_response").(*graphql.Object).Interfaces() {
		impl = impl || i.Name() == "mutation_response"
	}
	if !impl {
		t.Error("posts_mutation_response must implement mutation_response")
	}
}

func TestMutationResponseNameCollision(t *testing.T) {
	r, err := reserveNames(cat("x", "x_mutation_response"))
	if err != nil {
		t.Fatalf("a table named <t>_mutation_response must not fail the build: %v", err)
	}
	if r.mutResp["x"] != "x_mutation_response_1" || r.mutResp["x_mutation_response"] != "x_mutation_response_mutation_response" {
		t.Errorf("mutation response names = %v", r.mutResp)
	}
}

func TestWriteCheckNeedsPrimaryKey(t *testing.T) {
	c := uniqueKeyCatalog()
	c.Tables["comments"].PrimaryKey = nil
	cfg := &config.Config{Roles: map[string]*config.Role{"r": {Tables: map[string]*config.TablePerm{
		"comments": {Insert: &config.OpPerm{Allow: true, Check: "user_id = :jwt.sub"}},
	}}}}
	cfg.SchemaGen.DefaultPageSize, cfg.SchemaGen.MaxPageSize = 25, 200
	if _, err := BuildAll(Options{Catalog: c, Config: cfg}); err == nil || !strings.Contains(err.Error(), "primary key") {
		t.Errorf("insert check on a table without a primary key: got %v", err)
	}
}

func TestCastType(t *testing.T) {
	tests := []struct{ dataType, columnType, want string }{
		{"decimal", "decimal(10,2)", "DECIMAL(10,2)"},
		{"decimal", "decimal(10,2) unsigned zerofill", "DECIMAL(10,2)"},
		{"datetime", "datetime", "DATETIME"},
		{"datetime", "datetime(3)", "DATETIME(3)"},
		{"timestamp", "timestamp(6)", "DATETIME(6)"},
		{"time", "time(1)", "TIME(1)"},
		{"date", "date", "DATE"},
		{"binary", "binary(4)", "BINARY(4)"},
		{"bigint", "bigint(20) unsigned", ""},
		{"varchar", "varchar(36)", ""},
		{"float", "float", ""},
	}
	for _, tc := range tests {
		if got := castType(&introspect.Column{DataType: tc.dataType, ColumnType: tc.columnType}); got != tc.want {
			t.Errorf("castType(%s) = %q, want %q", tc.columnType, got, tc.want)
		}
	}
	if castType(nil) != "" {
		t.Error("castType(nil) must be empty")
	}
}

func TestExactKey(t *testing.T) {
	id := &introspect.Column{Name: "id", DataType: "bigint", IsPrimary: true}
	code := &introspect.Column{Name: "code", DataType: "varchar", IsPrimary: true}
	amount := &introspect.Column{Name: "amount", DataType: "decimal", IsPrimary: true}
	if !exactKey(insertTable(id, code), []string{"id", "code"}) {
		t.Error("integer and character keys compare exactly")
	}
	if exactKey(insertTable(id, amount), []string{"id", "amount"}) {
		t.Error("a decimal key part needs the pre-write guard")
	}
	if exactKey(insertTable(id), []string{"missing"}) {
		t.Error("an unknown column is not exact")
	}
}

func TestDistinctKeys(t *testing.T) {
	got := distinctKeys([][]any{{int64(1)}, {"1"}, {[]byte("2")}, {int64(2)}, {int64(3)}})
	if !reflect.DeepEqual(got, [][]any{{int64(1)}, {[]byte("2")}, {int64(3)}}) {
		t.Errorf("distinctKeys = %v", got)
	}
}

func TestMovedCols(t *testing.T) {
	if got := movedCols([]string{"a", "b"}, map[string]any{"b": 1, "c": 2}); !reflect.DeepEqual(got, []string{"b"}) {
		t.Errorf("movedCols = %v", got)
	}
	if got := movedCols([]string{"a"}, map[string]any{"c": 2}); got != nil {
		t.Errorf("movedCols = %v, want none", got)
	}
}

// A legacy insert.filter (accepted and ignored by earlier versions) must not
// stop a config from booting where it cannot be enforced: on a table without
// a primary key it is skipped, while an explicit check there still fails.
func TestLegacyInsertFilterWithoutPrimaryKey(t *testing.T) {
	c := uniqueKeyCatalog()
	c.Tables["comments"].PrimaryKey = nil
	cfg := &config.Config{Roles: map[string]*config.Role{"r": {Tables: map[string]*config.TablePerm{
		"*": {Select: &config.OpPerm{Allow: true}, Insert: &config.OpPerm{Allow: true, Filter: "1 = 1"}},
	}}}}
	cfg.SchemaGen.DefaultPageSize, cfg.SchemaGen.MaxPageSize = 25, 200
	schemas, err := BuildAll(Options{Catalog: c, Config: cfg})
	if err != nil {
		t.Fatalf("a wildcard insert.filter with a PK-less table must still build: %v", err)
	}
	if !hasMutationField(schemas["r"], "insert_comments") || !hasMutationField(schemas["r"], "insert_posts") {
		t.Error("insert fields must stay available")
	}

	// The builder keeps enforcing it where it can, and drops it (on a copy)
	// where it cannot.
	access, err := rbac.Resolve("r", cfg.Roles["r"], c)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := newBuildShared(Options{Catalog: c, Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := buildRoleBuilder(Options{Catalog: c, Config: cfg}, shared, "r", access)
	if err != nil {
		t.Fatal(err)
	}
	if b.tinfos["comments"].access.Insert.Check != nil {
		t.Error("the legacy filter must not be enforced on the PK-less table")
	}
	if b.tinfos["posts"].access.Insert.Check == nil {
		t.Error("the legacy filter must still be enforced on a table with a primary key")
	}
	if access.Table("comments").Insert.Check == nil {
		t.Error("the resolved role access must not be modified")
	}
}

// A custom field whose own type is already named <t>_mutation_response keeps
// the name; the generated type takes the next free numbered one.
func TestMutationResponseAvoidsCustomTypes(t *testing.T) {
	custom := graphql.NewObject(graphql.ObjectConfig{
		Name:   "posts_mutation_response",
		Fields: graphql.Fields{"ok": &graphql.Field{Type: graphql.Boolean}},
	})
	input := graphql.NewInputObject(graphql.InputObjectConfig{
		Name:   "users_mutation_response",
		Fields: graphql.InputObjectConfigFieldMap{"x": &graphql.InputObjectFieldConfig{Type: graphql.String}},
	})
	field := &graphql.Field{
		Type: graphql.NewNonNull(custom),
		Args: graphql.FieldConfigArgument{"in": &graphql.ArgumentConfig{Type: input}},
		Resolve: func(graphql.ResolveParams) (any, error) {
			return map[string]any{"ok": true}, nil
		},
	}
	hooks := NewHooks(nil, nil, []CustomField{{Name: "publish", Operation: "mutation", Field: field}})
	all := &config.OpPerm{Allow: true}
	s, err := buildUniqueRole(t, &config.Role{Tables: map[string]*config.TablePerm{"*": {Select: all, Insert: all, Update: all, Delete: all}}}, hooks)
	if err != nil {
		t.Fatalf("a custom type named like a mutation response must not break the build: %v", err)
	}
	if got := s.MutationType().Fields()["insert_posts"].Type.String(); got != "posts_mutation_response_1!" {
		t.Errorf("insert_posts returns %s", got)
	}
	if got := s.MutationType().Fields()["insert_users"].Type.String(); got != "users_mutation_response_1!" {
		t.Errorf("insert_users returns %s", got)
	}
	if got := s.MutationType().Fields()["publish"].Type.String(); got != "posts_mutation_response!" {
		t.Errorf("the custom field lost its type: %s", got)
	}
	if got := s.MutationType().Fields()["insert_comments"].Type.String(); got != "comments_mutation_response!" {
		t.Errorf("unaffected tables keep their names, got %s", got)
	}
}
