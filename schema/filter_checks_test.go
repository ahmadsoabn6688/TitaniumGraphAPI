package schema

import (
	"context"
	"database/sql/driver"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/graphql-go/graphql"

	"gqlgate/config"
)

// Tests for the filter surface's RBAC edge cases and its startup checks
// against the database.

func TestFilterOperatorsEmptyMeansNone(t *testing.T) {
	role := selectAll()
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, FilterOperators: opList()}}
	b, s := buildFilterRole(t, role)
	if got := inputFields(t, s, "posts_bool_exp"); !reflect.DeepEqual(got, []string{"_and", "_not", "_or"}) {
		t.Errorf("filter_operators: [] must leave no column (or relationship) filters, got %v", got)
	}
	ti := b.tinfos["posts"]
	for name, where := range map[string]map[string]any{
		"_regex":       {"title": map[string]any{"_regex": "^N"}},
		"_eq":          {"id": map[string]any{"_eq": 1}},
		"relationship": {"author": map[string]any{}},
	} {
		if _, err := b.whereSQL(ti, where, testID); err == nil {
			t.Errorf("%s accepted with filter_operators: []", name)
		}
	}
	// Other tables are unaffected.
	if got := fieldTypeName(t, s, "users_bool_exp", "name"); got != "String_comparison_exp" {
		t.Errorf("users.name type = %s", got)
	}
}

func TestRelationshipFilterNeedsFilterableJoinColumns(t *testing.T) {
	// posts.author_id is readable but not filterable: the author relationship
	// must not be usable to filter on it (`author: {id: {_eq: 2}}` is
	// author_id = 2). comments joins on posts.id, which stays filterable.
	role := selectAll()
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{
		Allow:             true,
		Columns:           []string{"id", "author_id", "title"},
		FilterableColumns: &config.FilterableColumns{Names: []string{"id", "title"}},
	}}
	b, s := buildFilterRole(t, role)
	fields := inputFields(t, s, "posts_bool_exp")
	if has(fields, "author") || has(fields, "author_id") {
		t.Errorf("author must not be filterable when author_id is not: %v", fields)
	}
	if !has(fields, "comments") {
		t.Errorf("comments (joined on the filterable id) should stay filterable: %v", fields)
	}
	for _, where := range []map[string]any{
		{"author": map[string]any{"id": map[string]any{"_eq": 2}}},
		{"author": map[string]any{}},
		{"_not": map[string]any{"author": map[string]any{}}},
	} {
		if _, err := b.whereSQL(b.tinfos["posts"], where, testID); err == nil {
			t.Errorf("relationship filter over a non-filterable join column accepted: %v", where)
		}
	}
	// Navigation is unaffected.
	if s.Type("posts").(*graphql.Object).Fields()["author"] == nil {
		t.Error("author must stay navigable")
	}

	// Array relationships: users.id not filterable hides users.posts,
	// users.comments and users.users (all join on users.id); manager joins on
	// manager_id, which stays filterable.
	role = selectAll()
	role.Tables["users"] = &config.TablePerm{Select: &config.OpPerm{
		Allow:             true,
		FilterableColumns: &config.FilterableColumns{Names: []string{"name", "manager_id"}},
	}}
	b, s = buildFilterRole(t, role)
	fields = inputFields(t, s, "users_bool_exp")
	for _, f := range []string{"posts", "comments", "users"} {
		if has(fields, f) {
			t.Errorf("users_bool_exp must not offer %q when users.id is not filterable: %v", f, fields)
		}
	}
	if !has(fields, "manager") {
		t.Errorf("manager should stay filterable: %v", fields)
	}
	if _, err := b.whereSQL(b.tinfos["users"], map[string]any{"posts": map[string]any{"author_id": map[string]any{"_eq": 1}}}, testID); err == nil {
		t.Error("users.posts filter accepted although users.id is not filterable")
	}

	// Filterable, but without _eq: same as not filterable.
	role = selectAll()
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{
		Allow: true,
		FilterableColumns: &config.FilterableColumns{
			Names: []string{"id", "author_id"}, Ops: map[string][]string{"author_id": {"_is_null"}}},
	}}
	_, s = buildFilterRole(t, role)
	if has(inputFields(t, s, "posts_bool_exp"), "author") {
		t.Error("author must not be filterable when author_id lacks _eq")
	}
	// ...and a table-wide filter_operators without _eq removes every relationship.
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, FilterOperators: opList("_ilike")}}
	_, s = buildFilterRole(t, role)
	if got := inputFields(t, s, "posts_bool_exp"); has(got, "author") || has(got, "comments") {
		t.Errorf("relationships need _eq on their join columns: %v", got)
	}

	// Naming the relationship explicitly while hiding its join column fails
	// the build; a wildcard rule just withholds it.
	only := []string{"author"}
	role.Tables["posts"] = &config.TablePerm{Select: &config.OpPerm{
		Allow:               true,
		FilterableColumns:   &config.FilterableColumns{Names: []string{"id"}},
		FilterRelationships: &only,
	}}
	if _, _, err := tryBuildFilterRole(role); err == nil || !strings.Contains(err.Error(), "author_id") {
		t.Errorf("explicit filter_relationships over a hidden join column must fail, got %v", err)
	}
	wild := &config.Role{Tables: map[string]*config.TablePerm{"*": {Select: &config.OpPerm{
		Allow:               true,
		FilterableColumns:   &config.FilterableColumns{Names: []string{"id", "name"}},
		FilterRelationships: &only,
	}}}}
	_, s = buildFilterRole(t, wild)
	if has(inputFields(t, s, "posts_bool_exp"), "author") {
		t.Error("wildcard rule: author must be withheld when author_id is not filterable")
	}
}

// fakeTiDB answers the startup probes like a TiDB cluster: ciProbe is the
// result of the collation probe (or probeErr its failure), and filterErr the
// outcome of every select row filter dry run.
func fakeTiDB(ciProbe int64, probeErr, filterErr error) fakeAnswer {
	return func(q string) ([]string, [][]driver.Value, error) {
		switch {
		case q == ciProbeSQL:
			if probeErr != nil {
				return nil, nil, probeErr
			}
			return []string{"v"}, [][]driver.Value{{ciProbe}}, nil
		case strings.HasPrefix(q, "SELECT 1 FROM `appdb`."):
			if filterErr != nil {
				return nil, nil, filterErr
			}
			return []string{"1"}, nil, nil
		}
		return nil, nil, errors.New("unexpected query: " + q)
	}
}

func TestRoleFilterCheckErrors(t *testing.T) {
	role := selectAll()
	role.Tables["users"] = &config.TablePerm{Select: &config.OpPerm{Allow: true, Filter: "is_public = 1"}}

	// Verified: relationships into users are offered.
	db, log := newFakeDB(fakeTiDB(1, nil, nil))
	_, s, err := tryBuildFilterRoleDB(db, role)
	if err != nil {
		t.Fatal(err)
	}
	if !has(inputFields(t, s, "posts_bool_exp"), "author") {
		t.Error("author should be filterable once users' filter is verified")
	}
	if q := log.all(); !has(q, "SELECT 1 FROM `appdb`.`users` WHERE (is_public = 1) LIMIT 0") {
		t.Errorf("filter dry run not issued: %v", q)
	}

	// The database rejects the filter itself: build succeeds, relationship withheld.
	for _, code := range []uint16{1054, 1064, 1146, 1305} {
		db, _ = newFakeDB(fakeTiDB(1, nil, &mysql.MySQLError{Number: code, Message: "bad filter"}))
		_, s, err = tryBuildFilterRoleDB(db, role)
		if err != nil {
			t.Fatalf("error %d: build must succeed, got %v", code, err)
		}
		if has(inputFields(t, s, "posts_bool_exp"), "author") {
			t.Errorf("error %d: author must be withheld", code)
		}
	}

	// Infrastructure trouble fails the build (a reload keeps the old schema)
	// instead of silently dropping fields.
	for name, e := range map[string]error{
		"timeout":   context.DeadlineExceeded,
		"network":   errors.New("read tcp 10.0.0.1:4000: i/o timeout"),
		"lock wait": &mysql.MySQLError{Number: 1205, Message: "Lock wait timeout exceeded"},
		"tikv":      &mysql.MySQLError{Number: 9002, Message: "TiKV server timeout"},
	} {
		db, _ = newFakeDB(fakeTiDB(1, nil, e))
		if _, _, err := tryBuildFilterRoleDB(db, role); err == nil || !strings.Contains(err.Error(), "select filter") {
			t.Errorf("%s: build must fail, got %v", name, err)
		}
	}
}

func TestCollationProbe(t *testing.T) {
	where := map[string]any{"email": map[string]any{"_icontains": "ada"}}

	db, _ := newFakeDB(fakeTiDB(1, nil, nil))
	b, _, err := tryBuildFilterRoleDB(db, selectAll())
	if err != nil {
		t.Fatal(err)
	}
	c, err := b.whereSQL(b.tinfos["users"], where, testID)
	if err != nil {
		t.Fatal(err)
	}
	if c.sql != "`email` LIKE ? ESCAPE '!'" {
		t.Errorf("new collation framework: sql = %s", c.sql)
	}

	// Old framework: *_ci compares as binary, so LOWER() on both sides.
	db, _ = newFakeDB(fakeTiDB(0, nil, nil))
	b, _, err = tryBuildFilterRoleDB(db, selectAll())
	if err != nil {
		t.Fatal(err)
	}
	c, err = b.whereSQL(b.tinfos["users"], where, testID)
	if err != nil {
		t.Fatal(err)
	}
	if c.sql != "LOWER(`email`) LIKE LOWER(?) ESCAPE '!'" {
		t.Errorf("old collation framework: sql = %s", c.sql)
	}

	// A failing probe fails the build.
	db, _ = newFakeDB(fakeTiDB(1, errors.New("connection refused"), nil))
	if _, _, err := tryBuildFilterRoleDB(db, selectAll()); err == nil || !strings.Contains(err.Error(), "collation") {
		t.Errorf("probe failure must fail the build, got %v", err)
	}
}
