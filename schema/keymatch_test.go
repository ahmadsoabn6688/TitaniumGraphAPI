package schema

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
)

// TestKeyIndexCollation: rows of a character join column are matched to the
// batch's keys by collation weight, not by their exact bytes. The fake
// database plays utf8mb4_general_ci with PAD SPACE: the weight of a value is
// its upper-cased form without trailing spaces.
func TestKeyIndexCollation(t *testing.T) {
	keys := [][]any{{"a@x"}, {"A@X"}, {"b@x "}, {"c@x"}}
	weight := func(s string) []byte { return []byte(strings.ToUpper(strings.TrimRight(s, " "))) }
	answer := func(q string) ([]string, [][]driver.Value, error) {
		switch {
		case q == ciProbeSQL:
			return []string{"v"}, [][]driver.Value{{int64(1)}}, nil
		case strings.HasPrefix(q, "SELECT WEIGHT_STRING(CONVERT(? USING utf8mb4) COLLATE utf8mb4_general_ci)"):
			if n := strings.Count(q, "WEIGHT_STRING("); n != len(keys) {
				return nil, nil, errors.New("want one weight per key")
			}
			var cols []string
			var row []driver.Value
			for _, k := range keys {
				cols = append(cols, "w")
				row = append(row, weight(k[0].(string)))
			}
			return cols, [][]driver.Value{row}, nil
		}
		return nil, nil, errors.New("unexpected query: " + q)
	}
	db, log := newFakeDB(answer)
	b, _, err := tryBuildFilterRoleDB(db, selectAll())
	if err != nil {
		t.Fatal(err)
	}
	users := b.tinfos["users"]
	ki, err := b.newKeyIndex(context.Background(), users, []string{"email"}, keys)
	if err != nil {
		t.Fatal(err)
	}
	if got := ki.weightExprs(); len(got) != 1 || got[0] != "WEIGHT_STRING(`email`)" {
		t.Errorf("weight exprs = %v", got)
	}

	rows := []map[string]any{{"id": 1, "email": "A@x"}, {"id": 2, "email": "b@X"}, {"id": 3, "email": "d@x"}, {"id": 4, "email": "a@x"}}
	var ws [][]any
	for _, r := range rows {
		ws = append(ws, []any{weight(r["email"].(string))})
	}
	got := ki.group(rows, ws)
	ids := func(k []any) []int {
		var out []int
		for _, r := range got[keySig(k)] {
			out = append(out, r["id"].(int))
		}
		return out
	}
	// Both 'a@x' and 'A@X' (a to-one batch can hold both) get rows 1 and 4,
	// in input order; 'b@x ' matches 'b@X' despite case and trailing space.
	for i, want := range [][]int{{1, 4}, {1, 4}, {2}, nil} {
		if g := ids(keys[i]); len(g) != len(want) || (len(want) > 0 && (g[0] != want[0] || g[len(g)-1] != want[len(want)-1])) {
			t.Errorf("key %v: rows %v, want %v", keys[i], g, want)
		}
	}
	// A NULL weight matches nothing.
	if m := ki.match([]any{nil}, []any{nil}); m != nil {
		t.Errorf("NULL weight matched %v", m)
	}

	// Integer join columns match by value without a weight query.
	before := len(log.all())
	ki, err = b.newKeyIndex(context.Background(), users, []string{"id"}, [][]any{{int64(1)}, {int64(2)}})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(log.all()) - before; n != 0 || len(ki.weightExprs()) != 0 {
		t.Errorf("integer keys ran %d weight queries, exprs %v", n, ki.weightExprs())
	}
	if m := ki.match([]any{int64(2)}, nil); len(m) != 1 || m[0] != 1 {
		t.Errorf("integer match = %v", m)
	}
}

func TestWeightedKeyCol(t *testing.T) {
	users := filterCatalog().Tables["users"]
	for col, want := range map[string]bool{"id": false, "email": true, "name": true} {
		if got := weightedKeyCol(users.ColumnMap[col]); got != want {
			t.Errorf("weightedKeyCol(%s) = %v, want %v", col, got, want)
		}
	}
	bin := *users.ColumnMap["name"]
	bin.Charset, bin.Collation = "binary", "binary"
	if weightedKeyCol(&bin) {
		t.Error("binary strings compare byte-exact; no weight needed")
	}
	evil := *users.ColumnMap["name"]
	evil.Collation = "utf8mb4_bin) OR (1"
	if weightedKeyCol(&evil) {
		t.Error("a collation name that is not a plain identifier must never be inlined")
	}
}

// TestSerialMutation: relationship fields resolve eagerly only under a
// mutation with several root fields (fragments followed).
func TestSerialMutation(t *testing.T) {
	for doc, want := range map[string]bool{
		`{ a: users_by_pk(id: 1) { id } b: users_by_pk(id: 2) { id } }`:                                                        false,
		`mutation { delete_users_by_pk(id: 1) { id } }`:                                                                        false,
		`mutation { a: delete_users_by_pk(id: 1) { id } b: delete_users_by_pk(id: 2) { id } }`:                                 true,
		`mutation { ... on Mutation { a: delete_users_by_pk(id: 1) { id } } b: delete_users_by_pk(id: 2) { id } }`:             true,
		`mutation { ...F } fragment F on Mutation { a: delete_users_by_pk(id: 1) { id } b: delete_users_by_pk(id: 2) { id } }`: true,
		`mutation { ...F } fragment F on Mutation { a: delete_users_by_pk(id: 1) { id } }`:                                     false,
	} {
		d, err := parser.Parse(parser.ParseParams{Source: doc})
		if err != nil {
			t.Fatal(err)
		}
		info := graphql.ResolveInfo{Fragments: map[string]ast.Definition{}}
		for _, def := range d.Definitions {
			switch n := def.(type) {
			case *ast.OperationDefinition:
				info.Operation = n
			case *ast.FragmentDefinition:
				info.Fragments[n.Name.Value] = n
			}
		}
		if got := serialMutation(info); got != want {
			t.Errorf("serialMutation(%s) = %v, want %v", doc, got, want)
		}
	}
}
