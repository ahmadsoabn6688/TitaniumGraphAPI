package schema

import (
	"strings"
	"testing"

	"gqlgate/introspect"
)

func cat(tables ...string) *introspect.Catalog {
	c := &introspect.Catalog{SchemaName: "appdb", Tables: map[string]*introspect.Table{}}
	for _, tn := range tables {
		c.Tables[tn] = &introspect.Table{Name: tn, ColumnMap: map[string]*introspect.Column{}}
		c.TableOrder = append(c.TableOrder, tn)
	}
	return c
}

func TestCheckNameCollisions(t *testing.T) {
	tests := []struct {
		name    string
		tables  []string
		wantErr string // substring; "" means no error
	}{
		{"clean", []string{"users", "posts", "comments"}, ""},
		{"base name dup", []string{"user-events", "user_events"}, "both map to GraphQL name"},
		{"connection type clash", []string{"users", "users_connection"}, "collides"},
		{"aggregate result clash", []string{"users", "users_aggregate_result"}, "collides"},
		{"insert_one clash", []string{"x", "x_one"}, "collides"},
		{"reserved type page_info", []string{"page_info"}, "collides"},
		{"reserved type order_by", []string{"order_by"}, "collides"},
		{"reserved mutation_response", []string{"mutation_response"}, "collides"},
		{"bool_exp clash", []string{"users", "users_bool_exp"}, "collides"},
		// A table named <t>_approx must not collide with <t>'s aggregate
		// types (approx_count_distinct's type once ended in count_distinct's).
		{"approx suffix table", []string{"events", "events_approx"}, ""},
		{"stats suffix tables", []string{"events", "events_stddev", "events_var", "events_count"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkNameCollisions(cat(tc.tables...))
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("got %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestAggTypeSuffixesUnambiguous: no per-table type suffix may be a proper
// suffix of another, or tables <t> and <t>_<x> would generate the same type
// name (the collision check would then reject a valid schema).
func TestAggTypeSuffixesUnambiguous(t *testing.T) {
	types, err := reservedNames(cat("t"))
	if err != nil {
		t.Fatal(err)
	}
	var suffixes []string
	for name, owner := range types {
		if owner == "table t" && name != "t" {
			suffixes = append(suffixes, strings.TrimPrefix(name, "t"))
		}
	}
	if len(suffixes) < len(aggFuncs) {
		t.Fatalf("suffixes = %v", suffixes)
	}
	for _, a := range suffixes {
		for _, b := range suffixes {
			if a != b && strings.HasSuffix(a, b) {
				t.Errorf("type suffix %q ends with %q: tables x and x%s would collide", a, b, strings.TrimSuffix(a, b))
			}
		}
	}
}
