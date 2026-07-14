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
