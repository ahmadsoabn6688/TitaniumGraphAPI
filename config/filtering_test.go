package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseFilterSurface(t *testing.T) {
	yaml := strings.Replace(minimalYAML, "select: true", `select:
          allow: true
          filterable_columns:
            id: all
            title: [_eq, _ilike]
            body: "*"
          filter_operators: [_eq, _ilike, _in]
          filter_relationships: []`, 1)
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	sel := cfg.Roles["admin"].Tables["*"].Select
	fc := sel.FilterableColumns
	if fc == nil || !reflect.DeepEqual(fc.Names, []string{"id", "title", "body"}) {
		t.Fatalf("filterable_columns names = %+v", fc)
	}
	if fc.Ops["id"] != nil || fc.Ops["body"] != nil || !reflect.DeepEqual(fc.Ops["title"], []string{"_eq", "_ilike"}) {
		t.Errorf("filterable_columns ops = %+v", fc.Ops)
	}
	if !reflect.DeepEqual(sel.FilterOperators, []string{"_eq", "_ilike", "_in"}) {
		t.Errorf("filter_operators = %v", sel.FilterOperators)
	}
	if sel.FilterRelationships == nil || len(*sel.FilterRelationships) != 0 {
		t.Errorf("filter_relationships: [] must decode to an empty, non-nil list, got %v", sel.FilterRelationships)
	}
}

func TestParseFilterableColumnsList(t *testing.T) {
	yaml := strings.Replace(minimalYAML, "select: true", `select:
          allow: true
          filterable_columns: [id, name]`, 1)
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	fc := cfg.Roles["admin"].Tables["*"].Select.FilterableColumns
	if !reflect.DeepEqual(fc.Names, []string{"id", "name"}) || len(fc.Ops) != 0 {
		t.Errorf("list form = %+v", fc)
	}
	// Omitted keys mean "default surface".
	cfg, err = Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	sel := cfg.Roles["admin"].Tables["*"].Select
	if sel.FilterableColumns != nil || sel.FilterOperators != nil || sel.FilterRelationships != nil {
		t.Errorf("defaults must be nil: %+v", sel)
	}
}

func TestFilterSurfaceRejected(t *testing.T) {
	for name, block := range map[string]string{
		"bad column value": `select:
          allow: true
          filterable_columns:
            id: some`,
		"bad op name": `select:
          allow: true
          filter_operators: [eq]`,
		"bad per-column op": `select:
          allow: true
          filterable_columns:
            id: ["_eq;drop"]`,
		"duplicate column": `select:
          allow: true
          filterable_columns:
            id: all
            id: [_eq]`,
		"under insert": `select: true
        insert:
          allow: true
          filter_operators: [_eq]`,
	} {
		yaml := strings.Replace(minimalYAML, "select: true", block, 1)
		if _, err := Parse([]byte(yaml)); err == nil {
			t.Errorf("%s: expected a parse error", name)
		}
	}
}

func TestCustomOperatorConfig(t *testing.T) {
	yaml := strings.Replace(minimalYAML, "roles:", `schema_gen:
  custom_operators:
    - name: _year_eq
      argument: Int
      applies_to: [Date, DateTime]
      sql: "YEAR({column}) = {value}"
roles:`, 1)
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	ops := cfg.SchemaGen.CustomOperators
	if len(ops) != 1 || ops[0].Name != "_year_eq" || ops[0].Argument != "Int" || len(ops[0].AppliesTo) != 2 {
		t.Errorf("custom operators = %+v", ops)
	}

	for name, op := range map[string]string{
		"bad name":     "name: year_eq\n      argument: Int\n      sql: \"YEAR({column}) = {value}\"",
		"bad scalar":   "name: _y\n      argument: Integer\n      sql: \"YEAR({column}) = {value}\"",
		"bad applies":  "name: _y\n      argument: Int\n      applies_to: [Text]\n      sql: \"YEAR({column}) = {value}\"",
		"bad template": "name: _y\n      argument: Int\n      sql: \"YEAR({column}) = ?\"",
		"empty":        "name: _y\n      argument: Int\n      sql: \"\"",
		"no value":     "name: _y\n      argument: Int\n      sql: \"{column} IS NULL\"",
		"dup":          "name: _y\n      argument: Int\n      sql: \"{column} = {value}\"\n    - name: _y\n      argument: Int\n      sql: \"{column} = {value}\"",
	} {
		y := strings.Replace(minimalYAML, "roles:", "schema_gen:\n  custom_operators:\n    - "+op+"\nroles:", 1)
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestValidateOperatorTemplate(t *testing.T) {
	good := []string{
		"YEAR({column}) = {value}",
		"CHAR_LENGTH({column}) BETWEEN {value} AND {value} * 2",
		"JSON_EXTRACT({column}, '$.a') = {value}",
		"{column} LIKE CONCAT('it''s {x}?', {value})", // braces/? inside a literal are inert
		"REGEXP_LIKE({column}, {value}, 'i')",
	}
	for _, tmpl := range good {
		if err := ValidateOperatorTemplate(tmpl); err != nil {
			t.Errorf("%q rejected: %v", tmpl, err)
		}
	}
	bad := map[string]string{
		"{column} = ?":                         "literal ?",
		"{column} = {value}; DROP TABLE users": "separators",
		"{column} = {value} -- x":              "comments",
		"{column} = {value} /* x */":           "comments",
		"{column} = {value} # x":               "comments",
		"{column} = {val}":                     "unknown placeholder",
		"{value} = 1":                          "{column}",
		"{column} = 1":                         "{value}",
		"({column} = {value}":                  "parentheses",
		"{column} = {value})":                  "parentheses",
		"{column} = '{value}":                  "unterminated",
		"{column} = {value":                    "unterminated placeholder",
		"{column} } {value}":                   "unbalanced }",
		"   ":                                  "empty",
	}
	for tmpl, wantErr := range bad {
		err := ValidateOperatorTemplate(tmpl)
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("%q: got %v, want error containing %q", tmpl, err, wantErr)
		}
	}
}
