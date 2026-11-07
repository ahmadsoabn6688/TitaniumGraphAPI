package config

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Filter-surface configuration: which columns, operators and relationships a
// role may use in `where`, plus developer-defined comparison operators.

// ColumnScalarNames are the GraphQL scalars a column can map to. Custom
// operators name them in `argument` and `applies_to`.
var ColumnScalarNames = []string{
	"String", "Int", "Float", "Boolean", "BigInt", "Decimal",
	"DateTime", "Date", "JSON", "Bytes", "Vector",
}

// OperatorNamePattern is the shape of every comparison operator name (built-in
// or custom): a GraphQL name with a leading underscore, e.g. _eq, _ilike.
var OperatorNamePattern = regexp.MustCompile(`^_[A-Za-z][A-Za-z0-9_]*$`)

// CustomOperator is a developer-defined comparison operator, declared under
// schema_gen.custom_operators:
//
//	custom_operators:
//	  - name: _year_eq               # field name in <Scalar>_comparison_exp
//	    argument: Int                # GraphQL scalar type of the argument
//	    applies_to: [Date, DateTime] # column scalars that get it (default: [argument])
//	    sql: "YEAR({column}) = {value}"
//
// {column} is replaced by the backtick-quoted (and, inside relationship
// filters, alias-qualified) column; every {value} becomes a bound "?"
// parameter carrying the client's argument. The template is otherwise trusted
// developer SQL, but it is validated at load time (placeholders present, no
// literal "?", no statement separators or comments, balanced quotes and
// parentheses) and dry-run against the database at startup.
type CustomOperator struct {
	Name      string   `yaml:"name"`
	Argument  string   `yaml:"argument"`
	AppliesTo []string `yaml:"applies_to"`
	SQL       string   `yaml:"sql"`
}

// FilterableColumns is the select.filterable_columns setting. In YAML it is
// either a list of column names (each gets every operator allowed for the
// table) or a mapping from column name to `all` or an operator list:
//
//	filterable_columns: [id, title]
//	filterable_columns:
//	  id: all
//	  title: [_eq, _ilike, _starts_with]
type FilterableColumns struct {
	// Names lists the filterable columns in YAML order.
	Names []string
	// Ops holds per-column operator allow-lists; a missing entry means every
	// operator.
	Ops map[string][]string
}

// UnmarshalYAML accepts the list and the mapping forms.
func (f *FilterableColumns) UnmarshalYAML(node *yaml.Node) error {
	*f = FilterableColumns{Names: []string{}, Ops: map[string][]string{}}
	switch node.Kind {
	case yaml.SequenceNode:
		var names []string
		if err := node.Decode(&names); err != nil {
			return fmt.Errorf("filterable_columns list must contain column names: %w", err)
		}
		f.Names = append(f.Names, names...)
		return nil
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			k, v := node.Content[i], node.Content[i+1]
			var col string
			if err := k.Decode(&col); err != nil {
				return fmt.Errorf("filterable_columns key: %w", err)
			}
			if _, dup := f.Ops[col]; dup || containsString(f.Names, col) {
				return fmt.Errorf("filterable_columns lists column %q twice", col)
			}
			f.Names = append(f.Names, col)
			switch v.Kind {
			case yaml.ScalarNode:
				s := strings.TrimSpace(v.Value)
				if s != "all" && s != "*" && s != "true" {
					return fmt.Errorf("filterable_columns.%s must be `all` or a list of operators, got %q", col, v.Value)
				}
			case yaml.SequenceNode:
				var ops []string
				if err := v.Decode(&ops); err != nil {
					return fmt.Errorf("filterable_columns.%s: %w", col, err)
				}
				f.Ops[col] = ops
			default:
				return fmt.Errorf("filterable_columns.%s must be `all` or a list of operators", col)
			}
		}
		return nil
	}
	return fmt.Errorf("filterable_columns must be a list of columns or a mapping of column -> operators")
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// validateFilterSurface checks the filter-surface keys of every role and the
// custom operator declarations.
func (c *Config) validateFilterSurface() error {
	seen := map[string]bool{}
	for i, op := range c.SchemaGen.CustomOperators {
		where := fmt.Sprintf("schema_gen.custom_operators[%d]", i)
		if !OperatorNamePattern.MatchString(op.Name) {
			return fmt.Errorf("%s: name %q must start with _ followed by a letter (letters, digits, _)", where, op.Name)
		}
		if seen[op.Name] {
			return fmt.Errorf("%s: operator %q is declared twice", where, op.Name)
		}
		seen[op.Name] = true
		if !containsString(ColumnScalarNames, op.Argument) {
			return fmt.Errorf("%s (%s): argument %q is not a known scalar (one of %s)", where, op.Name, op.Argument, strings.Join(ColumnScalarNames, ", "))
		}
		for _, s := range op.AppliesTo {
			if !containsString(ColumnScalarNames, s) {
				return fmt.Errorf("%s (%s): applies_to %q is not a known scalar (one of %s)", where, op.Name, s, strings.Join(ColumnScalarNames, ", "))
			}
		}
		if err := ValidateOperatorTemplate(op.SQL); err != nil {
			return fmt.Errorf("%s (%s): sql: %w", where, op.Name, err)
		}
	}

	for roleName, role := range c.Roles {
		if role == nil {
			continue
		}
		for tableName, tp := range role.Tables {
			if tp == nil {
				continue
			}
			for opName, perm := range map[string]*OpPerm{"insert": tp.Insert, "update": tp.Update, "delete": tp.Delete} {
				if perm != nil && (perm.FilterableColumns != nil || perm.FilterOperators != nil || perm.FilterRelationships != nil) {
					return fmt.Errorf("role %q, table %q: filterable_columns/filter_operators/filter_relationships belong under select, not %s", roleName, tableName, opName)
				}
			}
			sel := tp.Select
			if sel == nil {
				continue
			}
			check := func(ops []string, where string) error {
				for _, o := range ops {
					if !OperatorNamePattern.MatchString(o) {
						return fmt.Errorf("role %q, table %q, select.%s: %q is not an operator name (operators look like _eq, _ilike)", roleName, tableName, where, o)
					}
				}
				return nil
			}
			if sel.FilterOperators != nil {
				if err := check(*sel.FilterOperators, "filter_operators"); err != nil {
					return err
				}
			}
			if sel.FilterableColumns != nil {
				for col, ops := range sel.FilterableColumns.Ops {
					if err := check(ops, "filterable_columns."+col); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// ValidateOperatorTemplate statically checks a custom operator SQL template:
// it must reference {column} and {value}, use no other {placeholders}, contain
// no literal "?" (all values are bound through {value}), no statement
// separators or comments, and have balanced quotes and parentheses with every
// placeholder outside string literals and quoted identifiers.
func ValidateOperatorTemplate(tmpl string) error {
	if strings.TrimSpace(tmpl) == "" {
		return fmt.Errorf("template is empty")
	}
	// Byte-wise scan: every character of interest is ASCII, and UTF-8
	// continuation bytes never collide with them.
	var quote byte
	depth, cols, vals := 0, 0, 0
	for i := 0; i < len(tmpl); i++ {
		c := tmpl[i]
		if quote != 0 {
			// The renderer substitutes placeholders wherever they appear, so
			// one inside a literal would silently become a bound "?" there.
			if err := placeholderInQuote(tmpl[i:]); err != nil {
				return err
			}
			if c == '\\' && quote != '`' {
				i++ // skip the escaped character (still no placeholder there)
				if i < len(tmpl) {
					if err := placeholderInQuote(tmpl[i:]); err != nil {
						return err
					}
				}
				continue
			}
			if c == quote {
				if i+1 < len(tmpl) && tmpl[i+1] == quote { // doubled-quote escape
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return fmt.Errorf("unbalanced parentheses")
			}
		case '?':
			return fmt.Errorf("literal ? is not allowed; use {value} for the bound argument")
		case ';':
			return fmt.Errorf("statement separators (;) are not allowed")
		case '#':
			return fmt.Errorf("comments are not allowed")
		case '-':
			if i+1 < len(tmpl) && tmpl[i+1] == '-' {
				return fmt.Errorf("comments are not allowed")
			}
		case '/':
			if i+1 < len(tmpl) && tmpl[i+1] == '*' {
				return fmt.Errorf("comments are not allowed")
			}
		case '{':
			end := strings.IndexByte(tmpl[i:], '}')
			if end < 0 {
				return fmt.Errorf("unterminated placeholder")
			}
			switch name := tmpl[i+1 : i+end]; name {
			case "column":
				cols++
			case "value":
				vals++
			default:
				return fmt.Errorf("unknown placeholder {%s} (only {column} and {value} exist)", name)
			}
			i += end
		case '}':
			return fmt.Errorf("unbalanced }")
		}
	}
	if quote != 0 {
		return fmt.Errorf("unterminated string literal or quoted identifier")
	}
	if depth != 0 {
		return fmt.Errorf("unbalanced parentheses")
	}
	if cols == 0 {
		return fmt.Errorf("template must reference {column}")
	}
	if vals == 0 {
		return fmt.Errorf("template must reference {value}")
	}
	return nil
}

// placeholderInQuote rejects a {column}/{value} at the start of rest, which
// lies inside a quoted section: the renderer substitutes placeholders wherever
// they appear, so one inside a literal would silently become a bound "?".
func placeholderInQuote(rest string) error {
	for _, p := range []string{"{column}", "{value}"} {
		if strings.HasPrefix(rest, p) {
			return fmt.Errorf("placeholder %s inside a quoted string or identifier is not allowed", p)
		}
	}
	return nil
}
