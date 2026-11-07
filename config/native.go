package config

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Native queries: the top-level `native_queries:` section turns a
// parameterized, read-only SQL statement into a root query field:
//
//	native_queries:
//	  posts_in_month:
//	    sql: |
//	      SELECT p.id, p.title, p.author_id, COUNT(c.id) AS comment_count
//	      FROM posts p LEFT JOIN comments c ON c.post_id = p.id
//	      WHERE YEAR(p.created_at) = :year AND MONTH(p.created_at) = :month
//	      GROUP BY p.id, p.title, p.author_id
//	    arguments:
//	      year: Int!                       # shorthand: just the type
//	      month: {type: Int!, description: "1-12"}
//	    columns:                           # optional per result column
//	      comment_count: BigInt!           # shorthand: just the type
//	      title: {name: headline, description: "Post title"}
//	    key: [id]                          # optional: adds a cursor connection
//	    relationships:
//	      author: {type: object, target: users, mapping: {author_id: id}}
//	roles:
//	  author:
//	    native_queries:
//	      posts_in_month:
//	        allow: true
//	        filter: "author_id = :jwt.sub"   # row filter over the result columns
//	        presets: {month: ":jwt.month"}   # argument presets (hidden from the client)
//
// Every :name in the SQL must be a declared argument and is bound as a
// parameter at request time (never spliced into the SQL text). Only a SELECT
// (or WITH … SELECT) statement is accepted; it runs wrapped as a derived
// table, so the generated `where`, the role's row filter and the keyset
// cursor apply on top of it.

// NativeQuery is one entry of the top-level native_queries: section.
type NativeQuery struct {
	// SQL is the statement: SELECT or WITH … SELECT, with :name parameters.
	SQL string `yaml:"sql"`
	// Arguments declares the :name parameters, keyed by name.
	Arguments map[string]*NativeArgument `yaml:"arguments"`
	// Columns overrides the introspected type, the GraphQL name, the
	// description or the deprecation of result columns, keyed by column name.
	Columns map[string]*NativeColumn `yaml:"columns"`
	// Key lists result columns that identify one row; it enables the
	// cursor connection. It is not enforced.
	Key []string `yaml:"key"`
	// TypeName is the result object type's name (default: the query name).
	TypeName    string `yaml:"type_name"`
	Description string `yaml:"description"`
	// RootFields renames / documents / deprecates the list field (default:
	// the query name) and the connection field (default: <name>_connection).
	RootFields NativeRootFields `yaml:"root_fields"`
	// Relationships declares relationships from result rows to tables or
	// views (type, target and mapping, as under tables:).
	Relationships map[string]*RelationshipConfig `yaml:"relationships"`
}

// NativeRootFields configures a native query's root fields.
type NativeRootFields struct {
	List       *FieldConfig `yaml:"list"`
	Connection *FieldConfig `yaml:"connection"`
}

// NativeArgument declares one argument. In YAML it is either the bare type
// ("Int!") or a mapping {type, description}.
type NativeArgument struct {
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
}

// UnmarshalYAML accepts a bare type or the mapping form.
func (a *NativeArgument) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var t string
		if err := node.Decode(&t); err != nil {
			return err
		}
		*a = NativeArgument{Type: t}
		return nil
	}
	type raw NativeArgument
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*a = NativeArgument(r)
	return nil
}

// NativeColumn configures one result column. In YAML it is either the bare
// type ("BigInt!") or a mapping {type, name, description, deprecated}.
type NativeColumn struct {
	// Type overrides the introspected GraphQL scalar; a trailing ! makes
	// the field non-null (introspected columns are always nullable).
	Type        string `yaml:"type"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Deprecated  string `yaml:"deprecated"`
}

// UnmarshalYAML accepts a bare type or the mapping form.
func (c *NativeColumn) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var t string
		if err := node.Decode(&t); err != nil {
			return err
		}
		*c = NativeColumn{Type: t}
		return nil
	}
	type raw NativeColumn
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*c = NativeColumn(r)
	return nil
}

// NativeArgScalars are the GraphQL scalars a native query argument may have.
var NativeArgScalars = []string{"String", "Int", "BigInt", "Float", "Boolean", "Decimal", "Date", "DateTime"}

// ParseScalarType splits a "Scalar" or "Scalar!" type into its name and
// whether it is non-null.
func ParseScalarType(t string) (name string, nonNull bool) {
	t = strings.TrimSpace(t)
	if strings.HasSuffix(t, "!") {
		return strings.TrimSpace(strings.TrimSuffix(t, "!")), true
	}
	return t, false
}

// NativeSQL is a compiled native query statement: the SQL text cut at every
// :name parameter. Render joins the pieces with "?" placeholders.
type NativeSQL struct {
	segments []string // len(segments) == len(Params) + 1
	// Params are the parameter names in order of appearance (a name used
	// twice appears twice: each use is its own placeholder).
	Params []string
}

// Render returns the SQL with a "?" per parameter and the bound values in
// placeholder order, taken from values by name.
func (n *NativeSQL) Render(values map[string]any) (string, []any) {
	var sb strings.Builder
	args := make([]any, 0, len(n.Params))
	for i, seg := range n.segments {
		sb.WriteString(seg)
		if i < len(n.Params) {
			sb.WriteString("?")
			args = append(args, values[n.Params[i]])
		}
	}
	return sb.String(), args
}

// ParamSet returns the distinct parameter names.
func (n *NativeSQL) ParamSet() map[string]bool {
	set := map[string]bool{}
	for _, p := range n.Params {
		set[p] = true
	}
	return set
}

// nativeDenied are keywords that never belong in a read-only query used as
// a derived table: data changes, locking reads, SELECT … INTO and DDL. A word
// right after "." is a qualified identifier, and INSERT( / REPLACE( are
// string functions, so those are not matched.
var nativeDenied = map[string]bool{
	"INSERT": true, "UPDATE": true, "DELETE": true, "REPLACE": true, "INTO": true,
	"LOCK": true, "CREATE": true, "DROP": true, "ALTER": true, "GRANT": true,
	"REVOKE": true, "CALL": true, "LOAD": true, "RENAME": true,
}

// nativeFuncs are denied words that are also SQL functions when followed by
// "(" (INSERT(str, pos, len, new), REPLACE(str, from, to)).
var nativeFuncs = map[string]bool{"INSERT": true, "REPLACE": true}

var nativeParamPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// CompileNativeSQL checks a native query statement and cuts it at its :name
// parameters. The statement must start with SELECT or WITH (after comments,
// whitespace and opening parentheses) and may not contain statement
// separators (one trailing ; is dropped), "?" placeholders, := assignments,
// claim references (:jwt.x; declare an argument and preset it per role
// instead) or the keywords of writes, locking reads, SELECT … INTO and DDL.
// Quoted strings, quoted identifiers and comments are skipped, so a ':' or
// '?' inside them is just text.
func CompileNativeSQL(src string) (*NativeSQL, error) {
	s := strings.TrimRightFunc(src, isSQLSpace)
	s = strings.TrimSuffix(s, ";")
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("sql is empty")
	}
	n := &NativeSQL{}
	var seg strings.Builder
	first := ""      // the first keyword
	prevWord := ""   // the previous keyword (FOR SHARE)
	prevDot := false // the previous significant character was "."
	for i := 0; i < len(s); {
		c := s[i]
		if first == "" && (c == '\'' || c == '"' || c == '`' || c == ':') {
			return nil, fmt.Errorf("only SELECT (or WITH … SELECT) statements are allowed")
		}
		switch {
		case c == '\'' || c == '"' || c == '`':
			end, err := skipQuoted(s, i)
			if err != nil {
				return nil, err
			}
			seg.WriteString(s[i:end])
			i, prevDot = end, false
			continue
		case c == '#' || (c == '-' && i+1 < len(s) && s[i+1] == '-' && (i+2 >= len(s) || isSQLSpace(rune(s[i+2])))):
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				end = len(s) - i
			}
			// A comment becomes a single space: the statement is wrapped in
			// parentheses, which a trailing line comment would swallow.
			seg.WriteString(" ")
			i += end
			continue
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("unterminated /* comment")
			}
			if i+2 < len(s) && s[i+2] == '!' {
				return nil, fmt.Errorf("executable comments (/*! … */) are not allowed")
			}
			seg.WriteString(" ")
			i += end + 4
			continue
		case c == ';':
			return nil, fmt.Errorf("only one statement is allowed (found ;)")
		case c == '?':
			return nil, fmt.Errorf("literal ? placeholders are not allowed; declare an argument and write :name")
		case c == ':':
			if i+1 < len(s) && s[i+1] == '=' {
				return nil, fmt.Errorf(":= assignments are not allowed")
			}
			j := i + 1
			for j < len(s) && isIdentByte(s[j]) {
				j++
			}
			name := s[i+1 : j]
			if !nativeParamPattern.MatchString(name) {
				return nil, fmt.Errorf("':' at offset %d is not followed by a parameter name (write :name)", i)
			}
			if j < len(s) && s[j] == '.' {
				return nil, fmt.Errorf(":%s.… is not allowed: claims are not referenced in the SQL; declare an argument and preset it per role (roles.<role>.native_queries.<query>.presets)", name)
			}
			n.segments = append(n.segments, seg.String())
			seg.Reset()
			n.Params = append(n.Params, name)
			i, prevDot = j, false
			continue
		case isIdentByte(c) && (c < '0' || c > '9'):
			j := i
			for j < len(s) && isIdentByte(s[j]) {
				j++
			}
			word := strings.ToUpper(s[i:j])
			if first == "" {
				first = word
				if word != "SELECT" && word != "WITH" {
					return nil, fmt.Errorf("only SELECT (or WITH … SELECT) statements are allowed, not %s", word)
				}
			}
			if !prevDot && (nativeDenied[word] || (word == "SHARE" && prevWord == "FOR")) {
				k := j
				for k < len(s) && isSQLSpace(rune(s[k])) {
					k++
				}
				if !(nativeFuncs[word] && k < len(s) && s[k] == '(') {
					return nil, fmt.Errorf("%s is not allowed in a native query (read-only SELECT statements only)", word)
				}
			}
			seg.WriteString(s[i:j])
			i, prevDot, prevWord = j, false, word
			continue
		case c == '(' && first == "":
			// leading parentheses: "(SELECT …)" is a SELECT
		case !isSQLSpace(rune(c)) && first == "":
			return nil, fmt.Errorf("only SELECT (or WITH … SELECT) statements are allowed")
		}
		if !isSQLSpace(rune(c)) {
			prevDot = c == '.'
		}
		seg.WriteByte(c)
		i++
	}
	if first == "" {
		return nil, fmt.Errorf("only SELECT (or WITH … SELECT) statements are allowed")
	}
	n.segments = append(n.segments, seg.String())
	return n, nil
}

// skipQuoted returns the index just past the quoted section starting at
// s[i] (a string literal or quoted identifier). Doubled quotes and, outside
// backticks, backslash escapes stay inside.
func skipQuoted(s string, i int) (int, error) {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		switch {
		case s[j] == '\\' && q != '`':
			j++
		case s[j] == q:
			if j+1 < len(s) && s[j+1] == q {
				j++
				continue
			}
			return j + 1, nil
		}
	}
	return 0, fmt.Errorf("unterminated string literal or quoted identifier")
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 0x80
}

func isSQLSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' || r == '\v'
}

// validateNativeQueries checks the native_queries section and every role's
// native_queries grants without the database. Whether the SQL runs, which
// columns it returns and whether key, columns and relationships fit them is
// checked against the database when the API is built.
func (c *Config) validateNativeQueries() error {
	names := make([]string, 0, len(c.NativeQueries))
	for n := range c.NativeQueries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		nq := c.NativeQueries[name]
		where := "native_queries." + name
		if !ValidGraphQLName(name) {
			return fmt.Errorf("%s: %q is not a valid GraphQL name", where, name)
		}
		if nq == nil {
			return fmt.Errorf("%s: empty native query (sql is required)", where)
		}
		compiled, err := CompileNativeSQL(nq.SQL)
		if err != nil {
			return fmt.Errorf("%s.sql: %w", where, err)
		}
		used := compiled.ParamSet()
		for p := range used {
			if nq.Arguments[p] == nil {
				return fmt.Errorf("%s.sql: parameter :%s is not declared under arguments", where, p)
			}
		}
		for an, a := range nq.Arguments {
			aw := where + ".arguments." + an
			if !ValidGraphQLName(an) || !nativeParamPattern.MatchString(an) {
				return fmt.Errorf("%s: %q is not a valid argument name", aw, an)
			}
			if an == "jwt" {
				return fmt.Errorf("%s: the name jwt is reserved", aw)
			}
			if a == nil || a.Type == "" {
				return fmt.Errorf("%s: type is required", aw)
			}
			if s, _ := ParseScalarType(a.Type); !containsString(NativeArgScalars, s) {
				return fmt.Errorf("%s: type %q is not supported (one of %s, with ! for required)", aw, a.Type, strings.Join(NativeArgScalars, ", "))
			}
			if !used[an] {
				return fmt.Errorf("%s: the argument is not used in the sql (reference it as :%s)", aw, an)
			}
		}
		for col, nc := range nq.Columns {
			cw := where + ".columns." + col
			if nc == nil {
				continue
			}
			if nc.Type != "" {
				if s, _ := ParseScalarType(nc.Type); !containsString(ColumnScalarNames, s) {
					return fmt.Errorf("%s: type %q is not a known scalar (one of %s, with ! for non-null)", cw, nc.Type, strings.Join(ColumnScalarNames, ", "))
				}
			}
			if nc.Name != "" && !ValidGraphQLName(nc.Name) {
				return fmt.Errorf("%s: %q is not a valid GraphQL name", cw, nc.Name)
			}
			if nc.Name == "_and" || nc.Name == "_or" || nc.Name == "_not" {
				return fmt.Errorf("%s: %q is not a usable column field name (it is a logical operator of the where filter)", cw, nc.Name)
			}
		}
		seen := map[string]bool{}
		for _, k := range nq.Key {
			if k == "" || seen[k] {
				return fmt.Errorf("%s.key: column %q is empty or listed twice", where, k)
			}
			seen[k] = true
		}
		if nq.TypeName != "" && !ValidGraphQLName(nq.TypeName) {
			return fmt.Errorf("%s.type_name %q is not a valid GraphQL name", where, nq.TypeName)
		}
		for kind, fc := range map[string]*FieldConfig{"list": nq.RootFields.List, "connection": nq.RootFields.Connection} {
			if fc == nil {
				continue
			}
			if fc.Name != "" && !ValidGraphQLName(fc.Name) {
				return fmt.Errorf("%s.root_fields.%s: %q is not a valid GraphQL name", where, kind, fc.Name)
			}
			if fc.JSONType != "" {
				return fmt.Errorf("%s.root_fields.%s: json_type applies to table columns only", where, kind)
			}
		}
		if nq.RootFields.Connection != nil && len(nq.Key) == 0 {
			return fmt.Errorf("%s.root_fields.connection: a connection needs key", where)
		}
		if err := validateRelationships(where, nq.Relationships, false); err != nil {
			return err
		}
	}

	for roleName, role := range c.Roles {
		if role == nil {
			continue
		}
		for qn, perm := range role.NativeQueries {
			where := fmt.Sprintf("role %q, native query %q", roleName, qn)
			nq := c.NativeQueries[qn]
			if nq == nil {
				return fmt.Errorf("%s: no such entry under native_queries", where)
			}
			if perm == nil {
				continue
			}
			if perm.Check != "" {
				return fmt.Errorf("%s: check applies to table writes only (use filter to restrict the rows)", where)
			}
			for a, v := range perm.Presets {
				if nq.Arguments[a] == nil {
					return fmt.Errorf("%s: preset %q is not a declared argument", where, a)
				}
				if path, ok := strings.CutPrefix(v, ":jwt."); ok && !claimPathSyntax.MatchString(path) {
					return fmt.Errorf("%s: preset %q has an invalid claim path %q", where, a, v)
				}
			}
			check := func(ops []string, key string) error {
				for _, o := range ops {
					if !OperatorNamePattern.MatchString(o) {
						return fmt.Errorf("%s, %s: %q is not an operator name (operators look like _eq, _ilike)", where, key, o)
					}
				}
				return nil
			}
			if perm.FilterOperators != nil {
				if err := check(*perm.FilterOperators, "filter_operators"); err != nil {
					return err
				}
			}
			if perm.FilterableColumns != nil {
				for col, ops := range perm.FilterableColumns.Ops {
					if err := check(ops, "filterable_columns."+col); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

var claimPathSyntax = regexp.MustCompile(`^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$`)
