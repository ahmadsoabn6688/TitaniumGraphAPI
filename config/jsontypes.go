package config

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Typed JSON columns: the top-level `json_types:` section declares named
// object shapes, and a JSON column opts in to one under tables:
//
//	json_types:
//	  UserMetadata:
//	    description: "Profile data kept as JSON."
//	    fields:
//	      tier: String                     # shorthand: just the type
//	      tags: "[String]"                 # a list
//	      address: Address                 # another declared type
//	      zip: {type: String, key: "zip-code", description: "Postal code"}
//	  Address:
//	    fields:
//	      city: String
//	      lines: "[String]"
//	tables:
//	  users:
//	    columns:
//	      metadata: {json_type: UserMetadata}  # or "[Address]" for an array of objects
//
// A field type is one of the scalars String, Int, Float, Boolean or JSON (an
// opaque sub-document), the name of another declared type, or a list of
// either in brackets ("[Address]", "[[Int]]"). Every declared field is
// nullable: the database does not enforce the shape, so a missing key reads
// as null and a value of the wrong type reads as null with an error.

// JSONType is one entry of json_types.
type JSONType struct {
	Description string `yaml:"description"`
	// Fields maps GraphQL field names to their declaration.
	Fields map[string]*JSONField `yaml:"fields"`
}

// JSONField is one field of a declared JSON type. In YAML it is either the
// bare type or a mapping {type, key, description, deprecated}.
type JSONField struct {
	// Type is a scalar, a declared json_types name, or a [list] of either.
	Type string `yaml:"type"`
	// Key is the JSON object key the field reads (default: the field name);
	// use it for keys that are not valid GraphQL names.
	Key         string `yaml:"key"`
	Description string `yaml:"description"`
	Deprecated  string `yaml:"deprecated"`
}

// UnmarshalYAML accepts a bare type or the mapping form.
func (f *JSONField) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var t string
		if err := node.Decode(&t); err != nil {
			return err
		}
		*f = JSONField{Type: t}
		return nil
	}
	type raw JSONField
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*f = JSONField(r)
	return nil
}

// JSONScalars are the scalar types a JSON field may declare.
var JSONScalars = map[string]bool{"String": true, "Int": true, "Float": true, "Boolean": true, "JSON": true}

// JSONTypeRef is a parsed json type expression: Lists levels of [ ] around
// a scalar or declared type name.
type JSONTypeRef struct {
	Name  string
	Lists int
}

// maxJSONListDepth bounds nested list brackets in a type expression.
const maxJSONListDepth = 4

// ParseJSONTypeRef parses "Name", "[Name]", "[[Name]]", ... Spaces are not
// allowed and non-null markers (!) are rejected: every JSON field is
// nullable.
func ParseJSONTypeRef(expr string) (JSONTypeRef, error) {
	var ref JSONTypeRef
	s := expr
	for strings.HasPrefix(s, "[") {
		if !strings.HasSuffix(s, "]") {
			return ref, fmt.Errorf("type %q: unbalanced brackets", expr)
		}
		s = s[1 : len(s)-1]
		ref.Lists++
	}
	if strings.ContainsAny(s, "!") {
		return ref, fmt.Errorf("type %q: non-null (!) is not supported; JSON fields are always nullable (the database does not enforce the shape)", expr)
	}
	if ref.Lists > maxJSONListDepth {
		return ref, fmt.Errorf("type %q: lists nest at most %d levels", expr, maxJSONListDepth)
	}
	if !ValidGraphQLName(s) {
		return ref, fmt.Errorf("type %q is not a type name or [list] of one", expr)
	}
	ref.Name = s
	return ref, nil
}

// validateJSONTypes checks the json_types section and every json_type a
// column refers to (whether the column exists and is JSON is checked
// against the database when the API is built).
func (c *Config) validateJSONTypes() error {
	names := make([]string, 0, len(c.JSONTypes))
	for n := range c.JSONTypes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		where := "json_types." + n
		if !ValidGraphQLName(n) {
			return fmt.Errorf("%s: %q is not a valid GraphQL type name", where, n)
		}
		if JSONScalars[n] {
			return fmt.Errorf("%s: %q is a built-in scalar name", where, n)
		}
		jt := c.JSONTypes[n]
		if jt == nil || len(jt.Fields) == 0 {
			return fmt.Errorf("%s: a JSON type needs at least one field", where)
		}
		keys := map[string]string{}
		for fn, f := range jt.Fields {
			fw := where + ".fields." + fn
			if !ValidGraphQLName(fn) {
				return fmt.Errorf("%s: %q is not a valid GraphQL field name", fw, fn)
			}
			if f == nil || f.Type == "" {
				return fmt.Errorf("%s: type is required", fw)
			}
			if err := c.checkJSONTypeRef(f.Type); err != nil {
				return fmt.Errorf("%s: %w", fw, err)
			}
			key := f.JSONKey(fn)
			if other, dup := keys[key]; dup {
				return fmt.Errorf("%s: fields %q and %q both read the JSON key %q", where, other, fn, key)
			}
			keys[key] = fn
		}
	}
	tables := make([]string, 0, len(c.Tables))
	for tn := range c.Tables {
		tables = append(tables, tn)
	}
	sort.Strings(tables)
	for _, tn := range tables {
		tc := c.Tables[tn]
		if tc == nil {
			continue
		}
		for col, fc := range tc.Columns {
			if fc == nil || fc.JSONType == "" {
				continue
			}
			if err := c.checkJSONTypeRef(fc.JSONType); err != nil {
				return fmt.Errorf("tables.%s.columns.%s.json_type: %w", tn, col, err)
			}
			if ref, _ := ParseJSONTypeRef(fc.JSONType); JSONScalars[ref.Name] {
				return fmt.Errorf("tables.%s.columns.%s.json_type: %q must be (a list of) a type declared under json_types", tn, col, fc.JSONType)
			}
		}
	}
	return nil
}

// checkJSONTypeRef parses expr and checks that it names a scalar or a
// declared JSON type.
func (c *Config) checkJSONTypeRef(expr string) error {
	ref, err := ParseJSONTypeRef(expr)
	if err != nil {
		return err
	}
	if JSONScalars[ref.Name] {
		return nil
	}
	if _, ok := c.JSONTypes[ref.Name]; !ok {
		return fmt.Errorf("type %q is neither a JSON scalar (String, Int, Float, Boolean, JSON) nor declared under json_types", ref.Name)
	}
	return nil
}

// JSONKey is the JSON object key the field named name reads.
func (f *JSONField) JSONKey(name string) string {
	if f.Key != "" {
		return f.Key
	}
	return name
}
