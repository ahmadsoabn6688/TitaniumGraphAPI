package config

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Per-table modeling: the top-level `tables:` section shapes how one table
// (or view) appears in the GraphQL API, independent of any role:
//
//	tables:
//	  post_stats:                       # a view
//	    primary_key: [post_id]          # logical key: cursors + _by_pk
//	    type_name: PostStats
//	    description: "Per-post comment statistics."
//	    root_fields:
//	      connection: postStatsPage     # shorthand: just the name
//	      by_pk: {name: postStats, description: "...", deprecated: "use posts.stats"}
//	    columns:
//	      comment_count: commentCount   # shorthand: just the name
//	      last_comment_at: {description: "Newest comment", deprecated: "unused"}
//	    relationships:
//	      post:                         # declared (no FK in the database)
//	        type: object
//	        target: posts
//	        mapping: {post_id: id}
//	  posts:
//	    relationships:
//	      writer:                       # renames the FK relationship of fk_posts_author
//	        foreign_key: fk_posts_author
//
// Names given here are GraphQL names; every other part of the config (roles,
// presets, filters, mappings) keeps using the SQL table and column names.

// TableConfig is one entry of the top-level tables: section.
type TableConfig struct {
	// PrimaryKey declares a logical key for a table or view that has no
	// primary key. It is used for <t>_connection cursors and <t>_by_pk and
	// lets object relationships target the table; it is NOT enforced by the
	// database (it must really identify one row).
	PrimaryKey []string `yaml:"primary_key"`
	// TypeName renames the object type and every type derived from it
	// (<type>_bool_exp, <type>_connection, <type>_aggregate_result, ...).
	TypeName string `yaml:"type_name"`
	// Description replaces the object type's description.
	Description string `yaml:"description"`
	// RootFields renames / documents / deprecates the root fields.
	RootFields RootFields `yaml:"root_fields"`
	// Columns renames / documents / deprecates column fields, keyed by the
	// SQL column name.
	Columns map[string]*FieldConfig `yaml:"columns"`
	// Relationships declares relationships without a foreign key, or names
	// (documents, deprecates) a foreign-key relationship, keyed by the
	// GraphQL field name.
	Relationships map[string]*RelationshipConfig `yaml:"relationships"`
	// Subscriptions overrides the polling interval of the table's
	// subscription fields (see SubscriptionPolling).
	Subscriptions *SubscriptionPolling `yaml:"subscriptions"`
}

// RootFields configures the per-table root fields. Each entry is either a
// bare name or {name, description, deprecated}.
type RootFields struct {
	ByPK       *FieldConfig `yaml:"by_pk"`
	Connection *FieldConfig `yaml:"connection"`
	Aggregate  *FieldConfig `yaml:"aggregate"`
	List       *FieldConfig `yaml:"list"`
	Insert     *FieldConfig `yaml:"insert"`
	InsertOne  *FieldConfig `yaml:"insert_one"`
	Update     *FieldConfig `yaml:"update"`
	UpdateByPK *FieldConfig `yaml:"update_by_pk"`
	Delete     *FieldConfig `yaml:"delete"`
	DeleteByPK *FieldConfig `yaml:"delete_by_pk"`
}

// RootField kinds, as named under root_fields.
const (
	RootByPK       = "by_pk"
	RootConnection = "connection"
	RootAggregate  = "aggregate"
	RootList       = "list"
	RootInsert     = "insert"
	RootInsertOne  = "insert_one"
	RootUpdate     = "update"
	RootUpdateByPK = "update_by_pk"
	RootDelete     = "delete"
	RootDeleteByPK = "delete_by_pk"
)

// RootFieldKinds lists every root field kind in schema order.
var RootFieldKinds = []string{
	RootByPK, RootConnection, RootAggregate, RootList,
	RootInsert, RootInsertOne, RootUpdate, RootUpdateByPK, RootDelete, RootDeleteByPK,
}

// ByKind returns the configured entry of one root field kind (nil = defaults).
func (r *RootFields) ByKind(kind string) *FieldConfig {
	switch kind {
	case RootByPK:
		return r.ByPK
	case RootConnection:
		return r.Connection
	case RootAggregate:
		return r.Aggregate
	case RootList:
		return r.List
	case RootInsert:
		return r.Insert
	case RootInsertOne:
		return r.InsertOne
	case RootUpdate:
		return r.Update
	case RootUpdateByPK:
		return r.UpdateByPK
	case RootDelete:
		return r.Delete
	case RootDeleteByPK:
		return r.DeleteByPK
	}
	return nil
}

// FieldConfig renames, documents or deprecates one generated field. In YAML
// it is either a bare name or a mapping:
//
//	title: headline
//	title: {name: headline, description: "Shown in lists", deprecated: "use subject"}
type FieldConfig struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// Deprecated, when set, marks the field @deprecated with this reason.
	Deprecated string `yaml:"deprecated"`
	// JSONType gives a JSON column a declared shape from json_types
	// ("Profile", or "[Address]" for an array of objects). Columns only.
	JSONType string `yaml:"json_type"`
}

// UnmarshalYAML accepts a bare name or the mapping form.
func (f *FieldConfig) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var name string
		if err := node.Decode(&name); err != nil {
			return err
		}
		*f = FieldConfig{Name: name}
		return nil
	}
	type raw FieldConfig
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*f = FieldConfig(r)
	return nil
}

// Relationship types.
const (
	RelObject = "object"
	RelArray  = "array"
)

// RelationshipConfig is one entry of tables.<t>.relationships. Either it
// declares a relationship by column mapping (target + mapping + type), or it
// refers to a foreign-key relationship (foreign_key, plus type for a
// self-referencing key) to rename, document or deprecate it.
type RelationshipConfig struct {
	// Type is object (at most one target row; the target columns must be its
	// primary key, a unique key or its declared primary_key) or array.
	Type string `yaml:"type"`
	// Target is the related table or view.
	Target string `yaml:"target"`
	// Mapping maps this table's columns to the target's columns.
	Mapping map[string]string `yaml:"mapping"`
	// ForeignKey names the foreign-key constraint whose relationship this
	// entry names: "fk_name", or "child_table.fk_name" when ambiguous.
	ForeignKey  string `yaml:"foreign_key"`
	Description string `yaml:"description"`
	Deprecated  string `yaml:"deprecated"`
}

// MappingColumns returns the mapping as parallel column lists, ordered by
// the source column name (the caller re-orders by table position).
func (r *RelationshipConfig) MappingColumns() (local, target []string) {
	for k := range r.Mapping {
		local = append(local, k)
	}
	sort.Strings(local)
	for _, k := range local {
		target = append(target, r.Mapping[k])
	}
	return local, target
}

// GraphQLNamePattern is a valid GraphQL name.
var GraphQLNamePattern = regexp.MustCompile(`^[_A-Za-z][_0-9A-Za-z]*$`)

// ValidGraphQLName reports whether s is a GraphQL name usable for a
// generated type or field (the "__" prefix is reserved for introspection).
func ValidGraphQLName(s string) bool {
	return GraphQLNamePattern.MatchString(s) && !strings.HasPrefix(s, "__")
}

// validateTables checks the tables: section without the database: names are
// valid GraphQL names and every relationship entry is well-formed. Whether
// the tables, columns and constraints exist is checked against the
// introspected schema when the API is built.
func (c *Config) validateTables() error {
	names := make([]string, 0, len(c.Tables))
	for n := range c.Tables {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, tn := range names {
		tc := c.Tables[tn]
		if tc == nil {
			continue
		}
		where := "tables." + tn
		if tc.TypeName != "" && !ValidGraphQLName(tc.TypeName) {
			return fmt.Errorf("%s.type_name %q is not a valid GraphQL name", where, tc.TypeName)
		}
		seen := map[string]bool{}
		for _, k := range tc.PrimaryKey {
			if k == "" || seen[k] {
				return fmt.Errorf("%s.primary_key: column %q is empty or listed twice", where, k)
			}
			seen[k] = true
		}
		for _, kind := range RootFieldKinds {
			if fc := tc.RootFields.ByKind(kind); fc != nil && fc.Name != "" && !ValidGraphQLName(fc.Name) {
				return fmt.Errorf("%s.root_fields.%s: %q is not a valid GraphQL name", where, kind, fc.Name)
			}
			if fc := tc.RootFields.ByKind(kind); fc != nil && fc.JSONType != "" {
				return fmt.Errorf("%s.root_fields.%s: json_type applies to columns only", where, kind)
			}
		}
		for col, fc := range tc.Columns {
			if fc != nil && fc.Name != "" && !ValidGraphQLName(fc.Name) {
				return fmt.Errorf("%s.columns.%s: %q is not a valid GraphQL name", where, col, fc.Name)
			}
			// The logical operators of <t>_bool_exp share the column fields'
			// namespace.
			if fc != nil && (fc.Name == "_and" || fc.Name == "_or" || fc.Name == "_not") {
				return fmt.Errorf("%s.columns.%s: %q is not a usable column field name (it is a logical operator of the where filter)", where, col, fc.Name)
			}
		}
		if err := validateRelationships(where, tc.Relationships, true); err != nil {
			return err
		}
	}
	return nil
}

// validateRelationships checks the relationship entries under where (a
// tables.<t> or native_queries.<q> path). allowFK: entries may name a
// foreign-key relationship instead of declaring one.
func validateRelationships(where string, rels map[string]*RelationshipConfig, allowFK bool) error {
	for rn, rc := range rels {
		rw := where + ".relationships." + rn
		if !ValidGraphQLName(rn) || rn == "_and" || rn == "_or" || rn == "_not" {
			return fmt.Errorf("%s: %q is not a usable relationship field name", rw, rn)
		}
		if rc == nil {
			return fmt.Errorf("%s: empty relationship", rw)
		}
		if rc.Type != "" && rc.Type != RelObject && rc.Type != RelArray {
			return fmt.Errorf("%s.type %q must be object or array", rw, rc.Type)
		}
		if rc.ForeignKey != "" {
			if !allowFK {
				return fmt.Errorf("%s: foreign_key does not apply here (a native query has no foreign keys); declare target, mapping and type", rw)
			}
			if rc.Target != "" || len(rc.Mapping) > 0 {
				return fmt.Errorf("%s: foreign_key names an existing foreign-key relationship; it cannot also have target or mapping", rw)
			}
			continue
		}
		if rc.Target == "" || len(rc.Mapping) == 0 {
			if !allowFK {
				return fmt.Errorf("%s: a declared relationship needs target and mapping", rw)
			}
			return fmt.Errorf("%s: a declared relationship needs target and mapping (or foreign_key to name a foreign-key relationship)", rw)
		}
		if rc.Type == "" {
			return fmt.Errorf("%s: type is required (object or array)", rw)
		}
		targets := map[string]bool{}
		for l, t := range rc.Mapping {
			if l == "" || t == "" {
				return fmt.Errorf("%s.mapping: empty column name", rw)
			}
			if targets[t] {
				return fmt.Errorf("%s.mapping: target column %q is mapped twice", rw, t)
			}
			targets[t] = true
		}
	}
	return nil
}

// NamedTables returns every table name the config refers to explicitly: the
// schema_gen.tables include list, the role rules (not "*"), the tables:
// entries and their relationship targets, and the relationship targets of
// native queries. Views are introspected only when
// named here, so a config that never mentions a view sees the same catalog
// (and the same GraphQL names) as before views were supported.
func (c *Config) NamedTables() []string {
	set := map[string]bool{}
	for _, t := range c.SchemaGen.Tables.Include {
		set[t] = true
	}
	for _, role := range c.Roles {
		if role == nil {
			continue
		}
		for t := range role.Tables {
			if t != "*" {
				set[t] = true
			}
		}
	}
	for t, tc := range c.Tables {
		set[t] = true
		if tc == nil {
			continue
		}
		for _, rc := range tc.Relationships {
			if rc != nil && rc.Target != "" {
				set[rc.Target] = true
			}
		}
	}
	for _, nq := range c.NativeQueries {
		if nq == nil {
			continue
		}
		for _, rc := range nq.Relationships {
			if rc != nil && rc.Target != "" {
				set[rc.Target] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
