package schema

import (
	"fmt"
	"sort"
	"strings"

	"gqlgate/config"
	"gqlgate/introspect"
)

// The model is the role-independent GraphQL shape of the catalog: the names
// of every table's types, fields and root fields (defaults, or the overrides
// of the config's tables: section), descriptions and deprecations, the key
// reads page and look rows up by (the primary key, or a declared logical
// key), and the relationships declared in the config. It is built once per
// BuildAll — so again on every hot reload, against the freshly introspected
// catalog — and validated there: a tables: entry naming a missing table,
// column or constraint fails the build.

// tableModel is the shape of one table or view.
type tableModel struct {
	table *introspect.Table
	// typeName is the object type's name and the stem of every derived type
	// (<type>_bool_exp, <type>_connection, ...).
	typeName string
	// fieldBase is the stem of the default root field names (<base>_by_pk,
	// insert_<base>, ...) and of the unique-key and vector fields.
	fieldBase   string
	description string // config description ("" = generated)

	colField      map[string]string // column -> GraphQL field name
	colDoc        map[string]string // column -> config description
	colDeprecated map[string]string // column -> deprecation reason

	roots map[string]rootSpec // root field kind -> name/description/deprecation
	// listExplicit: root_fields.list names the list field, so its name is
	// claimed like any fixed name (a default list name yields on collision).
	listExplicit bool

	// readKey identifies one row for reads: the primary key, else the
	// declared primary_key. Empty = none (no connection or by_pk).
	readKey []string
	// logicalKey: readKey is declared in the config, not enforced by the
	// database.
	logicalKey bool

	declared []*declaredRel // relationships by column mapping, by name
	fkNames  []*fkRelName   // names for foreign-key relationships
}

// rootSpec is the configured shape of one root field.
type rootSpec struct {
	name, description, deprecated string
}

// declaredRel is a relationship declared under tables.<t>.relationships by
// column mapping (no foreign key in the database).
type declaredRel struct {
	name       string
	object     bool // object (to-one) rather than array (to-many)
	target     string
	localCols  []string // on the declaring table, in its column order
	targetCols []string // matching target columns
	// unenforced: an object relationship whose target columns are only a
	// declared (logical) key, so the database does not guarantee one row.
	unenforced              bool
	description, deprecated string
}

// fkRelName gives a foreign-key relationship of a table its name (and
// optionally a description / deprecation).
type fkRelName struct {
	fk                      *introspect.ForeignKey
	outgoing                bool // the object side (the FK is on this table)
	name                    string
	description, deprecated string
}

// catalogModel is the model of every exposed table.
type catalogModel struct {
	tables map[string]*tableModel
	// related marks the tables taking part in any relationship (as source
	// or target, by foreign key or declaration); their select filters are
	// verified for use inside relationship filters.
	related map[string]bool
	// commentDocs: schema_gen.descriptions_from_comments.
	commentDocs bool
}

// defaultRootName is the generated name of a root field kind.
func defaultRootName(kind, base string) string {
	switch kind {
	case config.RootByPK:
		return base + "_by_pk"
	case config.RootConnection:
		return base + "_connection"
	case config.RootAggregate:
		return base + "_aggregate"
	case config.RootList:
		return base + "_list"
	case config.RootInsert:
		return "insert_" + base
	case config.RootInsertOne:
		return "insert_" + base + "_one"
	case config.RootUpdate:
		return "update_" + base
	case config.RootUpdateByPK:
		return "update_" + base + "_by_pk"
	case config.RootDelete:
		return "delete_" + base
	case config.RootDeleteByPK:
		return "delete_" + base + "_by_pk"
	}
	return ""
}

// mutationRootKinds are the root field kinds a view never has.
var mutationRootKinds = map[string]bool{
	config.RootInsert: true, config.RootInsertOne: true, config.RootUpdate: true,
	config.RootUpdateByPK: true, config.RootDelete: true, config.RootDeleteByPK: true,
}

// buildModel derives and validates the model of cat under cfg (nil = every
// default).
func buildModel(cat *introspect.Catalog, cfg *config.Config) (*catalogModel, error) {
	m := &catalogModel{tables: map[string]*tableModel{}, related: map[string]bool{}}
	var tcfg map[string]*config.TableConfig
	if cfg != nil {
		tcfg = cfg.Tables
		m.commentDocs = cfg.SchemaGen.DescriptionsFromComments
	}
	for _, tn := range cat.TableOrder {
		t := cat.Tables[tn]
		tm := &tableModel{
			table:         t,
			typeName:      graphqlName(tn),
			fieldBase:     graphqlName(tn),
			colField:      map[string]string{},
			colDoc:        map[string]string{},
			colDeprecated: map[string]string{},
			roots:         map[string]rootSpec{},
			readKey:       t.PrimaryKey,
		}
		for _, c := range t.Columns {
			tm.colField[c.Name] = graphqlName(c.Name)
		}
		for _, kind := range config.RootFieldKinds {
			tm.roots[kind] = rootSpec{name: defaultRootName(kind, tm.fieldBase)}
		}
		m.tables[tn] = tm
		if len(t.ForeignKeys) > 0 || len(t.IncomingFKs) > 0 {
			m.related[tn] = true
		}
	}

	names := make([]string, 0, len(tcfg))
	for tn := range tcfg {
		names = append(names, tn)
	}
	sort.Strings(names)
	// Pass 1: names, docs and keys (object relationships may target any
	// table's declared key, so keys come first).
	for _, tn := range names {
		tc := tcfg[tn]
		if tc == nil {
			continue
		}
		tm := m.tables[tn]
		if tm == nil {
			return nil, fmt.Errorf("tables.%s: %q is not among the exposed tables/views of schema %q", tn, tn, cat.SchemaName)
		}
		if err := tm.applyConfig(tc); err != nil {
			return nil, fmt.Errorf("tables.%s%w", tn, err)
		}
	}
	// Pass 2: relationships.
	for _, tn := range names {
		tc := tcfg[tn]
		if tc == nil || len(tc.Relationships) == 0 {
			continue
		}
		if err := m.applyRelationships(tn, tc); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// applyConfig applies one table's names, docs and logical key. Errors start
// with the key path below tables.<t> (".columns.x: ...").
func (tm *tableModel) applyConfig(tc *config.TableConfig) error {
	t := tm.table
	if tc.TypeName != "" {
		tm.typeName = tc.TypeName
	}
	tm.description = tc.Description
	for col, fc := range tc.Columns {
		if !t.HasColumn(col) {
			return fmt.Errorf(".columns: %q has no column %q", t.Name, col)
		}
		if fc == nil {
			continue
		}
		if fc.Name != "" {
			tm.colField[col] = fc.Name
		}
		tm.colDoc[col] = fc.Description
		tm.colDeprecated[col] = fc.Deprecated
	}
	for _, kind := range config.RootFieldKinds {
		fc := tc.RootFields.ByKind(kind)
		if fc == nil {
			continue
		}
		if t.IsView && mutationRootKinds[kind] {
			return fmt.Errorf(".root_fields.%s: %q is a view, which has no mutations", kind, t.Name)
		}
		spec := tm.roots[kind]
		if fc.Name != "" {
			spec.name = fc.Name
			if kind == config.RootList {
				tm.listExplicit = true
			}
		}
		spec.description, spec.deprecated = fc.Description, fc.Deprecated
		tm.roots[kind] = spec
	}
	if len(tc.PrimaryKey) > 0 {
		if len(t.PrimaryKey) > 0 {
			return fmt.Errorf(".primary_key: table %q already has a primary key (%s); primary_key is for views and tables without one",
				t.Name, strings.Join(t.PrimaryKey, ", "))
		}
		for _, k := range tc.PrimaryKey {
			c := t.ColumnMap[k]
			if c == nil {
				return fmt.Errorf(".primary_key: %q has no column %q", t.Name, k)
			}
			if !keyableColumn(c) {
				return fmt.Errorf(".primary_key: column %q (%s) cannot be a key column", k, c.ColumnType)
			}
		}
		tm.readKey = append([]string{}, tc.PrimaryKey...)
		tm.logicalKey = true
	}
	return nil
}

// keyableColumn reports whether a column can be part of a key: compared by
// plain equality and order (cursors seek on it). JSON, VECTOR and the large
// object types can't.
func keyableColumn(c *introspect.Column) bool {
	switch c.DataType {
	case "json", "vector", "tinyblob", "blob", "mediumblob", "longblob",
		"tinytext", "text", "mediumtext", "longtext":
		return false
	}
	return true
}

// joinCompatible reports whether a declared relationship may join column a
// to column b: both must be keyable and map to the same GraphQL scalar (or
// both to an integer one), so equal values also batch to the same key; a
// DECIMAL pair must have the same declared type (equal values of different
// scales would not match after conversion).
func joinCompatible(a, b *introspect.Column) bool {
	if !keyableColumn(a) || !keyableColumn(b) {
		return false
	}
	sa, sb := scalarFor(a).Name(), scalarFor(b).Name()
	if sa == "Decimal" || sb == "Decimal" {
		return sa == sb && a.ColumnType == b.ColumnType
	}
	if sa == sb {
		return true
	}
	isInt := func(s string) bool { return s == "Int" || s == "BigInt" }
	return isInt(sa) && isInt(sb)
}

// sameColumnSet reports whether a and b hold the same column names.
func sameColumnSet(a, b []string) bool {
	return len(a) > 0 && len(a) == len(b) && colSetKey(a) == colSetKey(b)
}

func colSetKey(cols []string) string {
	s := append([]string{}, cols...)
	sort.Strings(s)
	return strings.Join(s, "\x00")
}

// applyRelationships validates and records the relationships of one table.
func (m *catalogModel) applyRelationships(tn string, tc *config.TableConfig) error {
	tm := m.tables[tn]
	t := tm.table
	fieldOwner := map[string]string{}
	for col, f := range tm.colField {
		fieldOwner[f] = col
	}
	rnames := make([]string, 0, len(tc.Relationships))
	for rn := range tc.Relationships {
		rnames = append(rnames, rn)
	}
	sort.Strings(rnames)
	type fkSide struct {
		fk       *introspect.ForeignKey
		outgoing bool
	}
	named := map[fkSide]string{}
	for _, rn := range rnames {
		rc := tc.Relationships[rn]
		where := "tables." + tn + ".relationships." + rn
		if col, taken := fieldOwner[rn]; taken {
			return fmt.Errorf("%s: the name is already the field of column %q", where, col)
		}
		if rc.ForeignKey != "" {
			var found []fkSide
			match := func(fk *introspect.ForeignKey) bool {
				return rc.ForeignKey == fk.ConstraintName || rc.ForeignKey == fk.Table+"."+fk.ConstraintName
			}
			if rc.Type != config.RelArray {
				for _, fk := range t.ForeignKeys {
					if match(fk) {
						found = append(found, fkSide{fk, true})
					}
				}
			}
			if rc.Type != config.RelObject {
				for _, fk := range t.IncomingFKs {
					if match(fk) {
						found = append(found, fkSide{fk, false})
					}
				}
			}
			switch {
			case len(found) == 0:
				return fmt.Errorf("%s: %q has no foreign-key relationship %q (between exposed tables)", where, tn, rc.ForeignKey)
			case len(found) > 1:
				return fmt.Errorf("%s: foreign_key %q is ambiguous here (a self-referencing key, or several tables use the name); set type: object|array or write it as <child_table>.<constraint>", where, rc.ForeignKey)
			}
			if other, dup := named[found[0]]; dup {
				return fmt.Errorf("%s: foreign key %q is already named %q", where, rc.ForeignKey, other)
			}
			named[found[0]] = rn
			tm.fkNames = append(tm.fkNames, &fkRelName{fk: found[0].fk, outgoing: found[0].outgoing,
				name: rn, description: rc.Description, deprecated: rc.Deprecated})
			continue
		}

		target := m.tables[rc.Target]
		if target == nil {
			return fmt.Errorf("%s: target %q is not among the exposed tables/views", where, rc.Target)
		}
		local, remote := rc.MappingColumns()
		// Order the pairs by the declaring table's column order (stable
		// loader keys and SQL).
		idx := make([]int, len(local))
		for i := range idx {
			idx[i] = i
		}
		for _, c := range local {
			if !t.HasColumn(c) {
				return fmt.Errorf("%s.mapping: %q has no column %q", where, tn, c)
			}
		}
		for _, c := range remote {
			if !target.table.HasColumn(c) {
				return fmt.Errorf("%s.mapping: target %q has no column %q", where, rc.Target, c)
			}
		}
		sort.SliceStable(idx, func(i, j int) bool {
			return t.ColumnMap[local[idx[i]]].Ordinal < t.ColumnMap[local[idx[j]]].Ordinal
		})
		dr := &declaredRel{name: rn, object: rc.Type == config.RelObject, target: rc.Target,
			description: rc.Description, deprecated: rc.Deprecated}
		for _, i := range idx {
			lc, rcol := t.ColumnMap[local[i]], target.table.ColumnMap[remote[i]]
			if !joinCompatible(lc, rcol) {
				return fmt.Errorf("%s.mapping: %s.%s (%s) and %s.%s (%s) are not join-compatible types",
					where, tn, lc.Name, lc.ColumnType, rc.Target, rcol.Name, rcol.ColumnType)
			}
			dr.localCols = append(dr.localCols, lc.Name)
			dr.targetCols = append(dr.targetCols, rcol.Name)
		}
		if dr.object {
			unique := sameColumnSet(dr.targetCols, target.table.PrimaryKey)
			for _, uk := range target.table.UniqueKeys {
				unique = unique || sameColumnSet(dr.targetCols, uk.Columns)
			}
			if !unique && target.logicalKey && sameColumnSet(dr.targetCols, target.readKey) {
				unique, dr.unenforced = true, true
			}
			if !unique {
				return fmt.Errorf("%s: an object relationship must map onto the target's primary key, a unique key or its declared primary_key; (%s) is none of them on %q (use type: array)",
					where, strings.Join(dr.targetCols, ", "), rc.Target)
			}
		}
		tm.declared = append(tm.declared, dr)
		m.related[tn] = true
		m.related[rc.Target] = true
	}
	return nil
}

// fkName returns the configured name of a foreign-key relationship of the
// table, or nil.
func (tm *tableModel) fkName(fk *introspect.ForeignKey, outgoing bool) *fkRelName {
	if tm == nil {
		return nil
	}
	for _, n := range tm.fkNames {
		if n.fk == fk && n.outgoing == outgoing {
			return n
		}
	}
	return nil
}

// tableDescription is the object type's description: the config's, else (if
// enabled) the table comment, else the generated text.
func (m *catalogModel) tableDescription(tm *tableModel, schemaName string) string {
	if tm.description != "" {
		return tm.description
	}
	if m.commentDocs && tm.table.Comment != "" {
		return tm.table.Comment
	}
	kind := "table"
	if tm.table.IsView {
		kind = "view"
	}
	return fmt.Sprintf("Row of %s %s.%s", kind, schemaName, tm.table.Name)
}

// columnDescription is a column field's description, chosen like
// tableDescription.
func (m *catalogModel) columnDescription(tm *tableModel, c *introspect.Column) string {
	if d := tm.colDoc[c.Name]; d != "" {
		return d
	}
	if m.commentDocs && c.Comment != "" {
		return c.Comment
	}
	return fmt.Sprintf("Column %s (%s)", c.Name, c.ColumnType)
}
