package schema

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/graphql-go/graphql"

	"gqlgate/config"
	"gqlgate/introspect"
	"gqlgate/rbac"
)

// This file holds the `where` surface: the comparison operators (built-in and
// YAML-declared custom ones), the per-role operator/column allow-lists, and
// relationship filters compiled to correlated EXISTS subqueries.

// maxRelFilterDepth caps how deeply relationship filters may nest inside one
// `where` (each level is one correlated subquery).
const maxRelFilterDepth = 8

// likeEscapeChar escapes LIKE wildcards in the literal-match operators
// (_contains, _starts_with, ...). '!' rather than '\' so the meaning does not
// depend on the NO_BACKSLASH_ESCAPES sql_mode.
const likeEscapeChar = "!"

// stringOps are the String-only operators, in schema order.
var stringOps = []string{
	"_like", "_nlike", "_ilike", "_nilike",
	"_regex", "_nregex", "_iregex", "_niregex",
	"_contains", "_icontains", "_starts_with", "_istarts_with", "_ends_with", "_iends_with",
}

// builtinOpNames is every built-in operator name across all scalars; custom
// operators may not reuse them.
var builtinOpNames = func() map[string]bool {
	m := map[string]bool{}
	for _, s := range []string{"String", "JSON", "Boolean", "Int"} {
		for _, op := range builtinOps(s) {
			m[op] = true
		}
	}
	return m
}()

// builtinOps lists the built-in operators of one scalar, in schema order.
func builtinOps(scalar string) []string {
	ops := []string{"_eq", "_neq", "_is_null"}
	switch scalar {
	case "JSON":
		// TiDB JSON predicates: _contains (JSON_CONTAINS) and _has_key
		// (JSON_CONTAINS_PATH on a top-level key).
		ops = append(ops, "_contains", "_has_key")
	case "Boolean":
		// equality only
	default:
		ops = append(ops, "_gt", "_gte", "_lt", "_lte", "_in", "_nin")
		if scalar == "String" {
			ops = append(ops, stringOps...)
		}
	}
	return ops
}

// scalarsByName resolves the scalar names custom operators may reference.
var scalarsByName = map[string]*graphql.Scalar{
	"String": graphql.String, "Int": graphql.Int, "Float": graphql.Float, "Boolean": graphql.Boolean,
	"BigInt": bigIntScalar, "Decimal": decimalScalar, "DateTime": dateTimeScalar, "Date": dateScalar,
	"JSON": jsonScalar, "Bytes": bytesScalar, "Vector": vectorScalar,
}

// customOp is one compiled schema_gen.custom_operators entry.
type customOp struct {
	name      string
	arg       *graphql.Scalar
	appliesTo map[string]bool
	// parts alternate literal SQL and placeholders: placeholder entries are
	// exactly "{column}" or "{value}".
	parts []string
}

// compileCustomOps validates and compiles the configured custom operators.
func compileCustomOps(ops []config.CustomOperator) (map[string]*customOp, []string, error) {
	out := map[string]*customOp{}
	var order []string
	for _, op := range ops {
		if builtinOpNames[op.Name] {
			return nil, nil, fmt.Errorf("custom operator %q collides with a built-in operator", op.Name)
		}
		if err := config.ValidateOperatorTemplate(op.SQL); err != nil {
			return nil, nil, fmt.Errorf("custom operator %q: %w", op.Name, err)
		}
		arg, ok := scalarsByName[op.Argument]
		if !ok {
			return nil, nil, fmt.Errorf("custom operator %q: unknown argument scalar %q", op.Name, op.Argument)
		}
		co := &customOp{name: op.Name, arg: arg, appliesTo: map[string]bool{}}
		applies := op.AppliesTo
		if len(applies) == 0 {
			applies = []string{op.Argument}
		}
		for _, s := range applies {
			co.appliesTo[s] = true
		}
		co.parts = splitTemplate(op.SQL)
		out[op.Name] = co
		order = append(order, op.Name)
	}
	return out, order, nil
}

// splitTemplate cuts a validated template into literal and placeholder parts.
func splitTemplate(tmpl string) []string {
	var parts []string
	rest := tmpl
	for {
		i := strings.IndexByte(rest, '{')
		if i < 0 {
			parts = append(parts, rest)
			return parts
		}
		// Validated templates only have {column}/{value} outside quotes, but
		// braces may legitimately appear inside string literals; only cut on
		// the two placeholder spellings.
		switch {
		case strings.HasPrefix(rest[i:], "{column}"):
			parts = append(parts, rest[:i], "{column}")
			rest = rest[i+len("{column}"):]
		case strings.HasPrefix(rest[i:], "{value}"):
			parts = append(parts, rest[:i], "{value}")
			rest = rest[i+len("{value}"):]
		default:
			parts = append(parts, rest[:i+1])
			rest = rest[i+1:]
		}
	}
}

// render produces the operator's SQL for one column reference, binding the
// argument once per {value}.
func (co *customOp) render(colRef string, arg any) *condition {
	var sb strings.Builder
	var args []any
	for _, p := range co.parts {
		switch p {
		case "{column}":
			sb.WriteString(colRef)
		case "{value}":
			sb.WriteString("?")
			args = append(args, arg)
		default:
			sb.WriteString(p)
		}
	}
	return &condition{sql: "(" + sb.String() + ")", args: args}
}

// validateCustomOps dry-runs every custom operator against the database so a
// template with a typo'd function or bad syntax fails at startup, not on the
// first request.
func validateCustomOps(db *sql.DB, ops map[string]*customOp, order []string, timeout time.Duration) error {
	for _, name := range order {
		co := ops[name]
		c := co.render("`__gqlgate_v`.`c`", nil)
		q := "SELECT 1 FROM (SELECT NULL AS c) AS `__gqlgate_v` WHERE " + c.sql + " LIMIT 0"
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		rows, err := db.QueryContext(ctx, q, c.args...)
		if err == nil {
			err = rows.Close()
		}
		cancel()
		if err != nil {
			return fmt.Errorf("custom operator %q: sql does not run on the database: %w", name, err)
		}
	}
	return nil
}

// opsForScalar lists every operator (built-in, then custom in config order)
// available for a column scalar.
func (b *builder) opsForScalar(scalar string) []string {
	ops := builtinOps(scalar)
	for _, name := range b.shared.customOrder {
		if b.shared.customOps[name].appliesTo[scalar] {
			ops = append(ops, name)
		}
	}
	return ops
}

// knownOp reports whether name is any built-in or configured custom operator.
func (b *builder) knownOp(name string) bool {
	if builtinOpNames[name] {
		return true
	}
	_, ok := b.shared.customOps[name]
	return ok
}

// resolveFilterOps computes, for one select-able table, the operator set of
// every filterable column, validating the YAML allow-lists. A column absent
// from the result cannot be filtered on.
func (b *builder) resolveFilterOps(ti *tableInfo) error {
	sel := ti.access.Select
	ti.filterOps = map[string][]string{}
	ti.filterOpSet = map[string]map[string]bool{}
	for _, op := range sel.FilterOperators {
		if !b.knownOp(op) {
			return fmt.Errorf("table %q, select.filter_operators: unknown operator %q", ti.table.Name, op)
		}
	}
	for col, ops := range sel.FilterColumns {
		for _, op := range ops {
			if !b.knownOp(op) {
				return fmt.Errorf("table %q, select.filterable_columns.%s: unknown operator %q", ti.table.Name, col, op)
			}
		}
	}
	for _, col := range sel.Columns {
		if !sel.Filterable(col.Name) {
			continue
		}
		all := b.opsForScalar(scalarFor(col).Name())
		allowed := all
		if list := sel.FilterColumns[col.Name]; list != nil {
			if sel.Explicit {
				for _, op := range list {
					if !containsOp(all, op) {
						return fmt.Errorf("table %q, select.filterable_columns.%s: operator %q does not apply to %s columns", ti.table.Name, col.Name, op, scalarFor(col).Name())
					}
				}
			}
			allowed = intersectOps(allowed, list)
		}
		if sel.FilterOperators != nil {
			allowed = intersectOps(allowed, sel.FilterOperators)
		}
		if len(allowed) == 0 {
			continue
		}
		ti.filterOps[col.Name] = allowed
		set := make(map[string]bool, len(allowed))
		for _, op := range allowed {
			set[op] = true
		}
		ti.filterOpSet[col.Name] = set
	}
	return nil
}

func containsOp(list []string, op string) bool {
	for _, o := range list {
		if o == op {
			return true
		}
	}
	return false
}

// intersectOps keeps the entries of base (in base order) that appear in keep.
func intersectOps(base, keep []string) []string {
	var out []string
	for _, op := range base {
		if containsOp(keep, op) {
			out = append(out, op)
		}
	}
	return out
}

// cmpExpFor returns the comparison input type for one filterable column: the
// shared <Scalar>_comparison_exp when every operator of the scalar is allowed
// (the shape existing clients rely on), otherwise a column-specific
// <table>_<column>_comparison_exp carrying just the allowed operators.
func (b *builder) cmpExpFor(ti *tableInfo, col *introspect.Column) (*graphql.InputObject, error) {
	s := scalarFor(col)
	allowed := ti.filterOps[col.Name]
	all := b.opsForScalar(s.Name())
	name := s.Name() + "_comparison_exp"
	if len(allowed) != len(all) {
		name = ti.typeName + "_" + ti.colToField[col.Name] + "_comparison_exp"
		owner := ti.table.Name + "." + col.Name
		if other, taken := b.shared.reservedTypes[name]; taken {
			return nil, fmt.Errorf("restricted comparison type %q for %s collides with %s; adjust filterable_columns", name, owner, other)
		}
		if other, taken := b.cmpOwners[name]; taken && other != owner {
			return nil, fmt.Errorf("restricted comparison types for %s and %s are both named %q; adjust filterable_columns", other, owner, name)
		}
		b.cmpOwners[name] = owner
	}
	if e, ok := b.cmpExps[name]; ok {
		return e, nil
	}
	f := graphql.InputObjectConfigFieldMap{}
	for _, op := range allowed {
		f[op] = &graphql.InputObjectFieldConfig{Type: b.opInputType(s, op), Description: opDescriptions[op]}
	}
	e := graphql.NewInputObject(graphql.InputObjectConfig{Name: name, Fields: f})
	b.cmpExps[name] = e
	return e, nil
}

// opInputType is the argument type of one operator on scalar s.
func (b *builder) opInputType(s *graphql.Scalar, op string) graphql.Input {
	switch op {
	case "_is_null":
		return graphql.Boolean
	case "_in", "_nin":
		return graphql.NewList(graphql.NewNonNull(s))
	case "_has_key":
		return graphql.String
	}
	if co, ok := b.shared.customOps[op]; ok {
		return co.arg
	}
	return s
}

var opDescriptions = map[string]string{
	"_ilike":        "Case-insensitive LIKE pattern (% and _ are wildcards).",
	"_nilike":       "Case-insensitive NOT LIKE pattern.",
	"_iregex":       "Case-insensitive regular expression match.",
	"_niregex":      "Case-insensitive regular expression non-match.",
	"_contains":     "Contains the literal substring (case-sensitive; % and _ are not wildcards). On JSON columns: JSON_CONTAINS.",
	"_icontains":    "Contains the literal substring, ignoring case.",
	"_starts_with":  "Starts with the literal prefix (case-sensitive).",
	"_istarts_with": "Starts with the literal prefix, ignoring case.",
	"_ends_with":    "Ends with the literal suffix (case-sensitive).",
	"_iends_with":   "Ends with the literal suffix, ignoring case.",
}

// --- relationships ---------------------------------------------------------

// relInfo is one relationship of a table as seen by a role: an object
// relationship (this row -> at most one target row) or an array relationship
// (target rows matching this row). It comes from a foreign key (either
// direction) or from a declaration under tables.<t>.relationships.
type relInfo struct {
	name string
	// key identifies the relationship for request-scoped loaders: the FK's
	// table and constraint name (fkKey: a constraint name is unique per
	// table only, so two tables may each have an fk_x pointing at different
	// tables), or "\x00cfg:<table>.<name>" for a declared one (a table name
	// is never empty, so the two never collide).
	key string
	// aggKey identifies its <rel>_aggregate loader.
	aggKey     string
	fk         *introspect.ForeignKey // nil for a declared relationship
	outgoing   bool                   // object relationship
	target     *tableInfo
	localCols  []string // join columns on this table
	targetCols []string // join columns on the target table
	// unenforced: a declared object relationship onto a logical key.
	unenforced              bool
	description, deprecated string
	// filterable: offered in this table's <t>_bool_exp.
	filterable bool
	// aggName is the <rel>_aggregate field of an array relationship.
	aggName string
}

// relations returns the role-visible relationships of a select-able table,
// in the order (and with the names) their object-type fields get: outgoing
// FKs first, then incoming ones, then the declared relationships (by name).
// FK relationships keep their generated names (deconflicted against the
// readable columns and each other) unless the config names them; a name the
// config gives that another relationship of the role already has is an error
// (recorded in ti.relErr).
func (b *builder) relations(ti *tableInfo) []*relInfo {
	// fkKey identifies a foreign key across the schema: its table plus its
	// constraint name.
	fkKey := func(fk *introspect.ForeignKey) string { return fk.Table + "\x00" + fk.ConstraintName }
	if ti.relsDone {
		return ti.rels
	}
	ti.relsDone = true
	sel := ti.access.Select
	taken := map[string]bool{}
	for _, col := range sel.Columns {
		taken[ti.colToField[col.Name]] = true
	}
	readable := func(cols []string) bool {
		for _, c := range cols {
			if !sel.ColumnSet[c] {
				return false
			}
		}
		return true
	}
	var nameCols [][]string // per relationship: the columns a name suffix uses

	// Outgoing: this table's FK -> one row of the referenced table. The
	// parent row map only holds readable columns, and the join needs the
	// local FK values — so those must be readable for this role.
	for _, fk := range ti.table.ForeignKeys {
		target := b.tinfos[fk.RefTable]
		if target == nil || target.access.Select == nil || !readable(fk.Columns) {
			continue
		}
		candidate := graphqlName(fk.RefTable)
		if len(fk.Columns) == 1 && strings.HasSuffix(fk.Columns[0], "_id") && len(fk.Columns[0]) > 3 {
			candidate = graphqlName(strings.TrimSuffix(fk.Columns[0], "_id"))
		}
		name := relFieldName(taken, candidate, fk.Columns)
		taken[name] = true
		ti.rels = append(ti.rels, &relInfo{name: name, key: fkKey(fk), aggKey: fkKey(fk),
			fk: fk, outgoing: true, target: target, localCols: fk.Columns, targetCols: fk.RefColumns,
			description: fmt.Sprintf("Row of %s referenced by %s", fk.RefTable, strings.Join(fk.Columns, ", "))})
		nameCols = append(nameCols, fk.Columns)
	}
	// Incoming: FKs on other tables pointing here -> list of child rows.
	for _, fk := range ti.table.IncomingFKs {
		child := b.tinfos[fk.Table]
		if child == nil || child.access.Select == nil || !readable(fk.RefColumns) {
			continue
		}
		name := relFieldName(taken, graphqlName(fk.Table), fk.Columns)
		taken[name] = true
		ti.rels = append(ti.rels, &relInfo{name: name, key: fkKey(fk), aggKey: fkKey(fk),
			fk: fk, outgoing: false, target: child, localCols: fk.RefColumns, targetCols: fk.Columns,
			description: fmt.Sprintf("Rows of %s whose %s reference this row", fk.Table, strings.Join(fk.Columns, ", "))})
		nameCols = append(nameCols, fk.Columns)
	}
	// Names from the config: FK relationships it names, then declared ones.
	final := map[string]string{} // relationship name -> what owns it
	var explicit []*relInfo
	for _, r := range ti.rels {
		if n := ti.model.fkName(r.fk, r.outgoing); n != nil {
			r.name = n.name
			if n.description != "" {
				r.description = n.description
			}
			r.deprecated = n.deprecated
			explicit = append(explicit, r)
		}
	}
	for _, d := range ti.model.declared {
		target := b.tinfos[d.target]
		if target == nil || target.access.Select == nil || !readable(d.localCols) {
			continue
		}
		desc := d.description
		if desc == "" {
			if d.object {
				desc = fmt.Sprintf("Row of %s whose %s match this row's %s", d.target, strings.Join(d.targetCols, ", "), strings.Join(d.localCols, ", "))
			} else {
				desc = fmt.Sprintf("Rows of %s whose %s match this row's %s", d.target, strings.Join(d.targetCols, ", "), strings.Join(d.localCols, ", "))
			}
		}
		key := "\x00cfg:" + ti.table.Name + "." + d.name
		if ti.native { // a native query may share a table's name
			key = "\x00native:" + ti.table.Name + "." + d.name
		}
		r := &relInfo{name: d.name, key: key, aggKey: key, outgoing: d.object, target: target,
			localCols: d.localCols, targetCols: d.targetCols, unenforced: d.unenforced,
			description: desc, deprecated: d.deprecated}
		ti.rels = append(ti.rels, r)
		nameCols = append(nameCols, d.localCols)
		explicit = append(explicit, r)
	}
	isExplicit := map[*relInfo]bool{}
	for _, r := range explicit {
		isExplicit[r] = true
	}
	for _, r := range ti.rels {
		if !isExplicit[r] {
			final[r.name] = "the foreign-key relationship " + r.fk.ConstraintName
		}
	}
	for _, r := range explicit {
		if other, dup := final[r.name]; dup {
			ti.relErr = fmt.Errorf("table %q: relationship name %q from tables.%s.relationships is already used by %s for role %q; choose another name (or name that relationship with foreign_key:)",
				ti.table.Name, r.name, ti.table.Name, other, b.role)
			return ti.rels
		}
		final[r.name] = "tables." + ti.table.Name + ".relationships." + r.name
		taken[r.name] = true
	}
	// Array relationships also get <rel>_aggregate. Those names are assigned
	// only after every relationship is named, so adding them never renames an
	// existing relationship field; they are deconflicted against the columns,
	// the relationships and each other.
	for _, r := range ti.rels {
		taken[r.name] = true
	}
	for i, r := range ti.rels {
		if r.outgoing {
			continue
		}
		r.aggName = relFieldName(taken, r.name+"_aggregate", nameCols[i])
		taken[r.aggName] = true
	}
	return ti.rels
}

// resolveFilterRels decides which relationships appear in the table's
// bool_exp: the role must be able to select the target, the relationship must
// pass select.filter_relationships, every local join column must be
// filterable with _eq (a relationship filter is an equality filter on them:
// `author: {id: {_eq: 2}}` is `author_id = 2`), and the target's select row
// filter must have been verified to resolve against its own table (see
// validateRoleFilter) so it cannot bind to the outer query's columns.
func (b *builder) resolveFilterRels(ti *tableInfo) error {
	rels := b.relations(ti)
	sel := ti.access.Select
	var allow map[string]bool
	if sel.FilterRelationships != nil {
		allow = map[string]bool{}
		names := map[string]bool{}
		for _, r := range rels {
			names[r.name] = true
		}
		for _, n := range sel.FilterRelationships {
			if !names[n] {
				if sel.Explicit {
					return fmt.Errorf("table %q, select.filter_relationships: %q is not a relationship of %s visible to this role", ti.table.Name, n, ti.table.Name)
				}
				continue
			}
			allow[n] = true
		}
	}
	ti.filterRels = map[string]*relInfo{}
	for _, r := range rels {
		if allow != nil && !allow[r.name] {
			continue
		}
		if r.name == "_and" || r.name == "_or" || r.name == "_not" {
			continue
		}
		if col, ok := b.joinColsFilterable(ti, r); !ok {
			// Naming the relationship explicitly while hiding its join
			// column is a contradiction worth failing on; under the default
			// (every relationship) it is just withheld.
			if allow != nil && sel.Explicit {
				return fmt.Errorf("table %q, select.filter_relationships: %q filters on join column %q, which is not filterable with _eq for this role (add it to filterable_columns, or drop the relationship)", ti.table.Name, r.name, col)
			}
			continue
		}
		if r.target.access.Select.Filter != nil && !r.target.selectFilterOK {
			continue
		}
		r.filterable = true
		ti.filterRels[r.name] = r
	}
	return nil
}

// joinColsFilterable reports whether every local join column of r may be
// compared with _eq by the role; otherwise it returns the first one that may
// not.
func (b *builder) joinColsFilterable(ti *tableInfo, r *relInfo) (string, bool) {
	for _, c := range r.localCols {
		if !ti.filterOpSet[c]["_eq"] {
			return c, false
		}
	}
	return "", true
}

// filterRejectCodes are the MySQL/TiDB error numbers that mean "this filter
// SQL is wrong" (it does not parse, names something that does not exist, or
// may not be used here) rather than "the database is unhappy right now".
var filterRejectCodes = map[uint16]bool{
	1052: true, // ambiguous column
	1054: true, // unknown column
	1064: true, // syntax error
	1109: true, // unknown table in clause
	1111: true, // invalid use of group function
	1142: true, // command denied on table
	1143: true, // command denied on column
	1146: true, // table does not exist
	1241: true, // operand should contain N columns
	1247: true, // reference not supported
	1248: true, // derived table needs an alias
	1305: true, // function does not exist
	1582: true, // wrong parameter count (native function)
	1583: true, // wrong parameters (stored function)
	1630: true, // function does not exist (did you mean)
}

// validateRoleFilter dry-runs a select row filter against its own table
// alone. Relationship filters embed the target's row filter inside a
// correlated subquery, where an identifier that does not exist on the target
// would silently resolve against the OUTER table instead of failing. Running
// the filter in a statement with no outer scope proves every identifier binds
// to the filter's own table (or to subqueries inside it).
//
// It reports false (relationship filters into the table are withheld) when
// the database rejects the filter itself. Any other failure — a timeout, a
// dropped connection, a lock wait — is returned as an error so the build (and
// with it a hot reload) fails and the previous schema keeps serving, instead
// of silently publishing a schema with fields missing.
func (b *builder) validateRoleFilter(ti *tableInfo) (bool, error) {
	f := ti.access.Select.Filter
	if f == nil {
		return true, nil
	}
	if b.shared.db == nil {
		return false, nil // cannot verify: fail closed
	}
	key := ti.table.Name + "\x00" + f.ValidationSQL()
	if err, done := b.shared.filterChecks[key]; done {
		return err == nil, nil
	}
	q := "SELECT 1 FROM " + b.qualifiedTable(ti.table) + " WHERE (" + f.ValidationSQL() + ") LIMIT 0"
	ctx, cancel := context.WithTimeout(context.Background(), b.shared.timeout)
	defer cancel()
	rows, err := b.shared.db.QueryContext(ctx, q)
	if err == nil {
		err = rows.Close()
	}
	if err != nil && !filterRejected(err) {
		return false, fmt.Errorf("table %q: verifying the select filter: %w", ti.table.Name, err)
	}
	b.shared.filterChecks[key] = err
	if err != nil && b.opt.Logger != nil {
		b.opt.Logger.Warn("select filter does not resolve against its own table; relationship filters into it are disabled",
			"role", b.role, "table", ti.table.Name, "err", err)
	}
	return err == nil, nil
}

// filterRejected reports whether err is the database rejecting the SQL
// itself (see filterRejectCodes).
func filterRejected(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && filterRejectCodes[me.Number]
}

// --- WHERE compilation -----------------------------------------------------

// whereCtx is the state of one `where` compilation: the caller's identity
// (for target-table row filters) and the subquery alias counter.
type whereCtx struct {
	id *rbac.Identity
	n  int
}

// whereSQL translates a GraphQL bool_exp value into SQL for the root table of
// a statement, which is always referenced as an unaliased `schema`.`table`.
// Column names come from the schema-validated input type and are re-checked
// against the role's read/filter permissions; all values are bound as
// parameters.
func (b *builder) whereSQL(ti *tableInfo, expr map[string]any, id *rbac.Identity) (*condition, error) {
	wc := &whereCtx{id: id}
	return b.compileWhere(wc, ti, expr, "", b.qualifiedTable(ti.table), 0)
}

// compileWhere compiles one bool_exp level. qual prefixes this level's column
// references ("" at the root, "`alias`." inside relationship subqueries) and
// self is how nested subqueries refer back to this level's row.
func (b *builder) compileWhere(wc *whereCtx, ti *tableInfo, expr map[string]any, qual, self string, depth int) (*condition, error) {
	var parts []string
	var args []any
	for _, key := range sortedKeys(expr) {
		val := expr[key]
		if val == nil {
			continue
		}
		switch key {
		case "_and", "_or":
			items, ok := val.([]any)
			if !ok {
				return nil, fmt.Errorf("%s must be a list", key)
			}
			var sub []string
			for _, item := range items {
				m, ok := item.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("%s entries must be objects", key)
				}
				c, err := b.compileWhere(wc, ti, m, qual, self, depth)
				if err != nil {
					return nil, err
				}
				sub = append(sub, "("+c.sql+")")
				args = append(args, c.args...)
			}
			if len(sub) == 0 {
				continue
			}
			joiner := " AND "
			if key == "_or" {
				joiner = " OR "
			}
			parts = append(parts, "("+strings.Join(sub, joiner)+")")
		case "_not":
			m, ok := val.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("_not must be an object")
			}
			c, err := b.compileWhere(wc, ti, m, qual, self, depth)
			if err != nil {
				return nil, err
			}
			parts = append(parts, "NOT ("+c.sql+")")
			args = append(args, c.args...)
		default:
			if rel, ok := ti.filterRels[key]; ok {
				c, err := b.relationshipCond(wc, rel, val, self, depth)
				if err != nil {
					return nil, err
				}
				parts = append(parts, c.sql)
				args = append(args, c.args...)
				continue
			}
			col, ok := ti.fieldToCol[key]
			// Re-check read and filter visibility here: the input types
			// already hide such columns, but values arriving through
			// variables must not be able to probe hidden columns either.
			if !ok || ti.access.Select == nil || !ti.access.Select.ColumnSet[col.Name] || ti.filterOpSet[col.Name] == nil {
				return nil, fmt.Errorf("unknown filter column %q", key)
			}
			opMap, ok := val.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("filter on %q must be an object of operators", key)
			}
			colRef := qual + quoteIdent(col.Name)
			for _, op := range sortedKeys(opMap) {
				if !ti.filterOpSet[col.Name][op] {
					return nil, fmt.Errorf("operator %q is not allowed on %q", op, key)
				}
				c, err := b.columnCond(col, colRef, op, opMap[op])
				if err != nil {
					return nil, err
				}
				if c == nil {
					continue
				}
				parts = append(parts, c.sql)
				args = append(args, c.args...)
			}
		}
	}
	if len(parts) == 0 {
		return &condition{sql: "1=1"}, nil
	}
	return &condition{sql: strings.Join(parts, " AND "), args: args}, nil
}

// relationshipCond compiles a relationship predicate into a correlated
// EXISTS: "some related row matches" for array relationships, "the related
// row matches" for object relationships. An empty predicate means "has a
// related row"; wrapped in _not it means "has none". The TARGET table's select
// row filter for the role is applied inside the subquery (so hidden rows can
// never be matched), and every level gets its own alias, which keeps
// self-referential relationships unambiguous.
func (b *builder) relationshipCond(wc *whereCtx, rel *relInfo, val any, self string, depth int) (*condition, error) {
	m, ok := val.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("filter on relationship %q must be an object", rel.name)
	}
	if depth >= maxRelFilterDepth {
		return nil, fmt.Errorf("relationship filters nest deeper than %d levels", maxRelFilterDepth)
	}
	target := rel.target
	sel := target.access.Select
	if sel == nil || !rel.filterable {
		return nil, fmt.Errorf("unknown filter field %q", rel.name)
	}
	if sel.Filter != nil && !target.selectFilterOK {
		return nil, fmt.Errorf("relationship %q cannot be filtered on: the select filter of %q was not verified", rel.name, target.table.Name)
	}

	wc.n++
	alias := quoteIdent(fmt.Sprintf("__gqlgate_r%d", wc.n))
	tbl := b.qualifiedTable(target.table)
	from := tbl + " AS " + alias
	var args []any
	if sel.Filter != nil {
		var claims map[string]any
		if wc.id != nil {
			claims = wc.id.Claims
		}
		fsql, fargs, err := sel.Filter.SQL(claims)
		if err != nil {
			return nil, err
		}
		// The row filter is written against the bare table; a derived
		// table keeps it scoped there (table-qualified references in the
		// filter keep working) while the outer level sees only the alias.
		from = "(SELECT * FROM " + tbl + " WHERE " + fsql + ") AS " + alias
		args = append(args, fargs...)
	}
	joins := make([]string, len(rel.targetCols))
	for i := range rel.targetCols {
		joins[i] = alias + "." + quoteIdent(rel.targetCols[i]) + " = " + self + "." + quoteIdent(rel.localCols[i])
	}
	inner, err := b.compileWhere(wc, target, m, alias+".", alias, depth+1)
	if err != nil {
		return nil, err
	}
	args = append(args, inner.args...)
	sqlStr := "EXISTS (SELECT 1 FROM " + from + " WHERE " + strings.Join(joins, " AND ")
	if inner.sql != "1=1" {
		sqlStr += " AND (" + inner.sql + ")"
	}
	return &condition{sql: sqlStr + ")", args: args}, nil
}

var binaryOps = map[string]string{
	"_eq": "= ?", "_neq": "<> ?",
	"_gt": "> ?", "_gte": ">= ?",
	"_lt": "< ?", "_lte": "<= ?",
	"_like": "LIKE ?", "_nlike": "NOT LIKE ?",
	"_regex": "REGEXP ?", "_nregex": "NOT REGEXP ?",
}

// columnCond renders one operator on one column reference.
func (b *builder) columnCond(col *introspect.Column, qc, op string, val any) (*condition, error) {
	if co, ok := b.shared.customOps[op]; ok {
		if val == nil {
			return nil, fmt.Errorf("%s.%s: null is not a valid argument", col.Name, op)
		}
		arg, err := bindArg(co.arg.Name(), val)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", col.Name, op, err)
		}
		return co.render(qc, arg), nil
	}
	isString := scalarFor(col).Name() == "String"
	if isString {
		if c, handled, err := stringCond(col, qc, op, val, b.shared.ciCollations); handled {
			return c, err
		}
	}
	if tmpl, ok := binaryOps[op]; ok {
		if val == nil {
			return nil, fmt.Errorf("%s.%s: null is not a valid comparison value, use _is_null", col.Name, op)
		}
		bound, err := bindValue(col, val)
		if err != nil {
			return nil, err
		}
		return &condition{sql: qc + " " + tmpl, args: []any{bound}}, nil
	}
	switch op {
	case "_in", "_nin":
		items, ok := val.([]any)
		if !ok {
			return nil, fmt.Errorf("%s.%s expects a list", col.Name, op)
		}
		if len(items) == 0 {
			if op == "_in" {
				return &condition{sql: "1=0"}, nil // IN () matches nothing
			}
			return &condition{sql: "1=1"}, nil // NOT IN () matches everything
		}
		placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(items)), ", ")
		args := make([]any, 0, len(items))
		for _, item := range items {
			bound, err := bindValue(col, item)
			if err != nil {
				return nil, err
			}
			args = append(args, bound)
		}
		kw := "IN"
		if op == "_nin" {
			kw = "NOT IN"
		}
		return &condition{sql: fmt.Sprintf("%s %s (%s)", qc, kw, placeholders), args: args}, nil
	case "_is_null":
		isNull, ok := val.(bool)
		if !ok {
			return nil, fmt.Errorf("%s._is_null expects a boolean", col.Name)
		}
		if isNull {
			return &condition{sql: qc + " IS NULL"}, nil
		}
		return &condition{sql: qc + " IS NOT NULL"}, nil
	case "_contains":
		if scalarFor(col).Name() != "JSON" {
			break
		}
		// TiDB JSON_CONTAINS(col, candidate): does the JSON doc contain the value?
		bound, err := bindValue(col, val)
		if err != nil {
			return nil, err
		}
		return &condition{sql: "JSON_CONTAINS(" + qc + ", ?)", args: []any{bound}}, nil
	case "_has_key":
		if scalarFor(col).Name() != "JSON" {
			break
		}
		// TiDB JSON_CONTAINS_PATH(col, 'one', '$.<key>'): top-level key present?
		key, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("%s._has_key expects a string", col.Name)
		}
		return &condition{sql: "JSON_CONTAINS_PATH(" + qc + ", 'one', CONCAT('$.', ?))", args: []any{key}}, nil
	}
	return nil, fmt.Errorf("unsupported operator %q on column %q", op, col.Name)
}

// stringCond renders the String-only text operators. handled is false for
// operators it does not own (they fall through to the generic ones).
//
// Case handling: TiDB's LIKE/REGEXP follow the column collation, so
//   - the i-variants use a plain LIKE on *_ci columns (index-friendly) and
//     LOWER(col) LIKE LOWER(?) otherwise;
//   - the case-sensitive literal operators (_contains/_starts_with/
//     _ends_with) force the charset's _bin collation on *_ci columns.
//     _starts_with additionally keeps a plain `col LIKE ?` on the same
//     pattern, which the _bin match implies, so TiDB can still use the
//     column's (ci) index for a range scan.
//
// ciCollations is false on clusters bootstrapped without the new collation
// framework, where every *_ci collation compares as binary; every column is
// then treated as case-sensitive.
//
// The literal operators escape % and _ (and the escape char) in the client
// value and build the pattern in Go, binding `LIKE ?` so _starts_with stays an
// index range scan.
func stringCond(col *introspect.Column, qc, op string, val any, ciCollations bool) (*condition, bool, error) {
	var (
		pattern  string
		ci       bool // case-insensitive
		negate   bool
		escaped  bool
		isRegexp bool
	)
	switch op {
	case "_ilike", "_nilike":
		ci, negate = true, op == "_nilike"
	case "_iregex", "_niregex":
		isRegexp, negate = true, op == "_niregex"
	case "_contains", "_icontains", "_starts_with", "_istarts_with", "_ends_with", "_iends_with":
		escaped, ci = true, strings.HasPrefix(op, "_i")
	default:
		return nil, false, nil
	}
	if val == nil {
		return nil, true, fmt.Errorf("%s.%s: null is not a valid comparison value, use _is_null", col.Name, op)
	}
	s, ok := val.(string)
	if !ok {
		return nil, true, fmt.Errorf("%s.%s expects a string", col.Name, op)
	}
	not := ""
	if negate {
		not = "NOT "
	}
	if isRegexp {
		return &condition{sql: not + "REGEXP_LIKE(" + qc + ", ?, 'i')", args: []any{s}}, true, nil
	}
	pattern = s
	escapeClause := ""
	if escaped {
		lit := likeEscape(s)
		switch strings.TrimPrefix(strings.TrimPrefix(op, "_i"), "_") {
		case "contains":
			pattern = "%" + lit + "%"
		case "starts_with":
			pattern = lit + "%"
		case "ends_with":
			pattern = "%" + lit
		}
		escapeClause = " ESCAPE '" + likeEscapeChar + "'"
	}
	colIsCI := ciCollations && strings.HasSuffix(col.Collation, "_ci")
	switch {
	case ci && colIsCI:
		return &condition{sql: qc + " " + not + "LIKE ?" + escapeClause, args: []any{pattern}}, true, nil
	case ci:
		return &condition{sql: "LOWER(" + qc + ") " + not + "LIKE LOWER(?)" + escapeClause, args: []any{pattern}}, true, nil
	case colIsCI && col.Charset != "" && collationNamePattern(col.Charset):
		bin := qc + " COLLATE " + col.Charset + "_bin " + not + "LIKE ?" + escapeClause
		if op == "_starts_with" {
			return &condition{sql: "(" + qc + " LIKE ?" + escapeClause + " AND " + bin + ")", args: []any{pattern, pattern}}, true, nil
		}
		return &condition{sql: bin, args: []any{pattern}}, true, nil
	default:
		return &condition{sql: qc + " " + not + "LIKE ?" + escapeClause, args: []any{pattern}}, true, nil
	}
}

// collationNamePattern guards the charset name spliced into a COLLATE clause
// (it comes from information_schema, but is checked to be a bare identifier).
func collationNamePattern(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// likeEscape makes s match literally inside a LIKE pattern that uses
// ESCAPE '!'.
func likeEscape(s string) string {
	r := strings.NewReplacer(likeEscapeChar, likeEscapeChar+likeEscapeChar, "%", likeEscapeChar+"%", "_", likeEscapeChar+"_")
	return r.Replace(s)
}

// bindArg normalizes a coerced custom-operator argument for the driver.
func bindArg(scalar string, v any) (any, error) {
	if scalar == "JSON" {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("cannot encode JSON argument: %w", err)
		}
		return string(raw), nil
	}
	return v, nil
}
