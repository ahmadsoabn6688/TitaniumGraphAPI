package schema

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"gqlgate/introspect"
	"gqlgate/rbac"
)

// quoteIdent backtick-quotes a SQL identifier.
func quoteIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

func (b *builder) qualifiedTable(t *introspect.Table) string {
	return quoteIdent(b.opt.Catalog.SchemaName) + "." + quoteIdent(t.Name)
}

// condition is a SQL fragment plus its bound arguments.
type condition struct {
	sql  string
	args []any
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// whereSQL translates a GraphQL bool_exp value into SQL. Column names come
// from the schema-validated input type, so only known fields can appear; all
// values are bound as parameters.
func (b *builder) whereSQL(ti *tableInfo, expr map[string]any) (*condition, error) {
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
				c, err := b.whereSQL(ti, m)
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
			c, err := b.whereSQL(ti, m)
			if err != nil {
				return nil, err
			}
			parts = append(parts, "NOT ("+c.sql+")")
			args = append(args, c.args...)
		default:
			col, ok := ti.fieldToCol[key]
			// Re-check read visibility here: the input types already hide
			// non-readable columns, but values arriving through variables
			// must not be able to probe hidden columns either.
			if !ok || ti.access.Select == nil || !ti.access.Select.ColumnSet[col.Name] {
				return nil, fmt.Errorf("unknown filter column %q", key)
			}
			opMap, ok := val.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("filter on %q must be an object of operators", key)
			}
			for _, op := range sortedKeys(opMap) {
				c, err := b.columnCond(col, op, opMap[op])
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

var binaryOps = map[string]string{
	"_eq": "= ?", "_neq": "<> ?",
	"_gt": "> ?", "_gte": ">= ?",
	"_lt": "< ?", "_lte": "<= ?",
	"_like": "LIKE ?", "_nlike": "NOT LIKE ?",
	"_regex": "REGEXP ?", "_nregex": "NOT REGEXP ?",
}

func (b *builder) columnCond(col *introspect.Column, op string, val any) (*condition, error) {
	qc := quoteIdent(col.Name)
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
		// TiDB JSON_CONTAINS(col, candidate): does the JSON doc contain the value?
		bound, err := bindValue(col, val)
		if err != nil {
			return nil, err
		}
		return &condition{sql: "JSON_CONTAINS(" + qc + ", ?)", args: []any{bound}}, nil
	case "_has_key":
		// TiDB JSON_CONTAINS_PATH(col, 'one', '$.<key>'): top-level key present?
		key, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("%s._has_key expects a string", col.Name)
		}
		return &condition{sql: "JSON_CONTAINS_PATH(" + qc + ", 'one', CONCAT('$.', ?))", args: []any{key}}, nil
	}
	return nil, fmt.Errorf("unsupported operator %q on column %q", op, col.Name)
}

// rbacCond renders an operation's row-level filter for the current identity.
func rbacCond(oa *rbac.OpAccess, id *rbac.Identity) (*condition, error) {
	if oa.Filter == nil {
		return nil, nil
	}
	sqlStr, args, err := oa.Filter.SQL(id.Claims)
	if err != nil {
		return nil, err
	}
	return &condition{sql: sqlStr, args: args}, nil
}

func combineConds(conds ...*condition) *condition {
	var parts []string
	var args []any
	for _, c := range conds {
		if c == nil || c.sql == "" {
			continue
		}
		parts = append(parts, "("+c.sql+")")
		args = append(args, c.args...)
	}
	if len(parts) == 0 {
		return &condition{sql: "1=1"}
	}
	return &condition{sql: strings.Join(parts, " AND "), args: args}
}

// orderColumns translates an order_by argument ([{field: asc|desc}, ...]) into
// the comma-separated column list for an ORDER BY (no keyword prefix). Within
// one object, keys are ordered by table ordinal (GraphQL input objects are
// unordered); use one object per column for explicit multi-key ordering.
func (b *builder) orderColumns(ti *tableInfo, orderBy []any) (string, error) {
	var parts []string
	for _, item := range orderBy {
		m, ok := item.(map[string]any)
		if !ok {
			return "", fmt.Errorf("order_by entries must be objects")
		}
		type kv struct {
			col *introspect.Column
			dir string
		}
		var pairs []kv
		for field, dirVal := range m {
			if dirVal == nil {
				continue
			}
			col, ok := ti.fieldToCol[field]
			if !ok || ti.access.Select == nil || !ti.access.Select.ColumnSet[col.Name] {
				return "", fmt.Errorf("unknown order_by column %q", field)
			}
			dir, ok := dirVal.(string)
			if !ok || (dir != "ASC" && dir != "DESC") {
				return "", fmt.Errorf("order_by.%s must be asc or desc", field)
			}
			pairs = append(pairs, kv{col, dir})
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].col.Ordinal < pairs[j].col.Ordinal })
		for _, p := range pairs {
			parts = append(parts, quoteIdent(p.col.Name)+" "+p.dir)
		}
	}
	return strings.Join(parts, ", "), nil
}

// orderSQL is orderColumns with the leading " ORDER BY " (empty when no keys).
func (b *builder) orderSQL(ti *tableInfo, orderBy []any) (string, error) {
	cols, err := b.orderColumns(ti, orderBy)
	if err != nil || cols == "" {
		return "", err
	}
	return " ORDER BY " + cols, nil
}

// windowOrder returns a deterministic ORDER BY column list for the ROW_NUMBER
// window: the requested order_by if any, otherwise the primary key, otherwise
// the join columns (so the window is always well-defined).
func (b *builder) windowOrder(ti *tableInfo, orderBy []any, joinCols []string) (string, error) {
	cols, err := b.orderColumns(ti, orderBy)
	if err != nil {
		return "", err
	}
	if cols != "" {
		return cols, nil
	}
	fallback := ti.table.PrimaryKey
	if len(fallback) == 0 {
		fallback = joinCols
	}
	quoted := make([]string, len(fallback))
	for i, c := range fallback {
		quoted[i] = quoteIdent(c)
	}
	return strings.Join(quoted, ", "), nil
}

// listArgs are the standard arguments of every list-returning field.
type listArgs struct {
	where   map[string]any
	orderBy []any
	limit   *int
	offset  *int
}

func extractListArgs(args map[string]any) (listArgs, error) {
	var la listArgs
	if w, ok := args["where"].(map[string]any); ok {
		la.where = w
	}
	if o, ok := args["order_by"].([]any); ok {
		la.orderBy = o
	}
	if l, ok := args["limit"].(int); ok {
		la.limit = &l
	}
	if o, ok := args["offset"].(int); ok {
		la.offset = &o
	}
	return la, nil
}

// pageBounds resolves the effective limit and offset for a list request,
// applying the default and clamping to the configured maximum.
func (b *builder) pageBounds(la listArgs) (limit, offset int, err error) {
	limit = b.opt.Config.SchemaGen.DefaultPageSize
	if la.limit != nil {
		limit = *la.limit
	}
	if limit < 0 {
		return 0, 0, fmt.Errorf("limit must be >= 0")
	}
	if limit > b.opt.Config.SchemaGen.MaxPageSize {
		limit = b.opt.Config.SchemaGen.MaxPageSize
	}
	if la.offset != nil {
		offset = *la.offset
	}
	if offset < 0 {
		return 0, 0, fmt.Errorf("offset must be >= 0")
	}
	return limit, offset, nil
}

func (b *builder) limitClause(la listArgs) (string, []any, error) {
	limit, offset, err := b.pageBounds(la)
	if err != nil {
		return "", nil, err
	}
	if offset > 0 {
		return " LIMIT ? OFFSET ?", []any{limit, offset}, nil
	}
	return " LIMIT ?", []any{limit}, nil
}

// applyPage slices an already-fetched, already-ordered group of rows to the
// request's limit/offset — the in-memory equivalent of limitClause, used by
// the batched to-many dataloader where one query serves all parent rows.
func (b *builder) applyPage(rows []map[string]any, la listArgs) ([]map[string]any, error) {
	limit, offset, err := b.pageBounds(la)
	if err != nil {
		return nil, err
	}
	if offset >= len(rows) {
		return []map[string]any{}, nil
	}
	rows = rows[offset:]
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

// runSelect executes a role-scoped SELECT and returns rows as maps keyed by
// column name (the object type's field resolvers translate to GraphQL names).
func (b *builder) runSelect(ctx context.Context, ti *tableInfo, id *rbac.Identity, la listArgs, extra *condition, single bool) ([]map[string]any, error) {
	sel := ti.access.Select
	if sel == nil {
		return nil, fmt.Errorf("select on %q is not permitted for role %q", ti.table.Name, b.role)
	}

	var userCond *condition
	var err error
	if la.where != nil {
		if userCond, err = b.whereSQL(ti, la.where); err != nil {
			return nil, err
		}
	}
	filterCond, err := rbacCond(sel, id)
	if err != nil {
		return nil, err
	}
	where := combineConds(userCond, filterCond, extra)

	orderClause, err := b.orderSQL(ti, la.orderBy)
	if err != nil {
		return nil, err
	}

	var limitClause string
	var limitArgs []any
	if single {
		limitClause = " LIMIT 1"
	} else {
		if limitClause, limitArgs, err = b.limitClause(la); err != nil {
			return nil, err
		}
	}

	query := "SELECT " + selectList(sel.Columns) + " FROM " + b.qualifiedTable(ti.table) +
		" WHERE " + where.sql + orderClause + limitClause
	args := append(append([]any{}, where.args...), limitArgs...)
	return b.scanRows(ctx, sel.Columns, query, args)
}

func selectList(cols []*introspect.Column) string {
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = quoteIdent(c.Name)
	}
	return strings.Join(names, ", ")
}

// scanRows executes a SELECT and maps each row into a column-name-keyed map,
// applying convertValue per column. Shared by runSelect and runSelectByKeys.
func (b *builder) scanRows(ctx context.Context, cols []*introspect.Column, query string, args []any) ([]map[string]any, error) {
	b.logSQL(query, args)
	rows, err := b.opt.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, b.dbErr(err)
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, b.dbErr(err)
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			v, err := convertValue(c, vals[i])
			if err != nil {
				return nil, b.dbErr(err)
			}
			row[c.Name] = v
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, b.dbErr(err)
	}
	return out, nil
}

// pkOrderClause orders by the primary key ascending — the clustered-index
// order in TiDB, so it is a range scan, not a sort.
func (b *builder) pkOrderClause(ti *tableInfo) string {
	parts := make([]string, len(ti.table.PrimaryKey))
	for i, pk := range ti.table.PrimaryKey {
		parts[i] = quoteIdent(pk) + " ASC"
	}
	return " ORDER BY " + strings.Join(parts, ", ")
}

// keysetCondition builds the seek predicate "(pk...) > (?, ...)" that skips
// everything up to and including the cursor row. Single-column keys use the
// plain form; composite keys use TiDB's row-value comparison.
func keysetCondition(pkCols []string, vals []string) *condition {
	args := make([]any, len(vals))
	for i, v := range vals {
		args[i] = v
	}
	if len(pkCols) == 1 {
		return &condition{sql: quoteIdent(pkCols[0]) + " > ?", args: args}
	}
	quoted := make([]string, len(pkCols))
	for i, c := range pkCols {
		quoted[i] = quoteIdent(c)
	}
	ph := strings.TrimSuffix(strings.Repeat("?, ", len(pkCols)), ", ")
	return &condition{sql: "(" + strings.Join(quoted, ", ") + ") > (" + ph + ")", args: args}
}

// runKeysetPage fetches one keyset page: rows matching userWhere (+ role
// filter) that sort after the cursor, in primary-key order, up to limit. The
// caller passes limit = pageSize+1 to detect whether another page follows.
func (b *builder) runKeysetPage(ctx context.Context, ti *tableInfo, id *rbac.Identity, userWhere map[string]any, after *condition, limit int) ([]map[string]any, error) {
	sel := ti.access.Select
	if sel == nil {
		return nil, fmt.Errorf("select on %q is not permitted for role %q", ti.table.Name, b.role)
	}
	var userCond *condition
	var err error
	if userWhere != nil {
		if userCond, err = b.whereSQL(ti, userWhere); err != nil {
			return nil, err
		}
	}
	filterCond, err := rbacCond(sel, id)
	if err != nil {
		return nil, err
	}
	where := combineConds(userCond, filterCond, after)
	query := "SELECT " + selectList(sel.Columns) + " FROM " + b.qualifiedTable(ti.table) +
		" WHERE " + where.sql + b.pkOrderClause(ti) + " LIMIT ?"
	args := append(append([]any{}, where.args...), limit)
	return b.scanRows(ctx, sel.Columns, query, args)
}

// runSelectByKeys is the batched form used by relationship dataloaders: it
// selects rows whose joinCols match any of the given key tuples, applying the
// role's row filter and (for to-many relations) the field's where/order_by, so
// one query serves every parent row (defeating the N+1 pattern). All key
// values are bound as parameters; the caller groups by joinCols and slices
// each parent's page in memory.
//
// perKeyLimit bounds how many rows are fetched PER parent key via a
// ROW_NUMBER() window (0 = unbounded, used by to-one where each key yields one
// row). Without it a nested to-many query could pull an entire child table
// into memory; with it the batch is capped at len(keys) * perKeyLimit rows.
func (b *builder) runSelectByKeys(ctx context.Context, ti *tableInfo, id *rbac.Identity, joinCols []string, keys [][]any, userWhere map[string]any, orderBy []any, perKeyLimit int) ([]map[string]any, error) {
	sel := ti.access.Select
	if sel == nil {
		return nil, fmt.Errorf("select on %q is not permitted for role %q", ti.table.Name, b.role)
	}
	inCond := inCondition(joinCols, keys)

	var userCond *condition
	var err error
	if userWhere != nil {
		if userCond, err = b.whereSQL(ti, userWhere); err != nil {
			return nil, err
		}
	}
	filterCond, err := rbacCond(sel, id)
	if err != nil {
		return nil, err
	}
	where := combineConds(inCond, userCond, filterCond)

	orderClause, err := b.orderSQL(ti, orderBy)
	if err != nil {
		return nil, err
	}

	if perKeyLimit > 0 {
		winOrder, err := b.windowOrder(ti, orderBy, joinCols)
		if err != nil {
			return nil, err
		}
		partition := make([]string, len(joinCols))
		for i, c := range joinCols {
			partition[i] = quoteIdent(c)
		}
		// Rank rows within each parent partition and keep only the first
		// perKeyLimit; the outer ORDER BY makes each group contiguous and
		// ordered so groupByColumns + applyPage produce the right page.
		inner := "SELECT " + selectList(sel.Columns) +
			", ROW_NUMBER() OVER (PARTITION BY " + strings.Join(partition, ", ") +
			" ORDER BY " + winOrder + ") AS __gqlgate_rn" +
			" FROM " + b.qualifiedTable(ti.table) + " WHERE " + where.sql
		query := "SELECT " + selectList(sel.Columns) + " FROM (" + inner +
			") AS __gqlgate_w WHERE __gqlgate_rn <= ?" + orderClause
		args := append(append([]any{}, where.args...), perKeyLimit)
		return b.scanRows(ctx, sel.Columns, query, args)
	}

	query := "SELECT " + selectList(sel.Columns) + " FROM " + b.qualifiedTable(ti.table) +
		" WHERE " + where.sql + orderClause
	return b.scanRows(ctx, sel.Columns, query, where.args)
}

// inCondition builds "col IN (?, ?, …)" for a single join column, or the
// row-value form "(c1, c2) IN ((?,?), …)" for a composite key. An empty key
// set matches nothing.
func inCondition(cols []string, keys [][]any) *condition {
	if len(keys) == 0 {
		return &condition{sql: "1=0"}
	}
	var args []any
	if len(cols) == 1 {
		ph := strings.TrimSuffix(strings.Repeat("?, ", len(keys)), ", ")
		for _, k := range keys {
			args = append(args, k[0])
		}
		return &condition{sql: quoteIdent(cols[0]) + " IN (" + ph + ")", args: args}
	}
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = quoteIdent(c)
	}
	tuple := "(" + strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ") + ")"
	tuples := make([]string, len(keys))
	for i, k := range keys {
		tuples[i] = tuple
		args = append(args, k...)
	}
	return &condition{sql: "(" + strings.Join(quoted, ", ") + ") IN (" + strings.Join(tuples, ", ") + ")", args: args}
}

func (b *builder) runCount(ctx context.Context, ti *tableInfo, id *rbac.Identity, where map[string]any) (int64, error) {
	var userCond *condition
	var err error
	if where != nil {
		if userCond, err = b.whereSQL(ti, where); err != nil {
			return 0, err
		}
	}
	filterCond, err := rbacCond(ti.access.Select, id)
	if err != nil {
		return 0, err
	}
	cond := combineConds(userCond, filterCond)
	query := "SELECT COUNT(*) FROM " + b.qualifiedTable(ti.table) + " WHERE " + cond.sql

	b.logSQL(query, cond.args)
	var n int64
	if err := b.opt.DB.QueryRowContext(ctx, query, cond.args...).Scan(&n); err != nil {
		return 0, b.dbErr(err)
	}
	return n, nil
}

// mergedRowValues resolves one insert object: client fields (already
// schema-validated as writable) plus presets, presets winning.
func mergedRowValues(ti *tableInfo, oa *rbac.OpAccess, obj map[string]any, id *rbac.Identity) ([]*introspect.Column, []any, error) {
	byCol := map[string]any{}
	presetCols := map[string]bool{}
	for _, p := range oa.Presets {
		presetCols[p.Column.Name] = true
	}
	for field, v := range obj {
		col, ok := ti.fieldToCol[field]
		// Writability is re-checked here (not only via the input type) so
		// that values smuggled in through variables cannot reach columns the
		// role may not write — preset and generated columns included.
		if !ok || !oa.ColumnSet[col.Name] || presetCols[col.Name] || col.Generated {
			return nil, nil, fmt.Errorf("column for field %q is not writable", field)
		}
		bound, err := bindValue(col, v)
		if err != nil {
			return nil, nil, err
		}
		byCol[col.Name] = bound
	}
	for _, p := range oa.Presets {
		v, err := p.Value(id.Claims)
		if err != nil {
			return nil, nil, err
		}
		byCol[p.Column.Name] = v
	}
	var cols []*introspect.Column
	var vals []any
	for _, c := range ti.table.Columns { // ordinal order for determinism
		if v, ok := byCol[c.Name]; ok {
			cols = append(cols, c)
			vals = append(vals, v)
		}
	}
	return cols, vals, nil
}

// runInsert inserts the given objects in one transaction and returns the
// number of inserted rows and the last insert id of the final row.
func (b *builder) runInsert(ctx context.Context, ti *tableInfo, id *rbac.Identity, objects []any) (int64, int64, map[string]any, error) {
	oa := ti.access.Insert
	if oa == nil {
		return 0, 0, nil, fmt.Errorf("insert into %q is not permitted for role %q", ti.table.Name, b.role)
	}
	if len(objects) == 0 {
		return 0, 0, nil, fmt.Errorf("objects must not be empty")
	}

	// Resolve every object's columns/values first, so lifecycle hooks see the
	// full batch (with presets applied) before anything is written.
	type mergedRow struct {
		cols []*introspect.Column
		vals []any
	}
	merged := make([]mergedRow, 0, len(objects))
	eventValues := make([]map[string]any, 0, len(objects))
	for _, item := range objects {
		obj, ok := item.(map[string]any)
		if !ok {
			return 0, 0, nil, fmt.Errorf("insert objects must be objects")
		}
		cols, vals, err := mergedRowValues(ti, oa, obj, id)
		if err != nil {
			return 0, 0, nil, err
		}
		if len(cols) == 0 {
			return 0, 0, nil, fmt.Errorf("insert object for %q has no columns", ti.table.Name)
		}
		merged = append(merged, mergedRow{cols, vals})
		rowMap := make(map[string]any, len(cols))
		for i, c := range cols {
			rowMap[c.Name] = vals[i]
		}
		eventValues = append(eventValues, rowMap)
	}

	tx, err := b.opt.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, nil, b.dbErr(err)
	}
	defer tx.Rollback()

	ev := &MutationEvent{Op: OpInsert, Table: ti.table.Name, Role: b.role, Claims: id.Claims, Values: eventValues, Tx: tx}
	if err := b.opt.Hooks.runBefore(ctx, ev); err != nil {
		return 0, 0, nil, err
	}

	var affected, lastID int64
	var lastValues map[string]any
	for _, m := range merged {
		names := make([]string, len(m.cols))
		for i, c := range m.cols {
			names[i] = quoteIdent(c.Name)
		}
		query := "INSERT INTO " + b.qualifiedTable(ti.table) +
			" (" + strings.Join(names, ", ") + ") VALUES (" +
			strings.TrimSuffix(strings.Repeat("?, ", len(m.cols)), ", ") + ")"
		b.logSQL(query, m.vals)
		res, err := tx.ExecContext(ctx, query, m.vals...)
		if err != nil {
			return 0, 0, nil, b.dbErr(err)
		}
		n, _ := res.RowsAffected()
		affected += n
		lastID, _ = res.LastInsertId()
		lastValues = map[string]any{}
		for i, c := range m.cols {
			lastValues[c.Name] = m.vals[i]
		}
	}

	ev.Affected = int(affected)
	if err := b.opt.Hooks.runAfter(ctx, ev); err != nil {
		return 0, 0, nil, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, nil, b.dbErr(err)
	}
	return affected, lastID, lastValues, nil
}

// setClause builds the SET part of an UPDATE from the _set input + presets.
// It also returns the resolved column map (SQL names -> bound values, presets
// merged) so callers can surface the true written values to lifecycle hooks.
func setClause(ti *tableInfo, oa *rbac.OpAccess, set map[string]any, id *rbac.Identity) (string, []any, map[string]any, error) {
	byCol := map[string]any{}
	presetCols := map[string]bool{}
	for _, p := range oa.Presets {
		presetCols[p.Column.Name] = true
	}
	for field, v := range set {
		col, ok := ti.fieldToCol[field]
		if !ok || !oa.ColumnSet[col.Name] || presetCols[col.Name] || col.Generated {
			return "", nil, nil, fmt.Errorf("column for field %q is not writable", field)
		}
		bound, err := bindValue(col, v)
		if err != nil {
			return "", nil, nil, err
		}
		byCol[col.Name] = bound
	}
	for _, p := range oa.Presets {
		v, err := p.Value(id.Claims)
		if err != nil {
			return "", nil, nil, err
		}
		byCol[p.Column.Name] = v
	}
	if len(byCol) == 0 {
		return "", nil, nil, fmt.Errorf("_set must contain at least one column")
	}
	var parts []string
	var args []any
	for _, c := range ti.table.Columns {
		if v, ok := byCol[c.Name]; ok {
			parts = append(parts, quoteIdent(c.Name)+" = ?")
			args = append(args, v)
		}
	}
	return strings.Join(parts, ", "), args, byCol, nil
}

func (b *builder) runUpdate(ctx context.Context, ti *tableInfo, id *rbac.Identity, set map[string]any, where *condition) (int64, error) {
	oa := ti.access.Update
	if oa == nil {
		return 0, fmt.Errorf("update on %q is not permitted for role %q", ti.table.Name, b.role)
	}
	setSQL, setArgs, setValues, err := setClause(ti, oa, set, id)
	if err != nil {
		return 0, err
	}
	filterCond, err := rbacCond(oa, id)
	if err != nil {
		return 0, err
	}
	cond := combineConds(where, filterCond)
	query := "UPDATE " + b.qualifiedTable(ti.table) + " SET " + setSQL + " WHERE " + cond.sql
	args := append(setArgs, cond.args...)

	return b.execInTx(ctx, func(tx *sql.Tx) (int64, error) {
		// Values matches the insert path's contract: SQL column names, presets
		// applied, values bound — so a hook sees what is actually written.
		ev := &MutationEvent{Op: OpUpdate, Table: ti.table.Name, Role: b.role, Claims: id.Claims, Values: []map[string]any{setValues}, Tx: tx}
		if err := b.opt.Hooks.runBefore(ctx, ev); err != nil {
			return 0, err
		}
		b.logSQL(query, args)
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return 0, b.dbErr(err)
		}
		n, _ := res.RowsAffected()
		ev.Affected = int(n)
		if err := b.opt.Hooks.runAfter(ctx, ev); err != nil {
			return 0, err
		}
		return n, nil
	})
}

func (b *builder) runDelete(ctx context.Context, ti *tableInfo, id *rbac.Identity, where *condition) (int64, error) {
	oa := ti.access.Delete
	if oa == nil {
		return 0, fmt.Errorf("delete on %q is not permitted for role %q", ti.table.Name, b.role)
	}
	filterCond, err := rbacCond(oa, id)
	if err != nil {
		return 0, err
	}
	cond := combineConds(where, filterCond)
	query := "DELETE FROM " + b.qualifiedTable(ti.table) + " WHERE " + cond.sql

	return b.execInTx(ctx, func(tx *sql.Tx) (int64, error) {
		ev := &MutationEvent{Op: OpDelete, Table: ti.table.Name, Role: b.role, Claims: id.Claims, Tx: tx}
		if err := b.opt.Hooks.runBefore(ctx, ev); err != nil {
			return 0, err
		}
		b.logSQL(query, cond.args)
		res, err := tx.ExecContext(ctx, query, cond.args...)
		if err != nil {
			return 0, b.dbErr(err)
		}
		n, _ := res.RowsAffected()
		ev.Affected = int(n)
		if err := b.opt.Hooks.runAfter(ctx, ev); err != nil {
			return 0, err
		}
		return n, nil
	})
}

// execInTx runs fn inside a transaction, committing on success and rolling
// back on error. It lets update/delete run their lifecycle hooks atomically
// with the write (a hook returning an error rolls the whole thing back).
func (b *builder) execInTx(ctx context.Context, fn func(tx *sql.Tx) (int64, error)) (int64, error) {
	tx, err := b.opt.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, b.dbErr(err)
	}
	defer tx.Rollback()
	n, err := fn(tx)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, b.dbErr(err)
	}
	return n, nil
}

// pkCond builds the primary-key equality condition from by_pk arguments.
func (b *builder) pkCond(ti *tableInfo, args map[string]any) (*condition, error) {
	var parts []string
	var vals []any
	for _, pkName := range ti.table.PrimaryKey {
		col := ti.table.ColumnMap[pkName]
		v, ok := args[ti.colToField[pkName]]
		if !ok || v == nil {
			return nil, fmt.Errorf("missing primary key argument %q", ti.colToField[pkName])
		}
		bound, err := bindValue(col, v)
		if err != nil {
			return nil, err
		}
		parts = append(parts, quoteIdent(col.Name)+" = ?")
		vals = append(vals, bound)
	}
	return &condition{sql: strings.Join(parts, " AND "), args: vals}, nil
}

func (b *builder) logSQL(query string, args []any) {
	if b.opt.Config.Server.Debug && b.opt.Logger != nil {
		b.opt.Logger.Debug("sql", "role", b.role, "query", query, "args", fmt.Sprintf("%v", args))
	}
}

// dbErr hides database error details from clients unless debug mode is on.
func (b *builder) dbErr(err error) error {
	if err == nil {
		return nil
	}
	if b.opt.Config.Server.Debug {
		return err
	}
	if b.opt.Logger != nil {
		b.opt.Logger.Error("database error", "role", b.role, "err", err)
	}
	if err == sql.ErrNoRows {
		return err
	}
	return fmt.Errorf("database error (enable server.debug to see details)")
}
