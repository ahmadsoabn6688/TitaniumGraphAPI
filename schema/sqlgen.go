package schema

import (
	"context"
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
		fallback = ti.model.readKey // a declared key (views, keyless tables)
	}
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
		if userCond, err = b.whereSQL(ti, la.where, id); err != nil {
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
	rows, err := b.scanRows(ctx, sel.Columns, query, args)
	if err != nil {
		return nil, err
	}
	// Every caller returns all of these rows to the client.
	if err := countRows(ctx, len(rows)); err != nil {
		return nil, err
	}
	return rows, nil
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
	rows, _, err := b.scanRowsExtra(ctx, cols, 0, query, args)
	return rows, err
}

// scanRowsExtra is scanRows for a SELECT that lists nExtra raw values after
// cols (e.g. key weights); those are returned per row, unconverted.
func (b *builder) scanRowsExtra(ctx context.Context, cols []*introspect.Column, nExtra int, query string, args []any) ([]map[string]any, [][]any, error) {
	return b.scanRowsOn(ctx, b.opt.DB, cols, nExtra, query, args)
}

// scanRowsOn is scanRowsExtra through q (the pool, or a mutation's
// transaction).
func (b *builder) scanRowsOn(ctx context.Context, q queryer, cols []*introspect.Column, nExtra int, query string, args []any) ([]map[string]any, [][]any, error) {
	b.logSQL(query, args)
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, b.dbErr(err)
	}
	defer rows.Close()

	var out []map[string]any
	var extras [][]any
	for rows.Next() {
		vals := make([]any, len(cols)+nExtra)
		ptrs := make([]any, len(vals))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, b.dbErr(err)
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			v, err := convertValue(c, vals[i])
			if err != nil {
				return nil, nil, b.dbErr(err)
			}
			row[c.Name] = v
		}
		out = append(out, row)
		if nExtra > 0 {
			extras = append(extras, vals[len(cols):])
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, b.dbErr(err)
	}
	return out, extras, nil
}

// pkOrderClause orders by the read key ascending: the primary key — the
// clustered-index order in TiDB, so it is a range scan, not a sort — or a
// declared logical key (on a view this may sort).
func (b *builder) pkOrderClause(ti *tableInfo) string {
	parts := make([]string, len(ti.model.readKey))
	for i, pk := range ti.model.readKey {
		parts[i] = quoteIdent(pk) + " ASC"
	}
	return " ORDER BY " + strings.Join(parts, ", ")
}

// keysetCondition builds the seek predicate "(pk...) > (?, ...)" that skips
// everything up to and including the cursor row. Single-column keys use the
// plain form; composite keys use TiDB's row-value comparison.
func keysetCondition(pkCols []string, vals []any) *condition {
	args := append([]any{}, vals...)
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
		if userCond, err = b.whereSQL(ti, userWhere, id); err != nil {
			return nil, err
		}
	}
	filterCond, err := rbacCond(sel, id)
	if err != nil {
		return nil, err
	}
	where := combineConds(userCond, filterCond, b.readKeyNotNull(ti), after)
	query := "SELECT " + selectList(sel.Columns) + " FROM " + b.qualifiedTable(ti.table) +
		" WHERE " + where.sql + b.pkOrderClause(ti) + " LIMIT ?"
	args := append(append([]any{}, where.args...), limit)
	return b.scanRows(ctx, sel.Columns, query, args)
}

// runSelectByKeys is the batched form used by relationship dataloaders: it
// selects rows whose joinCols match any of the given key tuples, applying the
// role's row filter and (for to-many relations) the field's where/order_by, so
// one query serves every parent row (defeating the N+1 pattern). All key
// values are bound as parameters. The rows come back bucketed by the
// signature of the key(s) they match (see keyIndex: character keys match by
// collation, as the IN did), each bucket in ORDER BY order, so the caller
// only slices each parent's page.
//
// perKeyLimit bounds how many rows are fetched PER parent key via a
// ROW_NUMBER() window (0 = unbounded, used by to-one where each key yields one
// row). Without it a nested to-many query could pull an entire child table
// into memory; with it the batch is capped at len(keys) * perKeyLimit rows.
func (b *builder) runSelectByKeys(ctx context.Context, ti *tableInfo, id *rbac.Identity, joinCols []string, keys [][]any, userWhere map[string]any, orderBy []any, perKeyLimit int) (map[string][]map[string]any, error) {
	sel := ti.access.Select
	if sel == nil {
		return nil, fmt.Errorf("select on %q is not permitted for role %q", ti.table.Name, b.role)
	}
	inCond := inCondition(joinCols, keys)

	var userCond *condition
	var err error
	if userWhere != nil {
		if userCond, err = b.whereSQL(ti, userWhere, id); err != nil {
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
	ki, err := b.newKeyIndex(ctx, ti, joinCols, keys)
	if err != nil {
		return nil, err
	}
	// Collation weights of character join columns ride along as extra
	// columns: as expressions in a plain query, and through the window's
	// derived table under __gqlgate_kw<i> aliases.
	weights := ki.weightExprs()
	var innerExtra, outerExtra string
	for i, w := range weights {
		alias := quoteIdent(fmt.Sprintf("__gqlgate_kw%d", i))
		innerExtra += ", " + w + " AS " + alias
		outerExtra += ", " + alias
	}

	var query string
	var args []any
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
		// ordered so the buckets + applyPage produce the right page.
		inner := "SELECT " + selectList(sel.Columns) + innerExtra +
			", ROW_NUMBER() OVER (PARTITION BY " + strings.Join(partition, ", ") +
			" ORDER BY " + winOrder + ") AS __gqlgate_rn" +
			" FROM " + b.qualifiedTable(ti.table) + " WHERE " + where.sql
		query = "SELECT " + selectList(sel.Columns) + outerExtra + " FROM (" + inner +
			") AS __gqlgate_w WHERE __gqlgate_rn <= ?" + orderClause
		args = append(append([]any{}, where.args...), perKeyLimit)
	} else {
		query = "SELECT " + selectList(sel.Columns) + innerExtra + " FROM " + b.qualifiedTable(ti.table) +
			" WHERE " + where.sql + orderClause
		args = where.args
	}
	rows, extras, err := b.scanRowsExtra(ctx, sel.Columns, len(weights), query, args)
	if err != nil {
		return nil, err
	}
	return ki.group(rows, extras), nil
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

func (b *builder) runCount(ctx context.Context, ti *tableInfo, id *rbac.Identity, where map[string]any, extra *condition) (int64, error) {
	var userCond *condition
	var err error
	if where != nil {
		if userCond, err = b.whereSQL(ti, where, id); err != nil {
			return 0, err
		}
	}
	filterCond, err := rbacCond(ti.access.Select, id)
	if err != nil {
		return 0, err
	}
	cond := combineConds(userCond, filterCond, extra)
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

func (b *builder) logSQL(query string, args []any) {
	if b.opt.Config.Server.Debug && b.opt.Logger != nil {
		b.opt.Logger.Debug("sql", "role", b.role, "query", query, "args", fmt.Sprintf("%v", args))
	}
}
