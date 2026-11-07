package schema

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"

	"gqlgate/config"
	"gqlgate/introspect"
	"gqlgate/rbac"
)

// Aggregates: <t>_aggregate(where) { count  sum{..} avg{..} min{..} max{..}
// count_columns{..} count_distinct{..} approx_count_distinct{..}
// stddev{..} stddev_pop{..} stddev_samp{..} variance{..} var_pop{..}
// var_samp{..} }, and the same result type on every array relationship as
// <rel>_aggregate(where). The resolver inspects the selection set and runs ONE
// SELECT computing only the aggregates actually requested, so `{ count }`
// never triggers a SUM over billions of rows. Nested (relationship)
// aggregates run one GROUP BY query per batch of parent rows.

// isNumeric reports whether a column can be summed/averaged.
func isNumeric(c *introspect.Column) bool {
	switch c.DataType {
	case "tinyint", "smallint", "mediumint", "int", "integer", "bigint",
		"decimal", "numeric", "float", "double", "real", "year", "bit":
		return true
	}
	return false
}

// isStatNumeric reports whether a column takes the statistical aggregates
// (stddev/variance): numeric, minus BIT (a bit string, not a quantity).
func isStatNumeric(c *introspect.Column) bool {
	return isNumeric(c) && c.DataType != "bit"
}

// isDistinctCountable reports whether COUNT(DISTINCT col) and
// APPROX_COUNT_DISTINCT(col) are offered on a column. JSON, VECTOR and the
// BLOB/TEXT families are left out: comparing whole documents/vectors/large
// values is unusual semantics and very expensive on big tables.
func isDistinctCountable(c *introspect.Column) bool {
	switch c.DataType {
	case "json", "vector",
		"tinyblob", "blob", "mediumblob", "longblob",
		"tinytext", "text", "mediumtext", "longtext":
		return false
	}
	return true
}

// aggFunc is one per-column aggregate bucket of <t>_aggregate_result: the
// `sum` in `sum { views }`. Each bucket becomes a <t>_<name>_fields object
// with one field per role-readable column it applies to.
type aggFunc struct {
	name    string // GraphQL field name; the type is <t>_<name>_fields
	desc    string
	sql     func(colRef string) string
	applies func(*introspect.Column) bool
	out     func(*introspect.Column) graphql.Output
	convert func(*introspect.Column, any) (any, error)
	isCount bool // an empty group yields 0, not null
}

func sqlFn(fn string) func(string) string {
	return func(c string) string { return fn + "(" + c + ")" }
}

func anyColumn(*introspect.Column) bool { return true }

func floatOut(*introspect.Column) graphql.Output { return graphql.Float }

func floatConv(_ *introspect.Column, v any) (any, error) { return toFloat(v), nil }

func countOut(*introspect.Column) graphql.Output { return graphql.NewNonNull(bigIntScalar) }

func countConv(_ *introspect.Column, v any) (any, error) { return toInt64(v), nil }

// statFunc is a stddev/variance aggregate: numeric columns, Float result.
func statFunc(name, fn, desc string) *aggFunc {
	return &aggFunc{name: name, desc: desc, sql: sqlFn(fn), applies: isStatNumeric, out: floatOut, convert: floatConv}
}

// aggFuncs are the per-column aggregates in schema order. stddev/variance
// follow Hasura (and PostgreSQL): they are the SAMPLE statistics — unlike
// TiDB/MySQL's STDDEV()/VARIANCE(), which are the population ones.
var aggFuncs = []*aggFunc{
	{name: "sum", desc: "SUM per numeric column (exact Decimal).", sql: sqlFn("SUM"), applies: isNumeric,
		out:     func(*introspect.Column) graphql.Output { return decimalScalar },
		convert: func(_ *introspect.Column, v any) (any, error) { return aggScalar(v), nil }},
	{name: "avg", desc: "AVG per numeric column.", sql: sqlFn("AVG"), applies: isNumeric, out: floatOut, convert: floatConv},
	{name: "min", desc: "MIN per column.", sql: sqlFn("MIN"), applies: anyColumn,
		out: func(c *introspect.Column) graphql.Output { return scalarFor(c) }, convert: convertValue},
	{name: "max", desc: "MAX per column.", sql: sqlFn("MAX"), applies: anyColumn,
		out: func(c *introspect.Column) graphql.Output { return scalarFor(c) }, convert: convertValue},
	{name: "count_columns", desc: "Number of non-null values per column: COUNT(col).", sql: sqlFn("COUNT"),
		applies: anyColumn, out: countOut, convert: countConv, isCount: true},
	{name: "count_distinct", desc: "Number of distinct non-null values per column: COUNT(DISTINCT col). Exact but costly on very large tables; see approx_count_distinct.",
		sql:     func(c string) string { return "COUNT(DISTINCT " + c + ")" },
		applies: isDistinctCountable, out: countOut, convert: countConv, isCount: true},
	{name: "approx_count_distinct", desc: "Approximate number of distinct non-null values per column (TiDB APPROX_COUNT_DISTINCT, HyperLogLog): much cheaper than count_distinct on large tables.",
		sql: sqlFn("APPROX_COUNT_DISTINCT"), applies: isDistinctCountable, out: countOut, convert: countConv, isCount: true},
	statFunc("stddev", "STDDEV_SAMP", "Sample standard deviation per numeric column (same as stddev_samp)."),
	statFunc("stddev_pop", "STDDEV_POP", "Population standard deviation per numeric column."),
	statFunc("stddev_samp", "STDDEV_SAMP", "Sample standard deviation per numeric column."),
	statFunc("variance", "VAR_SAMP", "Sample variance per numeric column (same as var_samp)."),
	statFunc("var_pop", "VAR_POP", "Population variance per numeric column."),
	statFunc("var_samp", "VAR_SAMP", "Sample variance per numeric column."),
}

var aggFuncByName = func() map[string]*aggFunc {
	m := make(map[string]*aggFunc, len(aggFuncs))
	for _, f := range aggFuncs {
		m[f.name] = f
	}
	return m
}()

// aggTypeSuffixes are the type-name suffixes of the per-function field types
// (reserved per table by the collision check).
func aggTypeSuffixes() []string {
	out := make([]string, len(aggFuncs))
	for i, f := range aggFuncs {
		out[i] = "_" + f.name + "_fields"
	}
	return out
}

// countScalar is the GraphQL scalar of row counts (count, total_count,
// affected_rows), per schema_gen.count_type: BigInt unless Int was chosen.
func (b *builder) countScalar() *graphql.Scalar {
	if b.opt.Config != nil && b.opt.Config.SchemaGen.CountType == config.CountTypeInt {
		return graphql.Int
	}
	return bigIntScalar
}

// addAggregateField adds the <t>_aggregate query field.
func (b *builder) addAggregateField(fields graphql.Fields, ti *tableInfo) {
	fields[ti.typeName+"_aggregate"] = &graphql.Field{
		Type:        graphql.NewNonNull(b.aggTypes[ti.table.Name]),
		Description: fmt.Sprintf("Aggregates over %s matching the filter (count/sum/avg/min/max/count_distinct/stddev/...).", ti.table.Name),
		Args: graphql.FieldConfigArgument{
			"where": &graphql.ArgumentConfig{Type: b.boolExps[ti.table.Name]},
		},
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, err := identityFrom(p)
			if err != nil {
				return nil, err
			}
			where, _ := p.Args["where"].(map[string]any)
			req := b.collectAggSelections(ti, p.Info)
			return b.runAggregate(p.Context, ti, id, where, req)
		},
	}
}

// buildAggregateType builds <t>_aggregate_result plus one <t>_<fn>_fields
// sub-type per aggregate function. Each function covers the role-readable
// columns it applies to; a function with no such column is left out (an
// empty GraphQL object type is invalid).
func (b *builder) buildAggregateType(ti *tableInfo) *graphql.Object {
	sel := ti.access.Select
	fields := graphql.Fields{
		"count": &graphql.Field{
			Type:        graphql.NewNonNull(b.countScalar()),
			Description: "Number of rows: COUNT(*).",
			Resolve:     func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "count"), nil },
		},
	}
	for _, fn := range aggFuncs {
		colFields := graphql.Fields{}
		for _, col := range sel.Columns {
			if !fn.applies(col) {
				continue
			}
			colFields[ti.colToField[col.Name]] = &graphql.Field{
				Type:    fn.out(col),
				Resolve: aggColResolve(col.Name),
			}
		}
		if len(colFields) == 0 {
			continue
		}
		name := fn.name
		t := graphql.NewObject(graphql.ObjectConfig{Name: ti.typeName + "_" + name + "_fields", Fields: colFields})
		fields[name] = &graphql.Field{
			Type:        t,
			Description: fn.desc,
			Resolve:     func(p graphql.ResolveParams) (any, error) { return sourceKey(p, name), nil },
		}
	}
	return graphql.NewObject(graphql.ObjectConfig{
		Name:        ti.typeName + "_aggregate_result",
		Description: fmt.Sprintf("Aggregate results for %s.", ti.table.Name),
		Fields:      fields,
	})
}

// aggColResolve reads one aggregated column value from the nested source map.
func aggColResolve(col string) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		m, _ := p.Source.(map[string]any)
		return m[col], nil
	}
}

// aggRequest is the set of aggregates the query actually selected.
type aggRequest struct {
	count bool
	// cols: function name -> requested columns, deduplicated, in selection
	// order.
	cols map[string][]*introspect.Column
}

func (r aggRequest) empty() bool {
	if r.count {
		return false
	}
	for _, cs := range r.cols {
		if len(cs) > 0 {
			return false
		}
	}
	return true
}

// signature identifies the request (used to key relationship loaders, so two
// call sites selecting different aggregates never share a batch).
func (r aggRequest) signature() string {
	var sb strings.Builder
	if r.count {
		sb.WriteString("count;")
	}
	for _, fn := range aggFuncs {
		cs := r.cols[fn.name]
		if len(cs) == 0 {
			continue
		}
		sb.WriteString(fn.name)
		for _, c := range cs {
			sb.WriteString(",")
			sb.WriteString(c.Name)
		}
		sb.WriteString(";")
	}
	return sb.String()
}

// collectAggSelections walks the aggregate field's selection set to learn
// which functions and columns are requested, so only those are computed.
// Columns are re-checked against the role's readable set and the function's
// applicability (the schema already enforces both).
func (b *builder) collectAggSelections(ti *tableInfo, info graphql.ResolveInfo) aggRequest {
	req := aggRequest{cols: map[string][]*introspect.Column{}}
	sel := ti.access.Select
	for _, fa := range info.FieldASTs {
		// Flatten fragments at this level too — Apollo/Relay/urql emit the
		// count/sum/avg/min/max selections inside fragments on the result type.
		for _, f := range b.flattenFields(fa.SelectionSet, info) {
			if f.Name == nil {
				continue
			}
			if f.Name.Value == "count" {
				req.count = true
				continue
			}
			fn, ok := aggFuncByName[f.Name.Value]
			if !ok {
				continue
			}
			for _, name := range b.fieldNames(f.SelectionSet, info) {
				c, ok := ti.fieldToCol[name]
				if !ok || sel == nil || !sel.ColumnSet[c.Name] || !fn.applies(c) || containsCol(req.cols[fn.name], c) {
					continue
				}
				req.cols[fn.name] = append(req.cols[fn.name], c)
			}
		}
	}
	return req
}

func containsCol(list []*introspect.Column, c *introspect.Column) bool {
	for _, x := range list {
		if x == c {
			return true
		}
	}
	return false
}

// flattenFields returns the *ast.Field selections of a set, following inline
// fragments and named fragment spreads so fragment-wrapped selections are seen.
func (b *builder) flattenFields(set *ast.SelectionSet, info graphql.ResolveInfo) []*ast.Field {
	if set == nil {
		return nil
	}
	var out []*ast.Field
	for _, s := range set.Selections {
		switch node := s.(type) {
		case *ast.Field:
			out = append(out, node)
		case *ast.InlineFragment:
			out = append(out, b.flattenFields(node.SelectionSet, info)...)
		case *ast.FragmentSpread:
			if node.Name != nil {
				if def, ok := info.Fragments[node.Name.Value].(*ast.FragmentDefinition); ok {
					out = append(out, b.flattenFields(def.GetSelectionSet(), info)...)
				}
			}
		}
	}
	return out
}

// fieldNames returns the plain field names selected in a set (fragments
// followed).
func (b *builder) fieldNames(set *ast.SelectionSet, info graphql.ResolveInfo) []string {
	var names []string
	for _, f := range b.flattenFields(set, info) {
		if f.Name != nil {
			names = append(names, f.Name.Value)
		}
	}
	return names
}

// aggSlot maps one SELECT expression to where its result is stored: the
// row count (fn == nil) or one function's column.
type aggSlot struct {
	fn  *aggFunc
	col *introspect.Column
}

// aggPlan turns a request into SELECT expressions and their result slots. An
// empty request still counts, so the query is always valid.
func aggPlan(req aggRequest) ([]string, []aggSlot) {
	var exprs []string
	var plan []aggSlot
	if req.count || req.empty() {
		exprs = append(exprs, "COUNT(*)")
		plan = append(plan, aggSlot{})
	}
	for _, fn := range aggFuncs {
		for _, c := range req.cols[fn.name] {
			exprs = append(exprs, fn.sql(quoteIdent(c.Name)))
			plan = append(plan, aggSlot{fn: fn, col: c})
		}
	}
	return exprs, plan
}

// emptyAggResult is the result over zero rows: count 0, the requested
// count-type columns 0, everything else null.
func emptyAggResult(req aggRequest) map[string]any {
	out := map[string]any{"count": int64(0)}
	for _, fn := range aggFuncs {
		m := map[string]any{}
		if fn.isCount {
			for _, c := range req.cols[fn.name] {
				m[c.Name] = int64(0)
			}
		}
		out[fn.name] = m
	}
	return out
}

// fillAggResult stores scanned values into a result map built by
// emptyAggResult.
func (b *builder) fillAggResult(out map[string]any, plan []aggSlot, vals []any) error {
	for i, s := range plan {
		if s.fn == nil {
			out["count"] = toInt64(vals[i])
			continue
		}
		v, err := s.fn.convert(s.col, vals[i])
		if err != nil {
			return b.dbErr(err)
		}
		out[s.fn.name].(map[string]any)[s.col.Name] = v
	}
	return nil
}

// aggWhere is the WHERE of an aggregate: the client filter, the role's
// select row filter, and any extra condition (relationship keys).
func (b *builder) aggWhere(ti *tableInfo, id *rbac.Identity, where map[string]any, extra *condition) (*condition, error) {
	sel := ti.access.Select
	if sel == nil {
		return nil, fmt.Errorf("select on %q is not permitted for role %q", ti.table.Name, b.role)
	}
	var userCond *condition
	var err error
	if where != nil {
		if userCond, err = b.whereSQL(ti, where, id); err != nil {
			return nil, err
		}
	}
	filterCond, err := rbacCond(sel, id)
	if err != nil {
		return nil, err
	}
	return combineConds(extra, userCond, filterCond), nil
}

// runAggregate runs one SELECT computing exactly the requested aggregates,
// applying the role's row filter, and shapes the row into the nested source
// the aggregate types read.
func (b *builder) runAggregate(ctx context.Context, ti *tableInfo, id *rbac.Identity, where map[string]any, req aggRequest) (map[string]any, error) {
	exprs, plan := aggPlan(req)
	cond, err := b.aggWhere(ti, id, where, nil)
	if err != nil {
		return nil, err
	}
	query := "SELECT " + strings.Join(exprs, ", ") + " FROM " + b.qualifiedTable(ti.table) + " WHERE " + cond.sql
	b.logSQL(query, cond.args)

	vals := make([]any, len(plan))
	ptrs := make([]any, len(plan))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := b.opt.DB.QueryRowContext(ctx, query, cond.args...).Scan(ptrs...); err != nil {
		return nil, b.dbErr(err)
	}
	out := emptyAggResult(req)
	if err := b.fillAggResult(out, plan, vals); err != nil {
		return nil, err
	}
	return out, nil
}

// runAggregateByKeys is the batched form behind <rel>_aggregate: ONE
// `SELECT <join cols>, <aggregates> … WHERE <join cols> IN (keys) AND <where>
// AND <role filter> GROUP BY <join cols>` serves every parent row of a batch.
// keyCols are the parent columns the join columns reference; group keys are
// normalized through them so they match the parent rows' key signatures.
// Parents without matching rows are absent from the result (the caller
// substitutes emptyAggResult).
func (b *builder) runAggregateByKeys(ctx context.Context, ti *tableInfo, id *rbac.Identity, joinCols []string, keyCols []*introspect.Column, keys [][]any, where map[string]any, req aggRequest) (map[string][]map[string]any, error) {
	exprs, plan := aggPlan(req)
	cond, err := b.aggWhere(ti, id, where, inCondition(joinCols, keys))
	if err != nil {
		return nil, err
	}
	group := make([]string, len(joinCols))
	for i, c := range joinCols {
		group[i] = quoteIdent(c)
	}
	query := "SELECT " + strings.Join(group, ", ") + ", " + strings.Join(exprs, ", ") +
		" FROM " + b.qualifiedTable(ti.table) + " WHERE " + cond.sql +
		" GROUP BY " + strings.Join(group, ", ")
	b.logSQL(query, cond.args)

	rows, err := b.opt.DB.QueryContext(ctx, query, cond.args...)
	if err != nil {
		return nil, b.dbErr(err)
	}
	defer rows.Close()
	out := map[string][]map[string]any{}
	n := len(joinCols)
	for rows.Next() {
		vals := make([]any, n+len(plan))
		ptrs := make([]any, len(vals))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, b.dbErr(err)
		}
		key := make([]any, n)
		for i := range key {
			v, err := convertValue(keyCols[i], vals[i])
			if err != nil {
				return nil, b.dbErr(err)
			}
			key[i] = v
		}
		res := emptyAggResult(req)
		if err := b.fillAggResult(res, plan, vals[n:]); err != nil {
			return nil, err
		}
		out[keySig(key)] = []map[string]any{res}
	}
	if err := rows.Err(); err != nil {
		return nil, b.dbErr(err)
	}
	return out, nil
}

// addArrayRelAggField adds <rel>_aggregate(where) next to an array
// relationship: the child table's aggregate result type, computed over the
// child rows referencing this row. The child's select row filter and column
// permissions apply exactly as for <child>_aggregate. Every parent of a batch
// is served by one GROUP BY query (runAggregateByKeys), never one query per
// parent.
//
// Unlike the list field, batching does not need the child's FK columns to be
// readable: they are only selected as the GROUP BY key and matched against
// parent key values the role can already read, never returned to the client.
func (b *builder) addArrayRelAggField(fields graphql.Fields, rel *relInfo) {
	fk, child := rel.fk, rel.target
	parent := b.tinfos[fk.RefTable]
	keyCols := make([]*introspect.Column, len(fk.RefColumns))
	for i, rc := range fk.RefColumns {
		keyCols[i] = parent.table.ColumnMap[rc]
	}
	fields[rel.aggName] = &graphql.Field{
		Type:        graphql.NewNonNull(b.aggTypes[fk.Table]),
		Description: fmt.Sprintf("Aggregates over the %s rows whose %s reference this row.", fk.Table, strings.Join(fk.Columns, ", ")),
		Args: graphql.FieldConfigArgument{
			"where": &graphql.ArgumentConfig{Type: b.boolExps[fk.Table]},
		},
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, err := identityFrom(p)
			if err != nil {
				return nil, err
			}
			req := b.collectAggSelections(child, p.Info)
			row, _ := p.Source.(map[string]any)
			key := make([]any, len(fk.RefColumns))
			for i, rc := range fk.RefColumns {
				v := row[rc]
				if v == nil {
					return emptyAggResult(req), nil // NULL key: no child can reference it
				}
				key[i] = v
			}
			where, _ := p.Args["where"].(map[string]any)
			sig, err := json.Marshal(where)
			if err != nil {
				return nil, fmt.Errorf("encoding where: %w", err)
			}
			loader := loadersFrom(p.Context).getOrCreate(
				loaderKey("agg", fk.Table+"."+fk.ConstraintName, string(sig)+"\x00"+req.signature()),
				func() *relLoader {
					return newRelLoader(func(ctx context.Context, keys [][]any) (map[string][]map[string]any, error) {
						return b.runAggregateByKeys(ctx, child, id, fk.Columns, keyCols, keys, where, req)
					})
				})
			loader.enqueue(key)
			return func() (any, error) {
				res, err := loader.fetch(p.Context, key)
				if err != nil {
					return nil, err
				}
				if len(res) == 0 {
					return emptyAggResult(req), nil
				}
				return res[0], nil
			}, nil
		},
	}
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case uint64:
		return int64(n)
	case int:
		return int64(n)
	case []byte:
		i, _ := strconv.ParseInt(string(n), 10, 64)
		return i
	case float64:
		return int64(n)
	}
	return 0
}

func toFloat(v any) any {
	switch n := v.(type) {
	case nil:
		return nil
	case float64:
		return n
	case float32:
		return float64(n)
	case int64:
		return float64(n)
	case []byte:
		f, err := strconv.ParseFloat(string(n), 64)
		if err != nil {
			return nil
		}
		return f
	}
	return nil
}

// aggScalar renders a SUM result as an exact decimal string (Decimal scalar).
func aggScalar(v any) any {
	switch n := v.(type) {
	case nil:
		return nil
	case []byte:
		return string(n)
	case int64:
		return strconv.FormatInt(n, 10)
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	}
	return nil
}
