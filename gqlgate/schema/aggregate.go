package schema

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"

	"gqlgate/introspect"
	"gqlgate/rbac"
)

// Aggregates: <t>_aggregate(where) { count  sum{..} avg{..} min{..} max{..} }.
// The resolver inspects the selection set and runs ONE SELECT computing only
// the aggregates actually requested, so `{ count }` never triggers a SUM over
// billions of rows.

// isNumeric reports whether a column can be summed/averaged.
func isNumeric(c *introspect.Column) bool {
	switch c.DataType {
	case "tinyint", "smallint", "mediumint", "int", "integer", "bigint",
		"decimal", "numeric", "float", "double", "real", "year", "bit":
		return true
	}
	return false
}

// addAggregateField adds the <t>_aggregate query field and its result types.
func (b *builder) addAggregateField(fields graphql.Fields, ti *tableInfo) {
	resultType := b.buildAggregateType(ti)
	fields[ti.typeName+"_aggregate"] = &graphql.Field{
		Type:        graphql.NewNonNull(resultType),
		Description: fmt.Sprintf("Aggregates over %s matching the filter (count/sum/avg/min/max).", ti.table.Name),
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

// buildAggregateType builds <t>_aggregate_result plus the sum/avg/min/max
// field sub-types. sum/avg cover numeric columns; min/max cover every readable
// column (min/max is defined for strings and dates too).
func (b *builder) buildAggregateType(ti *tableInfo) *graphql.Object {
	sel := ti.access.Select
	numericFields := func(t graphql.Output) graphql.Fields {
		f := graphql.Fields{}
		for _, col := range sel.Columns {
			if !isNumeric(col) {
				continue
			}
			col := col
			f[ti.colToField[col.Name]] = &graphql.Field{
				Type:    t,
				Resolve: aggColResolve(col.Name),
			}
		}
		return f
	}
	sameTypeFields := func() graphql.Fields {
		f := graphql.Fields{}
		for _, col := range sel.Columns {
			col := col
			f[ti.colToField[col.Name]] = &graphql.Field{
				Type:    scalarFor(col),
				Resolve: aggColResolve(col.Name),
			}
		}
		return f
	}

	sumType := graphql.NewObject(graphql.ObjectConfig{Name: ti.typeName + "_sum_fields", Fields: numericFields(decimalScalar)})
	avgType := graphql.NewObject(graphql.ObjectConfig{Name: ti.typeName + "_avg_fields", Fields: numericFields(graphql.Float)})
	minType := graphql.NewObject(graphql.ObjectConfig{Name: ti.typeName + "_min_fields", Fields: sameTypeFields()})
	maxType := graphql.NewObject(graphql.ObjectConfig{Name: ti.typeName + "_max_fields", Fields: sameTypeFields()})

	return graphql.NewObject(graphql.ObjectConfig{
		Name:        ti.typeName + "_aggregate_result",
		Description: fmt.Sprintf("Aggregate results for %s.", ti.table.Name),
		Fields: graphql.Fields{
			"count": &graphql.Field{Type: graphql.NewNonNull(graphql.Int), Resolve: func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "count"), nil }},
			"sum":   &graphql.Field{Type: sumType, Resolve: func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "sum"), nil }},
			"avg":   &graphql.Field{Type: avgType, Resolve: func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "avg"), nil }},
			"min":   &graphql.Field{Type: minType, Resolve: func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "min"), nil }},
			"max":   &graphql.Field{Type: maxType, Resolve: func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "max"), nil }},
		},
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
	count              bool
	sum, avg, min, max []*introspect.Column
}

func (r aggRequest) empty() bool {
	return !r.count && len(r.sum) == 0 && len(r.avg) == 0 && len(r.min) == 0 && len(r.max) == 0
}

// collectAggSelections walks the aggregate field's selection set to learn
// which sub-aggregates and columns are requested, so only those are computed.
func (b *builder) collectAggSelections(ti *tableInfo, info graphql.ResolveInfo) aggRequest {
	var req aggRequest
	cols := func(set *ast.SelectionSet) []*introspect.Column {
		var out []*introspect.Column
		for _, name := range b.fieldNames(set, info) {
			if c, ok := ti.fieldToCol[name]; ok {
				out = append(out, c)
			}
		}
		return out
	}
	for _, fa := range info.FieldASTs {
		// Flatten fragments at this level too — Apollo/Relay/urql emit the
		// count/sum/avg/min/max selections inside fragments on the result type.
		for _, f := range b.flattenFields(fa.SelectionSet, info) {
			if f.Name == nil {
				continue
			}
			switch f.Name.Value {
			case "count":
				req.count = true
			case "sum":
				req.sum = cols(f.SelectionSet)
			case "avg":
				req.avg = cols(f.SelectionSet)
			case "min":
				req.min = cols(f.SelectionSet)
			case "max":
				req.max = cols(f.SelectionSet)
			}
		}
	}
	return req
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

// runAggregate runs one SELECT computing exactly the requested aggregates,
// applying the role's row filter, and shapes the row into the nested source
// the aggregate types read.
func (b *builder) runAggregate(ctx context.Context, ti *tableInfo, id *rbac.Identity, where map[string]any, req aggRequest) (map[string]any, error) {
	out := map[string]any{"count": 0, "sum": map[string]any{}, "avg": map[string]any{}, "min": map[string]any{}, "max": map[string]any{}}
	if req.empty() {
		req.count = true // a bare <t>_aggregate selection still needs a valid row
	}

	var exprs []string
	// scanPlan maps each SELECT column to how its result is stored.
	type slot struct {
		bucket string // "count", "sum", "avg", "min", "max"
		col    *introspect.Column
	}
	var plan []slot

	if req.count {
		exprs = append(exprs, "COUNT(*)")
		plan = append(plan, slot{bucket: "count"})
	}
	add := func(fn, bucket string, cs []*introspect.Column) {
		for _, c := range cs {
			exprs = append(exprs, fn+"("+quoteIdent(c.Name)+")")
			plan = append(plan, slot{bucket: bucket, col: c})
		}
	}
	add("SUM", "sum", req.sum)
	add("AVG", "avg", req.avg)
	add("MIN", "min", req.min)
	add("MAX", "max", req.max)

	if len(exprs) == 0 {
		return out, nil
	}

	var userCond *condition
	var err error
	if where != nil {
		if userCond, err = b.whereSQL(ti, where); err != nil {
			return nil, err
		}
	}
	filterCond, err := rbacCond(ti.access.Select, id)
	if err != nil {
		return nil, err
	}
	cond := combineConds(userCond, filterCond)
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

	for i, s := range plan {
		switch s.bucket {
		case "count":
			out["count"] = int(toInt64(vals[i]))
		case "sum":
			out["sum"].(map[string]any)[s.col.Name] = aggScalar(vals[i]) // Decimal string
		case "avg":
			out["avg"].(map[string]any)[s.col.Name] = toFloat(vals[i])
		case "min", "max":
			v, err := convertValue(s.col, vals[i])
			if err != nil {
				return nil, b.dbErr(err)
			}
			out[s.bucket].(map[string]any)[s.col.Name] = v
		}
	}
	return out, nil
}

func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
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
