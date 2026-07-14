package schema

import (
	"context"
	"fmt"

	"github.com/graphql-go/graphql"

	"gqlgate/introspect"
	"gqlgate/rbac"
)

// TiDB has no GIS/spatial types, but it does have native VECTOR columns and
// distance functions — the modern basis for similarity / nearest-neighbor
// search (embeddings, recommendations, "closest to" queries). gqlgate exposes
// each readable VECTOR column as a nearest-neighbor query:
//
//	<t>_nearest_by_<col>(to: Vector!, metric: vector_metric = COSINE,
//	                     first: Int, where: <t>_bool_exp): [<t>_neighbor!]!
//	<t>_neighbor { node: <t>!  distance: Float! }
//
// It runs `... ORDER BY VEC_<metric>_DISTANCE(<col>, :to) ASC LIMIT first`,
// which is top-K search (a distinct access pattern from cursor pagination).

// vectorMetricSQL maps the metric enum value to its TiDB distance function.
var vectorMetricSQL = map[string]string{
	"COSINE":        "VEC_COSINE_DISTANCE",
	"L2":            "VEC_L2_DISTANCE",
	"L1":            "VEC_L1_DISTANCE",
	"INNER_PRODUCT": "VEC_NEGATIVE_INNER_PRODUCT",
}

// vectorColumns returns the readable VECTOR columns of a table.
func (b *builder) vectorColumns(ti *tableInfo) []*introspect.Column {
	if ti.access.Select == nil {
		return nil
	}
	var out []*introspect.Column
	for _, c := range ti.access.Select.Columns {
		if c.DataType == "vector" {
			out = append(out, c)
		}
	}
	return out
}

// addVectorFields adds a nearest-neighbor query per readable vector column.
func (b *builder) addVectorFields(fields graphql.Fields, ti *tableInfo) {
	cols := b.vectorColumns(ti)
	if len(cols) == 0 {
		return
	}
	tn := ti.table.Name
	neighbor := graphql.NewObject(graphql.ObjectConfig{
		Name:        ti.typeName + "_neighbor",
		Description: fmt.Sprintf("A %s row paired with its distance from the query vector.", tn),
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			return graphql.Fields{
				"node":     &graphql.Field{Type: graphql.NewNonNull(b.objTypes[tn]), Resolve: func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "node"), nil }},
				"distance": &graphql.Field{Type: graphql.NewNonNull(graphql.Float), Resolve: func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "distance"), nil }},
			}
		}),
	})

	for _, col := range cols {
		col := col
		fields[ti.typeName+"_nearest_by_"+ti.colToField[col.Name]] = &graphql.Field{
			Type:        graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(neighbor))),
			Description: fmt.Sprintf("Rows of %s ordered by vector distance of %s to `to` (nearest first).", tn, col.Name),
			Args: graphql.FieldConfigArgument{
				"to":     &graphql.ArgumentConfig{Type: graphql.NewNonNull(vectorScalar), Description: "Query vector, e.g. \"[1,2,3]\"."},
				"metric": &graphql.ArgumentConfig{Type: b.vectorMetricEnum(), Description: "Distance metric (default COSINE)."},
				"first":  &graphql.ArgumentConfig{Type: graphql.Int, Description: "Max neighbors (defaults to default_page_size, clamped to max_page_size)."},
				"where":  &graphql.ArgumentConfig{Type: b.boolExps[tn]},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				id, err := identityFrom(p)
				if err != nil {
					return nil, err
				}
				to, _ := p.Args["to"].(string)
				metric := "COSINE"
				if m, ok := p.Args["metric"].(string); ok {
					metric = m
				}
				fn, ok := vectorMetricSQL[metric]
				if !ok {
					return nil, fmt.Errorf("unknown vector metric %q", metric)
				}
				first := b.opt.Config.SchemaGen.DefaultPageSize
				if f, ok := p.Args["first"].(int); ok {
					first = f
				}
				if first < 0 {
					return nil, fmt.Errorf("first must be >= 0")
				}
				if first > b.opt.Config.SchemaGen.MaxPageSize {
					first = b.opt.Config.SchemaGen.MaxPageSize
				}
				where, _ := p.Args["where"].(map[string]any)
				return b.runNearest(p.Context, ti, id, col, fn, to, where, first)
			},
		}
	}
}

// vectorMetricEnum is the shared metric enum (built once per schema).
func (b *builder) vectorMetricEnum() *graphql.Enum {
	if b.metricEnum != nil {
		return b.metricEnum
	}
	b.metricEnum = graphql.NewEnum(graphql.EnumConfig{
		Name:        "vector_metric",
		Description: "Vector distance metric.",
		Values: graphql.EnumValueConfigMap{
			"COSINE":        &graphql.EnumValueConfig{Value: "COSINE"},
			"L2":            &graphql.EnumValueConfig{Value: "L2"},
			"L1":            &graphql.EnumValueConfig{Value: "L1"},
			"INNER_PRODUCT": &graphql.EnumValueConfig{Value: "INNER_PRODUCT"},
		},
	})
	return b.metricEnum
}

// runNearest runs the top-K vector search: readable columns plus the distance,
// ordered nearest-first, honoring the role's row filter and any where. The
// query vector is bound as a parameter.
func (b *builder) runNearest(ctx context.Context, ti *tableInfo, id *rbac.Identity, col *introspect.Column, distFn, to string, where map[string]any, first int) ([]map[string]any, error) {
	sel := ti.access.Select
	var userCond *condition
	var err error
	if where != nil {
		if userCond, err = b.whereSQL(ti, where); err != nil {
			return nil, err
		}
	}
	filterCond, err := rbacCond(sel, id)
	if err != nil {
		return nil, err
	}
	// Exclude NULL vectors: VEC_*_DISTANCE(NULL, ?) is NULL, which sorts first
	// under ASC and would violate the non-null `distance` field (nulling the
	// whole result). A NULL vector has no meaningful distance anyway.
	notNull := &condition{sql: quoteIdent(col.Name) + " IS NOT NULL"}
	cond := combineConds(userCond, filterCond, notNull)

	distExpr := distFn + "(" + quoteIdent(col.Name) + ", ?)"
	query := "SELECT " + selectList(sel.Columns) + ", " + distExpr + " AS __gqlgate_dist" +
		" FROM " + b.qualifiedTable(ti.table) + " WHERE " + cond.sql +
		" ORDER BY __gqlgate_dist ASC LIMIT ?"
	// The distance-function vector arg is bound before the WHERE args in SQL
	// text order (SELECT precedes WHERE), so it leads the arg list.
	args := append([]any{to}, cond.args...)
	args = append(args, first)

	b.logSQL(query, args)
	rows, err := b.opt.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, b.dbErr(err)
	}
	defer rows.Close()

	scanCols := append(append([]*introspect.Column{}, sel.Columns...), nil) // last slot = distance
	out := []map[string]any{}
	for rows.Next() {
		vals := make([]any, len(scanCols))
		ptrs := make([]any, len(scanCols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, b.dbErr(err)
		}
		node := make(map[string]any, len(sel.Columns))
		for i, c := range sel.Columns {
			v, err := convertValue(c, vals[i])
			if err != nil {
				return nil, b.dbErr(err)
			}
			node[c.Name] = v
		}
		out = append(out, map[string]any{"node": node, "distance": toFloat(vals[len(sel.Columns)])})
	}
	if err := rows.Err(); err != nil {
		return nil, b.dbErr(err)
	}
	return out, nil
}
