// Package schema turns an introspected catalog plus resolved RBAC rules into
// executable GraphQL schemas — one schema per role, so introspection (and
// therefore GraphiQL autocompletion) only ever shows what the role may touch.
package schema

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	"github.com/graphql-go/graphql"

	"gqlgate/config"
	"gqlgate/introspect"
	"gqlgate/rbac"
)

// Options carries everything needed to build the per-role schemas.
type Options struct {
	DB      *sql.DB
	Catalog *introspect.Catalog
	Config  *config.Config
	Logger  *slog.Logger
	Hooks   *Hooks // optional lifecycle hooks + custom fields; nil = none
}

// BuildAll builds one GraphQL schema per configured role.
func BuildAll(opt Options) (map[string]graphql.Schema, error) {
	if err := checkNameCollisions(opt.Catalog); err != nil {
		return nil, err
	}
	out := make(map[string]graphql.Schema, len(opt.Config.Roles))
	for roleName, role := range opt.Config.Roles {
		access, err := rbac.Resolve(roleName, role, opt.Catalog)
		if err != nil {
			return nil, err
		}
		s, err := buildRole(opt, roleName, access)
		if err != nil {
			return nil, fmt.Errorf("building schema for role %q: %w", roleName, err)
		}
		out[roleName] = s
	}
	return out, nil
}

// scalarTypeNames are every scalar name that can appear in a generated schema,
// including the GraphQL builtins. Used to reserve their names (and their
// comparison-exp derivatives) against colliding table-derived type names.
var scalarTypeNames = []string{
	"String", "Int", "Float", "Boolean", "ID",
	"BigInt", "Decimal", "DateTime", "Date", "JSON", "Bytes", "Vector",
}

// checkNameCollisions rejects catalogs where two SQL identifiers sanitize to
// the same GraphQL name. It covers not just base table/column names but also
// the derived root-field names (<t>_connection, <t>_by_pk, <t>_aggregate,
// insert_<t>, …) and the generated/reserved type names (<t>_bool_exp,
// page_info, order_by, Query, …). Without this, a legal pair like tables
// `users` + `users_connection` would either silently clobber a field in the
// graphql.Fields map, or make graphql.NewSchema fail at startup with a cryptic
// "unique named types" error. Catching it here (independent of role) turns
// those into an actionable startup message pointing at the offending table.
func checkNameCollisions(cat *introspect.Catalog) error {
	seenTables := map[string]string{}
	for _, tn := range cat.TableOrder {
		n := graphqlName(tn)
		if other, dup := seenTables[n]; dup {
			return fmt.Errorf("tables %q and %q both map to GraphQL name %q; exclude one via schema_gen.tables", other, tn, n)
		}
		seenTables[n] = tn
		seenCols := map[string]string{}
		for _, c := range cat.Tables[tn].Columns {
			cn := graphqlName(c.Name)
			if other, dup := seenCols[cn]; dup {
				return fmt.Errorf("table %q: columns %q and %q both map to GraphQL name %q", tn, other, c.Name, cn)
			}
			seenCols[cn] = c.Name
		}
	}

	// Query field namespace.
	queryFields := map[string]string{"_role": "(built-in)"}
	// Mutation field namespace.
	mutationFields := map[string]string{}
	// Global type namespace, pre-seeded with the fixed and scalar type names.
	types := map[string]string{
		"Query": "(built-in)", "Mutation": "(built-in)",
		"order_by": "(built-in)", "mutation_response": "(built-in)",
		"page_info": "(built-in)", "vector_metric": "(built-in)",
	}
	for _, s := range scalarTypeNames {
		types[s] = "(built-in scalar)"
		types[s+"_comparison_exp"] = "(built-in)"
	}

	claim := func(ns map[string]string, name, owner, kind string) error {
		if other, dup := ns[name]; dup {
			return fmt.Errorf("generated %s name %q for table %q collides with %s; rename or exclude one table via schema_gen.tables",
				kind, name, owner, other)
		}
		ns[name] = "table " + owner
		return nil
	}

	for _, tn := range cat.TableOrder {
		n := graphqlName(tn)
		queryOf := []string{n + "_by_pk", n + "_connection", n + "_aggregate"}
		mutOf := []string{
			"insert_" + n, "insert_" + n + "_one",
			"update_" + n, "update_" + n + "_by_pk",
			"delete_" + n, "delete_" + n + "_by_pk",
		}
		typeOf := []string{
			n, n + "_bool_exp", n + "_order_by", n + "_insert_input", n + "_set_input",
			n + "_connection", n + "_aggregate_result",
			n + "_sum_fields", n + "_avg_fields", n + "_min_fields", n + "_max_fields",
			n + "_neighbor",
		}
		// A nearest-neighbor query field per vector column.
		for _, c := range cat.Tables[tn].Columns {
			if c.DataType == "vector" {
				queryOf = append(queryOf, n+"_nearest_by_"+graphqlName(c.Name))
			}
		}
		for _, f := range queryOf {
			if err := claim(queryFields, f, tn, "query field"); err != nil {
				return err
			}
		}
		for _, f := range mutOf {
			if err := claim(mutationFields, f, tn, "mutation field"); err != nil {
				return err
			}
		}
		for _, t := range typeOf {
			if err := claim(types, t, tn, "type"); err != nil {
				return err
			}
		}
	}
	return nil
}

// tableInfo is the per-role view of one table.
type tableInfo struct {
	table      *introspect.Table
	access     *rbac.TableAccess
	typeName   string
	fieldToCol map[string]*introspect.Column // GraphQL field name -> column
	colToField map[string]string             // column name -> GraphQL field name
}

type builder struct {
	opt        Options
	role       string
	access     *rbac.Access
	tinfos     map[string]*tableInfo
	objTypes   map[string]*graphql.Object
	connTypes  map[string]*graphql.Object
	boolExps   map[string]*graphql.InputObject
	orderBys   map[string]*graphql.InputObject
	cmpExps    map[string]*graphql.InputObject
	orderEnum  *graphql.Enum
	mutResp    *graphql.Object
	pageInfo   *graphql.Object
	metricEnum *graphql.Enum
}

func buildRole(opt Options, roleName string, access *rbac.Access) (graphql.Schema, error) {
	b := &builder{
		opt:       opt,
		role:      roleName,
		access:    access,
		tinfos:    map[string]*tableInfo{},
		objTypes:  map[string]*graphql.Object{},
		connTypes: map[string]*graphql.Object{},
		boolExps:  map[string]*graphql.InputObject{},
		orderBys:  map[string]*graphql.InputObject{},
		cmpExps:   map[string]*graphql.InputObject{},
	}

	// page_info is the cursor-pagination metadata, shared by every connection.
	b.pageInfo = graphql.NewObject(graphql.ObjectConfig{
		Name:        "page_info",
		Description: "Cursor-pagination metadata: whether more rows follow, and the cursor to resume after.",
		Fields: graphql.Fields{
			"has_next_page": &graphql.Field{
				Type:        graphql.NewNonNull(graphql.Boolean),
				Description: "True when more rows exist after this page.",
				Resolve:     func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "has_next_page"), nil },
			},
			"end_cursor": &graphql.Field{
				Type:        graphql.String,
				Description: "Opaque cursor for the last row; pass as `after` to fetch the next page. Null on an empty page.",
				Resolve:     func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "end_cursor"), nil },
			},
		},
	})

	b.orderEnum = graphql.NewEnum(graphql.EnumConfig{
		Name:        "order_by",
		Description: "Sort direction.",
		Values: graphql.EnumValueConfigMap{
			"asc":  &graphql.EnumValueConfig{Value: "ASC"},
			"desc": &graphql.EnumValueConfig{Value: "DESC"},
		},
	})
	b.mutResp = graphql.NewObject(graphql.ObjectConfig{
		Name: "mutation_response",
		Fields: graphql.Fields{
			"affected_rows": &graphql.Field{
				Type: graphql.NewNonNull(graphql.Int),
				Resolve: func(p graphql.ResolveParams) (any, error) {
					m, _ := p.Source.(map[string]any)
					return m["affected_rows"], nil
				},
			},
		},
	})

	// Pass 1: per-role table views for every table the role can touch at all.
	for _, tn := range opt.Catalog.TableOrder {
		ta := access.Table(tn)
		if ta == nil {
			continue
		}
		t := opt.Catalog.Tables[tn]
		ti := &tableInfo{
			table:      t,
			access:     ta,
			typeName:   graphqlName(tn),
			fieldToCol: map[string]*introspect.Column{},
			colToField: map[string]string{},
		}
		for _, c := range t.Columns {
			f := graphqlName(c.Name)
			ti.fieldToCol[f] = c
			ti.colToField[c.Name] = f
		}
		b.tinfos[tn] = ti
	}

	// Pass 2: types for select-able tables (mutation-only tables get none).
	for _, tn := range opt.Catalog.TableOrder {
		ti := b.tinfos[tn]
		if ti == nil || ti.access.Select == nil {
			continue
		}
		b.objTypes[tn] = b.buildObjectType(ti)
		b.boolExps[tn] = b.buildBoolExp(ti)
		b.orderBys[tn] = b.buildOrderBy(ti)
	}

	// Connection types (cursor pagination) for tables with a readable PK — the
	// PK gives the batch a stable total order and the cursor a resume point.
	for _, tn := range opt.Catalog.TableOrder {
		ti := b.tinfos[tn]
		if ti == nil || !b.pkExposable(ti) {
			continue
		}
		b.connTypes[tn] = b.buildConnectionType(ti)
	}

	// Pass 3: root fields.
	queryFields := graphql.Fields{
		"_role": &graphql.Field{
			Type:        graphql.NewNonNull(graphql.String),
			Description: "The role this request was authorized as.",
			Resolve: func(p graphql.ResolveParams) (any, error) {
				id, err := identityFrom(p)
				if err != nil {
					return nil, err
				}
				return id.Role, nil
			},
		},
	}
	mutationFields := graphql.Fields{}
	for _, tn := range opt.Catalog.TableOrder {
		ti := b.tinfos[tn]
		if ti == nil {
			continue
		}
		if ti.access.Select != nil {
			b.addQueryFields(queryFields, ti)
		}
		b.addMutationFields(mutationFields, ti)
	}

	// Developer-provided custom fields (e.g. a signup mutation) visible to
	// this role. They win over generated fields of the same name, and a
	// collision is reported so it can't silently shadow a table operation.
	if err := b.addCustomFields(queryFields, "query"); err != nil {
		return graphql.Schema{}, err
	}
	if err := b.addCustomFields(mutationFields, "mutation"); err != nil {
		return graphql.Schema{}, err
	}

	schemaCfg := graphql.SchemaConfig{
		Query: graphql.NewObject(graphql.ObjectConfig{Name: "Query", Fields: queryFields}),
	}
	if len(mutationFields) > 0 {
		schemaCfg.Mutation = graphql.NewObject(graphql.ObjectConfig{Name: "Mutation", Fields: mutationFields})
	}
	return graphql.NewSchema(schemaCfg)
}

// addCustomFields mounts the role's custom fields of the given operation onto
// the root field map, rejecting names that collide with generated fields.
func (b *builder) addCustomFields(fields graphql.Fields, operation string) error {
	for _, cf := range b.opt.Hooks.customFieldsFor(b.role, operation) {
		if cf.Name == "" || cf.Field == nil {
			return fmt.Errorf("custom %s field must have a non-empty Name and Field", operation)
		}
		if _, taken := fields[cf.Name]; taken {
			return fmt.Errorf("custom %s field %q collides with a generated field for role %q", operation, cf.Name, b.role)
		}
		fields[cf.Name] = cf.Field
	}
	return nil
}

func identityFrom(p graphql.ResolveParams) (*rbac.Identity, error) {
	if id, ok := rbac.IdentityFrom(p.Context); ok {
		return id, nil
	}
	return nil, fmt.Errorf("unauthenticated request")
}

// buildObjectType creates the output type of one table: its readable columns
// plus relationship fields derived from foreign keys.
func (b *builder) buildObjectType(ti *tableInfo) *graphql.Object {
	return graphql.NewObject(graphql.ObjectConfig{
		Name:        ti.typeName,
		Description: fmt.Sprintf("Row of table %s.%s", b.opt.Catalog.SchemaName, ti.table.Name),
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			fields := graphql.Fields{}
			for _, col := range ti.access.Select.Columns {
				col := col
				sc := scalarFor(col)
				var t graphql.Output = sc
				// A `json NOT NULL` column can still hold the JSON literal
				// `null` (a valid document, distinct from SQL NULL). GraphQL
				// cannot return null for a NonNull field, and the null would
				// propagate up through the NonNull list and blank the whole
				// response — so JSON fields are always nullable.
				if !col.Nullable && sc.Name() != "JSON" {
					t = graphql.NewNonNull(t)
				}
				fields[ti.colToField[col.Name]] = &graphql.Field{
					Type:        t,
					Description: fmt.Sprintf("Column %s (%s)", col.Name, col.ColumnType),
					Resolve: func(p graphql.ResolveParams) (any, error) {
						row, _ := p.Source.(map[string]any)
						return row[col.Name], nil
					},
				}
			}
			b.addRelationFields(ti, fields)
			return fields
		}),
	})
}

// relFieldName picks a free field name for a relationship, appending
// deterministic suffixes when the candidate is taken.
func relFieldName(fields graphql.Fields, candidate string, fk *introspect.ForeignKey) string {
	if _, taken := fields[candidate]; !taken {
		return candidate
	}
	cols := make([]string, len(fk.Columns))
	for i, c := range fk.Columns {
		cols[i] = graphqlName(c)
	}
	candidate = candidate + "_by_" + strings.Join(cols, "_")
	for i := 0; ; i++ {
		name := candidate
		if i > 0 {
			name = fmt.Sprintf("%s_%d", candidate, i)
		}
		if _, taken := fields[name]; !taken {
			return name
		}
	}
}

func (b *builder) addRelationFields(ti *tableInfo, fields graphql.Fields) {
	sel := ti.access.Select

	// Outgoing: this table's FK -> one row of the referenced table.
	for _, fk := range ti.table.ForeignKeys {
		fk := fk
		target := b.tinfos[fk.RefTable]
		if target == nil || target.access.Select == nil {
			continue
		}
		// The parent row map only holds readable columns, and the join needs
		// the local FK values — so those must be readable for this role.
		readable := true
		for _, c := range fk.Columns {
			if !sel.ColumnSet[c] {
				readable = false
				break
			}
		}
		if !readable {
			continue
		}
		candidate := graphqlName(fk.RefTable)
		if len(fk.Columns) == 1 && strings.HasSuffix(fk.Columns[0], "_id") && len(fk.Columns[0]) > 3 {
			candidate = graphqlName(strings.TrimSuffix(fk.Columns[0], "_id"))
		}
		name := relFieldName(fields, candidate, fk)
		// Batch only when the target's referenced columns (the grouping key)
		// are readable for this role; otherwise fall back to a per-row query.
		batchable := columnsReadable(target, fk.RefColumns)
		fields[name] = &graphql.Field{
			Type:        b.objTypes[fk.RefTable],
			Description: fmt.Sprintf("Row of %s referenced by %s", fk.RefTable, strings.Join(fk.Columns, ", ")),
			Resolve: func(p graphql.ResolveParams) (any, error) {
				id, err := identityFrom(p)
				if err != nil {
					return nil, err
				}
				row, _ := p.Source.(map[string]any)
				key := make([]any, len(fk.Columns))
				for i, lc := range fk.Columns {
					v := row[lc]
					if v == nil {
						return nil, nil // NULL FK -> no related row
					}
					key[i] = v
				}

				if !batchable {
					parts := make([]string, len(fk.RefColumns))
					for i, rc := range fk.RefColumns {
						parts[i] = quoteIdent(rc) + " = ?"
					}
					rows, err := b.runSelect(p.Context, target, id, listArgs{},
						&condition{sql: strings.Join(parts, " AND "), args: key}, true)
					if err != nil {
						return nil, err
					}
					if len(rows) == 0 {
						return nil, nil
					}
					return rows[0], nil
				}

				loader := loadersFrom(p.Context).getOrCreate(
					loaderKey("out", fk.ConstraintName, ""),
					func() *relLoader {
						return newRelLoader(func(ctx context.Context, keys [][]any) (map[string][]map[string]any, error) {
							// To-one: each referenced key yields at most one row.
							rows, err := b.runSelectByKeys(ctx, target, id, fk.RefColumns, keys, nil, nil, 0)
							if err != nil {
								return nil, err
							}
							return groupByColumns(rows, fk.RefColumns), nil
						})
					})
				loader.enqueue(key)
				return func() (any, error) {
					rows, err := loader.fetch(p.Context, key)
					if err != nil {
						return nil, err
					}
					if len(rows) == 0 {
						return nil, nil
					}
					return rows[0], nil // FK references a unique key
				}, nil
			},
		}
	}

	// Incoming: FKs on other tables pointing here -> list of child rows.
	for _, fk := range ti.table.IncomingFKs {
		fk := fk
		child := b.tinfos[fk.Table]
		if child == nil || child.access.Select == nil {
			continue
		}
		readable := true
		for _, rc := range fk.RefColumns {
			if !sel.ColumnSet[rc] {
				readable = false
				break
			}
		}
		if !readable {
			continue
		}
		name := relFieldName(fields, graphqlName(fk.Table), fk)
		// Batch only when the child's FK columns (the grouping key) are
		// readable for this role; otherwise fall back to a per-row query.
		batchable := columnsReadable(child, fk.Columns)
		fields[name] = &graphql.Field{
			Type:        graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(b.objTypes[fk.Table]))),
			Description: fmt.Sprintf("Rows of %s whose %s reference this row", fk.Table, strings.Join(fk.Columns, ", ")),
			Args:        b.listFieldArgs(fk.Table),
			Resolve: func(p graphql.ResolveParams) (any, error) {
				id, err := identityFrom(p)
				if err != nil {
					return nil, err
				}
				row, _ := p.Source.(map[string]any)
				key := make([]any, len(fk.RefColumns))
				for i, rc := range fk.RefColumns {
					v := row[rc]
					if v == nil {
						return []map[string]any{}, nil
					}
					key[i] = v
				}
				la, err := extractListArgs(p.Args)
				if err != nil {
					return nil, err
				}

				if !batchable {
					parts := make([]string, len(fk.Columns))
					for i, cc := range fk.Columns {
						parts[i] = quoteIdent(cc) + " = ?"
					}
					rows, err := b.runSelect(p.Context, child, id, la,
						&condition{sql: strings.Join(parts, " AND "), args: key}, false)
					if err != nil {
						return nil, err
					}
					if rows == nil {
						rows = []map[string]any{}
					}
					return rows, nil
				}

				// One windowed query fetches up to (limit+offset) children per
				// parent; each group is paged in memory below. The loader is
				// keyed by all list args (incl. limit/offset) so batches with
				// different page sizes don't share the capped fetch.
				limit, offset, err := b.pageBounds(la)
				if err != nil {
					return nil, err
				}
				perKey := limit + offset
				loader := loadersFrom(p.Context).getOrCreate(
					loaderKey("in", fk.ConstraintName, argsSignature(la)),
					func() *relLoader {
						return newRelLoader(func(ctx context.Context, keys [][]any) (map[string][]map[string]any, error) {
							rows, err := b.runSelectByKeys(ctx, child, id, fk.Columns, keys, la.where, la.orderBy, perKey)
							if err != nil {
								return nil, err
							}
							return groupByColumns(rows, fk.Columns), nil
						})
					})
				loader.enqueue(key)
				return func() (any, error) {
					rows, err := loader.fetch(p.Context, key)
					if err != nil {
						return nil, err
					}
					page, err := b.applyPage(rows, la)
					if err != nil {
						return nil, err
					}
					return page, nil
				}, nil
			},
		}
	}
}

func (b *builder) buildBoolExp(ti *tableInfo) *graphql.InputObject {
	var boolExp *graphql.InputObject
	boolExp = graphql.NewInputObject(graphql.InputObjectConfig{
		Name:        ti.typeName + "_bool_exp",
		Description: fmt.Sprintf("Row filter for %s.", ti.table.Name),
		Fields: (graphql.InputObjectConfigFieldMapThunk)(func() graphql.InputObjectConfigFieldMap {
			f := graphql.InputObjectConfigFieldMap{
				"_and": &graphql.InputObjectFieldConfig{Type: graphql.NewList(graphql.NewNonNull(boolExp))},
				"_or":  &graphql.InputObjectFieldConfig{Type: graphql.NewList(graphql.NewNonNull(boolExp))},
				"_not": &graphql.InputObjectFieldConfig{Type: boolExp},
			}
			for _, col := range ti.access.Select.Columns {
				f[ti.colToField[col.Name]] = &graphql.InputObjectFieldConfig{Type: b.cmpExp(scalarFor(col))}
			}
			return f
		}),
	})
	return boolExp
}

// cmpExp returns (building on first use) the comparison input type for one
// scalar, e.g. String_comparison_exp with _eq/_like/_in/...
func (b *builder) cmpExp(s *graphql.Scalar) *graphql.InputObject {
	if e, ok := b.cmpExps[s.Name()]; ok {
		return e
	}
	f := graphql.InputObjectConfigFieldMap{
		"_eq":      &graphql.InputObjectFieldConfig{Type: s},
		"_neq":     &graphql.InputObjectFieldConfig{Type: s},
		"_is_null": &graphql.InputObjectFieldConfig{Type: graphql.Boolean},
	}
	switch s.Name() {
	case "JSON":
		// TiDB JSON predicates: _contains (JSON_CONTAINS) and _has_key
		// (JSON_CONTAINS_PATH on a top-level key).
		f["_contains"] = &graphql.InputObjectFieldConfig{Type: s}
		f["_has_key"] = &graphql.InputObjectFieldConfig{Type: graphql.String}
	case "Boolean":
		// equality only
	default:
		f["_gt"] = &graphql.InputObjectFieldConfig{Type: s}
		f["_gte"] = &graphql.InputObjectFieldConfig{Type: s}
		f["_lt"] = &graphql.InputObjectFieldConfig{Type: s}
		f["_lte"] = &graphql.InputObjectFieldConfig{Type: s}
		f["_in"] = &graphql.InputObjectFieldConfig{Type: graphql.NewList(graphql.NewNonNull(s))}
		f["_nin"] = &graphql.InputObjectFieldConfig{Type: graphql.NewList(graphql.NewNonNull(s))}
		if s.Name() == "String" {
			f["_like"] = &graphql.InputObjectFieldConfig{Type: s}
			f["_nlike"] = &graphql.InputObjectFieldConfig{Type: s}
			// TiDB REGEXP (RE2). _regex / _nregex.
			f["_regex"] = &graphql.InputObjectFieldConfig{Type: s}
			f["_nregex"] = &graphql.InputObjectFieldConfig{Type: s}
		}
	}
	e := graphql.NewInputObject(graphql.InputObjectConfig{
		Name:   s.Name() + "_comparison_exp",
		Fields: f,
	})
	b.cmpExps[s.Name()] = e
	return e
}

func (b *builder) buildOrderBy(ti *tableInfo) *graphql.InputObject {
	f := graphql.InputObjectConfigFieldMap{}
	for _, col := range ti.access.Select.Columns {
		f[ti.colToField[col.Name]] = &graphql.InputObjectFieldConfig{Type: b.orderEnum}
	}
	return graphql.NewInputObject(graphql.InputObjectConfig{
		Name:        ti.typeName + "_order_by",
		Description: "Sort spec; use one column per entry for multi-key ordering.",
		Fields:      f,
	})
}

func (b *builder) listFieldArgs(tableName string) graphql.FieldConfigArgument {
	return graphql.FieldConfigArgument{
		"where":    &graphql.ArgumentConfig{Type: b.boolExps[tableName]},
		"order_by": &graphql.ArgumentConfig{Type: graphql.NewList(graphql.NewNonNull(b.orderBys[tableName]))},
		"limit":    &graphql.ArgumentConfig{Type: graphql.Int},
		"offset":   &graphql.ArgumentConfig{Type: graphql.Int},
	}
}

// pkExposable reports whether by-primary-key fields may be generated for this
// role: the table must have a PK and every PK column must be readable. This
// keeps by_pk from becoming an oracle on a PK column the role's select grant
// deliberately omits — the same invariant whereSQL/orderSQL enforce for
// filter and sort columns.
func (b *builder) pkExposable(ti *tableInfo) bool {
	if len(ti.table.PrimaryKey) == 0 || ti.access.Select == nil {
		return false
	}
	for _, pk := range ti.table.PrimaryKey {
		if !ti.access.Select.ColumnSet[pk] {
			return false
		}
	}
	return true
}

// pkArgs builds by-primary-key arguments (one per PK column).
func (b *builder) pkArgs(ti *tableInfo) graphql.FieldConfigArgument {
	args := graphql.FieldConfigArgument{}
	for _, pkName := range ti.table.PrimaryKey {
		col := ti.table.ColumnMap[pkName]
		args[ti.colToField[pkName]] = &graphql.ArgumentConfig{Type: graphql.NewNonNull(scalarFor(col))}
	}
	return args
}

func (b *builder) addQueryFields(fields graphql.Fields, ti *tableInfo) {
	// Collection reads are cursor-only (keyset pagination): <t>_connection for
	// pages and <t>_aggregate for counts/sum/avg/etc. There is deliberately no
	// offset-paginated list or standalone _count — offset scans don't scale to
	// TiDB's billions-of-rows tables.
	b.addAggregateField(fields, ti)
	b.addVectorFields(fields, ti) // nearest-neighbor search per vector column

	tn := ti.table.Name
	if b.pkExposable(ti) {
		fields[ti.typeName+"_by_pk"] = &graphql.Field{
			Type:        b.objTypes[tn],
			Description: fmt.Sprintf("One row of %s by primary key.", tn),
			Args:        b.pkArgs(ti),
			Resolve: func(p graphql.ResolveParams) (any, error) {
				id, err := identityFrom(p)
				if err != nil {
					return nil, err
				}
				cond, err := b.pkCond(ti, p.Args)
				if err != nil {
					return nil, err
				}
				rows, err := b.runSelect(p.Context, ti, id, listArgs{}, cond, true)
				if err != nil {
					return nil, err
				}
				if len(rows) == 0 {
					return nil, nil
				}
				return rows[0], nil
			},
		}
		b.addConnectionField(fields, ti)
	}
}

// addConnectionField adds `<t>_connection(first, after, where)`, the
// cursor-paginated view. The client walks pages by passing the previous
// page's page_info.end_cursor back as `after` — never touching offsets. It
// uses KEYSET pagination on the clustered primary key (a range scan, no sort,
// constant cost per page over billions of rows), so results come back in
// primary-key order with no arbitrary ORDER BY. It is gated on a readable PK
// (the caller checks pkExposable), which the cursor seeks on. total_count is a
// separate field, so COUNT only runs when the client selects it.
func (b *builder) addConnectionField(fields graphql.Fields, ti *tableInfo) {
	tn := ti.table.Name
	fields[ti.typeName+"_connection"] = &graphql.Field{
		Type:        graphql.NewNonNull(b.connTypes[tn]),
		Description: fmt.Sprintf("Keyset cursor-paginated %s: read nodes + page_info; pass page_info.end_cursor as `after` for the next page.", tn),
		Args: graphql.FieldConfigArgument{
			"first": &graphql.ArgumentConfig{Type: graphql.Int, Description: "Page size (defaults to default_page_size, clamped to max_page_size)."},
			"after": &graphql.ArgumentConfig{Type: graphql.String, Description: "Cursor from a previous page's page_info.end_cursor."},
			"where": &graphql.ArgumentConfig{Type: b.boolExps[tn]},
		},
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, err := identityFrom(p)
			if err != nil {
				return nil, err
			}
			where, _ := p.Args["where"].(map[string]any)

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

			// The cursor is bound to this exact filter (shape); reusing one
			// across a different where is rejected rather than mispaging.
			shape := cursorShape(tn, where)
			var after *condition
			if a, ok := p.Args["after"].(string); ok && a != "" {
				keys, err := decodeCursor(a, shape, len(ti.table.PrimaryKey))
				if err != nil {
					return nil, err
				}
				after = keysetCondition(ti.table.PrimaryKey, keys)
			}

			// Fetch one extra row to learn whether another page follows,
			// without a COUNT.
			rows, err := b.runKeysetPage(p.Context, ti, id, where, after, first+1)
			if err != nil {
				return nil, err
			}
			hasNext := len(rows) > first
			if hasNext {
				rows = rows[:first]
			}
			// A zero-size page (first: 0) must not claim a next page with no
			// cursor to advance with; keep has_next_page consistent with
			// end_cursor.
			if len(rows) == 0 {
				hasNext = false
			}
			var endCursor any
			if len(rows) > 0 {
				last := rows[len(rows)-1]
				keys := make([]string, len(ti.table.PrimaryKey))
				for i, pk := range ti.table.PrimaryKey {
					keys[i] = stringifyKey(last[pk])
				}
				endCursor = encodeCursor(keys, shape)
			}
			if rows == nil {
				rows = []map[string]any{}
			}

			// total_count is resolved lazily: this closure only runs the COUNT
			// if the client selected the total_count field.
			countFn := func() (int, error) {
				n, err := b.runCount(p.Context, ti, id, where)
				return int(n), err
			}
			return map[string]any{
				"nodes": rows,
				"count": countFn,
				"page_info": map[string]any{
					"has_next_page": hasNext,
					"end_cursor":    endCursor,
				},
			}, nil
		},
	}
}

// buildConnectionType is the <t>_connection object: nodes + page_info +
// total_count, all read from the map the connection resolver returns.
func (b *builder) buildConnectionType(ti *tableInfo) *graphql.Object {
	tn := ti.table.Name
	return graphql.NewObject(graphql.ObjectConfig{
		Name:        ti.typeName + "_connection",
		Description: fmt.Sprintf("A page of %s rows with cursor-pagination metadata.", tn),
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			return graphql.Fields{
				"nodes": &graphql.Field{
					Type:        graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(b.objTypes[tn]))),
					Description: "The rows in this page.",
					Resolve:     func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "nodes"), nil },
				},
				"page_info": &graphql.Field{
					Type:        graphql.NewNonNull(b.pageInfo),
					Description: "Whether more rows follow and the cursor to resume after.",
					Resolve:     func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "page_info"), nil },
				},
				"total_count": &graphql.Field{
					Type:        graphql.NewNonNull(graphql.Int),
					Description: "Total rows matching the filter across all pages. Runs a COUNT only when selected — can be slow on very large tables.",
					Resolve: func(p graphql.ResolveParams) (any, error) {
						fn, ok := sourceKey(p, "count").(func() (int, error))
						if !ok {
							return 0, nil
						}
						return fn()
					},
				},
			}
		}),
	})
}

// sourceKey reads a key from the map a resolver placed in p.Source.
func sourceKey(p graphql.ResolveParams, key string) any {
	m, _ := p.Source.(map[string]any)
	return m[key]
}

// insertInput builds the insert input type: writable columns minus presets.
// Returns nil when no client-settable column remains.
func (b *builder) insertInput(ti *tableInfo) *graphql.InputObject {
	oa := ti.access.Insert
	preset := map[string]bool{}
	for _, p := range oa.Presets {
		preset[p.Column.Name] = true
	}
	f := graphql.InputObjectConfigFieldMap{}
	for _, col := range oa.Columns {
		if preset[col.Name] || col.Generated {
			continue // generated columns reject any client-supplied value
		}
		var t graphql.Input = scalarFor(col)
		if !col.Nullable && !col.HasDefault && !col.AutoIncrement {
			t = graphql.NewNonNull(t)
		}
		f[ti.colToField[col.Name]] = &graphql.InputObjectFieldConfig{Type: t}
	}
	if len(f) == 0 {
		return nil
	}
	return graphql.NewInputObject(graphql.InputObjectConfig{
		Name:   ti.typeName + "_insert_input",
		Fields: f,
	})
}

// setInput builds the update _set input type: writable columns minus presets.
func (b *builder) setInput(ti *tableInfo) *graphql.InputObject {
	oa := ti.access.Update
	preset := map[string]bool{}
	for _, p := range oa.Presets {
		preset[p.Column.Name] = true
	}
	f := graphql.InputObjectConfigFieldMap{}
	for _, col := range oa.Columns {
		if preset[col.Name] || col.Generated {
			continue // generated columns reject any client-supplied value
		}
		f[ti.colToField[col.Name]] = &graphql.InputObjectFieldConfig{Type: scalarFor(col)}
	}
	if len(f) == 0 {
		return nil
	}
	return graphql.NewInputObject(graphql.InputObjectConfig{
		Name:   ti.typeName + "_set_input",
		Fields: f,
	})
}

func (b *builder) addMutationFields(fields graphql.Fields, ti *tableInfo) {
	tn := ti.table.Name

	if ti.access.Insert != nil {
		if input := b.insertInput(ti); input != nil {
			fields["insert_"+ti.typeName] = &graphql.Field{
				Type:        graphql.NewNonNull(b.mutResp),
				Description: fmt.Sprintf("Insert rows into %s.", tn),
				Args: graphql.FieldConfigArgument{
					"objects": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(input)))},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					id, err := identityFrom(p)
					if err != nil {
						return nil, err
					}
					objects, _ := p.Args["objects"].([]any)
					affected, _, _, err := b.runInsert(p.Context, ti, id, objects)
					if err != nil {
						return nil, err
					}
					return map[string]any{"affected_rows": int(affected)}, nil
				},
			}

			// insert_one returns the inserted row, so it needs read access
			// and a readable primary key to find the row again.
			if b.pkExposable(ti) {
				fields["insert_"+ti.typeName+"_one"] = &graphql.Field{
					Type:        b.objTypes[tn],
					Description: fmt.Sprintf("Insert one row into %s and return it (null if your select filter hides it).", tn),
					Args: graphql.FieldConfigArgument{
						"object": &graphql.ArgumentConfig{Type: graphql.NewNonNull(input)},
					},
					Resolve: func(p graphql.ResolveParams) (any, error) {
						id, err := identityFrom(p)
						if err != nil {
							return nil, err
						}
						obj := p.Args["object"]
						_, lastID, values, err := b.runInsert(p.Context, ti, id, []any{obj})
						if err != nil {
							return nil, err
						}
						cond, ok := b.insertedPKCond(ti, lastID, values)
						if !ok {
							return nil, nil // PK unknown (e.g. composite key left to defaults)
						}
						rows, err := b.runSelect(p.Context, ti, id, listArgs{}, cond, true)
						if err != nil {
							return nil, err
						}
						if len(rows) == 0 {
							return nil, nil
						}
						return rows[0], nil
					},
				}
			}
		}
	}

	if ti.access.Update != nil && ti.access.Select != nil {
		if setInput := b.setInput(ti); setInput != nil {
			fields["update_"+ti.typeName] = &graphql.Field{
				Type:        graphql.NewNonNull(b.mutResp),
				Description: fmt.Sprintf("Update rows of %s matching the filter (use where: {} to target all permitted rows).", tn),
				Args: graphql.FieldConfigArgument{
					"where": &graphql.ArgumentConfig{Type: graphql.NewNonNull(b.boolExps[tn])},
					"_set":  &graphql.ArgumentConfig{Type: graphql.NewNonNull(setInput)},
				},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					id, err := identityFrom(p)
					if err != nil {
						return nil, err
					}
					where, _ := p.Args["where"].(map[string]any)
					set, _ := p.Args["_set"].(map[string]any)
					userCond, err := b.whereSQL(ti, where)
					if err != nil {
						return nil, err
					}
					n, err := b.runUpdate(p.Context, ti, id, set, userCond)
					if err != nil {
						return nil, err
					}
					return map[string]any{"affected_rows": int(n)}, nil
				},
			}

			if b.pkExposable(ti) {
				args := b.pkArgs(ti)
				args["_set"] = &graphql.ArgumentConfig{Type: graphql.NewNonNull(setInput)}
				fields["update_"+ti.typeName+"_by_pk"] = &graphql.Field{
					Type:        b.objTypes[tn],
					Description: fmt.Sprintf("Update one row of %s by primary key and return it.", tn),
					Args:        args,
					Resolve: func(p graphql.ResolveParams) (any, error) {
						id, err := identityFrom(p)
						if err != nil {
							return nil, err
						}
						cond, err := b.pkCond(ti, p.Args)
						if err != nil {
							return nil, err
						}
						set, _ := p.Args["_set"].(map[string]any)
						n, err := b.runUpdate(p.Context, ti, id, set, cond)
						if err != nil {
							return nil, err
						}
						if n == 0 {
							return nil, nil
						}
						rows, err := b.runSelect(p.Context, ti, id, listArgs{}, cond, true)
						if err != nil {
							return nil, err
						}
						if len(rows) == 0 {
							return nil, nil
						}
						return rows[0], nil
					},
				}
			}
		}
	}

	if ti.access.Delete != nil && ti.access.Select != nil {
		fields["delete_"+ti.typeName] = &graphql.Field{
			Type:        graphql.NewNonNull(b.mutResp),
			Description: fmt.Sprintf("Delete rows of %s matching the filter (use where: {} to target all permitted rows).", tn),
			Args: graphql.FieldConfigArgument{
				"where": &graphql.ArgumentConfig{Type: graphql.NewNonNull(b.boolExps[tn])},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				id, err := identityFrom(p)
				if err != nil {
					return nil, err
				}
				where, _ := p.Args["where"].(map[string]any)
				userCond, err := b.whereSQL(ti, where)
				if err != nil {
					return nil, err
				}
				n, err := b.runDelete(p.Context, ti, id, userCond)
				if err != nil {
					return nil, err
				}
				return map[string]any{"affected_rows": int(n)}, nil
			},
		}

		if b.pkExposable(ti) {
			fields["delete_"+ti.typeName+"_by_pk"] = &graphql.Field{
				Type:        b.objTypes[tn],
				Description: fmt.Sprintf("Delete one row of %s by primary key and return it.", tn),
				Args:        b.pkArgs(ti),
				Resolve: func(p graphql.ResolveParams) (any, error) {
					id, err := identityFrom(p)
					if err != nil {
						return nil, err
					}
					cond, err := b.pkCond(ti, p.Args)
					if err != nil {
						return nil, err
					}
					// Fetch first (respecting select + delete filters), then delete.
					deleteCond, err := rbacCond(ti.access.Delete, id)
					if err != nil {
						return nil, err
					}
					rows, err := b.runSelect(p.Context, ti, id, listArgs{}, combineConds(cond, deleteCond), true)
					if err != nil {
						return nil, err
					}
					n, err := b.runDelete(p.Context, ti, id, cond)
					if err != nil {
						return nil, err
					}
					if n == 0 || len(rows) == 0 {
						return nil, nil
					}
					return rows[0], nil
				},
			}
		}
	}
}

// insertedPKCond figures out how to re-select a row that was just inserted.
func (b *builder) insertedPKCond(ti *tableInfo, lastID int64, values map[string]any) (*condition, bool) {
	pk := ti.table.PrimaryKey
	if len(pk) == 1 {
		col := ti.table.ColumnMap[pk[0]]
		if col.AutoIncrement && lastID != 0 {
			return &condition{sql: quoteIdent(col.Name) + " = ?", args: []any{lastID}}, true
		}
	}
	var parts []string
	var args []any
	for _, pkName := range pk {
		v, ok := values[pkName]
		if !ok || v == nil {
			return nil, false
		}
		parts = append(parts, quoteIdent(pkName)+" = ?")
		args = append(args, v)
	}
	return &condition{sql: strings.Join(parts, " AND "), args: args}, true
}
