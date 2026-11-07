package schema

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/graphql-go/graphql"

	"gqlgate/config"
	"gqlgate/introspect"
	"gqlgate/rbac"
)

// Native queries (native_queries: in the config) are read-only SQL
// statements with :name parameters, exposed as root query fields:
//
//	<name>(args: <T>_arguments, where: <T>_bool_exp, limit: Int): [<T>!]!
//	<name>_connection(args, where, first, after): <T>_connection!   (with key:)
//
// Each request renders the statement with "?" per parameter (values bound,
// never spliced in) and runs it as a derived table:
//
//	SELECT <readable cols> FROM (<sql>) AS `__gqlgate_nq`
//	WHERE <where> AND <role filter> [AND <key> > <cursor> ORDER BY <key>] LIMIT ?
//
// so the generated where (with relationship filters into tables), the role's
// row filter and the keyset cursor all apply over the result columns. The
// result columns are read from the database at build time (startup and every
// hot reload), which also proves the statement runs.

// nativeModel is the role-independent shape of one native query.
type nativeModel struct {
	name string
	sql  *config.NativeSQL
	args []*nativeArg // by name
	// tm is the model of the result: a synthetic view named after the query
	// (columns, field names, docs, key, declared relationships).
	tm                 *tableModel
	list, conn         rootSpec // root fields; conn.name is "" without a key
	argsType, connType string   // <T>_arguments ("" without arguments), <T>_connection
}

// nativeArg is one declared argument.
type nativeArg struct {
	name        string
	scalar      *graphql.Scalar
	required    bool
	description string
}

// nativeArgScalar maps a native argument type name to its scalar.
func nativeArgScalar(name string) *graphql.Scalar {
	switch name {
	case "String":
		return graphql.String
	case "Int":
		return graphql.Int
	case "BigInt":
		return bigIntScalar
	case "Float":
		return graphql.Float
	case "Boolean":
		return graphql.Boolean
	case "Decimal":
		return decimalScalar
	case "Date":
		return dateScalar
	case "DateTime":
		return dateTimeScalar
	}
	return nil
}

// sampleArgValue is the value an argument is bound to when the statement is
// checked at build time (its type matters, its value does not: the check
// reads no rows).
func sampleArgValue(scalar string) any {
	switch scalar {
	case "Int":
		return 0
	case "BigInt":
		return int64(0)
	case "Float":
		return 0.0
	case "Boolean":
		return false
	case "Decimal":
		return "0"
	case "Date":
		return "2000-01-01"
	case "DateTime":
		return "2000-01-01 00:00:00"
	}
	return ""
}

// columnTypeFor gives c the column type a declared scalar stands for, so
// scalarFor, convertValue and the filter operators treat it as declared.
// A character column declared String keeps its charset and collation.
func columnTypeFor(c *introspect.Column, scalar string) {
	keepCollation := scalar == "String" && c.Charset != ""
	types := map[string][2]string{
		"String": {"varchar", "varchar"}, "Int": {"int", "int"}, "BigInt": {"bigint", "bigint"},
		"Float": {"double", "double"}, "Boolean": {"tinyint", "tinyint(1)"}, "Decimal": {"decimal", "decimal"},
		"Date": {"date", "date"}, "DateTime": {"datetime", "datetime"}, "JSON": {"json", "json"},
		"Bytes": {"varbinary", "varbinary"}, "Vector": {"vector", "vector"},
	}
	t := types[scalar]
	if scalar == "Decimal" && c.DataType == "decimal" {
		t[1] = c.ColumnType // keep the precision
	}
	if scalar == "String" && (c.DataType == "char" || c.DataType == "varchar" || strings.HasSuffix(c.DataType, "text")) {
		t = [2]string{c.DataType, c.ColumnType}
	}
	c.DataType, c.ColumnType = t[0], t[1]
	if !keepCollation {
		c.Charset, c.Collation = "", ""
	}
}

// nativeSampleArgs are the build-time values of a query's parameters.
func nativeSampleArgs(nm *nativeModel) map[string]any {
	vals := map[string]any{}
	for _, a := range nm.args {
		vals[a.name] = sampleArgValue(a.scalar.Name())
	}
	return vals
}

// buildNatives derives and validates the model of every native query. With
// a database the statement is run (LIMIT 0) to read its result columns; the
// columns: entries override their types. Without one (tests) the columns
// come from the columns: entries alone, which must all have a type.
func buildNatives(ctx context.Context, opt Options, m *catalogModel) error {
	m.natives = map[string]*nativeModel{}
	if opt.Config == nil {
		return nil
	}
	for name := range opt.Config.NativeQueries {
		m.nativeOrder = append(m.nativeOrder, name)
	}
	sort.Strings(m.nativeOrder)
	for _, name := range m.nativeOrder {
		nm, err := buildNative(ctx, opt, m, name, opt.Config.NativeQueries[name])
		if err != nil {
			return fmt.Errorf("native_queries.%s%w", name, err)
		}
		m.natives[name] = nm
	}
	return nil
}

// buildNative builds one native query's model. Errors start with the key
// path below native_queries.<name> (": ..." or ".columns: ...").
func buildNative(ctx context.Context, opt Options, m *catalogModel, name string, nq *config.NativeQuery) (*nativeModel, error) {
	if nq == nil {
		return nil, fmt.Errorf(": empty native query")
	}
	compiled, err := config.CompileNativeSQL(nq.SQL)
	if err != nil {
		return nil, fmt.Errorf(".sql: %w", err)
	}
	nm := &nativeModel{name: name, sql: compiled}
	argNames := make([]string, 0, len(nq.Arguments))
	for an := range nq.Arguments {
		argNames = append(argNames, an)
	}
	sort.Strings(argNames)
	for _, an := range argNames {
		a := nq.Arguments[an]
		if a == nil {
			return nil, fmt.Errorf(".arguments.%s: type is required", an)
		}
		sn, required := config.ParseScalarType(a.Type)
		sc := nativeArgScalar(sn)
		if sc == nil {
			return nil, fmt.Errorf(".arguments.%s: type %q is not supported", an, a.Type)
		}
		nm.args = append(nm.args, &nativeArg{name: an, scalar: sc, required: required, description: a.Description})
	}
	for _, p := range compiled.Params {
		if nq.Arguments[p] == nil {
			return nil, fmt.Errorf(".sql: parameter :%s is not declared under arguments", p)
		}
	}

	// Result columns.
	var cols []*introspect.Column
	if opt.DB != nil {
		q, args := compiled.Render(nativeSampleArgs(nm))
		qctx, cancel := context.WithTimeout(ctx, queryTimeout(opt))
		cols, err = introspect.QueryColumns(qctx, opt.DB, q, args)
		cancel()
		if err != nil {
			return nil, fmt.Errorf(".sql: the statement does not run against the database: %w", err)
		}
	} else {
		names := make([]string, 0, len(nq.Columns))
		for c := range nq.Columns {
			names = append(names, c)
		}
		sort.Strings(names)
		for i, c := range names {
			cols = append(cols, &introspect.Column{Name: c, Ordinal: i, Nullable: true})
		}
	}
	t := &introspect.Table{Name: name, IsView: true, ColumnMap: map[string]*introspect.Column{}}
	for _, c := range cols {
		t.Columns = append(t.Columns, c)
		t.ColumnMap[c.Name] = c
	}
	for cn, nc := range nq.Columns {
		c := t.ColumnMap[cn]
		if c == nil {
			return nil, fmt.Errorf(".columns: the statement returns no column %q", cn)
		}
		if nc == nil || nc.Type == "" {
			continue
		}
		sn, nonNull := config.ParseScalarType(nc.Type)
		columnTypeFor(c, sn)
		c.Nullable = !nonNull
	}
	for _, c := range t.Columns {
		if c.DataType == "" {
			return nil, fmt.Errorf(".columns: the database reports no usable type for result column %q; declare one (columns: {%s: String})", c.Name, c.Name)
		}
	}

	typeName := name
	if nq.TypeName != "" {
		typeName = nq.TypeName
	}
	tm := &tableModel{
		table:         t,
		typeName:      typeName,
		fieldBase:     name,
		description:   nq.Description,
		colField:      map[string]string{},
		colDoc:        map[string]string{},
		colDeprecated: map[string]string{},
		colJSONType:   map[string]string{},
		roots:         map[string]rootSpec{},
		native:        true,
	}
	if tm.description == "" {
		tm.description = fmt.Sprintf("Row of native query %s.", name)
	}
	fieldOwner := map[string]string{}
	for _, c := range t.Columns {
		f := graphqlName(c.Name)
		if nc := nq.Columns[c.Name]; nc != nil {
			if nc.Name != "" {
				f = nc.Name
			}
			tm.colDoc[c.Name] = nc.Description
			tm.colDeprecated[c.Name] = nc.Deprecated
		}
		if f == "_and" || f == "_or" || f == "_not" {
			return nil, fmt.Errorf(".columns: result column %q maps to %q, a logical operator of where; rename it (columns: {%s: {name: …}})", c.Name, f, c.Name)
		}
		if other, dup := fieldOwner[f]; dup {
			return nil, fmt.Errorf(".columns: result columns %q and %q both map to GraphQL name %q; alias or rename one", other, c.Name, f)
		}
		fieldOwner[f] = c.Name
		tm.colField[c.Name] = f
	}
	for _, k := range nq.Key {
		c := t.ColumnMap[k]
		if c == nil {
			return nil, fmt.Errorf(".key: the statement returns no column %q", k)
		}
		if !keyableColumn(c) {
			return nil, fmt.Errorf(".key: column %q (%s) cannot be a key column", k, c.ColumnType)
		}
	}
	if len(nq.Key) > 0 {
		tm.readKey = append([]string{}, nq.Key...)
		tm.logicalKey = true
	}
	nm.tm = tm

	nm.list = rootSpec{name: name}
	if fc := nq.RootFields.List; fc != nil {
		if fc.Name != "" {
			nm.list.name = fc.Name
		}
		nm.list.description, nm.list.deprecated = fc.Description, fc.Deprecated
	}
	if len(nq.Key) > 0 {
		nm.conn = rootSpec{name: name + "_connection"}
		if fc := nq.RootFields.Connection; fc != nil {
			if fc.Name != "" {
				nm.conn.name = fc.Name
			}
			nm.conn.description, nm.conn.deprecated = fc.Description, fc.Deprecated
		}
		nm.connType = typeName + "_connection"
	} else if nq.RootFields.Connection != nil {
		return nil, fmt.Errorf(".root_fields.connection: a connection needs key")
	}
	if len(nm.args) > 0 {
		nm.argsType = typeName + "_arguments"
	}
	if err := m.applyRelationshipsOf(tm, nq.Relationships, "native_queries."+name); err != nil {
		return nil, fmt.Errorf(": %w", err)
	}
	return nm, nil
}

// queryTimeout is the per-check timeout of build-time database checks.
func queryTimeout(opt Options) time.Duration {
	if opt.Config != nil && opt.Config.Database.QueryTimeoutSeconds > 0 {
		return time.Duration(opt.Config.Database.QueryTimeoutSeconds) * time.Second
	}
	return 30 * time.Second
}

// reserveNativeNames claims the fixed names of every native query (its root
// fields and types) in the query-field and type namespaces.
func reserveNativeNames(m *catalogModel, queryFields, types map[string]string) error {
	for _, name := range m.nativeOrder {
		nm := m.natives[name]
		owner := "native query " + name
		claim := func(ns map[string]string, n, kind string) error {
			if other, dup := ns[n]; dup {
				return fmt.Errorf("generated %s name %q for native query %q collides with %s; rename one (native_queries.%s.type_name / root_fields)",
					kind, n, name, other, name)
			}
			ns[n] = owner
			return nil
		}
		fields := []string{nm.list.name}
		if nm.conn.name != "" {
			fields = append(fields, nm.conn.name)
		}
		for _, f := range fields {
			if err := claim(queryFields, f, "query field"); err != nil {
				return err
			}
		}
		tn := nm.tm.typeName
		typeOf := []string{tn, tn + "_bool_exp"}
		if nm.argsType != "" {
			typeOf = append(typeOf, nm.argsType)
		}
		if nm.connType != "" {
			typeOf = append(typeOf, nm.connType)
		}
		for _, t := range typeOf {
			if err := claim(types, t, "type"); err != nil {
				return err
			}
		}
	}
	return nil
}

// nativeInfo is one role's view of one native query.
type nativeInfo struct {
	model *nativeModel
	ti    *tableInfo // the result columns as a role-scoped table view
	// presets force argument values; clientArgs are the arguments the
	// client may (or, if required, must) pass.
	presets    map[string]rbac.ArgPreset
	clientArgs []*nativeArg
	obj        *graphql.Object
	boolExp    *graphql.InputObject
	argsInput  *graphql.InputObject // nil when the client passes no argument
	argsReq    bool                 // some client argument is required
	connType   *graphql.Object
}

// resolveNatives builds the role's views of the native queries it is
// granted: column access, filter surface, verified row filter, argument
// presets and relationships into the tables the role can read.
func (b *builder) resolveNatives() error {
	m := b.shared.model
	b.natives = map[string]*nativeInfo{}
	role := b.opt.Config.Roles[b.role]
	if role == nil {
		return nil
	}
	for qn := range role.NativeQueries {
		if m.natives[qn] == nil {
			return fmt.Errorf("role %q grants native query %q, which is not declared under native_queries", b.role, qn)
		}
	}
	for _, name := range m.nativeOrder {
		nm := m.natives[name]
		perm := role.NativeQueries[name]
		argSet := map[string]bool{}
		for _, a := range nm.args {
			argSet[a.name] = true
		}
		na, err := rbac.ResolveNative(b.role, perm, nm.tm.table, argSet)
		if err != nil {
			return fmt.Errorf("native query %q: %w", name, err)
		}
		if na == nil {
			continue
		}
		// A literal preset is the same on every request: one that does not
		// fit its argument's type fails the build, not every request.
		for _, a := range nm.args {
			if p, ok := na.Presets[a.name]; ok && p.ClaimPath == "" {
				if _, err := presetArgValue(a, p.Literal); err != nil {
					return fmt.Errorf("role %q, native query %q: %w", b.role, name, err)
				}
			}
		}
		ti := &tableInfo{
			table:      nm.tm.table,
			model:      nm.tm,
			access:     &rbac.TableAccess{Select: na.Select},
			typeName:   nm.tm.typeName,
			fieldToCol: map[string]*introspect.Column{},
			colToField: map[string]string{},
			native:     true,
		}
		for _, c := range nm.tm.table.Columns {
			f := nm.tm.colField[c.Name]
			ti.fieldToCol[f] = c
			ti.colToField[c.Name] = f
		}
		if err := b.resolveFilterOps(ti); err != nil {
			return fmt.Errorf("native query %q: %w", name, err)
		}
		if err := b.verifyNativeFilter(nm, na.Select); err != nil {
			return err
		}
		ti.selectFilterOK = true // nothing filters into a native query
		if b.relations(ti); ti.relErr != nil {
			return ti.relErr
		}
		if err := b.resolveFilterRels(ti); err != nil {
			return fmt.Errorf("native query %q: %w", name, err)
		}
		ni := &nativeInfo{model: nm, ti: ti, presets: na.Presets}
		for _, a := range nm.args {
			if _, preset := na.Presets[a.name]; preset {
				continue
			}
			ni.clientArgs = append(ni.clientArgs, a)
			ni.argsReq = ni.argsReq || a.required
		}
		b.natives[name] = ni
	}
	return nil
}

// verifyNativeFilter dry-runs a role's row filter over the native query's
// result, so a filter naming a column the statement does not return fails
// the build (startup or hot reload) instead of every request.
func (b *builder) verifyNativeFilter(nm *nativeModel, sel *rbac.OpAccess) error {
	if sel.Filter == nil || b.shared.db == nil {
		return nil
	}
	vsql := sel.Filter.ValidationSQL()
	key := "native\x00" + nm.name + "\x00" + vsql
	err, done := b.shared.filterChecks[key]
	if !done {
		q, args := nm.sql.Render(nativeSampleArgs(nm))
		q = "SELECT 1 FROM (" + q + "\n) AS " + quoteIdent(introspect.NativeAlias) + " WHERE (" + vsql + ") LIMIT 0"
		ctx, cancel := context.WithTimeout(context.Background(), b.shared.timeout)
		rows, qerr := b.shared.db.QueryContext(ctx, q, args...)
		if qerr == nil {
			qerr = rows.Close()
		}
		cancel()
		if qerr != nil {
			err = fmt.Errorf("role %q, native query %q: verifying the filter: %w", b.role, nm.name, qerr)
		}
		b.shared.filterChecks[key] = err
	}
	return err
}

// buildNativeTypes creates the role's types of every granted native query
// (after the table types, which relationships refer to).
func (b *builder) buildNativeTypes() error {
	for _, name := range b.shared.model.nativeOrder {
		ni := b.natives[name]
		if ni == nil {
			continue
		}
		ni.obj = b.buildObjectType(ni.ti)
		be, err := b.buildBoolExp(ni.ti)
		if err != nil {
			return fmt.Errorf("native query %q: %w", name, err)
		}
		ni.boolExp = be
		if len(ni.clientArgs) > 0 {
			f := graphql.InputObjectConfigFieldMap{}
			for _, a := range ni.clientArgs {
				var t graphql.Input = a.scalar
				if a.required {
					t = graphql.NewNonNull(t)
				}
				f[a.name] = &graphql.InputObjectFieldConfig{Type: t, Description: a.description}
			}
			ni.argsInput = graphql.NewInputObject(graphql.InputObjectConfig{
				Name:        ni.model.argsType,
				Description: fmt.Sprintf("Arguments of native query %s.", name),
				Fields:      f,
			})
		}
		if ni.model.conn.name != "" && b.readKeyExposable(ni.ti) {
			obj := ni.obj
			ni.connType = b.newConnectionType(ni.model.connType, "native query "+name, func() *graphql.Object { return obj })
		}
	}
	return nil
}

// addNativeFields adds the root fields of every granted native query.
func (b *builder) addNativeFields(fields graphql.Fields) {
	for _, name := range b.shared.model.nativeOrder {
		ni := b.natives[name]
		if ni == nil {
			continue
		}
		b.addNativeListField(fields, ni)
		if ni.connType != nil {
			b.addNativeConnectionField(fields, ni)
		}
	}
}

// nativeArgsArg is the `args` argument of a native query's fields (nil when
// the client passes none).
func (ni *nativeInfo) nativeArgsArg() *graphql.ArgumentConfig {
	if ni.argsInput == nil {
		return nil
	}
	var t graphql.Input = ni.argsInput
	if ni.argsReq {
		t = graphql.NewNonNull(t)
	}
	return &graphql.ArgumentConfig{Type: t, Description: "The query's arguments (preset arguments are set by the server)."}
}

func (b *builder) addNativeListField(fields graphql.Fields, ni *nativeInfo) {
	nm := ni.model
	args := graphql.FieldConfigArgument{
		"where": &graphql.ArgumentConfig{Type: ni.boolExp},
		"limit": &graphql.ArgumentConfig{Type: graphql.Int, Description: "Max rows (defaults to default_page_size, clamped to max_page_size)."},
	}
	if a := ni.nativeArgsArg(); a != nil {
		args["args"] = a
	}
	desc := nm.list.description
	if desc == "" {
		desc = fmt.Sprintf("Up to `limit` rows of native query %s matching the filter, in no particular order.", nm.name)
	}
	fields[nm.list.name] = &graphql.Field{
		Type:              graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(ni.obj))),
		Description:       desc,
		DeprecationReason: nm.list.deprecated,
		Args:              args,
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, err := identityFrom(p)
			if err != nil {
				return nil, err
			}
			values, err := b.nativeValues(ni, id, p.Args["args"])
			if err != nil {
				return nil, err
			}
			limit := b.opt.Config.SchemaGen.DefaultPageSize
			if l, ok := p.Args["limit"].(int); ok {
				limit = l
			}
			if limit < 0 {
				return nil, fmt.Errorf("limit must be >= 0")
			}
			if limit > b.opt.Config.SchemaGen.MaxPageSize {
				limit = b.opt.Config.SchemaGen.MaxPageSize
			}
			where, _ := p.Args["where"].(map[string]any)
			rows, err := b.runNativeSelect(p.Context, ni, id, values, where, nil, false, limit)
			if err != nil {
				return nil, err
			}
			if err := countRows(p.Context, len(rows)); err != nil {
				return nil, err
			}
			if rows == nil {
				rows = []map[string]any{}
			}
			return rows, nil
		},
	}
}

func (b *builder) addNativeConnectionField(fields graphql.Fields, ni *nativeInfo) {
	nm := ni.model
	ti := ni.ti
	key := ti.model.readKey
	args := graphql.FieldConfigArgument{
		"first": &graphql.ArgumentConfig{Type: graphql.Int, Description: "Page size (defaults to default_page_size, clamped to max_page_size)."},
		"after": &graphql.ArgumentConfig{Type: graphql.String, Description: "Cursor from a previous page's page_info.end_cursor."},
		"where": &graphql.ArgumentConfig{Type: ni.boolExp},
	}
	if a := ni.nativeArgsArg(); a != nil {
		args["args"] = a
	}
	desc := nm.conn.description
	if desc == "" {
		desc = fmt.Sprintf("Keyset cursor-paginated rows of native query %s in key order (%s): pass page_info.end_cursor as `after` for the next page.",
			nm.name, strings.Join(key, ", "))
	}
	fields[nm.conn.name] = &graphql.Field{
		Type:              graphql.NewNonNull(ni.connType),
		Description:       desc,
		DeprecationReason: nm.conn.deprecated,
		Args:              args,
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, err := identityFrom(p)
			if err != nil {
				return nil, err
			}
			values, err := b.nativeValues(ni, id, p.Args["args"])
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
			// The cursor is bound to the query, the client's argument values
			// and the filter.
			shape := nativeCursorShape(nm.name, ni.clientArgs, values, where)
			var after *condition
			if a, ok := p.Args["after"].(string); ok && a != "" {
				keys, err := decodeCursor(a, shape, len(key))
				if err != nil {
					return nil, err
				}
				after = keysetCondition(key, keys)
			}
			rows, err := b.runNativeSelect(p.Context, ni, id, values, where, after, true, first+1)
			if err != nil {
				return nil, err
			}
			hasNext := len(rows) > first
			if hasNext {
				rows = rows[:first]
			}
			if err := countRows(p.Context, len(rows)); err != nil {
				return nil, err
			}
			if len(rows) == 0 {
				hasNext = false
			}
			var endCursor any
			if len(rows) > 0 {
				last := rows[len(rows)-1]
				keys := make([]any, len(key))
				for i, k := range key {
					keys[i] = cursorKey(last[k])
				}
				endCursor = encodeCursor(keys, shape)
			}
			if rows == nil {
				rows = []map[string]any{}
			}
			countFn := func() (int64, error) {
				return b.runNativeCount(p.Context, ni, id, values, where)
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

// nativeCursorShape scopes a cursor to one native query, the values of the
// arguments the client may pass (clientArgs) and its filter. The role's
// argument presets are left out on purpose: the shape travels to the client
// inside the cursor as an unkeyed hash, and a literal preset is meant to
// stay hidden — hashing it would let a client confirm guesses offline.
// Presets are re-applied on every request anyway, and the seek uses only
// key values.
func nativeCursorShape(name string, clientArgs []*nativeArg, values, where map[string]any) string {
	client := make(map[string]any, len(clientArgs))
	for _, a := range clientArgs {
		client[a.name] = values[a.name]
	}
	return cursorShape("\x00native:"+name, map[string]any{"args": client, "where": where})
}

// nativeValues resolves the value of every argument for one request: the
// role's presets (from claims or literals; the client cannot set them),
// then the client's `args`. An omitted optional argument is NULL.
func (b *builder) nativeValues(ni *nativeInfo, id *rbac.Identity, raw any) (map[string]any, error) {
	client, _ := raw.(map[string]any)
	allowed := map[string]*nativeArg{}
	for _, a := range ni.clientArgs {
		allowed[a.name] = a
	}
	values := map[string]any{}
	for k, v := range client {
		a := allowed[k]
		if a == nil {
			// The input type has no such field; this guards values that
			// reach the resolver some other way (a preset is never
			// client-settable).
			return nil, fmt.Errorf("unknown argument %q", k)
		}
		values[k] = nativeBindValue(v)
	}
	for _, a := range ni.clientArgs {
		if _, ok := values[a.name]; !ok || values[a.name] == nil {
			if a.required {
				return nil, fmt.Errorf("argument %q is required", a.name)
			}
			values[a.name] = nil
		}
	}
	for _, a := range ni.model.args {
		p, ok := ni.presets[a.name]
		if !ok {
			continue
		}
		v, err := p.Value(id.Claims)
		if err != nil {
			return nil, err
		}
		if v, err = presetArgValue(a, v); err != nil {
			return nil, err
		}
		values[a.name] = v
	}
	return values, nil
}

// nativeBindValue converts a coerced GraphQL argument value for the driver.
func nativeBindValue(v any) any {
	if t, ok := v.(time.Time); ok {
		return t.UTC().Format("2006-01-02 15:04:05.999999")
	}
	return v
}

// presetArgValue coerces a preset value (a claim or a literal string) to the
// argument's scalar, so it is bound with the declared type. It is strict: a
// preset never binds NULL (a null claim is an error, as NULL often means "no
// restriction" in native SQL), and a value that does not fit the type exactly
// (a fractional or out-of-range number for Int, a number for Boolean) is an
// error instead of being rounded, truncated or dropped.
func presetArgValue(a *nativeArg, v any) (any, error) {
	bad := func(what string) error {
		return fmt.Errorf("argument preset %q: %s is not %s", a.name, presetValueText(v), what)
	}
	switch v.(type) {
	case nil:
		return nil, fmt.Errorf("argument preset %q: the value is null (a preset never binds NULL)", a.name)
	case string, float64, bool:
	default:
		return nil, fmt.Errorf("argument preset %q: the value is not a scalar", a.name)
	}
	switch a.scalar.Name() {
	case "Int", "BigInt":
		var n int64
		switch x := v.(type) {
		case string:
			var err error
			if n, err = strconv.ParseInt(strings.TrimSpace(x), 10, 64); err != nil {
				return nil, bad("an integer")
			}
		case float64:
			// 2^63 is exactly representable; every float64 below it converts.
			if x != math.Trunc(x) || x < -(1<<63) || x >= 1<<63 {
				return nil, bad("an integer")
			}
			n = int64(x)
		default:
			return nil, bad("an integer")
		}
		if a.scalar.Name() == "BigInt" {
			return n, nil
		}
		if n < math.MinInt32 || n > math.MaxInt32 {
			return nil, bad("in the range of Int (32-bit)")
		}
		return int(n), nil
	case "Float":
		var f float64
		switch x := v.(type) {
		case string:
			var err error
			if f, err = strconv.ParseFloat(strings.TrimSpace(x), 64); err != nil {
				return nil, bad("a number")
			}
		case float64:
			f = x
		default:
			return nil, bad("a number")
		}
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, bad("a finite number")
		}
		return f, nil
	case "Boolean":
		switch x := v.(type) {
		case string:
			bv, err := strconv.ParseBool(strings.TrimSpace(x))
			if err != nil {
				return nil, bad("a boolean")
			}
			return bv, nil
		case bool:
			return x, nil
		}
		return nil, bad("a boolean")
	case "String":
		switch x := v.(type) {
		case string:
			return x, nil
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64), nil // 1000000, not 1e+06
		case bool:
			return strconv.FormatBool(x), nil
		}
	}
	out := a.scalar.ParseValue(v)
	if out == nil {
		return nil, fmt.Errorf("argument preset %q: %s does not fit type %s", a.name, presetValueText(v), a.scalar.Name())
	}
	return nativeBindValue(out), nil
}

// presetValueText renders a preset value for an error message.
func presetValueText(v any) string {
	if s, ok := v.(string); ok {
		return strconv.Quote(s)
	}
	return fmt.Sprintf("%v", v)
}

// nativeFrom renders the FROM clause of one request: the statement with its
// argument values, as a derived table.
func nativeFrom(nm *nativeModel, values map[string]any) (string, []any) {
	q, args := nm.sql.Render(values)
	return "(" + q + "\n) AS " + quoteIdent(introspect.NativeAlias), args
}

// nativeWhere is the WHERE condition of one request: the client's where
// (relationship filters correlate to the derived table's alias) and the
// role's row filter, plus extra conditions.
func (b *builder) nativeWhere(ni *nativeInfo, id *rbac.Identity, where map[string]any, extra ...*condition) (*condition, error) {
	var userCond *condition
	if where != nil {
		var err error
		wc := &whereCtx{id: id}
		if userCond, err = b.compileWhere(wc, ni.ti, where, "", quoteIdent(introspect.NativeAlias), 0); err != nil {
			return nil, err
		}
	}
	filterCond, err := rbacCond(ni.ti.access.Select, id)
	if err != nil {
		return nil, err
	}
	return combineConds(append([]*condition{userCond, filterCond}, extra...)...), nil
}

// runNativeSelect runs one native query read: up to limit rows matching
// where and the role filter; with keyset, in key order after the cursor
// (rows with a NULL key are left out, as a cursor cannot seek past them).
func (b *builder) runNativeSelect(ctx context.Context, ni *nativeInfo, id *rbac.Identity, values, where map[string]any, after *condition, keyset bool, limit int) ([]map[string]any, error) {
	sel := ni.ti.access.Select
	from, args := nativeFrom(ni.model, values)
	var extra []*condition
	order := ""
	if keyset {
		extra = append(extra, b.readKeyNotNull(ni.ti), after)
		order = b.pkOrderClause(ni.ti)
	}
	cond, err := b.nativeWhere(ni, id, where, extra...)
	if err != nil {
		return nil, err
	}
	query := "SELECT " + selectList(sel.Columns) + " FROM " + from + " WHERE " + cond.sql + order + " LIMIT ?"
	args = append(append(args, cond.args...), limit)
	return b.scanRows(ctx, sel.Columns, query, args)
}

// runNativeCount counts a native query connection's rows (total_count).
func (b *builder) runNativeCount(ctx context.Context, ni *nativeInfo, id *rbac.Identity, values, where map[string]any) (int64, error) {
	from, args := nativeFrom(ni.model, values)
	cond, err := b.nativeWhere(ni, id, where, b.readKeyNotNull(ni.ti))
	if err != nil {
		return 0, err
	}
	query := "SELECT COUNT(*) FROM " + from + " WHERE " + cond.sql
	args = append(args, cond.args...)
	b.logSQL(query, args)
	var n int64
	if err := b.opt.DB.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, b.dbErr(err)
	}
	return n, nil
}
