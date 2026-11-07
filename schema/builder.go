// Package schema turns an introspected catalog plus resolved RBAC rules into
// executable GraphQL schemas — one schema per role, so introspection (and
// therefore GraphiQL autocompletion) only ever shows what the role may touch.
package schema

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

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
	shared, err := newBuildShared(opt)
	if err != nil {
		return nil, err
	}
	out := make(map[string]graphql.Schema, len(opt.Config.Roles))
	for roleName, role := range opt.Config.Roles {
		access, err := rbac.Resolve(roleName, role, opt.Catalog)
		if err != nil {
			return nil, err
		}
		s, err := buildRole(opt, shared, roleName, access)
		if err != nil {
			return nil, fmt.Errorf("building schema for role %q: %w", roleName, err)
		}
		out[roleName] = s
	}
	return out, nil
}

// newBuildShared runs the role-independent checks (name collisions, custom
// operator compilation + database dry run) and returns the state every role's
// build shares.
func newBuildShared(opt Options) (*buildShared, error) {
	model, err := buildModel(opt.Catalog, opt.Config)
	if err != nil {
		return nil, err
	}
	names, err := reserveNames(opt.Catalog, model)
	if err != nil {
		return nil, err
	}
	customTypes := opt.Hooks.customTypeNames()
	for n := range model.jsonTypes {
		if customTypes[n] {
			return nil, fmt.Errorf("json_types.%s: a custom or object field registered in hooks/ already uses the type name %q", n, n)
		}
	}
	renamed := names.avoidTypes(opt.Catalog, model, customTypes)
	if opt.Logger != nil {
		for _, s := range names.skipped {
			opt.Logger.Warn("generated field left out: name collision", "field", s)
		}
		for _, s := range renamed {
			opt.Logger.Warn("mutation response type renamed: a custom field's type already has the name", "type", s)
		}
	}
	shared := &buildShared{
		db:            opt.DB,
		model:         model,
		names:         names,
		reservedTypes: names.types,
		filterChecks:  map[string]error{},
		timeout:       time.Duration(opt.Config.Database.QueryTimeoutSeconds) * time.Second,
		ciCollations:  true, // without a database, assume the default (new) framework
	}
	if shared.timeout <= 0 {
		shared.timeout = 30 * time.Second
	}
	if shared.customOps, shared.customOrder, err = compileCustomOps(opt.Config.SchemaGen.CustomOperators); err != nil {
		return nil, err
	}
	if opt.DB != nil {
		if err := validateCustomOps(opt.DB, shared.customOps, shared.customOrder, shared.timeout); err != nil {
			return nil, err
		}
		if shared.ciCollations, err = probeCICollations(opt.DB, shared.timeout); err != nil {
			return nil, err
		}
	}
	return shared, nil
}

// ciProbeSQL asks the cluster whether a *_ci collation really ignores case.
// TiDB clusters bootstrapped with new_collations_enabled_on_first_bootstrap =
// false (e.g. upgraded from before v4.0) compare every collation as binary.
// The behavioural check needs no privileges, unlike reading mysql.tidb.
const ciProbeSQL = "SELECT _utf8mb4'A' COLLATE utf8mb4_general_ci LIKE _utf8mb4'a'"

// probeCICollations reports whether *_ci collations are case-insensitive on
// this cluster, which decides how the case-insensitive string operators are
// rendered (see stringCond).
func probeCICollations(db *sql.DB, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, ciProbeSQL).Scan(&v); err != nil {
		return false, fmt.Errorf("checking collation support: %w", err)
	}
	return v.Valid && v.Int64 == 1, nil
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
// The names checked are the final ones: the defaults, or what the config's
// tables: section renames them to.
func checkNameCollisions(cat *introspect.Catalog) error {
	_, err := reservedNames(cat)
	return err
}

// reservedNames runs the collision check (default names) and returns the
// global type namespace it built (type name -> owner), which later per-role
// type names (e.g. restricted comparison types) are checked against.
func reservedNames(cat *introspect.Catalog) (map[string]string, error) {
	m, err := buildModel(cat, nil)
	if err != nil {
		return nil, err
	}
	r, err := reserveNames(cat, m)
	if err != nil {
		return nil, err
	}
	return r.types, nil
}

// nameReservation is the role-independent GraphQL namespace of a catalog.
type nameReservation struct {
	types map[string]string // global type names -> owner
	// mutResp is each table's <t>_mutation_response type name.
	mutResp map[string]string
	// unique holds, per table and unique index, the root-field names of the
	// unique-key lookups; a name some other field already has is "".
	unique map[string]map[string]uniqueNames
	// list is each table's <t>_list root field name ("" when the default
	// name was already taken).
	list map[string]string
	// skipped describes the generated fields left out because of a name
	// collision (logged at startup).
	skipped []string
}

// avoidTypes renames every <t>_mutation_response type whose name is in taken
// (the types custom fields bring along) to the next free numbered name. The
// response types are newer than any custom field, so a custom type that
// already has the name keeps it and the schema still builds. It returns a
// description of each rename.
func (r *nameReservation) avoidTypes(cat *introspect.Catalog, m *catalogModel, taken map[string]bool) []string {
	var renamed []string
	for _, tn := range cat.TableOrder {
		old, ok := r.mutResp[tn]
		if !ok || !taken[old] {
			continue
		}
		delete(r.types, old)
		base := m.tables[tn].typeName + "_mutation_response"
		name := base
		for i := 1; r.types[name] != "" || taken[name]; i++ {
			name = fmt.Sprintf("%s_%d", base, i)
		}
		r.types[name] = "table " + tn
		r.mutResp[tn] = name
		renamed = append(renamed, fmt.Sprintf("%s -> %s (table %s)", old, name, tn))
	}
	return renamed
}

// uniqueNames are the root fields of one unique key: <t>_by_<cols>,
// update_<t>_by_<cols> and delete_<t>_by_<cols>.
type uniqueNames struct{ query, update, delete string }

// uniqueSuffix is "_by_<col1>_and_<col2>…" for a unique key (the columns'
// GraphQL field names).
func uniqueSuffix(tm *tableModel, uk *introspect.UniqueKey) string {
	cols := make([]string, len(uk.Columns))
	for i, c := range uk.Columns {
		cols[i] = tm.colField[c]
	}
	return "_by_" + strings.Join(cols, "_and_")
}

// reserveNames builds the namespace and rejects collisions among the fixed
// names (the defaults, or the names the config gives). Names added later
// (the per-table mutation response types, the unique-key fields and the
// default <t>_list fields) are claimed only after every fixed name, and never
// fail the build: a schema that worked before keeps working.
func reserveNames(cat *introspect.Catalog, m *catalogModel) (*nameReservation, error) {
	seenTables := map[string]string{}
	for _, tn := range cat.TableOrder {
		tm := m.tables[tn]
		n := tm.typeName
		if other, dup := seenTables[n]; dup {
			return nil, fmt.Errorf("tables %q and %q both map to GraphQL name %q; exclude one via schema_gen.tables (or rename one with tables.<t>.type_name)", other, tn, n)
		}
		seenTables[n] = tn
		seenCols := map[string]string{}
		for _, c := range cat.Tables[tn].Columns {
			cn := tm.colField[c.Name]
			if other, dup := seenCols[cn]; dup {
				return nil, fmt.Errorf("table %q: columns %q and %q both map to GraphQL name %q", tn, other, c.Name, cn)
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
	// Declared JSON shapes are fixed type names too (json_types).
	jsonNames := make([]string, 0, len(m.jsonTypes))
	for n := range m.jsonTypes {
		jsonNames = append(jsonNames, n)
	}
	sort.Strings(jsonNames)
	for _, n := range jsonNames {
		if other, dup := types[n]; dup {
			return nil, fmt.Errorf("json_types.%s: the type name is already used by %s", n, other)
		}
		types[n] = "json_types." + n
	}

	claim := func(ns map[string]string, name, owner, kind string) error {
		if other, dup := ns[name]; dup {
			return fmt.Errorf("generated %s name %q for table %q collides with %s; rename or exclude one table via schema_gen.tables (or rename it under tables:)",
				kind, name, owner, other)
		}
		ns[name] = "table " + owner
		return nil
	}

	for _, tn := range cat.TableOrder {
		tm := m.tables[tn]
		n := tm.typeName
		view := cat.Tables[tn].IsView
		queryOf := []string{
			tm.roots[config.RootByPK].name, tm.roots[config.RootConnection].name, tm.roots[config.RootAggregate].name,
		}
		if tm.listExplicit {
			queryOf = append(queryOf, tm.roots[config.RootList].name)
		}
		var mutOf []string
		if !view {
			for _, kind := range []string{config.RootInsert, config.RootInsertOne, config.RootUpdate,
				config.RootUpdateByPK, config.RootDelete, config.RootDeleteByPK} {
				mutOf = append(mutOf, tm.roots[kind].name)
			}
		}
		typeOf := []string{n, n + "_bool_exp", n + "_order_by"}
		if !view {
			typeOf = append(typeOf, n+"_insert_input", n+"_set_input")
		}
		typeOf = append(typeOf, n+"_connection", n+"_aggregate_result", n+"_neighbor")
		for _, suffix := range aggTypeSuffixes() {
			typeOf = append(typeOf, n+suffix)
		}
		// A nearest-neighbor query field per vector column.
		for _, c := range cat.Tables[tn].Columns {
			if c.DataType == "vector" {
				queryOf = append(queryOf, tm.fieldBase+"_nearest_by_"+tm.colField[c.Name])
			}
		}
		for _, f := range queryOf {
			if err := claim(queryFields, f, tn, "query field"); err != nil {
				return nil, err
			}
		}
		for _, f := range mutOf {
			if err := claim(mutationFields, f, tn, "mutation field"); err != nil {
				return nil, err
			}
		}
		for _, t := range typeOf {
			if err := claim(types, t, tn, "type"); err != nil {
				return nil, err
			}
		}
	}

	r := &nameReservation{
		types:   types,
		mutResp: map[string]string{},
		unique:  map[string]map[string]uniqueNames{},
		list:    map[string]string{},
	}
	// <t>_mutation_response, numbered if a table-derived name already has it.
	for _, tn := range cat.TableOrder {
		if cat.Tables[tn].IsView {
			continue
		}
		base := m.tables[tn].typeName + "_mutation_response"
		name := base
		for i := 1; types[name] != ""; i++ {
			name = fmt.Sprintf("%s_%d", base, i)
		}
		types[name] = "table " + tn
		r.mutResp[tn] = name
	}
	// Unique-key lookups; a name another field already has is left out.
	for _, tn := range cat.TableOrder {
		tm := m.tables[tn]
		n := tm.fieldBase
		r.unique[tn] = map[string]uniqueNames{}
		for _, uk := range cat.Tables[tn].UniqueKeys {
			soft := func(ns map[string]string, name, kind string) string {
				if other, taken := ns[name]; taken {
					r.skipped = append(r.skipped, fmt.Sprintf("%s %q for unique key %s.%s (already used by %s)", kind, name, tn, uk.Name, other))
					return ""
				}
				ns[name] = "table " + tn
				return name
			}
			suffix := uniqueSuffix(tm, uk)
			r.unique[tn][uk.Name] = uniqueNames{
				query:  soft(queryFields, n+suffix, "query field"),
				update: soft(mutationFields, "update_"+n+suffix, "mutation field"),
				delete: soft(mutationFields, "delete_"+n+suffix, "mutation field"),
			}
		}
	}
	// <t>_list (the bounded list of roles without a usable key) is the newest
	// generated field: a default name that is already taken is left out.
	for _, tn := range cat.TableOrder {
		tm := m.tables[tn]
		name := tm.roots[config.RootList].name
		if tm.listExplicit {
			r.list[tn] = name
			continue
		}
		if other, taken := queryFields[name]; taken {
			r.skipped = append(r.skipped, fmt.Sprintf("query field %q for the list of %s (already used by %s)", name, tn, other))
			r.list[tn] = ""
			continue
		}
		queryFields[name] = "table " + tn
		r.list[tn] = name
	}
	return r, nil
}

// tableInfo is the per-role view of one table.
type tableInfo struct {
	table      *introspect.Table
	model      *tableModel // role-independent names, docs, read key
	access     *rbac.TableAccess
	typeName   string
	fieldToCol map[string]*introspect.Column // GraphQL field name -> column
	colToField map[string]string             // column name -> GraphQL field name
	// relErr is a relationship naming conflict found for this role (see
	// relations); it fails the role's build.
	relErr error

	// Filter surface (select-able tables only).
	filterOps   map[string][]string        // filterable column -> allowed operators
	filterOpSet map[string]map[string]bool // same, as sets (enforced in compileWhere)
	rels        []*relInfo                 // role-visible relationships (see relations)
	relsDone    bool
	filterRels  map[string]*relInfo // relationships usable in this table's bool_exp
	// selectFilterOK: the select row filter (if any) was verified to resolve
	// against this table alone, so it may be embedded in relationship
	// subqueries (see validateRoleFilter).
	selectFilterOK bool
}

// buildShared is state shared by every role's build within one BuildAll.
type buildShared struct {
	db            *sql.DB
	model         *catalogModel // role-independent names, keys, declared relationships
	timeout       time.Duration
	names         *nameReservation
	reservedTypes map[string]string    // global type names -> owner
	customOps     map[string]*customOp // schema_gen.custom_operators
	customOrder   []string
	filterChecks  map[string]error // validateRoleFilter cache (table+filter)
	// ciCollations: the cluster honours *_ci collations (TiDB's new
	// collation framework); see probeCICollations.
	ciCollations bool
}

type builder struct {
	opt        Options
	shared     *buildShared
	role       string
	access     *rbac.Access
	tinfos     map[string]*tableInfo
	objTypes   map[string]*graphql.Object
	connTypes  map[string]*graphql.Object
	aggTypes   map[string]*graphql.Object // <t>_aggregate_result per select-able table
	boolExps   map[string]*graphql.InputObject
	orderBys   map[string]*graphql.InputObject
	cmpExps    map[string]*graphql.InputObject
	cmpOwners  map[string]string // restricted comparison type -> "table.column"
	orderEnum  *graphql.Enum
	pageInfo   *graphql.Object
	metricEnum *graphql.Enum
	// mutRespIface is the mutation_response interface every
	// <t>_mutation_response implements (so `... on mutation_response`
	// keeps working); mutRespTypes caches those types per table.
	mutRespIface *graphql.Interface
	mutRespTypes map[string]*graphql.Object
	// optionalFields are generated root fields a custom field of the same
	// name may replace ("query:<name>" / "mutation:<name>"): the unique-key
	// fields, which are newer than any custom field that might use the name.
	optionalFields map[string]bool
	// objFields are the hook-provided object fields this role sees, per
	// table (see resolveObjectFields).
	objFields map[string][]ObjectField
	// jsonObjs are the role's object types of declared JSON shapes, by
	// json_types name (see jsontyped.go).
	jsonObjs map[string]*graphql.Object
}

func buildRole(opt Options, shared *buildShared, roleName string, access *rbac.Access) (graphql.Schema, error) {
	_, s, err := buildRoleBuilder(opt, shared, roleName, access)
	return s, err
}

// buildRoleBuilder builds one role's schema and also returns the builder
// (whose table views tests use to inspect the generated SQL).
func buildRoleBuilder(opt Options, shared *buildShared, roleName string, access *rbac.Access) (*builder, graphql.Schema, error) {
	b := &builder{
		opt:       opt,
		shared:    shared,
		role:      roleName,
		access:    access,
		tinfos:    map[string]*tableInfo{},
		objTypes:  map[string]*graphql.Object{},
		connTypes: map[string]*graphql.Object{},
		aggTypes:  map[string]*graphql.Object{},
		boolExps:  map[string]*graphql.InputObject{},
		orderBys:  map[string]*graphql.InputObject{},
		cmpExps:   map[string]*graphql.InputObject{},
		cmpOwners: map[string]string{},

		mutRespTypes:   map[string]*graphql.Object{},
		optionalFields: map[string]bool{},
		jsonObjs:       map[string]*graphql.Object{},
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
	b.mutRespIface = graphql.NewInterface(graphql.InterfaceConfig{
		Name:        "mutation_response",
		Description: "The result of a bulk insert/update/delete; implemented by each <table>_mutation_response.",
		Fields: graphql.Fields{
			"affected_rows": &graphql.Field{Type: graphql.NewNonNull(b.countScalar())},
		},
		// No field returns the interface itself; resolution is never needed.
		ResolveType: func(graphql.ResolveTypeParams) *graphql.Object { return nil },
	})

	// Pass 1: per-role table views for every table the role can touch at all.
	for _, tn := range opt.Catalog.TableOrder {
		ta := access.Table(tn)
		if ta == nil {
			continue
		}
		t := opt.Catalog.Tables[tn]
		tm := shared.model.tables[tn]
		ti := &tableInfo{
			table:      t,
			model:      tm,
			access:     ta,
			typeName:   tm.typeName,
			fieldToCol: map[string]*introspect.Column{},
			colToField: map[string]string{},
		}
		for _, c := range t.Columns {
			f := tm.colField[c.Name]
			ti.fieldToCol[f] = c
			ti.colToField[c.Name] = f
		}
		if err := b.validateWriteChecks(ti); err != nil {
			return nil, graphql.Schema{}, err
		}
		b.tinfos[tn] = ti
	}

	// Filter surface: per-column operator sets, verified row filters, then
	// the relationships each table's bool_exp offers.
	for _, tn := range opt.Catalog.TableOrder {
		ti := b.tinfos[tn]
		if ti == nil || ti.access.Select == nil {
			continue
		}
		if err := b.resolveFilterOps(ti); err != nil {
			return nil, graphql.Schema{}, err
		}
		if shared.model.related[tn] {
			ok, err := b.validateRoleFilter(ti)
			if err != nil {
				return nil, graphql.Schema{}, err
			}
			ti.selectFilterOK = ok
		}
	}
	for _, tn := range opt.Catalog.TableOrder {
		ti := b.tinfos[tn]
		if ti == nil || ti.access.Select == nil {
			continue
		}
		if b.relations(ti); ti.relErr != nil {
			return nil, graphql.Schema{}, ti.relErr
		}
		if err := b.resolveFilterRels(ti); err != nil {
			return nil, graphql.Schema{}, err
		}
	}
	if err := b.resolveObjectFields(); err != nil {
		return nil, graphql.Schema{}, err
	}

	// Pass 2: types for select-able tables (mutation-only tables get none).
	for _, tn := range opt.Catalog.TableOrder {
		ti := b.tinfos[tn]
		if ti == nil || ti.access.Select == nil {
			continue
		}
		b.objTypes[tn] = b.buildObjectType(ti)
		be, err := b.buildBoolExp(ti)
		if err != nil {
			return nil, graphql.Schema{}, err
		}
		b.boolExps[tn] = be
		b.orderBys[tn] = b.buildOrderBy(ti)
		b.aggTypes[tn] = b.buildAggregateType(ti)
	}

	// Connection types (cursor pagination) for tables with a readable key
	// (the PK, or a declared logical key) — it gives the batch a stable total
	// order and the cursor a resume point.
	for _, tn := range opt.Catalog.TableOrder {
		ti := b.tinfos[tn]
		if ti == nil || !b.readKeyExposable(ti) {
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
	b.applyRootDocs(queryFields, mutationFields)

	// Developer-provided custom fields (e.g. a signup mutation) visible to
	// this role. They win over generated fields of the same name, and a
	// collision is reported so it can't silently shadow a table operation.
	if err := b.addCustomFields(queryFields, "query"); err != nil {
		return nil, graphql.Schema{}, err
	}
	if err := b.addCustomFields(mutationFields, "mutation"); err != nil {
		return nil, graphql.Schema{}, err
	}
	// Independent query root fields run concurrently (bounded per request;
	// see parallel.go). Mutation root fields stay serial.
	concurrentRootFields(queryFields)

	schemaCfg := graphql.SchemaConfig{
		Query: graphql.NewObject(graphql.ObjectConfig{Name: "Query", Fields: queryFields}),
	}
	if len(mutationFields) > 0 {
		schemaCfg.Mutation = graphql.NewObject(graphql.ObjectConfig{Name: "Mutation", Fields: mutationFields})
	}
	sch, err := graphql.NewSchema(schemaCfg)
	return b, sch, err
}

// addCustomFields mounts the role's custom fields of the given operation onto
// the root field map, rejecting names that collide with generated fields.
func (b *builder) addCustomFields(fields graphql.Fields, operation string) error {
	for _, cf := range b.opt.Hooks.customFieldsFor(b.role, operation) {
		if cf.Name == "" || cf.Field == nil {
			return fmt.Errorf("custom %s field must have a non-empty Name and Field", operation)
		}
		if _, taken := fields[cf.Name]; taken {
			if !b.optionalFields[operation+":"+cf.Name] {
				return fmt.Errorf("custom %s field %q collides with a generated field for role %q", operation, cf.Name, b.role)
			}
			// A unique-key field is newer than any custom field that may
			// already use its name; the custom field keeps it.
			if b.opt.Logger != nil {
				b.opt.Logger.Warn("custom field replaces the generated unique-key field of the same name",
					"role", b.role, "operation", operation, "field", cf.Name)
			}
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
	model := b.shared.model
	return graphql.NewObject(graphql.ObjectConfig{
		Name:        ti.typeName,
		Description: model.tableDescription(ti.model, b.opt.Catalog.SchemaName),
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			fields := graphql.Fields{}
			for _, col := range ti.access.Select.Columns {
				col := col
				if expr := ti.model.colJSONType[col.Name]; expr != "" {
					fields[ti.colToField[col.Name]] = b.typedJSONColumn(ti, col, expr)
					continue
				}
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
					Type:              t,
					Description:       model.columnDescription(ti.model, col),
					DeprecationReason: ti.model.colDeprecated[col.Name],
					Resolve: func(p graphql.ResolveParams) (any, error) {
						row, _ := p.Source.(map[string]any)
						return row[col.Name], nil
					},
				}
			}
			b.addRelationFields(ti, fields)
			b.addObjectHookFields(ti, fields)
			return fields
		}),
	})
}

// relFieldName picks a free field name for a relationship, appending
// deterministic suffixes when the candidate is taken.
func relFieldName(taken map[string]bool, candidate string, keyCols []string) string {
	if !taken[candidate] {
		return candidate
	}
	cols := make([]string, len(keyCols))
	for i, c := range keyCols {
		cols[i] = graphqlName(c)
	}
	candidate = candidate + "_by_" + strings.Join(cols, "_")
	for i := 0; ; i++ {
		name := candidate
		if i > 0 {
			name = fmt.Sprintf("%s_%d", candidate, i)
		}
		if !taken[name] {
			return name
		}
	}
}

// addRelationFields adds one field per role-visible relationship (see
// relations for which FKs qualify and how they are named).
func (b *builder) addRelationFields(ti *tableInfo, fields graphql.Fields) {
	for _, rel := range b.relations(ti) {
		if rel.outgoing {
			b.addObjectRelField(fields, rel)
		} else {
			b.addArrayRelField(fields, rel)
			b.addArrayRelAggField(fields, ti, rel)
		}
	}
}

// addObjectRelField: this table's join columns -> one row of the target (an
// outgoing FK, or a declared object relationship).
func (b *builder) addObjectRelField(fields graphql.Fields, rel *relInfo) {
	target, name := rel.target, rel.name
	localCols, targetCols := rel.localCols, rel.targetCols
	// Batch only when the target's join columns (the grouping key) are
	// readable for this role; otherwise fall back to a per-row query.
	batchable := columnsReadable(target, targetCols)
	// A declared object relationship onto an unenforced (logical) key could
	// match several rows; the batch keeps at most one per parent.
	perKey := 0
	if rel.unenforced {
		perKey = 1
	}
	fields[name] = &graphql.Field{
		Type:              b.objTypes[target.table.Name],
		Description:       rel.description,
		DeprecationReason: rel.deprecated,
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, err := identityFrom(p)
			if err != nil {
				return nil, err
			}
			row, _ := p.Source.(map[string]any)
			key := make([]any, len(localCols))
			for i, lc := range localCols {
				v := row[lc]
				if v == nil {
					return nil, nil // NULL FK -> no related row
				}
				key[i] = v
			}

			if !batchable || serialMutation(p.Info) {
				parts := make([]string, len(targetCols))
				for i, rc := range targetCols {
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
				loaderKey("out", rel.key, ""),
				func() *relLoader {
					return newRelLoader(func(ctx context.Context, keys [][]any) (map[string][]map[string]any, error) {
						// To-one: each referenced key yields at most one row.
						return b.runSelectByKeys(ctx, target, id, targetCols, keys, nil, nil, perKey)
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
				if err := countRows(p.Context, 1); err != nil {
					return nil, err
				}
				return rows[0], nil // the target columns are a (declared) unique key
			}, nil
		},
	}
}

// addArrayRelField: rows of the target whose join columns match this row (an
// FK on the target pointing here, or a declared array relationship).
func (b *builder) addArrayRelField(fields graphql.Fields, rel *relInfo) {
	child, name := rel.target, rel.name
	localCols, targetCols := rel.localCols, rel.targetCols
	// Batch only when the child's join columns (the grouping key) are
	// readable for this role; otherwise fall back to a per-row query.
	batchable := columnsReadable(child, targetCols)
	fields[name] = &graphql.Field{
		Type:              graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(b.objTypes[child.table.Name]))),
		Description:       rel.description,
		DeprecationReason: rel.deprecated,
		Args:              b.listFieldArgs(child.table.Name),
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, err := identityFrom(p)
			if err != nil {
				return nil, err
			}
			row, _ := p.Source.(map[string]any)
			key := make([]any, len(localCols))
			for i, lc := range localCols {
				v := row[lc]
				if v == nil {
					return []map[string]any{}, nil
				}
				key[i] = v
			}
			la, err := extractListArgs(p.Args)
			if err != nil {
				return nil, err
			}

			if !batchable || serialMutation(p.Info) {
				parts := make([]string, len(targetCols))
				for i, cc := range targetCols {
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
				loaderKey("in", rel.key, argsSignature(la)),
				func() *relLoader {
					return newRelLoader(func(ctx context.Context, keys [][]any) (map[string][]map[string]any, error) {
						return b.runSelectByKeys(ctx, child, id, targetCols, keys, la.where, la.orderBy, perKey)
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
				if err := countRows(p.Context, len(page)); err != nil {
					return nil, err
				}
				return page, nil
			}, nil
		},
	}
}

// buildBoolExp builds <t>_bool_exp: _and/_or/_not, one comparison field per
// filterable column (with the role's allowed operators), and one field per
// filterable relationship, typed as the target table's bool_exp.
func (b *builder) buildBoolExp(ti *tableInfo) (*graphql.InputObject, error) {
	colFields := graphql.InputObjectConfigFieldMap{}
	for _, col := range ti.access.Select.Columns {
		if ti.filterOps[col.Name] == nil {
			continue
		}
		e, err := b.cmpExpFor(ti, col)
		if err != nil {
			return nil, err
		}
		colFields[ti.colToField[col.Name]] = &graphql.InputObjectFieldConfig{Type: e}
	}
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
			for name, cf := range colFields {
				f[name] = cf
			}
			for _, rel := range b.relations(ti) {
				if !rel.filterable {
					continue
				}
				desc := fmt.Sprintf("Rows whose %s (%s) matches; {} = has one.", rel.name, rel.target.table.Name)
				if !rel.outgoing {
					desc = fmt.Sprintf("Rows with at least one %s row matching; {} = has any, wrap in _not for none.", rel.target.table.Name)
				}
				f[rel.name] = &graphql.InputObjectFieldConfig{Type: b.boolExps[rel.target.table.Name], Description: desc}
			}
			return f
		}),
	})
	return boolExp, nil
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

// readKeyExposable is pkExposable for reads: the table's read key (its
// primary key, or the primary_key declared for a view / keyless table) must
// exist and be wholly readable. It gates <t>_connection (whose cursor
// carries the key values) and the <t>_by_pk query.
func (b *builder) readKeyExposable(ti *tableInfo) bool {
	if len(ti.model.readKey) == 0 || ti.access.Select == nil {
		return false
	}
	for _, c := range ti.model.readKey {
		if !ti.access.Select.ColumnSet[c] {
			return false
		}
	}
	return true
}

// readKeyNotNull is the condition keeping rows whose (logical) read key has
// a NULL out of a connection: a cursor cannot seek past a NULL. A real
// primary key is never NULL, so it adds nothing there.
func (b *builder) readKeyNotNull(ti *tableInfo) *condition {
	if !ti.model.logicalKey {
		return nil
	}
	var parts []string
	for _, c := range ti.model.readKey {
		if ti.table.ColumnMap[c].Nullable {
			parts = append(parts, quoteIdent(c)+" IS NOT NULL")
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return &condition{sql: strings.Join(parts, " AND ")}
}

// rootName is the name of one of the table's root fields (see tableModel).
func (ti *tableInfo) rootName(kind string) string { return ti.model.roots[kind].name }

// applyRootDocs gives the generated root fields of every table the
// description and deprecation the config sets for them. It runs before the
// custom fields are mounted, so it never touches one of those.
func (b *builder) applyRootDocs(queryFields, mutationFields graphql.Fields) {
	for _, tn := range b.opt.Catalog.TableOrder {
		ti := b.tinfos[tn]
		if ti == nil {
			continue
		}
		for _, kind := range config.RootFieldKinds {
			spec := ti.model.roots[kind]
			if spec.description == "" && spec.deprecated == "" {
				continue
			}
			if kind == config.RootList && b.shared.names.list[tn] == "" {
				continue // the default list name belongs to another field
			}
			ns := mutationFields
			if !mutationRootKinds[kind] {
				ns = queryFields
			}
			f := ns[spec.name]
			if f == nil {
				continue
			}
			if spec.description != "" {
				f.Description = spec.description
			}
			f.DeprecationReason = spec.deprecated
		}
	}
}

// pkArgs builds by-primary-key arguments (one per PK column).
func (b *builder) pkArgs(ti *tableInfo) graphql.FieldConfigArgument {
	return b.keyArgs(ti, ti.table.PrimaryKey)
}

// keyArgs builds one non-null argument per key column, named like the
// column's field.
func (b *builder) keyArgs(ti *tableInfo, cols []string) graphql.FieldConfigArgument {
	args := graphql.FieldConfigArgument{}
	for _, name := range cols {
		col := ti.table.ColumnMap[name]
		args[ti.colToField[name]] = &graphql.ArgumentConfig{Type: graphql.NewNonNull(scalarFor(col))}
	}
	return args
}

// uniqueLookup is one unique key a role may address rows by.
type uniqueLookup struct {
	key   *introspect.UniqueKey
	names uniqueNames
}

// uniqueLookups returns the table's unique keys usable by this role: it must
// read every key column and be allowed to compare it with _eq in `where` (a
// lookup is exactly that equality filter), so a lookup never probes a column
// the role's permissions hide.
func (b *builder) uniqueLookups(ti *tableInfo) []uniqueLookup {
	sel := ti.access.Select
	if sel == nil {
		return nil
	}
	var out []uniqueLookup
	for _, uk := range ti.table.UniqueKeys {
		ok := true
		for _, c := range uk.Columns {
			if !sel.ColumnSet[c] || !ti.filterOpSet[c]["_eq"] {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, uniqueLookup{key: uk, names: b.shared.names.unique[ti.table.Name][uk.Name]})
		}
	}
	return out
}

// addUniqueQueryFields adds <t>_by_<cols>(cols…) for every usable unique key.
func (b *builder) addUniqueQueryFields(fields graphql.Fields, ti *tableInfo) {
	tn := ti.table.Name
	for _, ul := range b.uniqueLookups(ti) {
		if ul.names.query == "" {
			continue
		}
		cols := ul.key.Columns
		fields[ul.names.query] = &graphql.Field{
			Type:        b.objTypes[tn],
			Description: fmt.Sprintf("One row of %s by its unique key %s (%s).", tn, ul.key.Name, strings.Join(cols, ", ")),
			Args:        b.keyArgs(ti, cols),
			Resolve: func(p graphql.ResolveParams) (any, error) {
				id, err := identityFrom(p)
				if err != nil {
					return nil, err
				}
				cond, err := b.keyCond(ti, cols, p.Args)
				if err != nil {
					return nil, err
				}
				rows, err := b.runSelect(p.Context, ti, id, listArgs{}, cond, true)
				if err != nil || len(rows) == 0 {
					return nil, err
				}
				return rows[0], nil
			},
		}
		b.optionalFields["query:"+ul.names.query] = true
	}
}

// validateWriteChecks verifies a table's insert/update checks for the role at
// build time: the table needs a primary key (the written rows are found
// again by it), and with a database the check is dry-run against the table,
// so a typo fails startup (or a hot reload) instead of every write.
//
// An insert check that comes from a legacy insert.filter is the exception:
// earlier versions accepted and ignored it, so a config that booted then must
// still boot. Where it cannot be enforced (no primary key, or the dry run
// fails, e.g. a "*" rule naming a column this table lacks) it is skipped for
// this table with a warning, as it was before.
func (b *builder) validateWriteChecks(ti *tableInfo) error {
	for _, w := range []struct {
		op string
		oa *rbac.OpAccess
	}{{"insert", ti.access.Insert}, {"update", ti.access.Update}} {
		if w.oa == nil || w.oa.Check == nil {
			continue
		}
		err := b.verifyWriteCheck(ti, w.op, w.oa.Check)
		if !w.oa.CheckFromFilter {
			if err != nil {
				return err
			}
			continue
		}
		if err != nil {
			if b.opt.Logger != nil {
				b.opt.Logger.Warn("insert.filter cannot be enforced on this table and is ignored, as before; replace it with a check that fits the table",
					"role", b.role, "table", ti.table.Name, "reason", err.Error())
			}
			ta := *ti.access
			ins := *ta.Insert
			ins.Check, ins.CheckFromFilter = nil, false
			ta.Insert = &ins
			ti.access = &ta
			continue
		}
		if b.opt.Logger != nil {
			b.opt.Logger.Warn("insert.filter is enforced as the insert check; rename it to check",
				"role", b.role, "table", ti.table.Name)
		}
	}
	return nil
}

// verifyWriteCheck checks that one write check can be enforced on its table:
// the table has a primary key and (with a database) the check runs.
func (b *builder) verifyWriteCheck(ti *tableInfo, op string, check *rbac.Filter) error {
	if len(ti.table.PrimaryKey) == 0 {
		return fmt.Errorf("table %q: the %s check needs a primary key to find the written rows", ti.table.Name, op)
	}
	if b.shared.db == nil {
		return nil
	}
	vsql := check.ValidationSQL()
	key := "check\x00" + ti.table.Name + "\x00" + vsql
	err, done := b.shared.filterChecks[key]
	if !done {
		q := "SELECT 1 FROM " + b.qualifiedTable(ti.table) + " WHERE (" + vsql + ") IS NOT TRUE LIMIT 0"
		ctx, cancel := context.WithTimeout(context.Background(), b.shared.timeout)
		rows, qerr := b.shared.db.QueryContext(ctx, q)
		if qerr == nil {
			qerr = rows.Close()
		}
		cancel()
		if qerr != nil {
			err = fmt.Errorf("table %q: verifying the %s check: %w", ti.table.Name, op, qerr)
		}
		b.shared.filterChecks[key] = err
	}
	return err
}

func (b *builder) addQueryFields(fields graphql.Fields, ti *tableInfo) {
	// Collection reads are cursor-only (keyset pagination): <t>_connection for
	// pages and <t>_aggregate for counts/sum/avg/etc. There is deliberately no
	// offset-paginated list or standalone _count — offset scans don't scale to
	// TiDB's billions-of-rows tables.
	b.addAggregateField(fields, ti)
	b.addVectorFields(fields, ti)      // nearest-neighbor search per vector column
	b.addUniqueQueryFields(fields, ti) // <t>_by_<unique key cols>

	tn := ti.table.Name
	if !b.readKeyExposable(ti) {
		// No key the role can page on: a bounded, unordered list instead.
		b.addListField(fields, ti)
		return
	}
	key := ti.model.readKey
	desc := fmt.Sprintf("One row of %s by primary key.", tn)
	if ti.model.logicalKey {
		desc = fmt.Sprintf("One row of %s by its declared key (%s).", tn, strings.Join(key, ", "))
	}
	fields[ti.rootName(config.RootByPK)] = &graphql.Field{
		Type:        b.objTypes[tn],
		Description: desc,
		Args:        b.keyArgs(ti, key),
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, err := identityFrom(p)
			if err != nil {
				return nil, err
			}
			cond, err := b.keyCond(ti, key, p.Args)
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

// addListField adds `<t>_list(limit, where)`: rows of a table or view the
// role has no usable key for (none at all, or one it cannot read), so no
// cursor can page through it. It returns at most `limit` rows (default
// default_page_size, clamped to max_page_size) in no particular order; there
// is deliberately no offset and no order_by — narrow it with `where`.
func (b *builder) addListField(fields graphql.Fields, ti *tableInfo) {
	name := b.shared.names.list[ti.table.Name]
	if name == "" {
		return // the default name was taken (startup warning)
	}
	tn := ti.table.Name
	fields[name] = &graphql.Field{
		Type: graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(b.objTypes[tn]))),
		Description: fmt.Sprintf("Up to `limit` rows of %s matching the filter, in no particular order "+
			"(%s has no key this role can page on, so there is no cursor).", tn, tn),
		Args: graphql.FieldConfigArgument{
			"limit": &graphql.ArgumentConfig{Type: graphql.Int, Description: "Max rows (defaults to default_page_size, clamped to max_page_size)."},
			"where": &graphql.ArgumentConfig{Type: b.boolExps[tn]},
		},
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, err := identityFrom(p)
			if err != nil {
				return nil, err
			}
			var la listArgs
			la.where, _ = p.Args["where"].(map[string]any)
			if l, ok := p.Args["limit"].(int); ok {
				la.limit = &l
			}
			rows, err := b.runSelect(p.Context, ti, id, la, nil, false)
			if err != nil {
				return nil, err
			}
			if rows == nil {
				rows = []map[string]any{}
			}
			return rows, nil
		},
	}
	if !ti.model.listExplicit {
		b.optionalFields["query:"+name] = true
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
	fields[ti.rootName(config.RootConnection)] = &graphql.Field{
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
				keys, err := decodeCursor(a, shape, len(ti.model.readKey))
				if err != nil {
					return nil, err
				}
				after = keysetCondition(ti.model.readKey, keys)
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
			if err := countRows(p.Context, len(rows)); err != nil {
				return nil, err
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
				keys := make([]string, len(ti.model.readKey))
				for i, pk := range ti.model.readKey {
					keys[i] = stringifyKey(last[pk])
				}
				endCursor = encodeCursor(keys, shape)
			}
			if rows == nil {
				rows = []map[string]any{}
			}

			// total_count is resolved lazily: this closure only runs the COUNT
			// if the client selected the total_count field.
			countFn := func() (int64, error) {
				return b.runCount(p.Context, ti, id, where, b.readKeyNotNull(ti))
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
					Type:        graphql.NewNonNull(b.countScalar()),
					Description: "Total rows matching the filter across all pages. Runs a COUNT only when selected — can be slow on very large tables.",
					Resolve: func(p graphql.ResolveParams) (any, error) {
						fn, ok := sourceKey(p, "count").(func() (int64, error))
						if !ok {
							return int64(0), nil
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

// returningAvailable reports whether this role's mutation responses for the
// table carry `returning`: the role must read the table, and the rows are
// found again by primary key (it need not be readable).
func (b *builder) returningAvailable(ti *tableInfo) bool {
	return ti.access.Select != nil && len(ti.table.PrimaryKey) > 0
}

// mutationResponse returns the table's <t>_mutation_response type: the
// affected_rows count plus, when available, `returning` — the written rows as
// the role may read them, with every relationship of the row type.
func (b *builder) mutationResponse(ti *tableInfo) *graphql.Object {
	tn := ti.table.Name
	if o := b.mutRespTypes[tn]; o != nil {
		return o
	}
	fields := graphql.Fields{
		"affected_rows": &graphql.Field{
			Type:        graphql.NewNonNull(b.countScalar()),
			Description: "Number of rows the mutation wrote.",
			Resolve:     func(p graphql.ResolveParams) (any, error) { return sourceKey(p, "affected_rows"), nil },
		},
	}
	if b.returningAvailable(ti) {
		fields["returning"] = &graphql.Field{
			Type: graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(b.objTypes[tn]))),
			Description: "The written rows (deleted rows as they were), read inside the mutation's transaction " +
				"through your select permission: rows it hides are written but not returned.",
			Resolve: func(p graphql.ResolveParams) (any, error) {
				rows, _ := sourceKey(p, "returning").([]map[string]any)
				if rows == nil {
					rows = []map[string]any{}
				}
				return rows, nil
			},
		}
	}
	o := graphql.NewObject(graphql.ObjectConfig{
		Name:        b.shared.names.mutResp[tn],
		Description: fmt.Sprintf("Result of a bulk mutation on %s.", tn),
		Interfaces:  []*graphql.Interface{b.mutRespIface},
		Fields:      fields,
	})
	b.mutRespTypes[tn] = o
	return o
}

// wantsReturning reports whether the client selected `returning` on this
// mutation field (fragments followed). Without it the write skips reading the
// rows back.
func (b *builder) wantsReturning(p graphql.ResolveParams) bool {
	for _, f := range p.Info.FieldASTs {
		for _, sub := range b.flattenFields(f.SelectionSet, p.Info) {
			if sub.Name != nil && sub.Name.Value == "returning" {
				return true
			}
		}
	}
	return false
}

// mutationResult is the source map of a <t>_mutation_response.
func mutationResult(affected int64, rows []map[string]any) map[string]any {
	return map[string]any{"affected_rows": affected, "returning": rows}
}

// firstRow is the single-row mutation result: the row, or null.
func firstRow(rows []map[string]any) any {
	if len(rows) == 0 {
		return nil
	}
	return rows[0]
}

func (b *builder) addMutationFields(fields graphql.Fields, ti *tableInfo) {
	tn := ti.table.Name

	if ti.access.Insert != nil {
		if input := b.insertInput(ti); input != nil {
			fields[ti.rootName(config.RootInsert)] = &graphql.Field{
				Type:        graphql.NewNonNull(b.mutationResponse(ti)),
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
					ret := b.returningAvailable(ti) && b.wantsReturning(p)
					affected, rows, err := b.runInsert(p.Context, ti, id, objects, ret)
					if err != nil {
						return nil, err
					}
					return mutationResult(affected, rows), nil
				},
			}

			// insert_one returns the inserted row, so it needs read access
			// and a readable primary key.
			if b.pkExposable(ti) {
				fields[ti.rootName(config.RootInsertOne)] = &graphql.Field{
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
						_, rows, err := b.runInsert(p.Context, ti, id, []any{p.Args["object"]}, true)
						if err != nil {
							return nil, err
						}
						return firstRow(rows), nil
					},
				}
			}
		}
	}

	if ti.access.Update != nil && ti.access.Select != nil {
		if setInput := b.setInput(ti); setInput != nil {
			fields[ti.rootName(config.RootUpdate)] = &graphql.Field{
				Type:        graphql.NewNonNull(b.mutationResponse(ti)),
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
					userCond, err := b.whereSQL(ti, where, id)
					if err != nil {
						return nil, err
					}
					opts := writeOpts{returning: b.returningAvailable(ti) && b.wantsReturning(p)}
					n, rows, err := b.runUpdate(p.Context, ti, id, set, userCond, opts)
					if err != nil {
						return nil, err
					}
					return mutationResult(n, rows), nil
				},
			}

			if b.pkExposable(ti) {
				args := b.pkArgs(ti)
				args["_set"] = &graphql.ArgumentConfig{Type: graphql.NewNonNull(setInput)}
				fields[ti.rootName(config.RootUpdateByPK)] = &graphql.Field{
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
						_, rows, err := b.runUpdate(p.Context, ti, id, set, cond, writeOpts{returning: true})
						if err != nil {
							return nil, err
						}
						return firstRow(rows), nil
					},
				}
			}

			for _, ul := range b.uniqueLookups(ti) {
				if ul.names.update == "" {
					continue
				}
				cols := ul.key.Columns
				args := b.keyArgs(ti, cols)
				args["_set"] = &graphql.ArgumentConfig{Type: graphql.NewNonNull(setInput)}
				fields[ul.names.update] = &graphql.Field{
					Type: b.objTypes[tn],
					Description: fmt.Sprintf("Update one row of %s by its unique key %s (%s) and return it; "+
						"_set may change the key itself.", tn, ul.key.Name, strings.Join(cols, ", ")),
					Args: args,
					Resolve: func(p graphql.ResolveParams) (any, error) {
						id, err := identityFrom(p)
						if err != nil {
							return nil, err
						}
						cond, err := b.keyCond(ti, cols, p.Args)
						if err != nil {
							return nil, err
						}
						set, _ := p.Args["_set"].(map[string]any)
						_, rows, err := b.runUpdate(p.Context, ti, id, set, cond, writeOpts{returning: true, keyCols: cols})
						if err != nil {
							return nil, err
						}
						return firstRow(rows), nil
					},
				}
				b.optionalFields["mutation:"+ul.names.update] = true
			}
		}
	}

	if ti.access.Delete != nil && ti.access.Select != nil {
		fields[ti.rootName(config.RootDelete)] = &graphql.Field{
			Type:        graphql.NewNonNull(b.mutationResponse(ti)),
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
				userCond, err := b.whereSQL(ti, where, id)
				if err != nil {
					return nil, err
				}
				opts := writeOpts{returning: b.returningAvailable(ti) && b.wantsReturning(p)}
				n, rows, err := b.runDelete(p.Context, ti, id, userCond, opts)
				if err != nil {
					return nil, err
				}
				return mutationResult(n, rows), nil
			},
		}

		if b.pkExposable(ti) {
			fields[ti.rootName(config.RootDeleteByPK)] = &graphql.Field{
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
					// The delete filter decides the row; the select filter only
					// whether it is shown (read in the same transaction).
					_, rows, err := b.runDelete(p.Context, ti, id, cond, writeOpts{returning: true})
					if err != nil {
						return nil, err
					}
					return firstRow(rows), nil
				},
			}
		}

		for _, ul := range b.uniqueLookups(ti) {
			if ul.names.delete == "" {
				continue
			}
			cols := ul.key.Columns
			fields[ul.names.delete] = &graphql.Field{
				Type:        b.objTypes[tn],
				Description: fmt.Sprintf("Delete one row of %s by its unique key %s (%s) and return it.", tn, ul.key.Name, strings.Join(cols, ", ")),
				Args:        b.keyArgs(ti, cols),
				Resolve: func(p graphql.ResolveParams) (any, error) {
					id, err := identityFrom(p)
					if err != nil {
						return nil, err
					}
					cond, err := b.keyCond(ti, cols, p.Args)
					if err != nil {
						return nil, err
					}
					_, rows, err := b.runDelete(p.Context, ti, id, cond, writeOpts{returning: true, keyCols: cols})
					if err != nil {
						return nil, err
					}
					return firstRow(rows), nil
				},
			}
			b.optionalFields["mutation:"+ul.names.delete] = true
		}
	}
}
