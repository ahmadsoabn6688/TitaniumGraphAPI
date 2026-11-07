package schema

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/graphql-go/graphql"

	"gqlgate/config"
)

// ObjectField is a computed field a hook attaches to a generated table
// object type (e.g. users.avatar_url). It appears wherever the type does —
// connection nodes, _by_pk, relationships, mutation `returning` — for every
// role that may see it: a role named in AllowedRoles (all roles if empty)
// that can read the table and every column in Requires. Its resolver gets
// those parent columns, its own arguments, the caller's role and claims and
// the database handle.
//
// Exactly one of Resolve and ResolveBatch must be set. Resolve runs once per
// parent row; ResolveBatch runs once per wave of parent rows of a request
// (like a relationship batch) and must return one result per params entry,
// in order. Use ResolveBatch whenever the field reads the database or calls
// a service, to avoid N+1 round trips.
//
// The DB handle is the gateway's own pool: queries through it bypass RBAC,
// so the resolver must apply whatever permission logic its data needs
// (Role/Claims tell it who is asking).
type ObjectField struct {
	// Table is the SQL name of the table or view whose type gets the field.
	Table string
	// Name is the GraphQL field name; it may not collide with a column or
	// relationship field of the type.
	Name string
	// AllowedRoles limits the roles that see the field (empty = all).
	AllowedRoles []string
	// Requires lists the SQL columns of the parent row the resolver reads.
	// The field is left out for a role that cannot read all of them, and
	// ObjectFieldParams.Row carries exactly these columns.
	Requires []string

	Type              graphql.Output
	Args              graphql.FieldConfigArgument
	Description       string
	DeprecationReason string

	Resolve      func(ctx context.Context, p ObjectFieldParams) (any, error)
	ResolveBatch func(ctx context.Context, ps []ObjectFieldParams) ([]any, error)
}

// ObjectFieldParams is the input of an object field resolver for one parent
// row.
type ObjectFieldParams struct {
	// Row holds the Requires columns of the parent row, keyed by SQL column
	// name, with the values the generated fields resolve from (e.g. int64 for
	// BIGINT, string for VARCHAR, time.Time for DATETIME, decoded JSON).
	Row map[string]any
	// Args are the field's GraphQL arguments.
	Args map[string]any
	// Role and Claims identify the caller.
	Role   string
	Claims map[string]any
	// DB is the gateway's connection pool (no RBAC applies to it).
	DB *sql.DB
}

func (f ObjectField) allows(role string) bool {
	return CustomField{AllowedRoles: f.AllowedRoles}.allows(role)
}

// ValidateObjectFields checks object field registrations that need no
// database: names, types, resolvers, roles and duplicates. Tables and
// columns are checked when the schema is built.
func ValidateObjectFields(cfg *config.Config, defs []ObjectField) error {
	seen := map[string]bool{}
	for _, f := range defs {
		where := fmt.Sprintf("object field %s.%s", f.Table, f.Name)
		if f.Table == "" || !config.ValidGraphQLName(f.Name) {
			return fmt.Errorf("%s: needs a Table and a valid GraphQL Name", where)
		}
		if f.Type == nil {
			return fmt.Errorf("%s: Type is required", where)
		}
		if (f.Resolve == nil) == (f.ResolveBatch == nil) {
			return fmt.Errorf("%s: set exactly one of Resolve and ResolveBatch", where)
		}
		key := f.Table + "\x00" + f.Name
		if seen[key] {
			return fmt.Errorf("%s: registered twice", where)
		}
		seen[key] = true
		for _, r := range f.AllowedRoles {
			if _, ok := cfg.Roles[r]; !ok {
				return fmt.Errorf("%s allows role %q, which is not defined under roles:", where, r)
			}
		}
	}
	return nil
}

// resolveObjectFields picks, per select-able table, the object fields this
// role sees, and rejects ones whose table/columns don't exist or whose name
// collides with a generated field of the type.
func (b *builder) resolveObjectFields() error {
	b.objFields = map[string][]ObjectField{}
	for _, f := range b.opt.Hooks.objectFields() {
		t := b.opt.Catalog.Tables[f.Table]
		if t == nil {
			// The hooks/ directory is compiled into every deployment; a field
			// for a table this schema does not expose is skipped, not fatal.
			if b.opt.Logger != nil && b.role == b.firstRole() {
				b.opt.Logger.Warn("object field skipped: table is not exposed", "table", f.Table, "field", f.Name)
			}
			continue
		}
		for _, c := range f.Requires {
			if !t.HasColumn(c) {
				return fmt.Errorf("object field %s.%s requires column %q, which table %q does not have", f.Table, f.Name, c, f.Table)
			}
		}
		ti := b.tinfos[f.Table]
		if !f.allows(b.role) || ti == nil || ti.access.Select == nil {
			continue
		}
		if !columnsReadable(ti, f.Requires) {
			if len(f.AllowedRoles) > 0 && b.opt.Logger != nil {
				b.opt.Logger.Warn("object field left out for a role that cannot read the columns it requires",
					"role", b.role, "table", f.Table, "field", f.Name)
			}
			continue
		}
		if c := ti.fieldToCol[f.Name]; c != nil {
			return fmt.Errorf("object field %s.%s collides with the field of column %q", f.Table, f.Name, c.Name)
		}
		for _, rel := range b.relations(ti) {
			if rel.name == f.Name {
				return fmt.Errorf("object field %s.%s collides with the relationship field of the same name for role %q", f.Table, f.Name, b.role)
			}
			if !rel.outgoing && rel.name+"_aggregate" == f.Name {
				return fmt.Errorf("object field %s.%s collides with the nested aggregate field of the same name for role %q", f.Table, f.Name, b.role)
			}
		}
		b.objFields[f.Table] = append(b.objFields[f.Table], f)
	}
	return nil
}

// firstRole is the alphabetically first role, so role-independent warnings
// are logged once per build rather than once per role.
func (b *builder) firstRole() string {
	first := ""
	for r := range b.opt.Config.Roles {
		if first == "" || r < first {
			first = r
		}
	}
	return first
}

// addObjectHookFields mounts the role's object fields onto a table type.
func (b *builder) addObjectHookFields(ti *tableInfo, fields graphql.Fields) {
	for _, f := range b.objFields[ti.table.Name] {
		fields[f.Name] = b.objectHookField(f)
	}
}

func (b *builder) objectHookField(f ObjectField) *graphql.Field {
	return &graphql.Field{
		Type:              f.Type,
		Args:              f.Args,
		Description:       f.Description,
		DeprecationReason: f.DeprecationReason,
		Resolve: func(p graphql.ResolveParams) (any, error) {
			id, err := identityFrom(p)
			if err != nil {
				return nil, err
			}
			row, _ := p.Source.(map[string]any)
			sub := make(map[string]any, len(f.Requires))
			for _, c := range f.Requires {
				sub[c] = row[c]
			}
			params := ObjectFieldParams{Row: sub, Args: p.Args, Role: id.Role, Claims: id.Claims, DB: b.opt.DB}
			if f.Resolve != nil {
				return callObjectField(f, func() (any, error) { return f.Resolve(p.Context, params) })
			}
			// Under a multi-field mutation a deferred batch would run after the
			// last mutation (see serialMutation): resolve this row right away.
			if serialMutation(p.Info) {
				return callObjectField(f, func() (any, error) {
					vals, err := f.ResolveBatch(p.Context, []ObjectFieldParams{params})
					if err != nil {
						return nil, err
					}
					if len(vals) != 1 {
						return nil, fmt.Errorf("object field %s.%s: ResolveBatch returned %d results for 1 row", f.Table, f.Name, len(vals))
					}
					return vals[0], nil
				})
			}
			loader := loadersFrom(p.Context).fieldBatch(
				loaderKey("field", f.Table+"."+f.Name, argsKey(p.Args)),
				func() *fieldBatcher { return &fieldBatcher{field: f} })
			item := loader.add(params)
			return func() (any, error) { return loader.get(p.Context, item) }, nil
		},
	}
}

// callObjectField runs hook code, turning a panic into a field error.
func callObjectField(f ObjectField, fn func() (any, error)) (v any, err error) {
	defer func() {
		if r := recover(); r != nil {
			v, err = nil, fmt.Errorf("object field %s.%s: internal error: %v", f.Table, f.Name, r)
		}
	}()
	return fn()
}

// argsKey is a stable signature of a field's arguments (batches with
// different arguments are separate).
func argsKey(args map[string]any) string {
	raw, err := json.Marshal(args)
	if err != nil {
		return fmt.Sprintf("%#v", args)
	}
	return string(raw)
}

// fieldBatcher batches one object field (with one set of arguments) over a
// request. Like relLoader it is multi-round: the rows queued since the last
// flush form the next batch, so the field also resolves at every depth of a
// recursive selection.
type fieldBatcher struct {
	field   ObjectField
	mu      sync.Mutex
	pending []*fieldItem
}

type fieldItem struct {
	params ObjectFieldParams
	done   bool
	val    any
	err    error
}

func (l *fieldBatcher) add(p ObjectFieldParams) *fieldItem {
	it := &fieldItem{params: p}
	l.mu.Lock()
	l.pending = append(l.pending, it)
	l.mu.Unlock()
	return it
}

// get returns one row's result, first resolving every pending row in one
// ResolveBatch call when the row has not been resolved yet.
func (l *fieldBatcher) get(ctx context.Context, it *fieldItem) (any, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !it.done {
		batch := l.pending
		l.pending = nil
		ps := make([]ObjectFieldParams, len(batch))
		for i, b := range batch {
			ps[i] = b.params
		}
		var vals []any
		_, err := callObjectField(l.field, func() (any, error) {
			var err error
			vals, err = l.field.ResolveBatch(ctx, ps)
			return nil, err
		})
		if err == nil && len(vals) != len(batch) {
			err = fmt.Errorf("object field %s.%s: ResolveBatch returned %d results for %d rows", l.field.Table, l.field.Name, len(vals), len(batch))
		}
		for i, b := range batch {
			b.done = true
			if err != nil {
				b.err = err
			} else {
				b.val = vals[i]
			}
		}
	}
	return it.val, it.err
}
