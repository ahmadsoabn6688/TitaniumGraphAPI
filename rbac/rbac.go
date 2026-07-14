// Package rbac resolves the role rules from the YAML config against the
// introspected catalog, and evaluates row-level filters / column presets at
// request time by binding JWT claims as SQL parameters.
//
// Nothing in this package ever interpolates a claim value into SQL text:
// claim values always travel as driver placeholders.
package rbac

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"gqlgate/config"
	"gqlgate/introspect"
)

// Identity is the authenticated caller, as established by the auth middleware.
type Identity struct {
	Role   string
	Claims map[string]any
}

type ctxKey struct{}

// WithIdentity stores the identity in the context.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// IdentityFrom returns the identity previously stored with WithIdentity.
func IdentityFrom(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(*Identity)
	return id, ok
}

// Access is the fully resolved permission set of one role over one catalog.
type Access struct {
	Role   string
	tables map[string]*TableAccess
}

// Table returns the resolved access for a table, or nil when the role has no
// rule matching it.
func (a *Access) Table(name string) *TableAccess {
	return a.tables[name]
}

// TableAccess holds the per-operation access of one role on one table.
// A nil operation pointer means the operation is denied.
type TableAccess struct {
	Select *OpAccess
	Insert *OpAccess
	Update *OpAccess
	Delete *OpAccess
}

// OpAccess is one allowed operation.
type OpAccess struct {
	// Columns are the effective columns (readable for select, writable for
	// insert/update), in table ordinal order. Never empty.
	Columns   []*introspect.Column
	ColumnSet map[string]bool
	// Filter is the compiled row-level condition, nil when unrestricted.
	Filter *Filter
	// Presets are server-forced column values for insert/update.
	Presets []Preset
}

// Preset forces a column to a value on insert/update, overriding client input.
type Preset struct {
	Column    *introspect.Column
	ClaimPath string // set when the value comes from a JWT claim
	Literal   string // used when ClaimPath is empty
}

// Value resolves the preset for the given claims.
func (p Preset) Value(claims map[string]any) (any, error) {
	if p.ClaimPath == "" {
		return p.Literal, nil
	}
	v, ok := LookupClaim(claims, p.ClaimPath)
	if !ok {
		return nil, fmt.Errorf("permission preset for column %q needs JWT claim %q, which is missing from the token", p.Column.Name, p.ClaimPath)
	}
	switch v.(type) {
	case string, float64, bool, nil:
		return v, nil
	default:
		return nil, fmt.Errorf("JWT claim %q is not a scalar and cannot be used as a preset value", p.ClaimPath)
	}
}

// Resolve validates and flattens one role's config rules over the catalog.
func Resolve(roleName string, role *config.Role, cat *introspect.Catalog) (*Access, error) {
	acc := &Access{Role: roleName, tables: map[string]*TableAccess{}}

	// Explicitly named tables must exist in the exposed catalog; typos here
	// would otherwise silently grant nothing.
	for tableName := range role.Tables {
		if tableName == "*" {
			continue
		}
		if _, ok := cat.Tables[tableName]; !ok {
			return nil, fmt.Errorf("role %q grants permissions on table %q, which is not among the exposed tables of schema %q", roleName, tableName, cat.SchemaName)
		}
	}

	wildcard := role.Tables["*"]
	for _, tableName := range cat.TableOrder {
		table := cat.Tables[tableName]
		perm, explicit := role.Tables[tableName], true
		if perm == nil {
			perm, explicit = wildcard, false
		}
		if perm == nil {
			continue
		}
		ta := &TableAccess{}
		var err error
		if ta.Select, err = resolveOp(roleName, table, "select", perm.Select, explicit); err != nil {
			return nil, err
		}
		if ta.Insert, err = resolveOp(roleName, table, "insert", perm.Insert, explicit); err != nil {
			return nil, err
		}
		if ta.Update, err = resolveOp(roleName, table, "update", perm.Update, explicit); err != nil {
			return nil, err
		}
		if ta.Delete, err = resolveOp(roleName, table, "delete", perm.Delete, explicit); err != nil {
			return nil, err
		}
		if ta.Select != nil || ta.Insert != nil || ta.Update != nil || ta.Delete != nil {
			acc.tables[tableName] = ta
		}
	}
	return acc, nil
}

// resolveOp turns one OpPerm into an OpAccess. For rules coming from the "*"
// wildcard entry (explicit == false), column/preset names that a particular
// table lacks are skipped instead of rejected; if the column list then comes
// up empty the operation is denied for that table.
func resolveOp(roleName string, table *introspect.Table, op string, perm *config.OpPerm, explicit bool) (*OpAccess, error) {
	if perm == nil || !perm.Allow {
		return nil, nil
	}
	oa := &OpAccess{ColumnSet: map[string]bool{}}

	if len(perm.Columns) == 0 {
		oa.Columns = table.Columns
	} else {
		want := map[string]bool{}
		for _, c := range perm.Columns {
			if !table.HasColumn(c) {
				if explicit {
					return nil, fmt.Errorf("role %q, table %q, %s: column %q does not exist", roleName, table.Name, op, c)
				}
				continue
			}
			want[c] = true
		}
		for _, c := range table.Columns {
			if want[c.Name] {
				oa.Columns = append(oa.Columns, c)
			}
		}
		if len(oa.Columns) == 0 {
			return nil, nil // wildcard rule matched nothing on this table
		}
	}
	for _, c := range oa.Columns {
		oa.ColumnSet[c.Name] = true
	}

	if perm.Filter != "" {
		f, err := CompileFilter(perm.Filter)
		if err != nil {
			return nil, fmt.Errorf("role %q, table %q, %s filter: %w", roleName, table.Name, op, err)
		}
		oa.Filter = f
	}

	for col, val := range perm.Presets {
		c, ok := table.ColumnMap[col]
		if !ok {
			if explicit {
				return nil, fmt.Errorf("role %q, table %q, %s: preset column %q does not exist", roleName, table.Name, op, col)
			}
			continue
		}
		p := Preset{Column: c}
		if path, ok := strings.CutPrefix(val, ":jwt."); ok {
			if !claimPathPattern.MatchString(path) {
				return nil, fmt.Errorf("role %q, table %q, %s: preset %q has an invalid claim path", roleName, table.Name, op, val)
			}
			p.ClaimPath = path
		} else {
			p.Literal = val
		}
		oa.Presets = append(oa.Presets, p)
	}
	// Deterministic preset order (YAML maps are unordered).
	for i := 0; i < len(oa.Presets); i++ {
		for j := i + 1; j < len(oa.Presets); j++ {
			if oa.Presets[j].Column.Name < oa.Presets[i].Column.Name {
				oa.Presets[i], oa.Presets[j] = oa.Presets[j], oa.Presets[i]
			}
		}
	}
	return oa, nil
}

var (
	claimRefPattern  = regexp.MustCompile(`:jwt\.([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)`)
	claimPathPattern = regexp.MustCompile(`^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$`)
)

// Filter is a compiled row-level condition: a SQL fragment in which every
// ":jwt.<path>" reference has been cut out, leaving static segments plus the
// claim paths to bind between them at request time.
type Filter struct {
	segments []string // len(segments) == len(paths) + 1
	paths    []string
}

// CompileFilter parses a filter expression such as
//
//	"author_id = :jwt.sub AND tenant_id IN (:jwt.tenants)"
//
// The SQL around the claim references is passed through verbatim (the YAML
// config is trusted developer input); the claim values themselves are always
// bound as parameters, never spliced into the SQL text.
func CompileFilter(expr string) (*Filter, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, fmt.Errorf("filter is empty")
	}
	f := &Filter{}
	locs := claimRefPattern.FindAllStringSubmatchIndex(expr, -1)
	prev := 0
	for _, m := range locs {
		f.segments = append(f.segments, expr[prev:m[0]])
		f.paths = append(f.paths, expr[m[2]:m[3]])
		prev = m[1]
	}
	f.segments = append(f.segments, expr[prev:])
	return f, nil
}

// SQL renders the filter for one request, binding claim values as parameters.
// Scalar claims become a single "?"; array claims expand to "?, ?, ..." so
// they can be used inside an IN (...) list. An empty array renders as NULL,
// which never matches — i.e. it denies.
func (f *Filter) SQL(claims map[string]any) (string, []any, error) {
	var sb strings.Builder
	var args []any
	for i, seg := range f.segments {
		sb.WriteString(seg)
		if i >= len(f.paths) {
			break
		}
		path := f.paths[i]
		v, ok := LookupClaim(claims, path)
		if !ok {
			return "", nil, fmt.Errorf("this operation requires JWT claim %q, which is missing from the token", path)
		}
		switch vv := v.(type) {
		case []any:
			if len(vv) == 0 {
				sb.WriteString("NULL")
				break
			}
			for j, item := range vv {
				switch item.(type) {
				case string, float64, bool, nil:
				default:
					return "", nil, fmt.Errorf("JWT claim %q contains non-scalar elements and cannot be bound in a filter", path)
				}
				if j > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString("?")
				args = append(args, item)
			}
		case string, float64, bool, nil:
			sb.WriteString("?")
			args = append(args, vv)
		default:
			return "", nil, fmt.Errorf("JWT claim %q is not a scalar or array and cannot be bound in a filter", path)
		}
	}
	return sb.String(), args, nil
}

// LookupClaim resolves a dot path inside the claims map. Because claim names
// themselves may contain dots (e.g. Auth0-style "https://myapp.com/claims"),
// resolution is greedy: at each level the longest key that literally exists
// wins before the path is split further.
func LookupClaim(claims map[string]any, path string) (any, bool) {
	if v, ok := claims[path]; ok {
		return v, true
	}
	for i := len(path) - 1; i > 0; i-- {
		if path[i] != '.' {
			continue
		}
		prefix, rest := path[:i], path[i+1:]
		v, ok := claims[prefix]
		if !ok {
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if r, found := LookupClaim(m, rest); found {
			return r, true
		}
	}
	return nil, false
}
