package schema

import (
	"context"
	"database/sql"

	"github.com/graphql-go/graphql"
)

// MutationOp identifies a write operation for lifecycle hooks.
type MutationOp string

const (
	OpInsert MutationOp = "insert"
	OpUpdate MutationOp = "update"
	OpDelete MutationOp = "delete"
)

// MutationEvent is passed to lifecycle hooks. It describes one write as the
// authorized caller, including the values about to be written (already merged
// with RBAC presets). Hooks may inspect it, run side effects, or abort the
// operation by returning an error.
type MutationEvent struct {
	Op     MutationOp     // insert / update / delete
	Table  string         // SQL table name
	Role   string         // the caller's resolved role
	Claims map[string]any // verified JWT claims of the caller

	// Values holds the affected data: for insert, the objects to be written
	// (with presets applied); for update, a single map of the SET columns;
	// for delete, nil. Column names are SQL names.
	Values []map[string]any

	// Affected is the number of rows written. Only meaningful in "after"
	// hooks (it is 0 in "before" hooks, where nothing has been written yet).
	Affected int

	// Tx is the transaction the mutation runs in, exposed so a hook can read
	// or write within the same atomic unit (e.g. insert an audit row, or
	// enforce a cross-table invariant). Do NOT commit or roll it back —
	// gqlgate owns its lifecycle; return an error to trigger a rollback.
	Tx *sql.Tx
}

// MutationHookFunc is a user-provided lifecycle hook. Returning an error
// aborts the mutation and rolls back its transaction.
type MutationHookFunc func(ctx context.Context, ev *MutationEvent) error

// CustomField is a developer-provided root field (query or mutation) — the
// extension point for custom signup/signin/business logic. The Field is a
// standard graphql-go field with its own args, type and resolver; gqlgate
// mounts it on the schemas of the AllowedRoles (all roles if empty).
type CustomField struct {
	Name         string
	Operation    string // "query" or "mutation"
	AllowedRoles []string
	Field        *graphql.Field
}

func (c CustomField) allows(role string) bool {
	if len(c.AllowedRoles) == 0 {
		return true
	}
	for _, r := range c.AllowedRoles {
		if r == role {
			return true
		}
	}
	return false
}

// Hooks is the resolved set of extension points handed to the schema builder.
// Construct it with NewHooks (gqlgate.Open does this from the YAML wiring plus
// the Go-provided implementations).
type Hooks struct {
	before map[string][]MutationHookFunc // key: HookKey(table, op)
	after  map[string][]MutationHookFunc
	fields []CustomField
}

// HookKey is the map key used for per-(table, op) hook lookup. Exported so the
// embedding package can build the before/after maps.
func HookKey(table string, op MutationOp) string {
	return table + "\x00" + string(op)
}

// NewHooks builds a Hooks from resolved before/after maps and custom fields.
// Any of the arguments may be nil/empty.
func NewHooks(before, after map[string][]MutationHookFunc, fields []CustomField) *Hooks {
	return &Hooks{before: before, after: after, fields: fields}
}

// runBefore runs the before-hooks registered for (table, op). It looks up both
// the explicit table entry and the "*" wildcard (wildcard first).
func (h *Hooks) runBefore(ctx context.Context, ev *MutationEvent) error {
	if h == nil {
		return nil
	}
	return runHookList(ctx, ev, h.before)
}

func (h *Hooks) runAfter(ctx context.Context, ev *MutationEvent) error {
	if h == nil {
		return nil
	}
	return runHookList(ctx, ev, h.after)
}

func runHookList(ctx context.Context, ev *MutationEvent, set map[string][]MutationHookFunc) error {
	if len(set) == 0 {
		return nil
	}
	for _, fn := range set[HookKey("*", ev.Op)] {
		if err := fn(ctx, ev); err != nil {
			return err
		}
	}
	for _, fn := range set[HookKey(ev.Table, ev.Op)] {
		if err := fn(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

// customFieldsFor returns the custom fields of the given operation visible to
// the role.
func (h *Hooks) customFieldsFor(role, operation string) []CustomField {
	if h == nil {
		return nil
	}
	var out []CustomField
	for _, cf := range h.fields {
		if cf.Operation == operation && cf.allows(role) {
			out = append(out, cf)
		}
	}
	return out
}
