// Package register is how compiled-in custom code plugs into gqlgate.
//
// Drop ordinary .go files into the top-level hooks/ directory (package hooks),
// register your functions from init(), and rebuild — `docker compose up
// --build` or `go build ./cmd/gqlgate`. Compiled hooks may import ANY
// third-party library (the build's `go mod tidy` resolves them), get full
// compile-time type checking, and run at native speed:
//
//	package hooks
//
//	import (
//	    "context"
//	    "gqlgate/register"
//	    "golang.org/x/crypto/bcrypt"
//	)
//
//	func init() {
//	    register.MutationHook("hash_password", func(ctx context.Context, ev *register.MutationEvent) error {
//	        for _, row := range ev.Values {
//	            if pw, ok := row["password"].(string); ok {
//	                h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
//	                if err != nil { return err }
//	                row["password"] = string(h)  // note: mutating Values does NOT rewrite the SQL;
//	            }                                 // use ev.Tx for writes, or veto by returning an error
//	        }
//	        return nil
//	    })
//	}
//
// Registered names are referenced from the YAML hooks: section exactly like
// script hooks; registered custom fields are mounted automatically.
package register

import (
	"fmt"
	"sync"

	"gqlgate/auth"
	"gqlgate/schema"
)

// Re-exported types so hook files only import this package.
type (
	// MutationEvent describes one write passed to a lifecycle hook.
	MutationEvent = schema.MutationEvent
	// MutationHookFunc is a before/after lifecycle hook.
	MutationHookFunc = schema.MutationHookFunc
	// CustomFieldDef is a developer-provided root query/mutation field.
	CustomFieldDef = schema.CustomField
	// RoleResolverFunc maps verified JWT claims to a role name.
	RoleResolverFunc = auth.RoleResolver
)

var (
	mu           sync.Mutex
	hooks        = map[string]MutationHookFunc{}
	fields       []CustomFieldDef
	roleResolver RoleResolverFunc
)

// MutationHook registers a named lifecycle hook. The name is what the YAML
// hooks: section references. Registering the same name twice panics at init
// time (a build-time mistake should fail loudly, not shadow silently).
func MutationHook(name string, fn MutationHookFunc) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := hooks[name]; dup {
		panic(fmt.Sprintf("gqlgate/register: mutation hook %q registered twice", name))
	}
	hooks[name] = fn
}

// CustomField registers a root query/mutation field. It is mounted on the
// schemas of its AllowedRoles (all roles if empty) automatically.
func CustomField(cf CustomFieldDef) {
	mu.Lock()
	defer mu.Unlock()
	fields = append(fields, cf)
}

// RoleResolver registers a custom role resolver. Only one may be registered;
// an explicit gqlgate.WithRoleResolver option takes precedence over it.
func RoleResolver(fn RoleResolverFunc) {
	mu.Lock()
	defer mu.Unlock()
	if roleResolver != nil {
		panic("gqlgate/register: role resolver registered twice")
	}
	roleResolver = fn
}

// Registered returns a snapshot of everything registered so far. Called by
// gqlgate.Open when assembling options.
func Registered() (map[string]MutationHookFunc, []CustomFieldDef, RoleResolverFunc) {
	mu.Lock()
	defer mu.Unlock()
	h := make(map[string]MutationHookFunc, len(hooks))
	for k, v := range hooks {
		h[k] = v
	}
	f := append([]CustomFieldDef{}, fields...)
	return h, f, roleResolver
}

// Reset clears all registrations. Only for tests.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	hooks = map[string]MutationHookFunc{}
	fields = nil
	roleResolver = nil
}
