// Package hooks is YOUR extension point: drop ordinary .go files in this
// directory and they are compiled into the gqlgate binary on the next build
// (`docker compose up --build` — no other wiring needed).
//
// Every file must declare `package hooks` and register its functions from
// init() via the gqlgate/register package:
//
//   - register.MutationHook("name", fn) — lifecycle hooks, referenced from the
//     YAML hooks: section by name; they run inside the mutation's transaction
//     (return an error to roll it back).
//   - register.CustomField(...) — extra root queries/mutations (e.g. signup),
//     mounted automatically for their AllowedRoles.
//   - register.RoleResolver(fn) — fully custom token→role mapping.
//
// Files here may import ANY third-party library — bcrypt, uuid, HTTP clients,
// anything; the Docker build runs `go mod tidy` so new imports resolve
// automatically. See signup.go.sample for a complete example (rename it to
// signup.go to activate).
package hooks
