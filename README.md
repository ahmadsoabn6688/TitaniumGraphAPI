# gqlgate

**YAML in → GraphQL out.** gqlgate is a Go package that connects to a
**TiDB** database, introspects the tables of one schema, and serves an
auto-generated, role-aware GraphQL API — with GraphiQL in dev. Everything is
driven by a single YAML file that defines how JWTs are verified and what each
role may see and do (RBAC down to rows and columns).

Built for TiDB specifically: collection reads use **keyset cursor pagination**
on the clustered primary key (a range scan, no sort, constant cost per page —
viable over billions of rows), plus **aggregates**, TiDB JSON/REGEXP filter
operators, and native **vector (similarity) search**. It also runs against
plain MySQL for the non-TiDB-specific parts.

gqlgate only **verifies** tokens. Signup / login / token issuance is your
application's job — issue JWTs with the same secret (or key pair) and a role
claim, and gqlgate takes it from there. Until your auth service exists, the
CLI can mint dev tokens (`-print-token`).

```
┌────────────┐   Authorization: Bearer <jwt>   ┌─────────────────────────┐
│ any client │ ──────────────────────────────► │ gqlgate                 │
│ / GraphiQL │ ◄────────────────────────────── │  verify JWT → role      │
└────────────┘        GraphQL JSON             │  role schema → SQL      │
                                               │  RBAC filters → TiDB    │
                                               └─────────────────────────┘
```

## Highlights

- **One GraphQL schema per role.** Introspection (and GraphiQL autocompletion)
  only shows the tables/columns that role can access — hidden columns aren't
  "denied", they simply don't exist in that role's schema.
- **Hasura-style query surface** per table: `posts(where, order_by, limit,
  offset)`, `posts_by_pk(id)`, `posts_count(where)`, and mutations
  `insert_posts`, `insert_posts_one`, `update_posts(_by_pk)`,
  `delete_posts(_by_pk)` — each generated only if the role is allowed.
- **Relationships from foreign keys.** `posts { author { name } }` and
  `users { posts(where: …) { … } }` are generated from FK metadata, and the
  target table's RBAC (column set + row filter) applies to nested data too.
- **Row-level security** via SQL filters with JWT claim bindings
  (`filter: "author_id = :jwt.sub"`) and **column presets** that force values
  from claims on insert/update (`presets: {author_id: ":jwt.sub"}`).
- **Roles from your users table.** With `jwt.role_lookup`, tokens carry only
  the user id and the role is read from your identity table on each request —
  change a row's `role` column and it applies instantly, no token re-issue.
  (Alternatively, read the role from a token claim with `role_claim`.)
- **Safe by construction**: claim values and all client inputs are always
  bound as SQL parameters; identifiers come from `information_schema` and are
  backtick-quoted; algorithm-pinned JWT verification (no alg confusion);
  query depth limit; request body limit; DB errors masked unless `debug`.

## Quickstart — one command

Prereq: Docker (with the Compose plugin). From the `gqlgate/` directory:

```sh
docker compose up --build
```

That's it. Compose compiles the gateway (with your `hooks/` directory baked
in), starts a demo TiDB, seeds it with a small blog schema, introspects it, and
serves **http://localhost:8080/graphql** (GraphiQL in the browser). The gateway
waits for the database/seeder to be ready, so start order never matters.

Get a dev token to play with (user `1` = an author, `4` = admin) and paste
`{"Authorization": "Bearer <token>"}` into GraphiQL's Headers tab:

```sh
docker compose exec gqlgate gqlgate -config /etc/gqlgate/gqlgate.yaml -print-token 1
```

**You touch exactly two things:**

- **`gqlgate.yaml`** — the database to expose, the roles/RBAC, JWT rules. It's
  mounted into the container, so edits hot-reload with no rebuild.
- **`hooks/`** — drop `.go` files here for custom logic (see below); they're
  compiled into the gateway on the next `docker compose up --build`.

### Point it at your own TiDB

Inject the connection through the environment — these **take priority over
`gqlgate.yaml`**, so you never edit the file (ideal for compose/K8s secrets):

```sh
GQLGATE_DB_HOST=my-tidb.internal \
GQLGATE_DB_PORT=4000 \
GQLGATE_DB_USER=svc_gql \
GQLGATE_DB_PASSWORD=... \
GQLGATE_DB_SCHEMA=mydb \
  docker compose up --build gqlgate
```

The `gqlgate` service already forwards those variables (see its `environment:`
block — set them in your shell or a `.env` file). Starting only `gqlgate` skips
the demo TiDB + seeder. Equivalently you can edit `database.*` in the YAML, but
env wins if both are set. The seeder is hard-pinned to the demo TiDB and
refuses to run against any other host, so it can never touch your real data.

## Embedding in your own app

```go
cfg, err := config.Load("gqlgate.yaml")
gate, err := gqlgate.Open(ctx, cfg)
defer gate.Close()

mux := http.NewServeMux()
mux.Handle("/graphql", gate.Handler()) // GraphQL + GraphiQL + /healthz
mux.Handle("/signup", yourSignupHandler) // you issue the JWTs
http.ListenAndServe(":8080", mux)
```

## The YAML config

```yaml
database:
  host: 127.0.0.1          # default 127.0.0.1
  port: 4000               # default 4000 (TiDB)
  user: root
  password: ""             # supports ${ENV_VAR} anywhere in the file
  schema: appdb            # REQUIRED — the schema whose tables are exposed
  max_open_conns: 10
  query_timeout_seconds: 30  # per-request execution timeout

server:
  host: 127.0.0.1
  port: 8080
  path: /graphql
  graphiql: true           # GET <path> serves GraphiQL — keep off in prod
  debug: true              # logs SQL+args, exposes DB errors — dev only
  max_query_depth: 15      # -1 disables
  hot_reload: true         # watch config + scripts, rebuild in place (dev only)
  reload_interval_seconds: 2
  cors:
    enabled: true
    allowed_origins: ["*"]

jwt:
  algorithm: HS256         # HS256/384/512, RS256/384/512, ES256/384/512 — exactly one
  secret: ${GQLGATE_JWT_SECRET}   # HS*: min 32 bytes; unset env vars fail fast
  # public_key_file: jwt.pem      # RS*/ES*: PEM public key or certificate
  # issuer: my-auth-service       # optional iss check
  # audience: my-api              # optional aud check
  leeway_seconds: 30
  anonymous_role: anonymous # role used when no Authorization header; omit to require auth

  # Role resolution, pick ONE:
  # (a) from your identity table — tokens carry only the user id:
  role_lookup:
    table: users           # setting this enables DB role resolution
    # schema: appdb        # defaults to database.schema; the table may be excluded from GraphQL
    id_claim: sub          # JWT claim (dot path) holding the user id
    id_column: id          # matched against the id claim
    role_column: role      # its value must be one of the roles below
    username_column: username  # your signup service's columns — verified to
    password_column: password  # exist at startup; set to "" to skip the check
    cache_seconds: 0       # >0 caches id->role; 0 = fresh lookup every request
  # (b) from a token claim:
  # role_claim: role       # dot path; Auth0-style URL keys work too

schema_gen:
  default_page_size: 25    # LIMIT when none given
  max_page_size: 200       # hard clamp
  tables:
    include: []            # empty = all base tables
    exclude: [migrations]

roles:
  <role-name>:
    tables:
      "<table-or-*>":      # "*" is the fallback for tables not named explicitly
        select: true|false|{...}   # same shape for insert/update/delete
        insert:
          allow: true
          columns: [a, b]  # writable columns (select: readable). empty = all
          filter: "owner_id = :jwt.sub"   # rows the op may touch (select/update/delete)
          presets:                        # forced values, hidden from the API
            owner_id: ":jwt.sub"          # from a claim — or a literal string
```

### RBAC semantics

| Piece | Meaning |
|---|---|
| `select.columns` | Only these columns exist in the role's object type, `where`, and `order_by`. |
| `select.filter` | SQL appended to every read — including `_by_pk`, `_count`, relationship hops, and mutation return values. `:jwt.<path>` binds claim values as parameters; arrays expand for `IN (…)`; an empty array matches nothing; a missing claim is an error, never "no filter". |
| `insert/update.presets` | Server-forced column values. Preset columns are removed from the input types, so clients cannot even attempt to set them. |
| `update/delete.filter` | Rows the role may touch. Everything else reports `affected_rows: 0`. |
| `"*"` wildcard | Applies to tables without an explicit entry. Unknown columns in wildcard rules are skipped per table; in named rules they are startup errors. |

Notes worth knowing:

- Mutations other than plain `insert_<table>` require `select` on the same
  table (they return rows / take `where` filters built from readable columns).
- `insert_<table>_one` / `update_<table>_by_pk` re-read the row through your
  select filter — if the filter hides it, you get `null` back (the write still
  happened).
- Roles are startup-validated against the real schema: a typo'd table or
  column name in the YAML refuses to boot.

### JWT contract (for your signup service)

Issue tokens signed with the configured algorithm/secret. With `role_lookup`
(recommended) a token only needs the user id and an expiry:

```json
{ "sub": 123, "exp": 1784022060 }
```

Your signup service owns the identity table: it inserts
`username / password(hash) / role` rows and issues the JWTs; gqlgate verifies
at startup that those columns exist (the contract), reads **only** the role
column at request time, and never touches passwords. A request whose id has
no row — a deleted user — is rejected with 403 immediately.

With `role_claim` mode instead, the token itself carries the role:

```json
{ "role": "author", "sub": 123, "exp": 1784022060 }
```

In both modes:

- `exp` is **required** (tokens without expiry are rejected).
- The resolved role must be one of the configured roles, or the request is
  rejected with 403.
- All claims are available to filters/presets as `:jwt.<path>`
  (nested paths like `:jwt.app_metadata.tenant_id` work).

## Generated API, per table (role permitting)

```graphql
# queries (collection reads are cursor-only)
posts_connection(first: Int, after: String, where: posts_bool_exp): posts_connection!
  # posts_connection { nodes: [posts!]!  page_info { has_next_page end_cursor }  total_count: Int! }
posts_by_pk(id: BigInt!): posts
posts_aggregate(where: posts_bool_exp): posts_aggregate_result!
  # { count: Int!  sum {..}  avg {..}  min {..}  max {..} }
posts_nearest_by_<vectorcol>(to: Vector!, metric: vector_metric, first: Int, where: posts_bool_exp): [posts_neighbor!]!
  # posts_neighbor { node: posts!  distance: Float! }   (only for VECTOR columns)

# mutations
insert_posts(objects: [posts_insert_input!]!): mutation_response!
insert_posts_one(object: posts_insert_input!): posts
update_posts(where: posts_bool_exp!, _set: posts_set_input!): mutation_response!
update_posts_by_pk(id: BigInt!, _set: posts_set_input!): posts
delete_posts(where: posts_bool_exp!): mutation_response!
delete_posts_by_pk(id: BigInt!): posts
```

`where` supports `_and/_or/_not` plus per-column `_eq _neq _gt _gte _lt _lte
_in _nin _is_null` (`_like/_nlike/_regex/_nregex` on strings; `_contains/
_has_key` on JSON). Type mapping: `BIGINT → BigInt`, `DECIMAL → Decimal`
(string, exact), `TINYINT(1) → Boolean`, `DATETIME/TIMESTAMP → DateTime`
(RFC 3339), `DATE → Date`, `JSON → JSON`, `VECTOR → Vector` (`"[1,2,3]"`),
binary → `Bytes` (base64). `BigInt` serializes as a JSON number — exact on the
wire; JavaScript clients should mind values above 2^53.

Schema-generation details that just work:

- **Generated/computed columns** (STORED/VIRTUAL) are read-only: they never
  appear in insert/update inputs (the database computes them) but are
  selectable like any other column.
- **JSON columns are always nullable** in the output — a `json NOT NULL`
  column can legally hold the JSON literal `null`, which GraphQL can't
  represent under a non-null field.
- **`_by_pk` fields** (`<t>_by_pk`, `update_<t>_by_pk`, `delete_<t>_by_pk`,
  `insert_<t>_one`) are generated only when the whole primary key is readable
  by the role — so hiding the PK via `select.columns` also removes it as a
  lookup argument, not just from output.
- **Foreign keys are scoped to the exposed schema**: an FK pointing at a
  same-named table in another schema is ignored rather than mis-joined.
- **Name collisions fail at startup** with an actionable message: if two
  tables (or a table and a reserved name) would produce the same GraphQL
  field or type — e.g. `users` + `users_connection`, or a table named
  `order_by` — the server refuses to boot instead of silently dropping an
  operation.

## Layout

```
gqlgate.yaml         the config you edit (mounted into the container)
hooks/               YOUR compiled-in .go hooks/fields (+ signup.go.sample)
docker-compose.yml   one-command build+seed+serve
Dockerfile           builds the gateway with hooks/ (runs `go mod tidy`)
register/            registry the hooks/ files use (MutationHook/CustomField/…)
config/              YAML loading + validation (env expansion, strict keys)
introspect/          information_schema → tables, columns, PKs, FKs
rbac/                role resolution, row-filter compilation, claim lookup
auth/                JWT verification middleware (alg-pinned) + DB role resolver
schema/              per-role GraphQL schema, parameterized SQL, dataloader,
                     keyset pagination, aggregates, vector search, hooks
server/              HTTP handler, GraphiQL (embedded), CORS, depth limit
options.go           hook resolution (YAML names → hooks/ registry) + JWT signer
cmd/gqlgate/         CLI: serve (with startup retry) + -print-token
example/             seed schema + seeding tool
```

## Relationship batching (dataloader)

Relationship fields are batched, so following a relationship over N rows costs
**2 queries, not N+1**. `posts { author { name } }` runs one query for the
posts and one `SELECT … FROM users WHERE id IN (…)` for all their authors
(duplicate keys deduped). The reverse, `users { posts { … } }`, batches the
same way — one query, bounded per parent by a `ROW_NUMBER()` window so each
parent's `limit`/`offset` also caps what the database returns (not just what's
shown), with `where`/`order_by` applied and each group paged in memory.
Batching is per-request, multi-round (so recursive/self-referential
relationships like category trees or org charts resolve correctly at every
depth), and applies whenever the join columns are readable by the role;
otherwise it falls back to a per-row query (never a correctness or RBAC
compromise).

## Hot config reload (dev)

With `server.hot_reload: true`, gqlgate watches the config file and rebuilds
roles, RBAC, hook wiring and the per-role schemas **in place** when it changes
— no restart, no dropped connections. Edit a role's columns, add a role, or
tweak a filter, save, and the next request sees it (poll interval
`reload_interval_seconds`, default 2s). Changing which `hooks/` files exist
still needs a rebuild (they're compiled in).

```yaml
server:
  hot_reload: true
  reload_interval_seconds: 2
```

Connection settings and the listen host/port/path can't change this way (they
need a new pool/listener); such a change is rejected and the previous config
keeps serving. Embedding hosts can also call `gate.Reload(ctx)` directly (e.g.
on SIGHUP). Keep `hot_reload` off in production.

## Querying it (React or any client)

The API is plain GraphQL over `POST <path>`, so any client works — `fetch`,
Apollo Client, urql, graphql-request. Send the JWT your signup service issued
in the `Authorization` header; the role (and thus the visible schema) follows
from it.

```ts
const res = await fetch("http://localhost:8080/graphql", {
  method: "POST",
  headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
  body: JSON.stringify({
    query: `query Posts($after: String) {
      posts_connection(first: 10, after: $after) {
        nodes { id title  author { name }  comments(limit: 3) { body } }  # author batched
        page_info { has_next_page end_cursor }
      }
    }`,
    variables: { after: null },
  }),
});
const { data } = await res.json();
// next page: variables.after = data.posts_connection.page_info.end_cursor
```

### Pagination — cursor only (keyset)

Collection reads are cursor-paginated; the client never computes offsets or
counts. `<table>_connection(first, after, where)` returns a page plus the
cursor to resume from:

```graphql
query Feed($after: String) {
  posts_connection(first: 10, after: $after, where: {published: {_eq: true}}) {
    nodes { id title author { name } }   # author is batched (no N+1)
    page_info { has_next_page end_cursor }
    total_count                          # optional; runs COUNT only if selected
  }
}
```

To load the next page, pass the previous `page_info.end_cursor` back as
`$after` — that's the whole protocol. `has_next_page` tells you when to stop.
This maps directly onto Apollo's `fetchMore` / infinite scroll.

Why keyset (and why no offset or `order_by`): TiDB stores rows in
clustered-primary-key order, so paging by the PK (`WHERE pk > cursor ORDER BY
pk LIMIT n`) is a **range scan with no sort** and **constant cost per page** no
matter how deep you've paged — the opposite of `OFFSET`, which re-scans and
discards every skipped row and collapses on billions of rows. So the connection
always orders by the PK (there is deliberately no offset list field and no
arbitrary `order_by`). The cursor is opaque, encodes the last row's PK, and is
bound to the query's `where`, so it can't be replayed against a different
filter. `first` is clamped to `schema_gen.max_page_size`. `total_count` is a
separate field whose `COUNT` runs only when selected (skip it for the fastest
paging on huge tables). Connections are generated for tables whose primary key
the role can read.

### Aggregates

`<table>_aggregate(where)` computes count/sum/avg/min/max in one query, and
only the aggregates you actually select are computed:

```graphql
query { posts_aggregate(where: {published: {_eq: true}}) {
  count
  avg { views }  sum { views }  min { views }  max { published_on }
} }
```

`sum`/`avg` cover numeric columns; `min`/`max` cover every readable column.
The role's row filter is always applied.

### TiDB filter operators

On top of `_eq _neq _gt _gte _lt _lte _in _nin _is_null` (and `_like/_nlike` on
strings), TiDB-backed operators are available: **`_regex` / `_nregex`**
(`REGEXP`), and on JSON columns **`_contains`** (`JSON_CONTAINS`) and
**`_has_key`** (`JSON_CONTAINS_PATH`). All values are bound as parameters.

```graphql
posts_connection(where: {title: {_regex: "^Notes"}, metadata: {_has_key: "tier"}}) { nodes { id } }
```

### Vector search (similarity / "nearest")

TiDB has **no GIS/spatial types** (no `GEOMETRY`/`POINT`/`ST_*`) — for lat/lng
geo, store coordinates as columns and filter with a bounding box
(`lat: {_gte, _lte}`, `lng: {_gte, _lte}`). What TiDB *does* have is native
**vector search**, which gqlgate exposes for any `VECTOR` column: a top-K
nearest-neighbor query per column.

```graphql
query { documents_nearest_by_embedding(to: "[1,2,3]", metric: COSINE, first: 5) {
  node { id title }
  distance
} }
```

`metric` is `COSINE` (default), `L2`, `L1`, or `INNER_PRODUCT`. It runs
`ORDER BY VEC_<metric>_DISTANCE(col, :to) ASC LIMIT first` (top-K, honoring the
role filter and any `where`). `VECTOR` columns are exposed as a `Vector` scalar
(`"[1,2,3]"`). Cursor connections map straight onto Apollo's `fetchMore`, and
because gqlgate serves a per-role schema, GraphQL codegen produces types that
are accurate for that role.

## Custom hooks & fields (the `hooks/` directory)

gqlgate is extensible with your own Go code — for custom sign-up/sign-in and
business logic. (It deliberately does **not** use compiled Go plugins: the
`plugin` package is unsupported on Windows and brittle elsewhere.)

Drop plain `.go` files into the top-level **`hooks/`** directory and they're
compiled into the gateway on the next `docker compose up --build` — no other
wiring. They can **import any third-party library** (bcrypt, uuid, an HTTP
client, …), get full compile-time type checking, and run at native speed. Each
file registers its functions from `init()`:

```go
// hooks/signup.go  (package hooks)
package hooks

import (
    "gqlgate"
    "gqlgate/register"
    "github.com/graphql-go/graphql"
    "golang.org/x/crypto/bcrypt"   // ← third-party, resolved automatically at build
)

func init() {
    register.MutationHook("validate_post", func(ctx context.Context, ev *register.MutationEvent) error {
        /* runs in the mutation's tx; return an error to roll back */ return nil
    })
    register.CustomField(register.CustomFieldDef{
        Name: "signup", Operation: "mutation", AllowedRoles: []string{"anonymous"},
        Field: &graphql.Field{ /* args/type + a resolver that bcrypt-hashes and calls gate.SignToken */ },
    })
}
```

Then reference hook names from `gqlgate.yaml` (`hooks.tables.posts.before_insert:
[validate_post]`); custom fields mount automatically. The build runs `go mod
tidy`, so new imports resolve with no manual dependency management. A complete,
runnable template is [`hooks/signup.go.sample`](hooks/signup.go.sample) — rename
it to `hooks/signup.go` and rebuild to activate a real bcrypt-hashing `signup`
mutation.

What hook files can do:

- **`register.MutationHook(name, fn)`** — lifecycle hooks around generated
  CRUD (`before_insert`, `after_update`, …, wired per table in YAML). They run
  **inside the mutation's transaction**: return an error to roll the write
  back; use `ev.Tx` to read/write atomically with it (e.g. audit rows).
  `ev` carries `Op/Table/Role/Claims/Values/Affected`.
- **`register.CustomField(def)`** — extra root queries/mutations with full
  graphql-go control over args/types/resolver, mounted only for the roles in
  `AllowedRoles` (empty = all). Inside a resolver,
  `gqlgate.FromContext(p.Context)` reaches the shared DB pool (`gate.DB()`)
  and token signing (`gate.SignToken(claims)`); `rbac.IdentityFrom(p.Context)`
  gives the caller's role and claims.
- **`register.RoleResolver(fn)`** — fully custom token→role mapping (takes
  precedence over `role_claim`/`role_lookup`).

## Limitations (deliberate, v1)

- Collection reads are cursor-only and ordered by the primary key; there's no
  arbitrary `order_by` on connections (that's the point — PK order is free on
  TiDB, arbitrary sorts aren't). Sort application-side, or add a covering index
  and query by it via `where`.
- Connections require a table with a role-readable primary key.
- No `GROUP BY`/grouped aggregates yet (aggregates are whole-filter), no
  subscriptions, no views (base tables only).
- TiDB has no spatial/GIS types; use lat/lng columns + bounding-box filters, or
  `VECTOR` columns for similarity search.
- Schema is introspected once at startup (or on hot reload) — restart after DDL
  changes that aren't picked up by a reload.
- GraphiQL loads its JS/CSS from unpkg.com (needs internet in dev).

## Hardening notes

This build has been through several adversarial review passes. Things it
deliberately gets right (with regression tests): all client input and JWT claim
values are bound as SQL parameters (never interpolated — verified even for
keyset cursor keys, which TiDB compares exactly against BIGINT PKs); the
query-depth guard is memoized so a small fan-out fragment document can't cause
exponential CPU; hidden columns can't be probed through `where`, `_by_pk`,
cursors, or variables; the RBAC row filter is applied on every read path
(connections, aggregates, relationships, vector search); aggregate and
relationship selections are computed correctly even when the client wraps them
in fragments; vector search skips NULL-vector rows; DB errors are masked from
clients unless `server.debug` is on; and identifier/name collisions are
rejected at startup rather than silently dropping an operation.
