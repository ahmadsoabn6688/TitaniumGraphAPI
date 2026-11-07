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
- **Filter through relationships.** `where: {author: {name: {_eq: "Ada"}},
  comments: {}}` compiles to correlated `EXISTS` subqueries that apply the
  related table's row filter for the role — in connections, aggregates,
  vector search, nested lists and update/delete alike.
- **Configurable filter surface.** Per role and table, choose which columns,
  operators and relationships `where` offers, and declare your own comparison
  operators in YAML (SQL templates with bound values). Case-insensitive and
  literal string operators (`_ilike`, `_icontains`, `_starts_with`, …) are
  built in.
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
  custom_operators:        # extra `where` operators (see "Custom operators")
    - name: _year_eq       # appears in Date_comparison_exp / DateTime_comparison_exp
      argument: Int        # GraphQL scalar of the argument
      applies_to: [Date, DateTime]   # column scalars that get it (default: [argument])
      sql: "YEAR({column}) = {value}"

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
        # select (object form) also takes the `where` surface, all optional:
        #   filterable_columns:           # default: every readable column
        #     id: all                     # all operators
        #     title: [_eq, _ilike, _starts_with]
        #   filter_operators: [_eq, _in, _is_null, _ilike, _starts_with]  # table-wide allow-list; [] = none
        #   filter_relationships: [author]  # default: every relationship; [] = none
```

### RBAC semantics

| Piece | Meaning |
|---|---|
| `select.columns` | Only these columns exist in the role's object type, `where`, and `order_by`. |
| `select.filter` | SQL appended to every read — including `_by_pk`, `_count`, relationship hops, and mutation return values. `:jwt.<path>` binds claim values as parameters; arrays expand for `IN (…)`; an empty array matches nothing; a missing claim is an error, never "no filter". |
| `insert/update.presets` | Server-forced column values. Preset columns are removed from the input types, so clients cannot even attempt to set them. |
| `update/delete.filter` | Rows the role may touch. Everything else reports `affected_rows: 0`. |
| `"*"` wildcard | Applies to tables without an explicit entry. Unknown columns in wildcard rules are skipped per table; in named rules they are startup errors. |
| `select.filterable_columns` | Which readable columns appear in `<table>_bool_exp` (default: all of them). A list (`[id, title]`) or a map of column → `all` / operator list. Non-filterable columns stay selectable. |
| `select.filter_operators` | Table-wide operator allow-list, intersected with any per-column list (default: every operator, custom ones included; `[]` = none, i.e. no column filters on the table, and so no relationship filters either). |
| `select.filter_relationships` | Relationship fields usable in `where` (default: every relationship the role can follow whose local join columns are filterable with `_eq`; `[]` = none). Navigation in the selection set is unaffected. |

Notes worth knowing:

- Mutations other than plain `insert_<table>` require `select` on the same
  table (they return rows / take `where` filters built from readable columns).
- `insert_<table>_one` / `update_<table>_by_pk` re-read the row through your
  select filter — if the filter hides it, you get `null` back (the write still
  happened).
- Roles are startup-validated against the real schema: a typo'd table or
  column name in the YAML refuses to boot. The same goes for unknown
  operator names, operators that don't apply to a column's type (in named
  rules), unknown `filter_relationships` names, and a named rule whose
  `filter_relationships` lists a relationship whose join column it hides
  from `where` (see below).
- `select.filter` is also applied **inside relationship filters** (the related
  table's filter, for the caller's role and claims). Because there it runs as
  a correlated subquery, every select filter on a table with foreign keys is
  dry-run against its own table at startup; one that references a column the
  table lacks (which SQL would otherwise silently resolve against the *outer*
  query's table) is logged as a warning and relationship filters into that
  table are withheld for the role. Only the database rejecting the filter
  itself (unknown column/table/function, syntax error, missing privilege)
  counts: a timeout or connection error during the dry run fails startup —
  or rejects a hot reload, which keeps the previous schema serving — instead
  of silently publishing a schema with relationship filters missing.

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

`where` supports `_and/_or/_not`, per-column `_eq _neq _gt _gte _lt _lte
_in _nin _is_null` (plus the string operators below on strings, and
`_contains/_has_key` on JSON), any configured custom operators, and one field
per relationship (see [Filtering through relationships](#filtering-through-relationships)).
Comparison types are shared per scalar (`String_comparison_exp`, …); a column
whose operators a role restricts gets its own `<table>_<column>_comparison_exp`
with just the allowed ones. Type mapping: `BIGINT → BigInt`, `DECIMAL → Decimal`
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
schema/              per-role GraphQL schema, parameterized SQL, where/filter
                     surface (operators, relationship EXISTS), dataloader,
                     keyset pagination, aggregates, vector search, hooks
server/              HTTP handler, GraphiQL (embedded), CORS, depth limit
options.go           hook resolution (YAML names → hooks/ registry) + JWT signer
cmd/gqlgate/         CLI: serve (with startup retry) + -print-token
example/             seed schema + seeding tool
e2e/                 end-to-end suite: in-process gateway vs. a live TiDB
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

### Filter operators

On top of `_eq _neq _gt _gte _lt _lte _in _nin _is_null`, string columns get:

| Operator | Meaning | SQL (values always bound) |
|---|---|---|
| `_like` / `_nlike` | LIKE pattern (`%`, `_` wildcards), column collation | `col LIKE ?` |
| `_ilike` / `_nilike` | case-insensitive LIKE pattern | `col LIKE ?` on `*_ci` columns, else `LOWER(col) LIKE LOWER(?)` |
| `_regex` / `_nregex` | regular expression, column collation | `col REGEXP ?` |
| `_iregex` / `_niregex` | case-insensitive regular expression | `REGEXP_LIKE(col, ?, 'i')` |
| `_contains` / `_icontains` | literal substring | `col LIKE '%…%' ESCAPE '!'` |
| `_starts_with` / `_istarts_with` | literal prefix | `col LIKE '…%' ESCAPE '!'` (see below for `*_ci` columns) |
| `_ends_with` / `_iends_with` | literal suffix | `col LIKE '%…' ESCAPE '!'` |

The literal operators take plain text, not a pattern: `%`, `_` and `!` in the
value are escaped, so `{title: {_contains: "50%"}}` matches only titles that
really contain `50%`. The pattern is built in Go and bound as one parameter,
so `_starts_with` stays an index range scan. The `_i*` variants ignore case;
the others compare exactly — on a `*_ci` column they force the charset's
`_bin` collation (`_like`, `_regex` and `_eq` keep following the column's
collation, as before). Forcing `_bin` alone would turn a prefix match into a
full index scan, so on a `*_ci` column `_starts_with` renders as
`(col LIKE ? ESCAPE '!' AND col COLLATE utf8mb4_bin LIKE ? ESCAPE '!')`
with the pattern bound twice: the first half keeps the range scan on the
column's index, the second enforces the case. JSON columns keep their own
**`_contains`** (`JSON_CONTAINS`) and **`_has_key`** (`JSON_CONTAINS_PATH`).

Case-insensitivity on `*_ci` columns relies on TiDB's new collation
framework (the default since v4.0). On a cluster bootstrapped with
`new_collations_enabled_on_first_bootstrap = false` — typically one upgraded
from an older release — every collation compares as binary. gqlgate checks
this at startup (`SELECT _utf8mb4'A' COLLATE utf8mb4_general_ci LIKE
_utf8mb4'a'`, no privileges needed) and then treats every column as
case-sensitive: the `_i*` operators use `LOWER(col) LIKE LOWER(?)`
everywhere, so they still ignore case, but can no longer use an index.

```graphql
posts_connection(where: {title: {_istarts_with: "notes"}, body: {_icontains: "engine"}}) { nodes { id } }
users_connection(where: {name: {_iregex: "^(ada|grace) "}, metadata: {_has_key: "tier"}}) { nodes { id } }
```

Performance on large tables: only `_starts_with` (on any collation) and
`_istarts_with` / `_ilike 'x%'` (on a `*_ci` column, with the new collation
framework) can use an index range; leading-wildcard operators, `LOWER(col)`
and regexes scan. Restrict them per role with the
filter surface below.

### Custom operators

`schema_gen.custom_operators` adds operators to the comparison types of the
scalars they apply to:

```yaml
schema_gen:
  custom_operators:
    - name: _year_eq                 # must start with _; may not reuse a built-in name
      argument: Int                  # scalar of the argument (String, Int, Float, Boolean,
                                     # BigInt, Decimal, DateTime, Date, JSON, Bytes, Vector)
      applies_to: [Date, DateTime]   # column scalars that get it (default: [argument])
      sql: "YEAR({column}) = {value}"
    - name: _len_gt
      argument: Int
      applies_to: [String]
      sql: "CHAR_LENGTH({column}) > {value}"
```

```graphql
posts_connection(where: {published_on: {_year_eq: 2026}, title: {_len_gt: 20}}) { nodes { id } }
```

`{column}` becomes the backtick-quoted (and, inside relationship filters,
alias-qualified) column; every `{value}` becomes a bound `?` carrying the
argument. Templates are validated when the config loads — both placeholders
present and outside quotes (`'{value}'` would not be a string literal but a
bound parameter; build strings with `CONCAT('%', {value})` instead), no other
`{…}`, no literal `?`, no `;` or comments, balanced quotes and parentheses —
and dry-run against the database at startup, so a typo'd
function fails the boot, not the first request. Custom operators obey
`filter_operators` / `filterable_columns` like built-ins.

### Restricting the filter surface

By default a role can filter on every column it can read, with every
operator, and through every relationship it can follow — exactly as before.
Narrow it per table under `select`:

```yaml
roles:
  anonymous:
    tables:
      posts:
        select:
          allow: true
          columns: [id, author_id, title, body, published_on]
          filterable_columns:              # body stays readable, but not filterable
            id: all
            author_id: all
            title: [_eq, _starts_with, _istarts_with]
            published_on: all
          filter_operators: [_eq, _in, _gt, _lt, _starts_with, _istarts_with, _year_eq]  # _year_eq: custom, above
          filter_relationships: [author]   # [] = no relationship filters
```

The role's schema then only contains what is allowed (`posts_title_comparison_exp
{ _eq _starts_with _istarts_with }`, no `body` in `posts_bool_exp`), and the same checks are
enforced again when the query runs, so values passed through variables can't
get around them. Restrictions on a related table apply when it is reached
through a relationship too. `filterable_columns` doesn't affect `_by_pk`
lookups or keyset cursors (they use the primary key directly).

A relationship filter is an equality filter on its join columns
(`author: {id: {_eq: 2}}` is `author_id = 2`; `_not: {author: {}}` is
"`author_id` is null or points at a row the role can't see"), so hiding a join
column from `where` also hides the relationships that join on it: leave
`author_id` out of `filterable_columns` above (or drop `_eq` from its
operators) and `author` disappears from `posts_bool_exp` too, while
`posts { author { … } }` keeps working. Listing such a relationship in a
named rule's `filter_relationships` is a startup error. The same goes for
`filter_operators: []`: no operators means no column filters and no
relationship filters on that table.

### Filtering through relationships

Every relationship the role can follow is also a field of `<table>_bool_exp`,
typed as the related table's `bool_exp`:

```graphql
# object relationship: the related row matches
posts_connection(where: {author: {name: {_eq: "Ada Lovelace"}}}) { nodes { id } }
# array relationship: at least one related row matches; {} = has any
posts_connection(where: {comments: {body: {_icontains: "cobol"}}}) { nodes { id } }
# _not = has none (users with no posts the role can see)
users_connection(where: {_not: {posts: {}}}) { nodes { id } }
# nesting, in aggregates, nested lists and mutations too
users_aggregate(where: {posts: {comments: {user: {name: {_eq: "Grace Hopper"}}}}}) { count }
users_by_pk(id: 1) { posts(where: {comments: {}}) { id } }
delete_comments(where: {post: {author_id: {_eq: 1}}}) { affected_rows }
```

Each relationship predicate compiles to one correlated `EXISTS (SELECT 1 FROM
… AS __gqlgate_rN WHERE <join> AND <predicate>)` — an `_and` inside an array
relationship must hold for the *same* related row — which TiDB runs as a
semi-join (anti-semi-join under `_not`) on the FK index, without changing
row multiplicity, cursors or aggregates. Every nesting level gets its own
alias, so self-referential FKs (`parent: {parent: {…}}`, `categories: {}`)
work, and `UPDATE`/`DELETE` whose `where` reads the same table through a
relationship run fine on TiDB (no MySQL error 1093).

RBAC: a relationship is offered only if the role can select the related table
and read the local join columns (the same rule as for navigating it), and may
filter on those join columns with `_eq` (see above); only
the related table's filterable columns can be used inside it; and the related
table's `select.filter` for the role (JWT claims bound) is applied inside the
subquery, so rows the role can't see can never be matched. Relationship
filters nest at most 8 levels deep.

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

## Testing

Unit tests need no database:

```sh
go test ./...
```

The **end-to-end suite** (`e2e/`) runs the real gateway in-process
(`gqlgate.Open` behind an `httptest` server) against a live TiDB and drives it
with GraphQL-over-HTTP requests as different roles. It is opt-in: set
`GQLGATE_E2E_DSN` to a go-sql-driver DSN for the TiDB server (no database
name needed); without it every e2e test skips, so `go test ./...` stays
database-free. Against the compose demo TiDB, from Docker:

```sh
docker compose up -d tidb
docker run --rm --network tidb-net -v "$PWD:/src" -w /src   -e GQLGATE_E2E_DSN="root@tcp(tidb:4000)/" golang:1.25 go test -count=1 ./e2e/...
```

(or, with Go installed locally, `GQLGATE_E2E_DSN='root@tcp(127.0.0.1:4000)/'
go test -count=1 ./e2e/...`). Unset any `GQLGATE_DB_*` variables first; the
harness refuses to run if they would redirect the gateway.

Isolation: each test gets its own database named
`gqlgate_e2e_<unix>_<rand>_<test>`, loaded from `e2e/testdata/blog.sql` (the
demo blog schema: FKs, JSON, `VECTOR`, UNIQUE email) and dropped on cleanup,
so tests can run in parallel and can never touch `appdb` or any other
database. Fixture SQL may not contain `USE` or `CREATE/DROP/ALTER DATABASE`.
Leftover `gqlgate_e2e_*` databases from killed runs are swept after 6 hours.

Writing a test:

```go
func TestPostsVisibility(t *testing.T) {
    t.Parallel()
    env := e2e.New(t)                       // fresh DB + gateway; skips without GQLGATE_E2E_DSN
    author := env.Token(t, "author", 2)     // HS256 token {role: author, sub: 2}
    r := env.MustGQL(t, author, `{ posts_aggregate { count } }`, nil)
    _ = r.Int(t, "posts_aggregate.count")
    env.GQL(t, "", `{ posts_connection { nodes { published } } }`, nil). // "" = anonymous
        MustFail(t, "published")            // hidden column: negative RBAC case
}
```

The default config mirrors the demo `gqlgate.yaml` roles (admin, author,
anonymous) with the role taken from the token's `role` claim. Options adjust
it: `WithRolesYAML`, `WithExtraYAML` (e.g. a `hooks:` block),
`WithConfigTemplate`, `WithFixtures`, `WithSQL`, `WithConfig`,
`WithGateOptions`, `WithDebug`. `env.Reload(t, rolesYAML)` rewrites the
config file and hot-reloads; `env.DB`/`env.Exec`/`env.QueryInt` reach the
private database directly to verify what actually happened.

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
- Relationship filters nest at most 8 levels; custom operators take a single
  scalar argument (no list arguments).
- A role's select filter that doesn't resolve against its own table (see RBAC
  notes) disables relationship filters into that table for the role rather
  than failing startup — watch the startup log for the warning.

## Hardening notes

This build has been through several adversarial review passes. Things it
deliberately gets right (with regression tests): all client input and JWT claim
values are bound as SQL parameters (never interpolated — verified even for
keyset cursor keys, which TiDB compares exactly against BIGINT PKs); the
query-depth guard is memoized so a small fan-out fragment document can't cause
exponential CPU; hidden columns can't be probed through `where`, `_by_pk`,
cursors, or variables; the RBAC row filter is applied on every read path
(connections, aggregates, relationships, vector search, and inside
relationship filters, where each role filter is verified at startup to bind
only to its own table); LIKE wildcards in literal string operators are
escaped; aggregate and
relationship selections are computed correctly even when the client wraps them
in fragments; vector search skips NULL-vector rows; DB errors are masked from
clients unless `server.debug` is on; and identifier/name collisions are
rejected at startup rather than silently dropping an operation.
