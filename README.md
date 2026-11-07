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
  Bulk mutations return `affected_rows` plus **`returning { … }`** (with
  relationships), and every UNIQUE index gets lookups and point mutations:
  `users_by_email(email)`, `update_users_by_email`, `delete_users_by_email`.
- **Relationships from foreign keys — or declared in YAML.** `posts { author
  { name } }` and `users { posts(where: …) { … } }` are generated from FK
  metadata; schemas without FKs (common on TiDB) declare them by column
  mapping. The target table's RBAC (column set + row filter) applies to
  nested data too.
- **Views and keyless tables.** Views are exposed read-only to the roles that
  name them; a view or a table without a primary key can declare a logical
  key for cursors and `_by_pk`, and otherwise gets a bounded `<t>_list`.
- **Native queries.** A parameterized, read-only SQL statement in YAML
  (`SELECT … WHERE month = :month`, CTEs and window functions welcome)
  becomes a root query field with typed arguments, the generated `where`,
  per-role columns, row filters and **argument presets** from JWT claims,
  a cursor connection when it declares a key, and relationships into your
  tables.
- **Your names, your docs.** Rename types, root fields, columns and
  relationships, take descriptions from TiDB `COMMENT`s or the YAML, and mark
  fields `@deprecated` — all from the `tables:` section.
- **Aggregates, nested too.** `posts_aggregate(where)` computes count, sum,
  avg, min/max, per-column and distinct counts (exact or TiDB's approximate
  HyperLogLog) and standard deviation/variance in one query, and every array
  relationship gets `<rel>_aggregate` (`users { posts_aggregate { count } }`),
  batched into one `GROUP BY` per page of parents. Counts can be 64-bit
  (`schema_gen.count_type: BigInt`).
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
  (`filter: "author_id = :jwt.sub"`), **column presets** that force values
  from claims on insert/update (`presets: {author_id: ":jwt.sub"}`), and
  **write checks** every inserted or updated row must pass, or the whole
  mutation rolls back (`check: "org_id IN (:jwt.orgs)"`).
- **Roles from your users table.** With `jwt.role_lookup`, tokens carry only
  the user id and the role is read from your identity table on each request —
  change a row's `role` column and it applies instantly, no token re-issue.
  (Alternatively, read the role from a token claim with `role_claim`.)
  A user with several roles picks one per request with the
  **`X-Gqlgate-Role` header**, checked against their allowed roles (a claim,
  a column or a user→role table).
- **Typed JSON columns.** Declare a shape for a JSON column in YAML and it
  becomes a real GraphQL object type (or a list of one) with selectable
  sub-fields, instead of an opaque `JSON` value.
- **Computed fields from Go.** A hook can attach a field to any table type
  (`users { avatar_url }`), per role, with access to the parent row, the
  caller's claims and the database — batched like relationships.
- **Concurrent root fields.** The independent root fields of one query run
  in parallel (bounded per request); mutations stay strictly serial.
- **Safe by construction**: claim values and all client inputs are always
  bound as SQL parameters; identifiers come from `information_schema` and are
  backtick-quoted; algorithm-pinned JWT verification (no alg confusion);
  query depth limit; request body limit; response row/byte limits; DB errors
  masked unless `debug`, with expected ones (duplicate key, foreign key, …)
  reported as safe messages with an `extensions.code`.

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
  max_response_rows: 10000 # rows one request may return (0 = unlimited, the default)
  max_response_bytes: 0    # size cap of the JSON response (0 = unlimited)
  max_parallel_root_fields: 4  # query root fields run at once (default min(4, max_open_conns/2); 1 = serial)
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
    # Optional: roles the user may switch to with the role header — ONE of:
    allowed_roles_column: allowed_roles   # JSON array or "a, b" on the identity table
    # allowed_roles_table: {table: user_roles, id_column: user_id, role_column: role}
  # (b) from a token claim:
  # role_claim: role       # dot path; Auth0-style URL keys work too
  # allowed_roles_claim: app_metadata.roles  # claim listing the roles the caller may switch to
  role_header: X-Gqlgate-Role  # request header picking one allowed role (this is the default)

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
  count_type: BigInt       # scalar of count/total_count/affected_rows: Int (default) or BigInt (64-bit)
  descriptions_from_comments: false  # true: TiDB table/column COMMENTs become GraphQL descriptions

tables:                    # optional per-table modeling (see "Modeling: views, keys, relationships, names")
  post_stats:              # a view, or a table without a primary key
    primary_key: [post_id] # logical key (not enforced): cursors + _by_pk
    type_name: PostStats   # renames the type and every <type>_… type
    description: "Comment statistics per post."
    root_fields:           # by_pk connection aggregate list insert insert_one update update_by_pk delete delete_by_pk
      connection: postStatsPage
      by_pk: {name: postStats, description: "…", deprecated: "use posts.stats"}
    columns:               # keyed by SQL column name
      comment_count: commentCount            # shorthand: just the new name
      author_id: {description: "…", deprecated: "use post"}
      details: {json_type: StatsDetails}     # a JSON column with a declared shape (see json_types)
    relationships:
      post: {type: object, target: posts, mapping: {post_id: id}}   # no FK needed
  posts:
    relationships:
      writer: {foreign_key: fk_posts_author, description: "The author"}  # names an FK relationship

json_types:                # optional shapes for JSON columns (see "Typed JSON columns")
  StatsDetails:
    fields:
      top_tags: "[String]"
      last_reader: Reader
  Reader:
    fields:
      name: String
      visits: Int

native_queries:            # optional parameterized SQL root fields (see "Native queries")
  author_post_stats:
    sql: |
      SELECT p.id AS post_id, p.author_id, p.title, COUNT(c.id) AS comment_count
      FROM posts p LEFT JOIN comments c ON c.post_id = p.id
      WHERE p.author_id = :author AND (:min_views IS NULL OR p.views >= :min_views)
      GROUP BY p.id, p.author_id, p.title
    arguments:             # every :name in the sql; "Type!" = required
      author: BigInt!
      min_views: {type: Int, description: "View floor"}   # optional: NULL when omitted
    columns:               # optional, per result column: type (shorthand) or {type, name, description, deprecated}
      comment_count: BigInt!
    key: [post_id]         # optional: adds author_post_stats_connection (keyset cursor)
    relationships:
      author: {type: object, target: users, mapping: {author_id: id}}

roles:
  <role-name>:
    tables:
      "<table-or-*>":      # "*" is the fallback for tables not named explicitly
        select: true|false|{...}   # same shape for insert/update/delete
        update:
          allow: true
          columns: [a, b]  # writable columns (select: readable). empty = all
          filter: "owner_id = :jwt.sub"   # rows the op may touch (select/update/delete)
          check: "owner_id = :jwt.sub"    # insert/update: every written row must satisfy it
          presets:                        # forced values, hidden from the API
            owner_id: ":jwt.sub"          # from a claim — or a literal string
        # select (object form) also takes the `where` surface, all optional:
        #   filterable_columns:           # default: every readable column
        #     id: all                     # all operators
        #     title: [_eq, _ilike, _starts_with]
        #   filter_operators: [_eq, _in, _is_null, _ilike, _starts_with]  # table-wide allow-list; [] = none
        #   filter_relationships: [author]  # default: every relationship; [] = none
    native_queries:        # grants by name (no "*"); same shape as select
      author_post_stats:
        allow: true
        columns: [post_id, title, comment_count]  # readable result columns; empty = all
        filter: "comment_count > 0"               # row filter over the result columns
        presets: {author: ":jwt.sub"}             # ARGUMENT presets: hidden from and not overridable by the client
```

### RBAC semantics

| Piece | Meaning |
|---|---|
| `select.columns` | Only these columns exist in the role's object type, `where`, and `order_by`. |
| `select.filter` | SQL appended to every read — including `_by_pk`, `_count`, relationship hops, and mutation return values. `:jwt.<path>` binds claim values as parameters; arrays expand for `IN (…)`; an empty array matches nothing; a missing claim is an error, never "no filter". |
| `insert/update.presets` | Server-forced column values. Preset columns are removed from the input types, so clients cannot even attempt to set them. |
| `update/delete.filter` | Rows the role may touch. Everything else reports `affected_rows: 0`. |
| `insert/update.check` | A row condition (same SQL + `:jwt.<path>` syntax as `filter`) that every inserted row, and every row an update leaves behind, must satisfy. One failing row rolls the whole mutation back with `extensions.code: permission_error`. See [Write checks](#write-checks). |
| `"*"` wildcard | Applies to tables without an explicit entry — base tables only: a view is visible to a role only when the role names it. Unknown columns in wildcard rules are skipped per table; in named rules they are startup errors. |
| `select.filterable_columns` | Which readable columns appear in `<table>_bool_exp` (default: all of them). A list (`[id, title]`) or a map of column → `all` / operator list. Non-filterable columns stay selectable. |
| `select.filter_operators` | Table-wide operator allow-list, intersected with any per-column list (default: every operator, custom ones included; `[]` = none, i.e. no column filters on the table, and so no relationship filters either). |
| `select.filter_relationships` | Relationship fields usable in `where` (default: every relationship the role can follow whose local join columns are filterable with `_eq`; `[]` = none). Navigation in the selection set is unaffected. |
| `native_queries.<q>` | Grants a native query to the role (explicit only; no wildcard). `columns`, `filter` and the filter-surface keys work as for `select`, over the query's result columns; `presets` force **argument** values. See [Native queries](#native-queries). |

Notes worth knowing:

- Mutations other than plain `insert_<table>` require `select` on the same
  table (they return rows / take `where` filters built from readable columns).
- `insert_<table>_one` / `update_<table>_by_pk` (and `returning`) re-read the
  row through your select filter, inside the mutation's transaction — if the
  filter hides it, you get `null` back (the write still happened). Use a
  `check` to stop a role from writing rows it could not see.
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

### Role selection (allowed roles)

A caller can hold several roles and pick one per request with a header
(`jwt.role_header`, default `X-Gqlgate-Role`). The role from `role_claim` /
`role_lookup` stays the **default** — used when the header is absent — and
is always allowed; any other role must be in the caller's allowed roles,
which come from exactly one of:

```yaml
jwt:
  role_claim: role
  allowed_roles_claim: roles            # (a) a claim: ["editor","admin"] or "editor, admin"
  # role_lookup:
  #   table: users
  #   allowed_roles_column: allowed_roles            # (b) a column of the identity table: JSON array or "a, b"
  #   allowed_roles_table: {table: user_roles}       # (c) one row per (user_id, role); id_column/role_column configurable
```

```http
POST /graphql
Authorization: Bearer <jwt: {"sub": 1, "role": "author", "roles": ["editor"], "exp": …}>
X-Gqlgate-Role: editor

{ "query": "{ _role posts_connection { nodes { id } } }" }   # served from the editor schema
```

- A requested role that is not allowed, or not configured under `roles:`,
  is rejected with **403** — never silently served as the default role.
  Without any allowed-roles source the header may only name the caller's own
  role. An unauthenticated request can only ever be the `anonymous_role`.
- The default role must itself be valid: a token whose default role is
  unknown, or whose identity row is gone, is rejected even with a header.
- The database sources bind the token's `role_lookup.id_claim` as a
  parameter, are read only when the header asks for another role, honour
  `role_lookup.cache_seconds`, and are checked to exist at startup. They
  work with a `register.RoleResolver` hook too (it supplies the default).
- With CORS enabled the header is an allowed request header. Changing
  `role_header` needs a restart for CORS; requests pick it up on reload.
- `{ _role }` reports the role a request was served as.
- **Keep the allowed-roles source out of reach of the roles it grants.**
  `allowed_roles_column` sits on the identity table and `allowed_roles_table`
  is a table of the exposed schema, so both are normally reachable through
  the generated API. A role that may write them can grant itself any role:
  `update: {allow: true, filter: "id = :jwt.sub"}` on `users` with no
  `columns:` list lets a user set its own `allowed_roles` to `'["admin"]'`
  and then send `X-Gqlgate-Role: admin`; `insert` on `user_roles` does the
  same. Leave the column out of the `insert`/`update` `columns:` of every
  role that must not escalate, grant writes on the role table only to
  admins (or keep that table outside `database.schema`), and treat an
  `allowed_roles_claim` the same way on the token issuer's side.

## Generated API, per table (role permitting)

```graphql
# queries (collection reads are cursor-only)
posts_connection(first: Int, after: String, where: posts_bool_exp): posts_connection!
  # posts_connection { nodes: [posts!]!  page_info { has_next_page end_cursor }  total_count: Int! }
posts_by_pk(id: BigInt!): posts
posts_aggregate(where: posts_bool_exp): posts_aggregate_result!
  # { count: Int!  sum {..}  avg {..}  min {..}  max {..}  count_columns {..}
  #   count_distinct {..}  approx_count_distinct {..}  stddev {..}  stddev_pop {..}
  #   stddev_samp {..}  variance {..}  var_pop {..}  var_samp {..} }
posts_nearest_by_<vectorcol>(to: Vector!, metric: vector_metric, first: Int, where: posts_bool_exp): [posts_neighbor!]!
  # posts_neighbor { node: posts!  distance: Float! }   (only for VECTOR columns)
users_by_email(email: String!): users          # one per UNIQUE index (see "Lookups by unique key")
event_log_list(limit: Int, where: event_log_bool_exp): [event_log!]!
  # only for a table/view the role has no readable key for (no cursor possible)
author_post_stats(args: author_post_stats_arguments, where: author_post_stats_bool_exp, limit: Int): [author_post_stats!]!
author_post_stats_connection(args: …, where: …, first: Int, after: String): author_post_stats_connection!
  # one pair per native query the role is granted (the connection needs `key`)

# mutations
insert_posts(objects: [posts_insert_input!]!): posts_mutation_response!
insert_posts_one(object: posts_insert_input!): posts
update_posts(where: posts_bool_exp!, _set: posts_set_input!): posts_mutation_response!
update_posts_by_pk(id: BigInt!, _set: posts_set_input!): posts
delete_posts(where: posts_bool_exp!): posts_mutation_response!
delete_posts_by_pk(id: BigInt!): posts
update_users_by_email(email: String!, _set: users_set_input!): users
delete_users_by_email(email: String!): users
  # posts_mutation_response implements mutation_response { affected_rows: Int! }
  #   and adds returning: [posts!]! (see "Mutation results")
  # (count, total_count and affected_rows are BigInt! with schema_gen.count_type: BigInt)

# on each row type, per array relationship (here users <- posts.author_id)
users { posts(where, order_by, limit, offset): [posts!]!
        posts_aggregate(where: posts_bool_exp): posts_aggregate_result! }
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
- **Descriptions** are generated ("Row of table appdb.posts", "Column title
  (varchar(200))") unless `tables:` sets one; with
  `schema_gen.descriptions_from_comments: true` the TiDB table and column
  `COMMENT`s are used where the config sets none. It is opt-in because a
  comment written for DBAs becomes visible to every role that can read the
  table.
- **Foreign keys are scoped to the exposed schema**: an FK pointing at a
  same-named table in another schema is ignored rather than mis-joined.
- **Name collisions fail at startup** with an actionable message: if two
  tables (or a table and a reserved name) would produce the same GraphQL
  field or type — e.g. `users` + `users_connection`, or a table named
  `order_by` — the server refuses to boot instead of silently dropping an
  operation. The newer generated names never do: a unique-key field whose
  name is already taken (by another generated field, or by a custom field
  from `hooks/`, which keeps it) is left out with a startup warning, and
  `<t>_mutation_response` gets a numeric suffix (with a startup warning) if
  a table, or a type a `hooks/` custom field uses (its result, argument and
  nested types), already owns that name — so a schema that booted before
  still boots.
- **`AUTO_RANDOM` primary keys** are recognized (TiDB reports them in
  `information_schema.tables`, not as `auto_increment`): they are optional
  on insert, and `insert_<t>_one` / `returning` find the generated rows.

## Modeling: views, keys, relationships, names

The optional top-level `tables:` section shapes individual tables and views,
independently of roles. Everything in it is validated against the
introspected schema at startup and on every hot reload (a table, column or
foreign key that does not exist, an incompatible mapping or a name collision
refuses to boot, or rejects the reload). Names given here are GraphQL names;
the rest of the config — roles, `columns`, `filter`, `check`, `presets`,
mappings — keeps using SQL table and column names.

### Views (read-only)

Views in `database.schema` are introspected when the config **names** them:
in a role rule, a `tables:` entry, a relationship `target`, or
`schema_gen.tables.include`. A view becomes a query-only type for every role
that grants it `select` by name — the `"*"` wildcard never covers a view, and
granting `insert`/`update`/`delete` on one is a startup error (TiDB views are
not updatable). Row filters, column lists, the filter surface, aggregates,
vector search and relationship filters work exactly as on tables.

```yaml
roles:
  author:
    tables:
      post_stats:
        select: {allow: true, filter: "author_id = :jwt.sub"}
```

A view has no primary key or foreign keys, so give it a `primary_key` (below)
for cursors, and `relationships` to join it.

A named view that has become invalid — a table it reads was dropped or
renamed — is listed by TiDB without columns; gqlgate then refuses to boot
(or rejects the reload, keeping the previous schema serving) with
`view "<name>" has no columns (is it invalid? ...)`. Recreate the view, or
stop naming it in the config.

### Logical keys and keyless tables

```yaml
tables:
  post_stats: {primary_key: [post_id]}
  post_tags:  {primary_key: [post_id, tag]}   # composite works too
```

A view or a base table **without** a primary key can declare one. It is used
for `<t>_connection` (keyset cursor on the key, in key order), `<t>_by_pk`,
the window order of nested lists, and as a target of object relationships.
It drives reads only: no `update_<t>_by_pk` / `delete_<t>_by_pk` /
`insert_<t>_one` is generated from it, and `returning` / write checks still
need a real primary key. Caveats:

- **It is not enforced.** If the columns do not really identify one row,
  pages can skip or repeat rows and `_by_pk` returns an arbitrary match.
- Rows whose key has a NULL (TiDB reports every view column as nullable) are
  left out of the connection and its `total_count`; `_aggregate` still counts
  them.
- On a view, `ORDER BY key` with `key > cursor` is a range scan only when TiDB
  can push the predicate into the view; for an aggregating view (`GROUP BY`)
  each page may compute and sort the whole view. Keep `max_page_size` modest
  for such views, or page a base table instead.
- The key columns must be readable by the role (as for a primary key), or the
  role gets the list field below instead. JSON, VECTOR, TEXT, BLOB, BIT and
  spatial columns cannot be key columns, and neither can ENUM or SET: they
  sort by member index rather than by value, so a cursor seeking on the value
  would skip rows. (Cast one in the view, e.g. `CAST(e AS CHAR(10)) AS e`, to key
  on it.)

A table or view a role has **no usable key** for — none at all, or one it
cannot read — gets a bounded list instead of a connection:

```graphql
query { event_log_list(limit: 50, where: {level: {_eq: "error"}}) { ts message } }
```

It returns at most `limit` rows (default `default_page_size`, clamped to
`max_page_size`) **in no particular order**. There is deliberately no
`offset`, `order_by` or cursor: narrow it with `where` (and use
`<t>_aggregate` for counts). The name `<t>_list` is new, so when another
generated or custom field already has it, the list is left out with a startup
warning; `root_fields.list` names it explicitly.

### Declared relationships

```yaml
tables:
  posts:
    relationships:
      stats: {type: object, target: post_stats, mapping: {id: post_id}}
      tags:  {type: array,  target: post_tags,  mapping: {id: post_id}, description: "Tags of the post"}
  users:
    relationships:
      events: {type: array, target: event_log, mapping: {id: user_id}}
```

Each entry adds one field (named by the key) on the declaring table,
following `mapping` (this table's columns → the target's columns; several
pairs make a composite join). Hasura-style, a declaration is one-directional:
declare the reverse on the target if you want it too. Declared relationships
behave exactly like foreign-key ones: batched by the dataloader, `where` /
`order_by` / `limit` / `offset` on array relationships, a nested
`<rel>_aggregate` on every array relationship, usable in relationship
filters (`posts(where: {stats: {commentCount: {_gt: 1}}})`) subject to
`filter_relationships`, and the target's row filter and column permissions
for the role apply everywhere. A role sees the field only if it can select
the target and read the local join columns.

Validated at startup: the target exists among the exposed tables/views; every
mapped column exists; each pair is join-compatible (same GraphQL scalar, or
`Int`/`BigInt`; `DECIMAL` with the same declared type; character columns
with the same charset **and collation**, as a real foreign key requires —
`utf8mb4_bin` vs `utf8mb4_general_ci` is rejected, since the field and its
`where` filter would compare `'ABC'` and `'abc'` differently; never JSON,
VECTOR, TEXT, BLOB, BIT, ENUM, SET or spatial columns); and an `object`
relationship must map onto the target's primary key, a usable unique key, or
its declared `primary_key` (a declared key is not enforced — at most one
matching row is returned). A usable unique key is a `UNIQUE` index whose
columns are all `NOT NULL` and indexed in full: an index on a nullable
column, or with a prefix (`col(10)`) or expression part, does not count
(declare the relationship as `array`, or make the column `NOT NULL`). The name may not be a
column's field name or another relationship's name (a clash with a generated
foreign-key relationship name is a startup error; rename either one).

`foreign_key:` instead names (and documents / deprecates) a relationship
generated from a foreign key, on either side:

```yaml
tables:
  posts:
    relationships:
      writer: {foreign_key: fk_posts_author}             # posts.author → posts.writer
  users:
    relationships:
      articles: {foreign_key: fk_posts_author}           # users.posts → users.articles
  categories:
    relationships:
      parent:   {foreign_key: fk_cat_parent, type: object}  # self-referencing: say which side
      children: {foreign_key: fk_cat_parent, type: array}
```

Write `<child_table>.<constraint>` if a constraint name alone is ambiguous.

### Custom names, descriptions, deprecation

```yaml
tables:
  posts:
    type_name: Post                     # Post, Post_bool_exp, Post_connection, Post_insert_input, …
    description: "A blog post."
    root_fields:
      connection: allPosts
      by_pk: {name: post, deprecated: "use allPosts"}
      insert_one: createPost
    columns:
      title: headline
      body: {description: "Markdown body", deprecated: "use content"}
```

- `type_name` renames the object type and every type derived from it.
  Root field names do **not** follow it: each keeps its default
  (`posts_by_pk`, `insert_posts`, …) unless `root_fields` renames it. The
  unique-key and nearest-neighbor fields keep their generated names (built
  from the column field names).
- Column renames apply everywhere the column appears: output fields, `where`,
  aggregates, insert/`_set` inputs, `_by_pk` / unique-key arguments.
- `deprecated: "reason"` marks a column field, relationship field (and its
  `<rel>_aggregate`) or root field `@deprecated(reason: …)`; deprecated fields
  keep working. GraphQL (and graphql-go) cannot deprecate input fields, so
  the column stays undeprecated in `where` and the insert/`_set` inputs.
- Descriptions: the YAML wins, then (with
  `schema_gen.descriptions_from_comments: true`) the TiDB `COMMENT`, then the
  generated text.
- Collisions are checked on the final names, like the defaults: a custom name
  that clashes with any other generated type or field (or with a built-in
  such as `page_info`) refuses to boot with a message naming both owners.
  A column may not be renamed `_and`, `_or` or `_not` (the logical operators
  of `where`), just as a relationship may not be named so.

### Typed JSON columns

By default a JSON column is the opaque `JSON` scalar. Declare its shape under
the top-level `json_types:` and point the column at it, and the column
becomes a GraphQL object type (or a list of one) whose sub-fields clients
select and introspection shows:

```yaml
json_types:
  UserMetadata:
    description: "Profile data kept in users.metadata."
    fields:
      tier: String                                 # shorthand: just the type
      tags: "[String]"                             # a list
      address: Address                             # another declared type (may nest, even recursively)
      score: {type: Int, description: "Loyalty score", deprecated: "use tier"}
      gift_wrap: {type: Boolean, key: "gift-wrap"} # JSON key that is not a GraphQL name
  Address:
    fields: {city: String, lines: "[String]"}
tables:
  users:
    columns:
      metadata: {json_type: UserMetadata}          # or "[Address]" for an array of objects
```

```graphql
{ users_connection { nodes { id metadata { tier tags address { city } } } } }
```

- Field types: `String`, `Int` (32-bit), `Float`, `Boolean`, `JSON` (an
  opaque sub-document), a declared type, or a list of any of these
  (`"[Address]"`, `"[[Int]]"`). Every field is **nullable**: the database
  does not enforce the shape, so `!` is rejected.
- Stored data that does not fit never breaks the response: a missing key or
  JSON `null` is `null`; a value of the wrong kind (a string where an `Int`
  is declared, an array where an object is) is `null` with an error
  carrying `extensions.code: json_shape_mismatch` and the path, while the
  rest of the row and the response resolve normally. Inside a list only the
  mismatched element is `null` (its error's path ends in the element's
  index): `[{"city": "A"}, "oops", {"city": "B"}]` as `[Address]` returns
  both addresses with `null` between them.
- Column RBAC is unchanged: a role that cannot read the column has neither
  the field nor the declared types in its schema. Shapes are not per-role:
  every role that reads the column sees all of its declared fields.
- Only output changes. Inserts/`_set` keep taking a JSON value, `where`
  keeps the JSON operators (`_contains`, `_has_key`, …), and `min`/`max`
  aggregates of the column stay `JSON`. The column is still read whole and
  decoded in Go (no per-field SQL projection).
- `json_type` must point at a JSON column (checked at startup and on
  reload); declared type names share the GraphQL type namespace and may not
  collide with generated or hook-provided types. Without `json_type`
  nothing changes.

## Native queries

A **native query** is a read-only SQL statement with named parameters,
declared in YAML and served as a root query field — for reports, CTEs,
window functions and joins the generated per-table API cannot express. The
generated machinery still applies on top of it: typed arguments, `where`
(including relationship filters), per-role columns and row filters, argument
presets from JWT claims, response limits, and a keyset cursor connection
when it declares a key.

```yaml
native_queries:
  author_post_stats:
    description: "Per-post statistics of one author."
    sql: |
      SELECT p.id AS post_id, p.author_id, p.title, p.views, p.published,
             COUNT(c.id) AS comment_count
      FROM posts p LEFT JOIN comments c ON c.post_id = p.id
      WHERE p.author_id = :author AND (:min_views IS NULL OR p.views >= :min_views)
      GROUP BY p.id, p.author_id, p.title, p.views, p.published
    arguments:
      author: BigInt!                                     # shorthand: just the type
      min_views: {type: Int, description: "View floor"}   # optional: NULL when omitted
    columns:
      published: Boolean!                                 # TINYINT(1) arrives as Int: declare Boolean
      comment_count: {type: BigInt!, name: commentCount}
    key: [post_id]                                        # adds author_post_stats_connection
    relationships:
      author:   {type: object, target: users,    mapping: {author_id: id}}
      comments: {type: array,  target: comments, mapping: {post_id: post_id}}
    # type_name: AuthorPostStat                           # default: the query name
    # root_fields: {list: authorStats, connection: {name: authorStatsPage, deprecated: "..."}}

roles:
  admin:
    native_queries:
      author_post_stats: true
  author:
    native_queries:
      author_post_stats:
        allow: true
        columns: [post_id, author_id, title, views, comment_count]   # hides published
        presets: {author: ":jwt.sub"}           # the caller's own posts, always
        filterable_columns: [views, title]
```

```graphql
# admin: every argument is the client's
{ author_post_stats(args: {author: 1, min_views: 100}, where: {commentCount: {_gt: 0}}, limit: 20) {
    post_id title commentCount author { name } comments(limit: 3) { body } comments_aggregate { count } } }

# author: `author` is preset from the token, so args holds min_views only (and is optional)
{ author_post_stats_connection(first: 10, after: $cursor) {
    nodes { post_id title } page_info { has_next_page end_cursor } total_count } }
```

Each request runs the statement as a derived table, with every `:name`
replaced by a bound `?` (never by text):

```sql
SELECT `post_id`, `title`, … FROM (<sql with ? per :name>) AS `__gqlgate_nq`
WHERE <where> AND (<role filter>) [AND `post_id` > ? ORDER BY `post_id`] LIMIT ?
```

**Generated fields** (for each role granted the query):

- `<name>(args, where, limit): [<T>!]!` — up to `limit` rows (default
  `default_page_size`, clamped to `max_page_size`) in no particular order.
  `root_fields.list` renames it.
- `<name>_connection(args, where, first, after): <T>_connection!` — only
  with `key:`, and only for roles that can read every key column: keyset
  pages in key order, `page_info`, and `total_count` (a `COUNT` only when
  selected). The cursor is bound to the query, its argument values (presets
  included, so one user's cursor never applies to another's rows) and the
  filter. `root_fields.connection` renames it.
- Types: `<T>`, `<T>_bool_exp`, `<T>_arguments`, `<T>_connection`, where
  `<T>` is `type_name` or the query name. Like every generated name they are
  checked for collisions at startup: a native root field or type that any
  table already generates — including a unique-key lookup such as
  `users_by_email` and the default `<t>_list` field — fails startup (or the
  reload) instead of replacing the table's field.
- Not generated: `_aggregate`, `_by_pk`, `order_by`/`offset` (collection
  reads stay cursor-only) and mutations. Count inside the statement, or use
  the connection's `total_count`.

**The statement.** It must be one `SELECT` (or `WITH … SELECT`); a trailing
`;` is dropped. Anything else is rejected when the config is loaded (startup
fails, or the hot reload is rejected): statement separators, literal `?`
placeholders, `:=` assignments, `:jwt.…` references (preset an argument
instead), executable `/*! … */` comments, and the keywords of writes,
locking reads and DDL (`INSERT`, `UPDATE`, `DELETE`, `REPLACE`, `INTO`,
`LOCK`, `FOR SHARE`, `CREATE`, `DROP`, `ALTER`, `GRANT`, `REVOKE`, `CALL`,
`LOAD`, `RENAME`; qualified names such as `t.update` and the string
functions `INSERT(…)` / `REPLACE(…)` are fine). Since it only ever runs as a
derived table, nothing but a query expression could execute anyway. Quoted
strings, quoted identifiers and comments are skipped when looking for
parameters. Comments are removed from the executed statement (TiDB's
`/*T! … */` executable comments with them), except **optimizer hints**:
`/*+ … */` is kept verbatim (it may not contain `;` or `?`), so
`SELECT /*+ USE_INDEX(posts, idx_author) */ …` or `READ_FROM_STORAGE(…)`
reaches TiDB. Hints apply to their own query block, which is now the derived
table: statement-level hints such as `MAX_EXECUTION_TIME` are ignored by
TiDB there — bound the time with `database.query_timeout_seconds` instead.

**Arguments.** Every `:name` must be declared under `arguments` and every
argument used; a name may appear several times (one bound value per use).
Types: `String`, `Int`, `BigInt`, `Float`, `Boolean`, `Decimal`, `Date`,
`DateTime`, with `!` for required. An omitted optional argument is `NULL`,
so write `(:x IS NULL OR col = :x)` for an optional condition. The client
passes them as `args: {…}` (`<T>_arguments`), which is non-null when the
role must pass a required argument and absent when the role passes none.

**Result columns** are read from the database when the API is built (at
startup and on every hot reload) by running the statement with `LIMIT 0`
and sample argument values (`0`, `''`, `2000-01-01`, …). So a statement that
does not run — a typo, a dropped column, two result columns with the same
name — refuses to boot with `native_queries.<name>.sql: the statement does
not run against the database: …`, or rejects the reload while the previous
schema keeps serving. Then:

- Every column is **nullable**: TiDB does not report reliable nullability
  for a derived table. `columns: {c: "Type!"}` makes one non-null (a `NULL`
  in it is then a field error).
- The scalar follows the column type as for tables, except that the wire
  protocol carries no display width, so `TINYINT(1)` arrives as `Int`:
  declare `Boolean`. A type the driver cannot name must be declared.
  `columns:` also renames (`name`), documents and deprecates columns.
- Character columns keep their collation (read from the database), so string
  operators and string joins behave as on the base column.
- Give expressions an alias (`COUNT(*) AS n`); result names that are not
  GraphQL names are sanitized like column names.

**Roles.** A role gets a native query only by naming it under
`roles.<role>.native_queries` (there is no `"*"`). The grant takes the
`select` shape over the result columns:

- `columns` — readable result columns (default all); hidden ones are absent
  from the type and from `where`, as for tables.
- `filter` — a row filter over the result columns (`:jwt.<path>` bound as
  parameters), ANDed to every read, including `total_count`. It is dry-run
  against the statement at build time, so a filter naming a column the
  statement does not return fails startup or the reload.
- `filterable_columns`, `filter_operators`, `filter_relationships` — the
  `where` surface, as for tables.
- `presets` — **argument** values forced by the server: `":jwt.<path>"` or a
  literal, coerced to the argument's type. A preset argument is removed from
  the role's `<T>_arguments`, so the client cannot set or override it (also
  not through variables). A missing claim is an error, never "no preset"; a
  non-scalar claim cannot be bound. A preset **never binds `NULL`** — inside
  native SQL `NULL` often means "no restriction" (`:x IS NULL OR …`) — so a
  claim that is JSON `null` fails the request too. Coercion is exact: a claim
  (`"42"` or `42`) that is fractional, out of range for `Int` (32-bit) or of
  the wrong kind (a boolean for `Int`, a number for `Boolean`) fails the
  request instead of being truncated or dropped; a numeric claim bound to a
  `String` is written in full (`1000000`). A literal preset is checked when
  the role is built, so one that does not fit its type fails startup or the
  reload. Use a preset when the value must sit
  *inside* the statement (before a `GROUP BY`, in a CTE); a row filter only
  sees the result.
- `check` does not apply (native queries are read-only).

**Relationships** go from result rows to tables and views (`type`, `target`,
`mapping`, validated exactly like [declared relationships](#declared-relationships)):
batched by the dataloader, array relationships with `where`/`order_by`/
`limit`/`offset` and `<rel>_aggregate`, usable in `where`, and the target's
column permissions and row filter apply for the role. A role sees one only
if it can select the target and read the local join columns (a relationship
filter also needs them filterable with `_eq`). `foreign_key:` does not
apply, and relationships *to* a native query are not supported (they would
need its argument values).

Caveats:

- **The statement runs as the gateway's database user.** Table permissions
  do not apply *inside* it: whatever it selects is visible to every role
  granted the query, limited only by that grant's `columns`, `filter` and
  `presets`. Grant it like access to its result, and select only what those
  roles may see.
- **Performance.** TiDB can often push `where`, the row filter and the cursor
  into the derived table, but not through `GROUP BY`, window functions or a
  `LIMIT` inside the statement: then every request (and every page) runs the
  whole statement before filtering. The connection's `ORDER BY key` is a sort
  over the result, not an index range scan. Keep such statements selective
  through their arguments, and `max_page_size` modest.
- `key` is not enforced: duplicate keys make pages skip or repeat rows, and
  rows with a `NULL` key are left out of the connection and `total_count`.
  JSON, VECTOR, TEXT/BLOB, BIT, ENUM and SET columns cannot be key columns.
- An `ORDER BY` inside the statement is not guaranteed to survive the
  wrapping; the list is unordered and the connection is in key order.

## Layout

```
gqlgate.yaml         the config you edit (mounted into the container)
hooks/               YOUR compiled-in .go hooks/fields (+ signup.go.sample, avatar.go.sample)
docker-compose.yml   one-command build+seed+serve
Dockerfile           builds the gateway with hooks/ (runs `go mod tidy`)
register/            registry the hooks/ files use (MutationHook/CustomField/ObjectField/…)
config/              YAML loading + validation (env expansion, strict keys)
introspect/          information_schema → tables, views, columns, PKs, FKs, comments;
                     result columns of native queries
rbac/                role resolution, row-filter compilation, claim lookup
auth/                JWT verification (alg-pinned), role header + allowed roles, DB role lookups
schema/              per-role GraphQL schema, parameterized SQL, where/filter
                     surface (operators, relationship EXISTS), dataloader,
                     keyset pagination, aggregates, vector search, hooks,
                     object fields, typed JSON, concurrent root fields,
                     writes (returning, checks), error codes, response limits,
                     native queries
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
Declared relationships (see "Modeling") batch exactly the same way.
Batching is per-request, multi-round (so recursive/self-referential
relationships like category trees or org charts resolve correctly at every
depth), and applies whenever the join columns are readable by the role;
otherwise it falls back to a per-row query (never a correctness or RBAC
compromise). Nested aggregates (`users { posts_aggregate { count } }`) always
batch into one `GROUP BY` query per wave of parents: the child's FK columns
are only used as the grouping key there, never returned.

String keys follow the column's collation, as SQL equality does: with a
`*_ci` collation a child whose FK holds `'ABC'` belongs to the parent `'abc'`,
and with a PAD SPACE collation (every `*_bin`/`*_ci` one except the
`utf8mb4_0900_*` family) `'def'` belongs to `'def '`. The list, the
`_aggregate` and the object relationship all agree on this: when a join
column is a character column, rows are matched to their parent by the
column's `WEIGHT_STRING()` (one extra small query per batch computes the
parents' weights). Integer, date and binary keys compare by value as before.

**Mutations with several root fields.** GraphQL runs `mutation { a: … b: … }`
one field after another, but batched relationship fields would only be read
after the last one. So in such a request every relationship and
`<rel>_aggregate` field resolves right away, one query per parent row, and
the rows nested under `a` show the database as `a` left it (not after `b`). A
request with a single mutation, and every query, keeps batching.

## Concurrent root fields

The independent root fields of one **query** run concurrently, each on its
own pooled connection, so a dashboard-style request costs about its slowest
root field instead of the sum of all of them:

```graphql
query Dashboard {
  open: posts_aggregate(where: {published: {_eq: false}}) { count }
  latest: posts_connection(first: 20) { nodes { id title author { name } } }
  people: users_aggregate { count }
}
```

```yaml
server:
  max_parallel_root_fields: 4   # per request; 1 = one after another
```

- The default is `min(4, database.max_open_conns / 2)` (at least 1). Above
  1 the value must be **less than** `max_open_conns`, so one wide request
  always leaves a pooled connection for role lookups and other requests. A
  request with a single root field runs exactly as before.
- The pool is sized once at startup, so a hot reload that changes
  `max_open_conns` / `max_idle_conns` is rejected (restart instead); the cap
  is therefore always checked against the pool in use.
- **Mutations always run serially**, in document order.
- Everything below the root still resolves on one goroutine, so
  relationship batching is unchanged — batches even merge across the root
  fields of a request. The response row limit, error codes, timeouts and
  cancellation apply as before.
- Root fields read at their own TiDB snapshot, so two root fields of one
  request are not guaranteed to see one consistent state (as two requests
  never were). Put reads that must agree under a single root field.
- Custom query fields from `hooks/` (`register.CustomField`) run
  concurrently too: their resolvers must be safe to run in parallel with
  others (they already had to be, across requests).

## Hot config reload (dev)

With `server.hot_reload: true`, gqlgate watches the config file and rebuilds
roles, RBAC, hook wiring and the per-role schemas **in place** when it changes
— no restart, no dropped connections. Edit a role's columns, add a role, or
tweak a filter, save, and the next request sees it (poll interval
`reload_interval_seconds`, default 2s). The `tables:` section reloads the
same way (the schema is re-introspected, so a view named for the first time
appears), and so does `native_queries:` (each statement is re-checked against
the database; one that no longer runs rejects the reload). Changing which `hooks/` files exist
still needs a rebuild (they're compiled in).

```yaml
server:
  hot_reload: true
  reload_interval_seconds: 2
```

Connection settings (including `max_open_conns` / `max_idle_conns`) and the
listen host/port/path can't change this way (they need a new pool/listener); such a change is rejected and the previous config
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
(or declared `primary_key`, for views and keyless tables) the role can read;
other readable tables get a bounded `<t>_list` instead (see "Modeling").

### Aggregates

`<table>_aggregate(where)` computes everything you select in **one** query,
and only the aggregates you actually select are computed (`{ count }` never
runs a `SUM`):

```graphql
query { posts_aggregate(where: {published: {_eq: true}}) {
  count                                   # COUNT(*)
  avg { views }  sum { views }  min { views }  max { published_on }
  count_columns { rating }                # COUNT(rating): non-null values
  count_distinct { author_id }            # COUNT(DISTINCT author_id)
  approx_count_distinct { author_id }     # APPROX_COUNT_DISTINCT(author_id)
  stddev { views }  variance { views }    # sample statistics
  stddev_pop { views }  var_pop { views }  stddev_samp { views }  var_samp { views }
} }
```

The shape is function-first like the original `sum`/`avg`/`min`/`max`: each
function is an object with one field per column it applies to, typed
`<t>_<function>_fields` (`approx_count_distinct`'s type is
`<t>_count_distinct_approx_fields`, so a table named `<t>_approx` can't clash
with it).

| Field | SQL | Columns | Result |
|---|---|---|---|
| `count` | `COUNT(*)` | — | `Int!`, or `BigInt!` (see `count_type`) |
| `sum` | `SUM(c)` | numeric | `Decimal` (exact string) |
| `avg` | `AVG(c)` | numeric | `Float` |
| `min` / `max` | `MIN(c)` / `MAX(c)` | every readable column | the column's scalar |
| `count_columns` | `COUNT(c)` | every readable column | `BigInt!` |
| `count_distinct` | `COUNT(DISTINCT c)` | readable, except JSON, VECTOR, BLOB/TEXT | `BigInt!` |
| `approx_count_distinct` | `APPROX_COUNT_DISTINCT(c)` | same as `count_distinct` | `BigInt!` |
| `stddev` / `stddev_samp` | `STDDEV_SAMP(c)` | numeric, except BIT | `Float` |
| `stddev_pop` | `STDDEV_POP(c)` | numeric, except BIT | `Float` |
| `variance` / `var_samp` | `VAR_SAMP(c)` | numeric, except BIT | `Float` |
| `var_pop` | `VAR_POP(c)` | numeric, except BIT | `Float` |

Notes:

- **`stddev` and `variance` are the sample statistics** (as in Hasura and
  PostgreSQL), unlike TiDB/MySQL's own `STDDEV()`/`VARIANCE()`, which are
  the population ones. Pick `stddev_pop`/`var_pop` explicitly for those. A
  sample statistic over a single row is `null`.
- Over zero matching rows the counts are `0` and every other function `null`.
- **`count_distinct` is exact but expensive** on very large tables (several
  distinct aggregates in one query may not push down to TiKV/TiFlash);
  `approx_count_distinct` uses TiDB's HyperLogLog and stays cheap. Distinct
  counts are not offered on JSON, VECTOR or BLOB/TEXT columns.
- **64-bit counts.** `count`, the connection's `total_count` and mutations'
  `affected_rows` are `Int!` by default, exactly as before, so existing
  configs and generated clients see an unchanged schema; a count above
  2,147,483,647 (GraphQL `Int`'s limit) then fails the field. Set
  `schema_gen.count_type: BigInt` (as the demo `gqlgate.yaml` does; recommended
  for new deployments and large tables) to make them `BigInt!`. `BigInt` is a
  JSON number on the wire, so responses look the same; only the declared type
  changes, which matters to clients generated from the schema (strict-scalar
  codegen needs a `BigInt` mapping). The per-column counts are new fields and
  always `BigInt!`. `sum` stays an exact `Decimal` string, so integer sums
  can't overflow or lose precision either (even past the 64-bit range).
  `avg` and the statistics are `Float` (a double); for an exact average of
  DECIMAL money columns divide `sum` by `count` client-side.
- Deliberately not offered: percentiles, `BIT_AND/OR/XOR`, and
  `GROUP_CONCAT`/`JSON_ARRAYAGG` (silently truncated or unbounded output over
  large tables).
- Functions follow the role's **column permissions** (only readable columns
  appear, and a function with no applicable column is left out) and the
  role's **row filter** is always applied. There is no `GROUP BY` beyond the
  relationship form below.

#### Nested aggregates (array relationships)

Every array relationship `<rel>` on a row type gets a sibling
`<rel>_aggregate(where)` with the child table's full aggregate result:

```graphql
query { users_connection { nodes {
  name
  posts_aggregate { count  sum { views }  max { published_on } }
  published: posts_aggregate(where: {published: {_eq: true}}) { count }
  commented: posts_aggregate(where: {comments: {user_id: {_eq: 2}}}) { count }
} } }
```

- One query per batch of parents, never one per parent: `SELECT author_id,
  COUNT(*), SUM(views) … FROM posts WHERE author_id IN (…) AND <where> AND
  <role filter> GROUP BY author_id` (composite foreign keys use
  `(a, b) IN ((?, ?), …)`). Parents without matching rows get `count: 0` and
  `null` sums. String keys group by their collation, like the `IN` (see
  [Relationship batching](#relationship-batching-dataloader)).
- The **child table's** row filter and column permissions apply, exactly as
  for `<child>_aggregate`; `where` is the child's `bool_exp`, including its
  filter surface and relationship filters.
- `where` is the only argument: no `limit`/`offset`/`order_by` (an aggregate
  is over all matching children).
- It exists whenever the array relationship does (the role can select the
  child table and read the parent's referenced columns). Object
  relationships have no aggregate. The name is `<rel>_aggregate`, or gets a
  `_by_<fk columns>` suffix if a column or relationship already uses it.

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

### Mutation results (`returning`)

`insert_<t>`, `update_<t>` and `delete_<t>` return `<t>_mutation_response`:
the `affected_rows` count plus `returning`, the written rows with any
fields and relationships of the row type:

```graphql
mutation {
  insert_posts(objects: [{title: "a"}, {title: "b"}]) {
    affected_rows
    returning { id title author { name } }
  }
  delete_comments(where: {post_id: {_eq: 7}}) { affected_rows returning { id body } }
}
```

TiDB has no `RETURNING` clause, so the rows are read back inside the
mutation's own transaction, and only when `returning` is selected (otherwise
an update or delete stays a single statement):

- **insert** runs one `INSERT` per object and records each row's primary key —
  the supplied value, or `LAST_INSERT_ID()` for an `AUTO_INCREMENT` /
  `AUTO_RANDOM` key (one row per statement, so non-contiguous `AUTO_RANDOM`
  values are exact). Rows come back in input order. A row whose key a column
  default generates (e.g. `DEFAULT (UUID())`) cannot be found again and is
  left out, as `insert_<t>_one` returns `null` for it — supply such keys
  explicitly.
- **update** locks the matching keys first (`SELECT <pk> … WHERE <where> AND
  <update filter> FOR UPDATE`), updates exactly those rows and re-reads them
  (by their new key if `_set` changed it). Rows come back in key order.
- A supplied or `_set` key is looked up in the form the column **stores**
  it: `DECIMAL`, `DATETIME`/`TIMESTAMP`, `TIME`, `DATE` and `BINARY(n)` key
  values are converted with `CAST` (TiDB converts them exactly like the
  write), so `{id: "1.005"}` into a `DECIMAL(10,2)` key returns the row with
  `id: "1.01"`. A key the database changes in a way no cast predicts — a
  `FLOAT`/`DOUBLE` value that is not exactly representable, a key column with
  `ON UPDATE CURRENT_TIMESTAMP` or generated from other columns — cannot be
  found again: the row is left out of `returning`, and with a write check
  the mutation fails (see below).
- **delete** locks the keys matching `<where> AND <delete filter>`, reads those
  rows, then deletes them. Which rows are deleted depends only on the DELETE
  permission.

`returning` shows rows through the role's **select** permission — its columns
and row filter — so a row written (or deleted) that the role cannot read
counts in `affected_rows` but is not returned. `returning` exists when the
role can select the table and the table has a primary key (it need not be
readable); otherwise the type has `affected_rows` only. Each
`<t>_mutation_response` implements the `mutation_response` interface, so
`... on mutation_response { affected_rows }` keeps working. Returned rows
count against `server.max_response_rows`: when the top-level `returning`
rows go over, the mutation is rolled back. Relationship fields inside
`returning` (and inside `insert_<t>_one` / `update_<t>_by_pk` results) are
read after the commit; when they go over, the write stays applied and the
`response_too_large` error says so (see [Response limits](#response-limits)).

### Write checks

`filter` decides which existing rows a role may update or delete. A
**`check`** constrains the rows a write produces: every row an insert writes,
and every row an update leaves behind, must satisfy it.

```yaml
roles:
  author:
    tables:
      comments:
        insert:
          allow: true
          columns: [post_id, body]
          presets: {user_id: ":jwt.sub"}
          # only comment on posts you can see
          check: "post_id IN (SELECT id FROM posts WHERE published = 1 OR author_id = :jwt.sub)"
      posts:
        update:
          allow: true
          columns: [title, body, status, org_id]
          filter: "org_id IN (:jwt.orgs)"   # rows you may touch ...
          check: "org_id IN (:jwt.orgs)"    # ... and may not move out of reach
```

```graphql
mutation { update_posts_by_pk(id: 7, _set: {org_id: 999}) { id } }
# errors: [{ message: "permission check failed: … update check …", extensions: { code: "permission_error" } }]
```

- Same syntax as `filter`: SQL over the table's columns (subqueries allowed),
  `:jwt.<path>` claims bound as parameters.
- It runs inside the mutation's transaction, after the before-hooks and the
  write and before the after-hooks: the rows are counted with
  `SELECT COUNT(*), SUM((<check>) IS NOT TRUE) … WHERE <written keys>`, and
  any failing row — including one where the check comes out `NULL` — rolls
  the **whole** mutation back (all objects of a bulk insert, all rows of a
  bulk update). After-hooks never see rows that are about to be rolled back.
- It **fails closed**: every written row must be found again by its key
  (in its stored form, see `returning` above), or the mutation is rolled
  back with `permission_error` ("could not be found again by their key").
  For key types other than integers and character columns, gqlgate also
  makes sure before the write that no existing row already answers to a
  written key, so the check can never be evaluated on a different row. In
  practice: a `FLOAT`/`DOUBLE` key must be sent as an exactly representable
  value, and a checked table should not have a key column that changes on
  its own (`ON UPDATE CURRENT_TIMESTAMP`, a generated column).
- Presets are applied before the check sees the row, as are column defaults
  and generated columns (the check reads the row as stored).
- It applies to `insert_<t>`, `insert_<t>_one`, `update_<t>`,
  `update_<t>_by_pk` and `update_<t>_by_<unique key>`. It is optional and
  never inferred from `filter`.
- The table needs a primary key (the written rows are found again by it);
  a check on a table without one fails at startup. Every check is dry-run
  against its table at startup, so a typo fails the boot (or a hot reload),
  not every write. For an insert, a key generated by a column default (not
  `AUTO_INCREMENT`/`AUTO_RANDOM`) must be supplied explicitly.
- `check` is accepted on insert and update only. **`insert.filter`** — accepted
  but ignored by earlier versions — is now enforced as the insert check (a
  startup warning suggests renaming it); setting both is an error. So that a
  config that booted before still boots, an `insert.filter` that cannot be
  enforced on a table — the table has no primary key, or the dry run fails
  there (e.g. a `"*"` rule naming a column that table lacks) — is skipped for
  that table with a startup warning, i.e. ignored there as before. An
  explicit `check` in the same situation still fails the boot. A legacy
  filter that is enforced follows the rules above, so an insert into such a
  table must supply keys a column default would otherwise generate.

### Lookups by unique key

Every UNIQUE index whose columns are all `NOT NULL` gets a select-one root
field, and point mutations where the role may update/delete:

```graphql
query { users_by_email(email: "ada@example.com") { id name } }
query { tags_by_owner_id_and_slug(owner_id: 1, slug: "go") { id label } }
mutation { update_users_by_email(email: "ada@example.com", _set: {email: "ada@new.example"}) { id email } }
mutation { delete_users_by_username(username: "temp") { id } }
```

- Names are `<t>_by_<col1>_and_<col2>…` (`update_` / `delete_` prefixed for
  mutations), arguments are the key columns (non-null). They behave like the
  `_by_pk` fields: the role's select (and update/delete) row filters apply,
  and they return the row or `null`. An update may change the key itself;
  the row is re-read by its new key.
- A role gets them only if it can **read** every key column and **filter** on
  it with `_eq` (the lookup is that equality filter), so they never probe a
  column the role's permissions hide. Point mutations also need the select
  permission, like `_by_pk`.
- Skipped: nullable unique indexes (they admit many `NULL`s), prefix
  (`col(10)`) and expression indexes, and an index on the primary key's
  columns (`_by_pk` covers it). A name that is already taken is skipped with a
  startup warning (see the schema-generation notes above).

### Errors

Errors follow the GraphQL spec, and carry an `extensions.code`:

| `extensions.code` | Cause (TiDB/MySQL error) |
|---|---|
| `constraint_violation` | duplicate value for a unique key (1062, 1586) |
| `foreign_key_violation` | referenced row missing (1452) or row still referenced (1451) |
| `not_null_violation` | `NULL` into a `NOT NULL` column (1048, 1364) |
| `data_too_long` | value longer than the column (1406) |
| `data_exception` | value out of range or invalid for the column (1264, 1690, 1265, 1292, 1366) |
| `check_violation` | a table `CHECK` constraint failed (3819; needs `tidb_enable_check_constraint`) |
| `conflict` | lock wait timeout, deadlock, write conflict or schema change during the transaction (1205, 1213, 8002, 8022, 8028, 9007) — retry |
| `timeout` | the request ran past `database.query_timeout_seconds` |
| `database_error` | anything else the database reported |
| `permission_error` | a row failed the role's insert/update `check`, or a written row could not be found again to verify it |
| `response_too_large` | `server.max_response_rows` / `max_response_bytes` exceeded |

```json
{ "data": { "insert_users_one": null },
  "errors": [{ "message": "unique constraint violated: a row with the same key already exists",
               "path": ["insert_users_one"], "extensions": { "code": "constraint_violation" } }] }
```

Messages are fixed, safe texts: the database's own message (which can quote
the conflicting value, key names or SQL) is logged server-side and only
returned with `server.debug: true`, which also adds `db_error_number`. The
same mapping covers errors raised at `COMMIT` (e.g. an optimistic-transaction
write conflict). Errors returned by hooks pass through unchanged.

### Response limits

List arguments are clamped one by one (`max_page_size`), but aliases and
nested relationships multiply them. Two server settings bound a whole
request:

```yaml
server:
  max_response_rows: 10000   # rows one request may return (0 = unlimited)
  max_response_bytes: 8388608  # size of the encoded JSON response (0 = unlimited)
```

- **Rows** counts every row a request returns: connection nodes, `_by_pk` and
  unique-key lookups, relationship rows (each time they appear), vector
  search results and mutation `returning` rows (aggregates are one row). The
  request fails with `extensions.code: response_too_large` and `data: null`
  as soon as it goes over. A mutation whose top-level `returning` rows go
  over is rolled back. Once a mutation has committed — a later field of the
  same request, or relationship rows nested in its `returning`, go over —
  its partial result is kept, and the `response_too_large` error says
  "the mutation itself was applied" and carries
  `extensions.mutation_applied: true`. `data` can still be `null` then
  (null propagation from the failed nested field), so check that flag
  before retrying a write.
- **Bytes** replaces a larger response with a single `response_too_large`
  error (with the same message and `mutation_applied` flag when a mutation
  was nonetheless applied).
- Both default to 0 (unlimited), so existing configs behave as before. They
  are read per request, so a hot reload changes them.

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
  `ev` carries `Op/Table/Role/Claims/Values/Affected`. After-hooks run once
  the role's write `check` has passed, so they never see rolled-back rows.
- **`register.CustomField(def)`** — extra root queries/mutations with full
  graphql-go control over args/types/resolver, mounted only for the roles in
  `AllowedRoles` (empty = all). Inside a resolver,
  `gqlgate.FromContext(p.Context)` reaches the shared DB pool (`gate.DB()`)
  and token signing (`gate.SignToken(claims)`); `rbac.IdentityFrom(p.Context)`
  gives the caller's role and claims.
- **`register.ObjectField(def)`** — a computed field on a generated table
  type (see below).
- **`register.RoleResolver(fn)`** — fully custom token→role mapping (takes
  precedence over `role_claim`/`role_lookup`; allowed roles for the role
  header still apply).

### Computed fields on table types (`register.ObjectField`)

An object field attaches Go-computed data to a table's type, so it appears
wherever the type does — connection nodes, `_by_pk`, relationships, unique
lookups, mutation `returning`:

```go
register.ObjectField(register.ObjectFieldDef{
    Table:    "users",
    Name:     "avatar_url",
    Requires: []string{"email"},          // parent columns the resolver reads
    AllowedRoles: nil,                    // nil = every role (that can read Requires)
    Type:     graphql.String,
    Args:     graphql.FieldConfigArgument{"size": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 80}},
    Resolve: func(ctx context.Context, p register.ObjectFieldParams) (any, error) {
        // p.Row (the Requires columns only), p.Args, p.Role, p.Claims, p.DB
        return avatarURL(p.Row["email"].(string), p.Args["size"].(int)), nil
    },
})
```

```graphql
{ users_connection { nodes { name avatar_url(size: 120) } } }
```

- **Visibility per role**: the field exists only in the schemas of the roles
  in `AllowedRoles` (all if empty) that can `select` the table **and read
  every `Requires` column** — so it can never leak a column the role's
  permissions hide. Elsewhere it is absent (`Cannot query field`).
- **Batching**: set `ResolveBatch func(ctx, []ObjectFieldParams) ([]any,
  error)` instead of `Resolve` to get every parent row of a wave in one call
  (one result per row, in order) — the same N+1 protection relationships
  have. Use it whenever the field queries the database or a service.
- `p.DB` is the gateway's pool and is **not** subject to RBAC: the
  resolver's own query decides what it reveals, so restrict it to what every
  role seeing the field may know (use `p.Role` / `p.Claims` to decide).
- Startup rejects a field whose name collides with a column, relationship
  or nested aggregate field (`<rel>_aggregate`, or the name it was renamed to
  when that was taken, e.g. `posts_aggregate_by_author_id`), a `Requires` column the table lacks, an
  unknown role, or a duplicate table+name; a field for a table the schema
  does not expose is skipped with a warning. A panic in the resolver
  becomes a field error.
- Embedding hosts can pass fields per gate with
  `gqlgate.WithObjectFields(...)` instead of the global registry.

A runnable template with a per-row and a batched field is
[`hooks/avatar.go.sample`](hooks/avatar.go.sample) — rename it to
`hooks/avatar.go` and rebuild.

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
config file and hot-reloads (`env.ReloadExtra(t, yaml)` does the same for
the extra block, e.g. a `tables:` section); `env.DB`/`env.Exec`/`env.QueryInt` reach the
private database directly to verify what actually happened.

## Limitations (deliberate, v1)

- Collection reads are cursor-only and ordered by the primary key; there's no
  arbitrary `order_by` on connections (that's the point — PK order is free on
  TiDB, arbitrary sorts aren't). Sort application-side, or add a covering index
  and query by it via `where`.
- Connections require a role-readable primary key or declared `primary_key`;
  otherwise only the bounded, unordered `<t>_list` (no paging) is offered.
  Declared keys and declared object relationships are not enforced by the
  database.
- No arbitrary `GROUP BY`/grouped aggregates yet (aggregates are whole-filter,
  or per parent row via `<rel>_aggregate`), no aggregate predicates in
  `where` (e.g. "authors with more than 5 posts"), no subscriptions. Views are
  read-only and must be named in the config to be exposed.
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
- `returning` and write checks need a primary key on the table; `returning`
  leaves out inserted rows whose key a column default (not `AUTO_INCREMENT`
  / `AUTO_RANDOM`) generates, and a check refuses such inserts unless the key
  is supplied. With `returning` or a check, an update/delete holds the keys
  of all matching rows in memory (written in chunks of 1000).
- Unique-key fields cover plain UNIQUE indexes on `NOT NULL` columns only (no
  nullable, prefix or expression indexes); their names (and the
  nearest-neighbor fields') follow the column field names but cannot be set
  individually.
- `SELECT … FOR UPDATE` only blocks in pessimistic transactions (TiDB's
  default); in optimistic mode a concurrent write to the same rows makes the
  commit fail with `extensions.code: conflict` instead.
- Typed JSON columns shape the output only: writes and `where` take plain
  JSON, the whole document is read and decoded in Go, nested fields are not
  per-role, and numbers are decoded as 64-bit floats (an `Int` field is
  32-bit; keep larger integers as `Float` or `JSON`).
- Concurrent root fields of one query are not snapshot-consistent with each
  other.
- Native queries are read-only, have no `_aggregate`/`_by_pk`, cannot be
  relationship targets, and their result columns are nullable unless
  declared (`TINYINT(1)` reads as `Int` unless declared `Boolean`). An
  aggregating statement is evaluated in full on every request and page.

## Hardening notes

This build has been through several adversarial review passes. Things it
deliberately gets right (with regression tests): all client input and JWT claim
values are bound as SQL parameters (never interpolated — verified even for
keyset cursor keys, which TiDB compares exactly against BIGINT PKs); the
query-depth guard is memoized so a small fan-out fragment document can't cause
exponential CPU; hidden columns can't be probed through `where`, `_by_pk`,
cursors, or variables; the RBAC row filter is applied on every read path
(connections, aggregates, nested relationship aggregates, relationships,
vector search, and inside relationship filters, where each role filter is verified at startup to bind
only to its own table); LIKE wildcards in literal string operators are
escaped; aggregate and
relationship selections are computed correctly even when the client wraps them
in fragments; vector search skips NULL-vector rows; DB errors are masked from
clients unless `server.debug` is on; and identifier/name collisions are
rejected at startup rather than silently dropping an operation. Native
query arguments are bound per use (a `:name` is never spliced into the SQL),
the statement must be a single `SELECT`/`WITH` and only ever runs as a
derived table, and preset arguments cannot be set by the client. Writes are
checked inside their transaction (`insert/update.check`, NULL counts as a
failure), a delete's rows depend only on the delete permission even when
`returning` reads them through the select permission, unique-key lookups
exist only for columns the role may read and `_eq`-filter, expected database
errors carry codes without leaking the database's message, and response
row/byte limits bound alias and relationship fan-out. A role header can only
select a configured role from the caller's allowed list (403 otherwise, and
never for unauthenticated requests) — keep `allowed_roles_column` and
`allowed_roles_table` out of the insert/update permissions of every role that
must not escalate (see "Role selection"), since a role that writes them grants
itself roles; hook object fields exist only for roles
that can read the columns they consume; mistyped stored JSON yields a coded
field error, never a crash; and concurrent root fields are capped per request
below the pool size.
