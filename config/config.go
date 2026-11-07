// Package config loads and validates the gqlgate YAML configuration.
//
// The YAML file defines four things:
//   - database: how to reach TiDB/MySQL and which schema to expose
//   - server:   HTTP listener + GraphiQL toggle (dev)
//   - jwt:      how to *verify* tokens (issuance/signup is out of scope)
//   - roles:    RBAC rules per role -> table -> operation
//
// plus the optional tables: section that shapes individual tables and views
// (logical keys, declared relationships, GraphQL names, docs), json_types:
// for typed JSON columns and native_queries: for parameterized SQL queries.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the root of the YAML document.
type Config struct {
	Version   int              `yaml:"version"`
	Database  Database         `yaml:"database"`
	Server    Server           `yaml:"server"`
	JWT       JWT              `yaml:"jwt"`
	SchemaGen SchemaGen        `yaml:"schema_gen"`
	Roles     map[string]*Role `yaml:"roles"`
	Hooks     HooksConfig      `yaml:"hooks"`
	// Tables shapes individual tables and views in the API: logical primary
	// keys, declared relationships, custom GraphQL names, descriptions and
	// deprecations (see TableConfig). Keyed by SQL table name.
	Tables map[string]*TableConfig `yaml:"tables"`
	// JSONTypes declares named object shapes for JSON columns. A column opts
	// in with tables.<t>.columns.<c>.json_type; without that, a JSON column
	// stays the opaque JSON scalar. Keyed by GraphQL type name.
	JSONTypes map[string]*JSONType `yaml:"json_types"`
	// NativeQueries are read-only parameterized SQL statements exposed as
	// root query fields (see NativeQuery). Keyed by query name, which is
	// also the default root field name.
	NativeQueries map[string]*NativeQuery `yaml:"native_queries"`
}

// HooksConfig wires custom logic to the API. Hook names referenced here are
// implemented in the top-level hooks/ directory (compiled into the binary;
// they register themselves via the gqlgate/register package). A name used
// here with no registered implementation is a startup error.
type HooksConfig struct {
	// Tables maps a table name (or "*" for all tables) to its lifecycle hooks.
	Tables map[string]*TableHooks `yaml:"tables"`
}

// TableHooks lists the hook names to run around each write on one table.
// before_* hooks run inside the mutation's transaction and can abort it by
// returning an error; after_* hooks also run in the transaction (so they can
// still veto by erroring) but see the affected-row count.
type TableHooks struct {
	BeforeInsert []string `yaml:"before_insert"`
	AfterInsert  []string `yaml:"after_insert"`
	BeforeUpdate []string `yaml:"before_update"`
	AfterUpdate  []string `yaml:"after_update"`
	BeforeDelete []string `yaml:"before_delete"`
	AfterDelete  []string `yaml:"after_delete"`
}

// Database describes the TiDB/MySQL connection and the schema to expose.
type Database struct {
	Host                string `yaml:"host"`
	Port                int    `yaml:"port"`
	User                string `yaml:"user"`
	Password            string `yaml:"password"`
	Schema              string `yaml:"schema"`
	Params              string `yaml:"params"`
	MaxOpenConns        int    `yaml:"max_open_conns"`
	MaxIdleConns        int    `yaml:"max_idle_conns"`
	QueryTimeoutSeconds int    `yaml:"query_timeout_seconds"`
	// StartupWaitSeconds makes the gateway retry startup for this long while
	// the database is unreachable or its schema is not yet populated (e.g. a
	// seeder is still running, or the DB container is still booting). 0 = fail
	// fast. The GQLGATE_WAIT_DB env var overrides it. This is why the gateway
	// tolerates starting before its dependencies without external
	// orchestration.
	StartupWaitSeconds int `yaml:"startup_wait_seconds"`
}

// DSN builds the go-sql-driver/mysql data source name.
// parseTime is always forced on so DATETIME/TIMESTAMP scan into time.Time;
// clientFoundRows makes UPDATE report matched rows (not changed rows), which
// is what affected_rows means in the GraphQL API.
func (d Database) DSN() string {
	params := "parseTime=true&charset=utf8mb4&clientFoundRows=true"
	if d.Params != "" {
		params = params + "&" + d.Params
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?%s", d.User, d.Password, d.Host, d.Port, d.Schema, params)
}

// Server configures the HTTP endpoint.
type Server struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Path     string `yaml:"path"`
	GraphiQL bool   `yaml:"graphiql"`
	Debug    bool   `yaml:"debug"` // logs generated SQL + args
	CORS     CORS   `yaml:"cors"`
	// MaxQueryDepth caps selection-set nesting to stop abusive recursive
	// queries over relationship fields. Default 15 (deep enough for
	// GraphiQL's introspection query); -1 disables the check.
	MaxQueryDepth int `yaml:"max_query_depth"`
	// HotReload watches the config file and rebuilds the schemas/roles/hooks
	// in place when it changes — a dev convenience.
	// Connection settings and the listen host/port/path cannot change this
	// way (they require a restart). Leave off in production.
	HotReload bool `yaml:"hot_reload"`
	// ReloadIntervalSeconds is how often the config file is polled when
	// HotReload is on. Default 2. (Polling is used rather than filesystem
	// events because it is reliable across Docker bind mounts.)
	ReloadIntervalSeconds int `yaml:"reload_interval_seconds"`
	// MaxResponseRows caps the number of rows one request may read for its
	// response (every page, relationship batch, vector search and mutation
	// `returning` counts). A request that goes over fails with the error
	// code response_too_large instead of returning a huge result. 0 (the
	// default) = unlimited.
	MaxResponseRows int `yaml:"max_response_rows"`
	// MaxResponseBytes caps the size of the encoded JSON response; a larger
	// one is replaced by a response_too_large error. 0 (the default) =
	// unlimited.
	MaxResponseBytes int `yaml:"max_response_bytes"`
	// MaxParallelRootFields caps how many root fields of one query
	// operation run at the same time (each on its own pooled connection).
	// 0 (the default) picks min(4, database.max_open_conns/2), at least 1;
	// 1 runs them one after another. Mutations always run serially. Above 1
	// it must be less than database.max_open_conns.
	MaxParallelRootFields int `yaml:"max_parallel_root_fields"`
}

// CORS configures cross-origin access (useful when GraphiQL or a SPA runs on
// a different origin during dev).
type CORS struct {
	Enabled        bool     `yaml:"enabled"`
	AllowedOrigins []string `yaml:"allowed_origins"`
}

// JWT configures token *verification*. gqlgate never issues tokens.
type JWT struct {
	// Algorithm is the only accepted signing algorithm (alg header allowlist
	// of exactly one entry). One of HS256/384/512, RS256/384/512, ES256/384/512.
	Algorithm string `yaml:"algorithm"`
	// Secret is the shared secret for HS* algorithms. Supports ${ENV_VAR}.
	Secret string `yaml:"secret"`
	// PublicKeyFile is a PEM file with the public key for RS*/ES* algorithms.
	PublicKeyFile string `yaml:"public_key_file"`
	Issuer        string `yaml:"issuer"`   // optional iss check
	Audience      string `yaml:"audience"` // optional aud check
	LeewaySeconds int    `yaml:"leeway_seconds"`
	// RoleClaim is a dot path into the claims that yields the role string,
	// e.g. "role" or "app_metadata.role" or "https://myapp/claims.role".
	// Ignored when RoleLookup is configured.
	RoleClaim string `yaml:"role_claim"`
	// RoleLookup, when set, resolves the role from an identity table in the
	// database instead of a token claim: the JWT carries only the user id.
	RoleLookup RoleLookup `yaml:"role_lookup"`
	// AnonymousRole is assumed when no Authorization header is present.
	// If empty, unauthenticated requests are rejected with 401.
	AnonymousRole string `yaml:"anonymous_role"`
	// AllowedRolesClaim is a dot path to the claim listing the roles the
	// caller may switch to with the role header (a JSON array of role names,
	// or one comma-separated string). The role from role_claim / role_lookup
	// stays the default and is always allowed. Alternatively the list comes
	// from the database (role_lookup.allowed_roles_column / _table).
	AllowedRolesClaim string `yaml:"allowed_roles_claim"`
	// RoleHeader is the request header a client sends to act as one of its
	// allowed roles for that request. Default "X-Gqlgate-Role". A requested
	// role outside the allowed list is rejected with 403; without an
	// allowed-roles source only the caller's own role may be requested.
	RoleHeader string `yaml:"role_header"`
}

// DefaultRoleHeader is the default jwt.role_header.
const DefaultRoleHeader = "X-Gqlgate-Role"

// AllowedRolesFromDB reports whether the allowed roles come from the
// identity database (role_lookup.allowed_roles_column or _table).
func (j JWT) AllowedRolesFromDB() bool {
	return j.RoleLookup.AllowedRolesColumn != "" || j.RoleLookup.AllowedRolesTable != nil
}

// AllowedRolesConfigured reports whether any allowed-roles source is set.
func (j JWT) AllowedRolesConfigured() bool {
	return j.AllowedRolesClaim != "" || j.AllowedRolesFromDB()
}

// RoleLookup describes the identity table your signup service maintains.
// gqlgate reads exactly one column from it (RoleColumn, matched on IDColumn
// by the token's IDClaim); the username/password columns are only validated
// to exist at startup so the contract with your signup code is checked early.
type RoleLookup struct {
	// Table is the identity table; setting it enables DB role resolution.
	Table string `yaml:"table"`
	// Schema of the identity table. Defaults to database.schema. The table
	// does NOT have to be exposed through GraphQL (exclude it if you don't
	// want it queryable).
	Schema string `yaml:"schema"`
	// IDClaim is the JWT claim (dot path) holding the user id. Default "sub".
	IDClaim string `yaml:"id_claim"`
	// IDColumn is matched against the id claim value. Default "id".
	IDColumn string `yaml:"id_column"`
	// RoleColumn holds the role name. Default "role".
	RoleColumn string `yaml:"role_column"`
	// UsernameColumn/PasswordColumn are your signup service's columns. They
	// default to "username" and "password" and are checked to exist at
	// startup; set explicitly to "" to skip the check.
	UsernameColumn *string `yaml:"username_column"`
	PasswordColumn *string `yaml:"password_column"`
	// CacheSeconds caches id->role lookups. 0 (default) queries on every
	// request, so role changes and deletions take effect immediately. It
	// applies to the allowed-roles lookup too.
	CacheSeconds int `yaml:"cache_seconds"`
	// AllowedRolesColumn is a column of the identity table listing the
	// roles the user may switch to with the role header: a JSON array of
	// role names or a comma-separated string. Optional.
	AllowedRolesColumn string `yaml:"allowed_roles_column"`
	// AllowedRolesTable lists the allowed roles one row per (user, role)
	// instead. Optional; at most one allowed-roles source may be set.
	AllowedRolesTable *AllowedRolesTable `yaml:"allowed_roles_table"`
}

// AllowedRolesTable is a (user id, role) table holding the roles each user
// may switch to with the role header.
type AllowedRolesTable struct {
	Table string `yaml:"table"`
	// Schema defaults to the identity table's schema.
	Schema string `yaml:"schema"`
	// IDColumn is matched against the role_lookup id claim. Default "user_id".
	IDColumn string `yaml:"id_column"`
	// RoleColumn holds one role name per row. Default "role".
	RoleColumn string `yaml:"role_column"`
}

// Enabled reports whether DB role resolution is configured.
func (r RoleLookup) Enabled() bool { return r.Table != "" }

// SchemaGen tunes GraphQL generation.
type SchemaGen struct {
	Tables          TableFilter `yaml:"tables"`
	DefaultPageSize int         `yaml:"default_page_size"`
	MaxPageSize     int         `yaml:"max_page_size"`
	// CustomOperators are developer-defined comparison operators added to the
	// <Scalar>_comparison_exp types of the scalars they apply to.
	CustomOperators []CustomOperator `yaml:"custom_operators"`
	// CountType is the GraphQL scalar of row counts (<t>_aggregate.count,
	// <t>_connection.total_count and mutation_response.affected_rows):
	// "Int" (the default, unchanged from earlier versions: GraphQL's 32-bit
	// Int, so a count above 2147483647 fails the field) or "BigInt" (64-bit,
	// recommended for new deployments and large tables; it changes the
	// declared type of those fields, which matters to generated clients).
	CountType string `yaml:"count_type"`
	// DescriptionsFromComments uses the TiDB table and column COMMENTs as
	// the GraphQL descriptions of the generated object types and column
	// fields (a description under tables: still wins). Off by default:
	// comments written for DBAs become visible in every role's schema.
	DescriptionsFromComments bool `yaml:"descriptions_from_comments"`
}

// Count scalar names accepted by schema_gen.count_type.
const (
	CountTypeBigInt = "BigInt"
	CountTypeInt    = "Int"
)

// TableFilter narrows which tables of the schema are exposed.
// Empty include list means "all tables". Exclude wins over include.
type TableFilter struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

// Role maps table names (or "*" as fallback for any table) to permissions,
// and grants native queries by name.
type Role struct {
	Tables map[string]*TablePerm `yaml:"tables"`
	// NativeQueries grants native queries to the role, keyed by query name
	// (there is no wildcard). The permission takes the select shape: allow,
	// columns (readable result columns), filter (a row filter over the
	// result columns, :jwt.<claim> bound as parameters), the filter surface
	// keys, and presets — server-forced ARGUMENT values (":jwt.<claim>" or a
	// literal) that the client cannot set or override.
	NativeQueries map[string]*OpPerm `yaml:"native_queries"`
}

// TablePerm holds per-operation permissions for one table.
type TablePerm struct {
	Select *OpPerm `yaml:"select"`
	Insert *OpPerm `yaml:"insert"`
	Update *OpPerm `yaml:"update"`
	Delete *OpPerm `yaml:"delete"`
}

// OpPerm is the permission for a single operation. In YAML it may be written
// either as a bare boolean (shorthand for allow-everything / deny):
//
//	select: true
//
// or as a full object:
//
//	select:
//	  allow: true
//	  columns: ["id", "title"]        # for select: readable; insert/update: writable
//	  filter: "author_id = :jwt.sub"  # row-level filter, claims bound as params
//	  check: "status IN ('draft', 'review')"  # insert/update: every written row must satisfy it
//	  presets:                        # insert/update: server-forced column values
//	    author_id: ":jwt.sub"
//
// select additionally shapes the role's `where` surface (all optional; the
// default is every readable column, every operator, every relationship):
//
//	select:
//	  allow: true
//	  filterable_columns:             # columns usable in where (+ per-column operators)
//	    id: all
//	    title: [_eq, _ilike, _starts_with]
//	  filter_operators: [_eq, _in, _is_null, _ilike]  # table-wide operator allow-list
//	  filter_relationships: [author]  # relationships usable in where ([] = none)
type OpPerm struct {
	Allow   bool              `yaml:"allow"`
	Columns []string          `yaml:"columns"`
	Filter  string            `yaml:"filter"`
	Presets map[string]string `yaml:"presets"`
	// Check is a row condition (same SQL + :jwt.<claim> syntax as Filter)
	// that every row an insert writes, or an update leaves behind, must
	// satisfy; otherwise the whole mutation is rolled back. insert/update
	// only.
	Check string `yaml:"check"`

	// FilterableColumns restricts which readable columns appear in the
	// role's <table>_bool_exp, optionally with per-column operator lists.
	// nil = every readable column. select only.
	FilterableColumns *FilterableColumns `yaml:"filterable_columns"`
	// FilterOperators is a table-wide operator allow-list, intersected with
	// any per-column list. nil = every operator; [] = none (no column
	// filtering, and so no relationship filters either). select only.
	FilterOperators *[]string `yaml:"filter_operators"`
	// FilterRelationships lists the relationship fields usable in where.
	// nil = every relationship the role can follow; [] = none. select only.
	FilterRelationships *[]string `yaml:"filter_relationships"`
}

// UnmarshalYAML accepts either a bool or a mapping for an operation permission.
func (o *OpPerm) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		var b bool
		if err := node.Decode(&b); err != nil {
			return fmt.Errorf("operation permission must be a boolean or a mapping: %w", err)
		}
		*o = OpPerm{Allow: b}
		return nil
	}
	// Use an alias type to avoid recursing into this method.
	type raw OpPerm
	var r raw
	if err := node.Decode(&r); err != nil {
		return err
	}
	*o = OpPerm(r)
	return nil
}

var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces ${VAR} references. Unset variables are an error so that
// a missing JWT secret can never silently become "".
func expandEnv(raw []byte) ([]byte, error) {
	var missing []string
	out := envVarPattern.ReplaceAllFunc(raw, func(m []byte) []byte {
		name := envVarPattern.FindSubmatch(m)[1]
		v, ok := os.LookupEnv(string(name))
		if !ok {
			missing = append(missing, string(name))
			return m
		}
		return []byte(v)
	})
	if len(missing) > 0 {
		return nil, fmt.Errorf("environment variable(s) referenced in config but not set: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// Load reads, expands and validates a YAML config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse parses raw YAML bytes into a validated Config.
func Parse(raw []byte) (*Config, error) {
	expanded, err := expandEnv(raw)
	if err != nil {
		return nil, err
	}
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(expanded)))
	dec.KnownFields(true) // typo'd keys are config bugs; fail loudly
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDatabaseEnvOverrides()
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applyDatabaseEnvOverrides lets the environment inject the database
// connection — the natural way to pass credentials in docker compose /
// Kubernetes without editing the YAML. Environment values take PRIORITY over
// whatever the config file says:
//
//	GQLGATE_DB_HOST, GQLGATE_DB_PORT, GQLGATE_DB_USER,
//	GQLGATE_DB_PASSWORD, GQLGATE_DB_SCHEMA
//
// GQLGATE_DB_PASSWORD is honored even when set to the empty string (an
// explicitly empty password, e.g. a fresh TiDB root); the others ignore empty
// values.
func (c *Config) applyDatabaseEnvOverrides() {
	if v := os.Getenv("GQLGATE_DB_HOST"); v != "" {
		c.Database.Host = v
	}
	if v := os.Getenv("GQLGATE_DB_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.Database.Port = n
		}
	}
	if v := os.Getenv("GQLGATE_DB_USER"); v != "" {
		c.Database.User = v
	}
	if v, ok := os.LookupEnv("GQLGATE_DB_PASSWORD"); ok {
		c.Database.Password = v
	}
	if v := os.Getenv("GQLGATE_DB_SCHEMA"); v != "" {
		c.Database.Schema = v
	}
}

func (c *Config) applyDefaults() {
	if c.Database.Host == "" {
		c.Database.Host = "127.0.0.1"
	}
	if c.Database.Port == 0 {
		c.Database.Port = 4000 // TiDB default
	}
	if c.Database.User == "" {
		c.Database.User = "root"
	}
	if c.Database.MaxOpenConns == 0 {
		c.Database.MaxOpenConns = 10
	}
	if c.Database.MaxIdleConns == 0 {
		c.Database.MaxIdleConns = 5
	}
	if c.Database.QueryTimeoutSeconds == 0 {
		c.Database.QueryTimeoutSeconds = 30
	}
	if c.Server.Host == "" {
		c.Server.Host = "127.0.0.1"
	}
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
	if c.Server.Path == "" {
		c.Server.Path = "/graphql"
	}
	if c.Server.MaxQueryDepth == 0 {
		c.Server.MaxQueryDepth = 15
	}
	if c.Server.ReloadIntervalSeconds == 0 {
		c.Server.ReloadIntervalSeconds = 2
	}
	if c.JWT.RoleClaim == "" {
		c.JWT.RoleClaim = "role"
	}
	if c.JWT.RoleHeader == "" {
		c.JWT.RoleHeader = DefaultRoleHeader
	}
	if c.Server.MaxParallelRootFields == 0 {
		n := c.Database.MaxOpenConns / 2
		if n > 4 {
			n = 4
		}
		if n < 1 {
			n = 1
		}
		c.Server.MaxParallelRootFields = n
	}
	if c.JWT.RoleLookup.Enabled() {
		rl := &c.JWT.RoleLookup
		if rl.Schema == "" {
			rl.Schema = c.Database.Schema
		}
		if rl.IDClaim == "" {
			rl.IDClaim = "sub"
		}
		if rl.IDColumn == "" {
			rl.IDColumn = "id"
		}
		if rl.RoleColumn == "" {
			rl.RoleColumn = "role"
		}
		if rl.UsernameColumn == nil {
			s := "username"
			rl.UsernameColumn = &s
		}
		if rl.PasswordColumn == nil {
			s := "password"
			rl.PasswordColumn = &s
		}
		if at := rl.AllowedRolesTable; at != nil {
			if at.Schema == "" {
				at.Schema = rl.Schema
			}
			if at.IDColumn == "" {
				at.IDColumn = "user_id"
			}
			if at.RoleColumn == "" {
				at.RoleColumn = "role"
			}
		}
	}
	if c.SchemaGen.DefaultPageSize == 0 {
		c.SchemaGen.DefaultPageSize = 25
	}
	if c.SchemaGen.MaxPageSize == 0 {
		c.SchemaGen.MaxPageSize = 200
	}
	if c.SchemaGen.CountType == "" {
		// Int keeps existing configs' schemas unchanged; BigInt is opt-in.
		c.SchemaGen.CountType = CountTypeInt
	}
}

var validAlgorithms = map[string]bool{
	"HS256": true, "HS384": true, "HS512": true,
	"RS256": true, "RS384": true, "RS512": true,
	"ES256": true, "ES384": true, "ES512": true,
}

func (c *Config) validate() error {
	if c.Database.Schema == "" {
		return fmt.Errorf("database.schema is required (the schema whose tables are exposed)")
	}
	if !validAlgorithms[c.JWT.Algorithm] {
		return fmt.Errorf("jwt.algorithm %q is not supported (use HS256/384/512, RS256/384/512 or ES256/384/512)", c.JWT.Algorithm)
	}
	if strings.HasPrefix(c.JWT.Algorithm, "HS") {
		if c.JWT.Secret == "" {
			return fmt.Errorf("jwt.secret is required for %s", c.JWT.Algorithm)
		}
		if len(c.JWT.Secret) < 32 {
			return fmt.Errorf("jwt.secret must be at least 32 bytes for %s (got %d)", c.JWT.Algorithm, len(c.JWT.Secret))
		}
	} else {
		if c.JWT.PublicKeyFile == "" {
			return fmt.Errorf("jwt.public_key_file is required for %s", c.JWT.Algorithm)
		}
	}
	if len(c.Roles) == 0 {
		return fmt.Errorf("at least one role must be defined under roles:")
	}
	if c.JWT.AnonymousRole != "" {
		if _, ok := c.Roles[c.JWT.AnonymousRole]; !ok {
			return fmt.Errorf("jwt.anonymous_role %q is not defined under roles:", c.JWT.AnonymousRole)
		}
	}
	if c.SchemaGen.DefaultPageSize > c.SchemaGen.MaxPageSize {
		return fmt.Errorf("schema_gen.default_page_size (%d) exceeds max_page_size (%d)",
			c.SchemaGen.DefaultPageSize, c.SchemaGen.MaxPageSize)
	}
	if ct := c.SchemaGen.CountType; ct != CountTypeBigInt && ct != CountTypeInt {
		return fmt.Errorf("schema_gen.count_type %q is not supported (use BigInt or Int)", ct)
	}
	if c.JWT.RoleLookup.Enabled() && c.JWT.RoleLookup.CacheSeconds < 0 {
		return fmt.Errorf("jwt.role_lookup.cache_seconds must be >= 0")
	}
	if c.Server.MaxResponseRows < 0 {
		return fmt.Errorf("server.max_response_rows must be >= 0 (0 = unlimited)")
	}
	if c.Server.MaxResponseBytes < 0 {
		return fmt.Errorf("server.max_response_bytes must be >= 0 (0 = unlimited)")
	}
	if n := c.Server.MaxParallelRootFields; n < 0 {
		return fmt.Errorf("server.max_parallel_root_fields must be >= 0 (0 = default, 1 = serial)")
	} else if n > 1 && n >= c.Database.MaxOpenConns {
		// At least one pooled connection must stay free for role lookups and
		// other requests while one wide query runs all its root fields.
		return fmt.Errorf("server.max_parallel_root_fields (%d) must be less than database.max_open_conns (%d): one request could take every pooled connection", n, c.Database.MaxOpenConns)
	}
	if err := c.validateRoleSelection(); err != nil {
		return err
	}
	if err := c.validateChecks(); err != nil {
		return err
	}
	if err := c.validateTables(); err != nil {
		return err
	}
	if err := c.validateJSONTypes(); err != nil {
		return err
	}
	if err := c.validateNativeQueries(); err != nil {
		return err
	}
	return c.validateFilterSurface()
}

// headerNamePattern is an HTTP header field name (an RFC 9110 token).
var headerNamePattern = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")

// validateRoleSelection checks the allowed-roles source and the role header.
func (c *Config) validateRoleSelection() error {
	j := c.JWT
	if !headerNamePattern.MatchString(j.RoleHeader) {
		return fmt.Errorf("jwt.role_header %q is not a valid HTTP header name", j.RoleHeader)
	}
	if strings.EqualFold(j.RoleHeader, "Authorization") || strings.EqualFold(j.RoleHeader, "Content-Type") {
		return fmt.Errorf("jwt.role_header cannot be %s", j.RoleHeader)
	}
	rl := j.RoleLookup
	sources := 0
	for _, set := range []bool{j.AllowedRolesClaim != "", rl.AllowedRolesColumn != "", rl.AllowedRolesTable != nil} {
		if set {
			sources++
		}
	}
	if sources > 1 {
		return fmt.Errorf("jwt: set at most one of allowed_roles_claim, role_lookup.allowed_roles_column and role_lookup.allowed_roles_table")
	}
	if j.AllowedRolesFromDB() && !rl.Enabled() {
		return fmt.Errorf("jwt.role_lookup.allowed_roles_column / allowed_roles_table need jwt.role_lookup.table (the user id is matched through it)")
	}
	if at := rl.AllowedRolesTable; at != nil && at.Table == "" {
		return fmt.Errorf("jwt.role_lookup.allowed_roles_table.table is required")
	}
	return nil
}

// validateChecks rejects write checks where they have no meaning: a check
// constrains the rows a write produces, so only insert and update take one.
// An insert rule may not carry both filter (accepted as the check for
// backward compatibility) and check.
func (c *Config) validateChecks() error {
	for roleName, role := range c.Roles {
		if role == nil {
			continue
		}
		for tableName, tp := range role.Tables {
			if tp == nil {
				continue
			}
			for opName, perm := range map[string]*OpPerm{"select": tp.Select, "delete": tp.Delete} {
				if perm != nil && perm.Check != "" {
					return fmt.Errorf("role %q, table %q: check applies to insert and update only, not %s (use filter to restrict which rows %s sees)", roleName, tableName, opName, opName)
				}
			}
			if ins := tp.Insert; ins != nil && ins.Filter != "" && ins.Check != "" {
				return fmt.Errorf("role %q, table %q: insert has both filter and check; an insert filter is enforced as the check, so keep only check", roleName, tableName)
			}
		}
	}
	return nil
}
