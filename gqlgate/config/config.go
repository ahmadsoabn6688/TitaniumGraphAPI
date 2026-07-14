// Package config loads and validates the gqlgate YAML configuration.
//
// The YAML file defines four things:
//   - database: how to reach TiDB/MySQL and which schema to expose
//   - server:   HTTP listener + GraphiQL toggle (dev)
//   - jwt:      how to *verify* tokens (issuance/signup is out of scope)
//   - roles:    RBAC rules per role -> table -> operation
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
	// request, so role changes and deletions take effect immediately.
	CacheSeconds int `yaml:"cache_seconds"`
}

// Enabled reports whether DB role resolution is configured.
func (r RoleLookup) Enabled() bool { return r.Table != "" }

// SchemaGen tunes GraphQL generation.
type SchemaGen struct {
	Tables          TableFilter `yaml:"tables"`
	DefaultPageSize int         `yaml:"default_page_size"`
	MaxPageSize     int         `yaml:"max_page_size"`
}

// TableFilter narrows which tables of the schema are exposed.
// Empty include list means "all tables". Exclude wins over include.
type TableFilter struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

// Role maps table names (or "*" as fallback for any table) to permissions.
type Role struct {
	Tables map[string]*TablePerm `yaml:"tables"`
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
//	  presets:                        # insert/update: server-forced column values
//	    author_id: ":jwt.sub"
type OpPerm struct {
	Allow   bool              `yaml:"allow"`
	Columns []string          `yaml:"columns"`
	Filter  string            `yaml:"filter"`
	Presets map[string]string `yaml:"presets"`
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
	}
	if c.SchemaGen.DefaultPageSize == 0 {
		c.SchemaGen.DefaultPageSize = 25
	}
	if c.SchemaGen.MaxPageSize == 0 {
		c.SchemaGen.MaxPageSize = 200
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
	if c.JWT.RoleLookup.Enabled() && c.JWT.RoleLookup.CacheSeconds < 0 {
		return fmt.Errorf("jwt.role_lookup.cache_seconds must be >= 0")
	}
	return nil
}
