// Package e2e is gqlgate's end-to-end test harness: it runs the real gateway
// in-process (gqlgate.Open + httptest) against a live TiDB and drives it with
// GraphQL-over-HTTP requests, exactly as a client would.
//
// The suite is opt-in. It runs only when GQLGATE_E2E_DSN points at a TiDB
// server, e.g.
//
//	GQLGATE_E2E_DSN='root@tcp(127.0.0.1:4000)/' go test -count=1 ./e2e/...
//
// Without it every test calls t.Skip, so a plain `go test ./...` stays
// database-free.
//
// Isolation: every New call creates its own database named
// gqlgate_e2e_<unix>_<rand>_<test>, loads the fixtures into it, and drops it
// on cleanup. The harness never creates, alters or drops any database without
// that prefix, and fixture SQL may not switch or (re)create databases.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/go-sql-driver/mysql"

	"gqlgate"
	"gqlgate/config"
)

// EnvDSN names the environment variable holding the go-sql-driver DSN of the
// TiDB server to test against (no database name needed; any given is ignored).
const EnvDSN = "GQLGATE_E2E_DSN"

// DBPrefix prefixes every database the harness creates. Nothing else is ever
// created or dropped.
const DBPrefix = "gqlgate_e2e_"

// JWTSecret is the HS256 secret of every harness gateway.
const JWTSecret = "gqlgate-e2e-secret-0123456789abcdef0123456789"

// staleAfter is how old a leftover gqlgate_e2e_* database (from a crashed or
// killed run) must be before a later run sweeps it.
const staleAfter = 6 * time.Hour

// BlogFixture is the default fixture: the demo blog schema (users, posts,
// comments, documents, audit_log) with FKs, a JSON column, a VECTOR column
// and UNIQUE username/email columns. See testdata/blog.sql for the rows.
//
//go:embed testdata/blog.sql
var BlogFixture string

// DefaultRolesYAML mirrors the roles of the demo gqlgate.yaml (admin, author,
// anonymous). Override it per test with WithRolesYAML.
const DefaultRolesYAML = `roles:
  admin:
    tables:
      "*":
        select: true
        insert: true
        update: true
        delete: true
      users:
        select:
          allow: true
          columns: [id, username, role, name, email, is_active, balance, metadata, created_at]
        insert: true
        update: true
        delete: true

  author:
    tables:
      users:
        select:
          allow: true
          columns: [id, name, is_active, created_at]
      posts:
        select: true
        insert:
          allow: true
          columns: [title, body, published, published_on]
          presets:
            author_id: ":jwt.sub"
        update:
          allow: true
          columns: [title, body, published, published_on]
          filter: "author_id = :jwt.sub"
        delete:
          allow: true
          filter: "author_id = :jwt.sub"
      comments:
        select: true
        insert:
          allow: true
          columns: [post_id, body]
          presets:
            user_id: ":jwt.sub"
        delete:
          allow: true
          filter: "user_id = :jwt.sub OR post_id IN (SELECT id FROM posts WHERE author_id = :jwt.sub)"

  anonymous:
    tables:
      posts:
        select:
          allow: true
          columns: [id, author_id, title, body, published_on, created_at]
          filter: "published = 1"
      users:
        select:
          allow: true
          columns: [id, name]
      comments:
        select: true
      documents:
        select: true
`

// DefaultConfigTemplate is the YAML the harness renders (text/template) into
// the gateway config. Fields: .Host .Port .User .Password .Schema .Secret
// (all already YAML-quoted where needed), .Debug, .Extra and .Roles (raw YAML
// blocks appended at the top level). The role comes from the `role` claim, so
// Env.Token can mint a token for any user/role pair.
const DefaultConfigTemplate = `version: 1
database:
  host: {{.Host}}
  port: {{.Port}}
  user: {{.User}}
  password: {{.Password}}
  schema: {{.Schema}}
  max_open_conns: 10
server:
  path: /graphql
  graphiql: false
  debug: {{.Debug}}
jwt:
  algorithm: HS256
  secret: {{.Secret}}
  role_claim: role
  anonymous_role: anonymous
  leeway_seconds: 5
schema_gen:
  default_page_size: 25
  max_page_size: 200
{{.Extra}}
{{.Roles}}
`

// Option customizes New.
type Option func(*settings)

type settings struct {
	fixtures []string
	extraSQL []string
	template string
	roles    string
	extra    string
	debug    bool
	mutate   []func(*config.Config)
	gateOpts []gqlgate.Option
}

// WithFixtures replaces the default fixture (BlogFixture) with the given SQL
// scripts, loaded in order.
func WithFixtures(scripts ...string) Option {
	return func(s *settings) { s.fixtures = scripts }
}

// WithSQL runs extra statements after the fixtures (e.g. a test-specific
// table or view). Each string is one statement or a ;-separated script.
func WithSQL(stmts ...string) Option {
	return func(s *settings) { s.extraSQL = append(s.extraSQL, stmts...) }
}

// WithRolesYAML replaces DefaultRolesYAML. It must be a complete top-level
// `roles:` block.
func WithRolesYAML(roles string) Option {
	return func(s *settings) { s.roles = roles }
}

// WithExtraYAML appends raw top-level YAML (e.g. a `hooks:` block) to the
// rendered config.
func WithExtraYAML(extra string) Option {
	return func(s *settings) { s.extra = extra }
}

// WithConfigTemplate replaces DefaultConfigTemplate entirely (same fields).
func WithConfigTemplate(tmpl string) Option {
	return func(s *settings) { s.template = tmpl }
}

// WithDebug turns on server.debug (SQL logging, unmasked DB errors).
func WithDebug() Option {
	return func(s *settings) { s.debug = true }
}

// WithConfig mutates the parsed config before the gateway opens. Mutations
// are not persisted to the config file, so Env.Reload does not replay them.
func WithConfig(fn func(*config.Config)) Option {
	return func(s *settings) { s.mutate = append(s.mutate, fn) }
}

// WithGateOptions passes extra gqlgate.Option values to gqlgate.Open.
func WithGateOptions(opts ...gqlgate.Option) Option {
	return func(s *settings) { s.gateOpts = append(s.gateOpts, opts...) }
}

// Env is one isolated gateway: a private database, the gateway opened over
// it, and an httptest server serving its handler.
type Env struct {
	// DBName is the private gqlgate_e2e_* database.
	DBName string
	// DB is a direct connection to DBName for test setup and verification
	// (it bypasses gqlgate and its RBAC entirely).
	DB *sql.DB
	// Gate is the in-process gateway.
	Gate *gqlgate.Gate
	// Config is the config the gateway was opened with.
	Config *config.Config
	// Server serves Gate.Handler().
	Server *httptest.Server
	// ConfigPath is the YAML file the config was loaded from (Reload target).
	ConfigPath string

	tmplData templateData
	settings settings
}

type templateData struct {
	Host, Port, User, Password, Schema, Secret string
	Debug                                      bool
	Extra, Roles                               string
}

// dbNamePattern matches exactly the names this harness generates.
var dbNamePattern = regexp.MustCompile(`^gqlgate_e2e_([0-9]{10})_[0-9a-f]{6}(_[a-z0-9_]*)?$`)

var forbiddenStmt = regexp.MustCompile(`(?is)^\s*(USE\s|(CREATE|DROP|ALTER)\s+(DATABASE|SCHEMA)\b)`)

var sweepOnce sync.Once

// New creates an isolated gateway for t. It skips t when GQLGATE_E2E_DSN is
// unset. Everything it creates is torn down via t.Cleanup.
func New(t testing.TB, opts ...Option) *Env {
	t.Helper()
	raw := os.Getenv(EnvDSN)
	if raw == "" {
		t.Skipf("%s not set; skipping end-to-end test", EnvDSN)
	}
	s := settings{fixtures: []string{BlogFixture}, template: DefaultConfigTemplate, roles: DefaultRolesYAML}
	for _, o := range opts {
		o(&s)
	}

	base, err := mysql.ParseDSN(raw)
	if err != nil {
		t.Fatalf("%s: %v", EnvDSN, err)
	}
	if base.Net != "tcp" {
		t.Fatalf("%s must use tcp(host:port), got %q", EnvDSN, base.Net)
	}
	host, port, err := net.SplitHostPort(base.Addr)
	if err != nil {
		t.Fatalf("%s address %q: %v", EnvDSN, base.Addr, err)
	}

	admin := openDB(t, base, "")
	defer admin.Close()
	sweepOnce.Do(func() { sweepStale(t, admin) })

	name := newDBName(t.Name())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE `"+name+"` CHARACTER SET utf8mb4"); err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	t.Cleanup(func() { dropDatabase(t, base, name) })

	env := &Env{DBName: name, settings: s}
	env.DB = openDB(t, base, name)
	t.Cleanup(func() { env.DB.Close() })

	for i, script := range s.fixtures {
		if err := execScript(ctx, env.DB, script); err != nil {
			t.Fatalf("load fixture %d into %s: %v", i+1, name, err)
		}
	}
	for _, script := range s.extraSQL {
		if err := execScript(ctx, env.DB, script); err != nil {
			t.Fatalf("extra SQL into %s: %v", name, err)
		}
	}

	env.tmplData = templateData{
		Host: yamlQuote(host), Port: port, User: yamlQuote(base.User),
		Password: yamlQuote(base.Passwd), Schema: yamlQuote(name),
		Secret: yamlQuote(JWTSecret), Debug: s.debug, Extra: s.extra, Roles: s.roles,
	}
	env.ConfigPath = filepath.Join(t.TempDir(), "gqlgate.yaml")
	if err := env.writeConfig(); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(env.ConfigPath)
	if err != nil {
		t.Fatalf("load harness config: %v", err)
	}
	// GQLGATE_DB_* environment overrides take priority over the file; refuse
	// to run if they would point the gateway anywhere but the private database.
	if cfg.Database.Schema != name || cfg.Database.Host != host || strconv.Itoa(cfg.Database.Port) != port {
		t.Fatalf("config resolved to %s:%d/%s instead of %s:%s/%s — unset GQLGATE_DB_* variables when running e2e tests",
			cfg.Database.Host, cfg.Database.Port, cfg.Database.Schema, host, port, name)
	}
	for _, fn := range s.mutate {
		fn(cfg)
	}
	env.Config = cfg

	gateOpts := append([]gqlgate.Option{gqlgate.WithConfigPath(env.ConfigPath)}, s.gateOpts...)
	gate, err := gqlgate.Open(ctx, cfg, gateOpts...)
	if err != nil {
		t.Fatalf("gqlgate.Open: %v", err)
	}
	env.Gate = gate
	t.Cleanup(func() { gate.Close() })

	env.Server = httptest.NewServer(gate.Handler())
	t.Cleanup(env.Server.Close)
	return env
}

// URL is the GraphQL endpoint.
func (e *Env) URL() string { return e.Server.URL + e.Config.Server.Path }

// Token mints a valid HS256 token carrying {"role": role, "sub": sub} plus
// any extra claims (extra keys win). Numeric subs are encoded as JSON numbers,
// as a real issuer would.
func (e *Env) Token(t testing.TB, role string, sub any, extra ...map[string]any) string {
	t.Helper()
	claims := map[string]any{"role": role, "sub": sub}
	for _, m := range extra {
		for k, v := range m {
			claims[k] = v
		}
	}
	return e.SignClaims(t, claims)
}

// SignClaims mints a token from exactly the given claims (iat/exp are added
// when absent), via the gateway's own Gate.SignToken.
func (e *Env) SignClaims(t testing.TB, claims map[string]any) string {
	t.Helper()
	tok, err := e.Gate.SignToken(claims)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tok
}

// Reload rewrites the config file with a new roles block (the rest of the
// rendered config is unchanged) and hot-reloads the gateway, returning the
// Reload error so tests can assert on rejected reloads.
func (e *Env) Reload(t testing.TB, rolesYAML string) error {
	t.Helper()
	e.tmplData.Roles = rolesYAML
	if err := e.writeConfig(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return e.Gate.Reload(ctx)
}

func (e *Env) writeConfig() error {
	tmpl, err := template.New("gqlgate.yaml").Parse(e.settings.template)
	if err != nil {
		return fmt.Errorf("config template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, e.tmplData); err != nil {
		return fmt.Errorf("config template: %w", err)
	}
	return os.WriteFile(e.ConfigPath, buf.Bytes(), 0o600)
}

// Exec runs one statement directly against the private database.
func (e *Env) Exec(t testing.TB, query string, args ...any) sql.Result {
	t.Helper()
	res, err := e.DB.Exec(query, args...)
	if err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
	return res
}

// QueryInt runs a single-value query directly against the private database.
func (e *Env) QueryInt(t testing.TB, query string, args ...any) int64 {
	t.Helper()
	var n sql.NullInt64
	if err := e.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return n.Int64
}

// QueryString runs a single-value query directly against the private database.
func (e *Env) QueryString(t testing.TB, query string, args ...any) string {
	t.Helper()
	var s sql.NullString
	if err := e.DB.QueryRow(query, args...).Scan(&s); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	return s.String
}

// GQLError is one entry of a GraphQL response's errors array.
type GQLError struct {
	Message    string         `json:"message"`
	Path       []any          `json:"path,omitempty"`
	Extensions map[string]any `json:"extensions,omitempty"`
}

// Result is a decoded GraphQL HTTP response.
type Result struct {
	Status int
	Data   map[string]any
	Errors []GQLError
	Raw    []byte
}

// GQL posts a query as the bearer of token ("" = no Authorization header,
// i.e. the anonymous role) and returns the decoded response. It fails the
// test only on transport/decoding problems; GraphQL errors are returned.
func (e *Env) GQL(t testing.TB, token, query string, vars map[string]any) *Result {
	t.Helper()
	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	return e.Do(t, headers, query, vars)
}

// Do posts a query with arbitrary request headers.
func (e *Env) Do(t testing.TB, headers map[string]string, query string, vars map[string]any) *Result {
	t.Helper()
	body, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, e.URL(), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.Server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", e.URL(), err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read response: %v", err)
	}
	r := &Result{Status: resp.StatusCode, Raw: buf.Bytes()}
	var decoded struct {
		Data   map[string]any `json:"data"`
		Errors []GQLError     `json:"errors"`
	}
	if err := json.Unmarshal(r.Raw, &decoded); err != nil {
		t.Fatalf("decode response (HTTP %d): %v\n%s", resp.StatusCode, err, r.Raw)
	}
	r.Data, r.Errors = decoded.Data, decoded.Errors
	return r
}

// MustGQL is GQL that fails the test on any GraphQL error or non-200 status.
func (e *Env) MustGQL(t testing.TB, token, query string, vars map[string]any) *Result {
	t.Helper()
	r := e.GQL(t, token, query, vars)
	r.MustOK(t)
	return r
}

// MustOK fails the test unless the response is HTTP 200 with no errors.
func (r *Result) MustOK(t testing.TB) *Result {
	t.Helper()
	if r.Status != http.StatusOK || len(r.Errors) > 0 {
		t.Fatalf("expected success, got HTTP %d: %s", r.Status, r.Raw)
	}
	return r
}

// MustFail fails the test unless the response carries an error whose message
// contains substr (any error when substr is "").
func (r *Result) MustFail(t testing.TB, substr string) *Result {
	t.Helper()
	if len(r.Errors) == 0 {
		t.Fatalf("expected an error containing %q, got HTTP %d: %s", substr, r.Status, r.Raw)
	}
	for _, e := range r.Errors {
		if strings.Contains(e.Message, substr) {
			return r
		}
	}
	t.Fatalf("no error contains %q: %s", substr, r.Raw)
	return r
}

// Get walks Data by a dot path; numeric segments index lists
// ("posts_connection.nodes.0.id"). Missing paths yield nil.
func (r *Result) Get(path string) any {
	var cur any = r.Data
	for _, seg := range strings.Split(path, ".") {
		switch c := cur.(type) {
		case map[string]any:
			cur = c[seg]
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(c) {
				return nil
			}
			cur = c[i]
		default:
			return nil
		}
	}
	return cur
}

// Int returns the number at path, failing the test if it is not one.
func (r *Result) Int(t testing.TB, path string) int64 {
	t.Helper()
	switch v := r.Get(path).(type) {
	case float64:
		return int64(v)
	case string: // Decimal / BigInt rendered as strings
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			return n
		}
	}
	t.Fatalf("%s: not an integer in %s", path, r.Raw)
	return 0
}

// String returns the string at path, failing the test if it is not one.
func (r *Result) String(t testing.TB, path string) string {
	t.Helper()
	s, ok := r.Get(path).(string)
	if !ok {
		t.Fatalf("%s: not a string in %s", path, r.Raw)
	}
	return s
}

// List returns the list at path, failing the test if it is not one.
func (r *Result) List(t testing.TB, path string) []any {
	t.Helper()
	l, ok := r.Get(path).([]any)
	if !ok {
		t.Fatalf("%s: not a list in %s", path, r.Raw)
	}
	return l
}

// IDs collects the "id" field (as int64) of every object in the list at path.
func (r *Result) IDs(t testing.TB, path string) []int64 {
	t.Helper()
	var ids []int64
	for i := range r.List(t, path) {
		ids = append(ids, r.Int(t, fmt.Sprintf("%s.%d.id", path, i)))
	}
	return ids
}

// --- database plumbing ------------------------------------------------------

func openDB(t testing.TB, base *mysql.Config, dbName string) *sql.DB {
	t.Helper()
	c := base.Clone()
	c.DBName = dbName
	c.ParseTime = true
	c.MultiStatements = false
	if c.Params == nil {
		c.Params = map[string]string{}
	}
	c.Params["charset"] = "utf8mb4"
	db, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		t.Fatalf("open %s: %v", EnvDSN, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Fatalf("cannot reach TiDB at %s (%s): %v", base.Addr, EnvDSN, err)
	}
	return db
}

// newDBName builds gqlgate_e2e_<unix>_<6 hex>_<sanitized test name>, at most
// 64 characters (the MySQL identifier limit).
func newDBName(testName string) string {
	var rb [3]byte
	_, _ = rand.Read(rb[:])
	name := fmt.Sprintf("%s%d_%s", DBPrefix, time.Now().Unix(), hex.EncodeToString(rb[:]))
	var b strings.Builder
	for _, r := range strings.ToLower(testName) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if suffix := strings.Trim(b.String(), "_"); suffix != "" {
		name += "_" + suffix
	}
	if len(name) > 64 {
		name = strings.TrimRight(name[:64], "_")
	}
	return name
}

// dropDatabase drops one harness database. It refuses any name the harness
// could not have generated.
func dropDatabase(t testing.TB, base *mysql.Config, name string) {
	if !dbNamePattern.MatchString(name) {
		t.Errorf("refusing to drop %q: not a harness database", name)
		return
	}
	admin := openDB(t, base, "")
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS `"+name+"`"); err != nil {
		t.Errorf("drop database %s: %v", name, err)
	}
}

// sweepStale drops harness databases left behind by runs that died before
// their cleanup (only names matching the harness pattern, older than
// staleAfter, so concurrent runs are never disturbed).
func sweepStale(t testing.TB, admin *sql.DB) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rows, err := admin.QueryContext(ctx,
		`SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'gqlgate\_e2e\_%'`)
	if err != nil {
		t.Logf("e2e: listing stale databases: %v", err)
		return
	}
	var stale []string
	cutoff := time.Now().Add(-staleAfter).Unix()
	for rows.Next() {
		var name string
		if rows.Scan(&name) != nil {
			continue
		}
		m := dbNamePattern.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		if ts, err := strconv.ParseInt(m[1], 10, 64); err == nil && ts < cutoff {
			stale = append(stale, name)
		}
	}
	rows.Close()
	for _, name := range stale {
		if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS `"+name+"`"); err != nil {
			t.Logf("e2e: dropping stale %s: %v", name, err)
		}
	}
}

// execScript runs a ;-separated SQL script on one pinned connection, using the
// same naive rules as example/seed: `--` comment lines are dropped, and
// semicolons inside string literals are not supported. Statements that switch
// or (re)create databases are rejected so a fixture can only ever touch the
// private database.
func execScript(ctx context.Context, db *sql.DB, script string) error {
	stmts, err := splitScript(script)
	if err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	for i, stmt := range stmts {
		if _, err := conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("statement %d failed: %w\n%s", i+1, err, stmt)
		}
	}
	return nil
}

// splitScript splits and validates a script; the whole script is rejected
// before anything runs if any statement is forbidden.
func splitScript(script string) ([]string, error) {
	var lines []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		lines = append(lines, line)
	}
	var stmts []string
	for _, stmt := range strings.Split(strings.Join(lines, "\n"), ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if forbiddenStmt.MatchString(stmt) {
			return nil, fmt.Errorf("statement %d is not allowed in e2e fixtures (they run inside the private database):\n%s", len(stmts)+1, stmt)
		}
		stmts = append(stmts, stmt)
	}
	return stmts, nil
}

// yamlQuote renders s as a double-quoted YAML scalar (JSON strings are valid
// YAML).
func yamlQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
