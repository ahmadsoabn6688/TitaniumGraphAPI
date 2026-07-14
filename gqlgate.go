// Package gqlgate auto-generates a role-aware GraphQL API (with GraphiQL in
// dev) from the tables of one TiDB/MySQL schema, driven entirely by a YAML
// config that defines the JWT verification rules and per-role RBAC.
//
// Typical usage as a standalone dev server:
//
//	err := gqlgate.Run(ctx, "gqlgate.yaml")
//
// Or embedded into an existing application (e.g. next to your own signup /
// token-issuing endpoints):
//
//	cfg, _ := config.Load("gqlgate.yaml")
//	gate, _ := gqlgate.Open(ctx, cfg)
//	defer gate.Close()
//	mux.Handle("/graphql", gate.Handler())
package gqlgate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"gqlgate/auth"
	"gqlgate/config"
	"gqlgate/introspect"
	"gqlgate/register"
	"gqlgate/schema"
	"gqlgate/server"
)

// gateState is one config generation: the serving state plus the catalog it
// was built from. It is swapped atomically on hot reload.
type gateState struct {
	srv     *server.State
	catalog *introspect.Catalog
}

// Gate is a ready-to-serve GraphQL gateway over one database schema.
type Gate struct {
	db         *sql.DB
	logger     *slog.Logger
	opts       options
	staticCfg  *config.Config // routing (path/cors/addr) fixed at Open
	configPath string         // for hot reload; "" disables it
	handler    http.Handler

	state    atomic.Pointer[gateState]
	reloadMu sync.Mutex // serializes reloads
}

// Open connects to the database, introspects the configured schema and builds
// one GraphQL schema per role. Optional hooks (custom fields, lifecycle hooks,
// a custom role resolver) are supplied via Option values.
func Open(ctx context.Context, cfg *config.Config, opts ...Option) (*Gate, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	level := slog.LevelInfo
	if cfg.Server.Debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	db, err := sql.Open("mysql", cfg.Database.DSN())
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	db.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	db.SetConnMaxLifetime(5 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("cannot reach database at %s:%d: %w", cfg.Database.Host, cfg.Database.Port, err)
	}

	g := &Gate{
		db:         db,
		logger:     logger,
		opts:       o,
		staticCfg:  cfg,
		configPath: o.configPath,
	}

	st, err := g.buildState(ctx, cfg)
	if err != nil {
		db.Close()
		return nil, err
	}
	g.state.Store(st)

	// Wrap the handler so every request context carries the Gate; custom
	// field resolvers reach it (and its DB) via gqlgate.FromContext. The
	// server reads live cfg/schemas/verifier through currentServerState.
	g.handler = g.injectContext(server.New(cfg, g.currentServerState, logger))
	return g, nil
}

// buildState builds one serving generation (hooks, catalog, per-role schemas,
// verifier) from cfg using the existing DB pool. Shared by Open and Reload.
func (g *Gate) buildState(ctx context.Context, cfg *config.Config) (*gateState, error) {
	hooks, err := buildHooks(cfg)
	if err != nil {
		return nil, err
	}
	catalog, err := introspect.Load(ctx, g.db, cfg.Database.Schema,
		cfg.SchemaGen.Tables.Include, cfg.SchemaGen.Tables.Exclude)
	if err != nil {
		return nil, err
	}
	schemas, err := schema.BuildAll(schema.Options{
		DB:      g.db,
		Catalog: catalog,
		Config:  cfg,
		Logger:  g.logger,
		Hooks:   hooks,
	})
	if err != nil {
		return nil, err
	}

	// Role resolution precedence: a resolver registered by a hooks/ file
	// (register.RoleResolver) wins, then jwt.role_lookup (from the DB), else
	// the jwt.role_claim path in auth.
	_, _, resolver := register.Registered()
	if resolver == nil && cfg.JWT.RoleLookup.Enabled() {
		if err := validateRoleLookup(ctx, g.db, cfg.JWT.RoleLookup); err != nil {
			return nil, err
		}
		resolver = auth.NewDBRoleResolver(g.db, cfg.JWT.RoleLookup)
	}
	roleNames := make([]string, 0, len(cfg.Roles))
	for r := range cfg.Roles {
		roleNames = append(roleNames, r)
	}
	verifier, err := auth.New(cfg.JWT, roleNames, resolver)
	if err != nil {
		return nil, err
	}
	return &gateState{
		srv:     &server.State{Cfg: cfg, Schemas: schemas, Verifier: verifier},
		catalog: catalog,
	}, nil
}

func (g *Gate) currentServerState() *server.State { return g.state.Load().srv }

// Reload re-reads the config file and rebuilds the schemas/roles/hooks in
// place, swapping them atomically so in-flight requests are unaffected.
// Connection settings and the listen host/port/path cannot change this way; a
// reload that alters them is rejected and the previous config keeps serving.
func (g *Gate) Reload(ctx context.Context) error {
	if g.configPath == "" {
		return fmt.Errorf("reload: no config path (open with gqlgate.WithConfigPath)")
	}
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()

	cfg, err := config.Load(g.configPath)
	if err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	if err := reloadCompatible(g.staticCfg, cfg); err != nil {
		return err
	}
	st, err := g.buildState(ctx, cfg)
	if err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	g.state.Store(st)
	g.logger.Info("config reloaded",
		"roles", len(st.srv.Schemas), "tables", len(st.catalog.TableOrder))
	return nil
}

// reloadCompatible rejects config changes that can't be applied without a
// restart (they'd need a new DB pool or a new listener).
func reloadCompatible(old, next *config.Config) error {
	if old.Database.DSN() != next.Database.DSN() {
		return fmt.Errorf("reload rejected: database connection/schema changed — restart required")
	}
	if old.Server.Host != next.Server.Host || old.Server.Port != next.Server.Port || old.Server.Path != next.Server.Path {
		return fmt.Errorf("reload rejected: server host/port/path changed — restart required")
	}
	return nil
}

type gateContextKey struct{}

// injectContext places the Gate into each request's context.
func (g *Gate) injectContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), gateContextKey{}, g)))
	})
}

// FromContext returns the Gate serving the current request, or nil if called
// outside a gqlgate request. Custom field resolvers use it to reach the shared
// DB pool (gate.DB()) for their own queries.
func FromContext(ctx context.Context) *Gate {
	g, _ := ctx.Value(gateContextKey{}).(*Gate)
	return g
}

// Handler returns the HTTP handler (GraphQL endpoint + GraphiQL + /healthz)
// for embedding into an existing server.
func (g *Gate) Handler() http.Handler { return g.handler }

// DB exposes the underlying connection pool (useful for embedding hosts).
func (g *Gate) DB() *sql.DB { return g.db }

// SignToken signs a JWT with the configured HS* secret, filling in iat/exp
// (24h default) and iss/aud when configured — the same tokens the gateway
// verifies. Custom signup hooks use this instead of touching the raw secret.
func (g *Gate) SignToken(claims map[string]any) (string, error) {
	return signHelper(g.staticCfg.JWT)(claims)
}

// Tables lists the exposed table names of the current config generation.
func (g *Gate) Tables() []string { return g.state.Load().catalog.TableOrder }

// Addr returns the configured listen address.
func (g *Gate) Addr() string {
	return net.JoinHostPort(g.staticCfg.Server.Host, fmt.Sprintf("%d", g.staticCfg.Server.Port))
}

// Close releases the database pool.
func (g *Gate) Close() error { return g.db.Close() }

// ListenAndServe serves until ctx is cancelled, then shuts down gracefully.
// When server.hot_reload is on and a config path is known, it also watches the
// config file and reloads on change.
func (g *Gate) ListenAndServe(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:              g.Addr(),
		Handler:           g.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	if g.staticCfg.Server.HotReload && g.configPath != "" {
		go g.watchConfig(ctx)
	}

	errCh := make(chan error, 1)
	go func() {
		st := g.state.Load()
		g.logger.Info("gqlgate listening",
			"addr", "http://"+g.Addr()+g.staticCfg.Server.Path,
			"schema", g.staticCfg.Database.Schema,
			"tables", len(st.catalog.TableOrder),
			"roles", len(st.srv.Schemas),
			"graphiql", g.staticCfg.Server.GraphiQL,
			"hot_reload", g.staticCfg.Server.HotReload && g.configPath != "")
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
}

// watchConfig polls the config file, reloading when a modification is seen.
// Polling (rather than fs events) is used because it is reliable across
// Docker bind mounts. A failed reload is logged and the previous config keeps
// serving.
func (g *Gate) watchConfig(ctx context.Context) {
	interval := time.Duration(g.staticCfg.Server.ReloadIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	last := g.watchStamps()
	g.logger.Info("watching config for changes", "path", g.configPath, "interval", interval.String())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur := g.watchStamps()
			if sameStamps(last, cur) {
				continue
			}
			reloadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := g.Reload(reloadCtx); err != nil {
				g.logger.Error("hot reload failed; keeping previous config", "err", err)
			}
			cancel()
			last = g.watchStamps()
		}
	}
}

// watchStamps returns modtime+size for the config file so edits trigger a
// reload.
func (g *Gate) watchStamps() map[string]string {
	files := []string{g.configPath}
	stamps := map[string]string{}
	for _, f := range files {
		if info, err := os.Stat(f); err == nil {
			stamps[f] = fmt.Sprintf("%d:%d", info.ModTime().UnixNano(), info.Size())
		} else {
			stamps[f] = "missing"
		}
	}
	return stamps
}

func sameStamps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// validateRoleLookup checks the identity-table contract at startup: the table
// your signup service maintains must exist and carry the configured id, role,
// and (unless opted out with "") username/password columns.
func validateRoleLookup(ctx context.Context, db *sql.DB, rl config.RoleLookup) error {
	cols, err := introspect.TableColumns(ctx, db, rl.Schema, rl.Table)
	if err != nil {
		return err
	}
	if len(cols) == 0 {
		return fmt.Errorf("jwt.role_lookup: identity table %s.%s does not exist", rl.Schema, rl.Table)
	}
	required := map[string]string{
		"id_column":   rl.IDColumn,
		"role_column": rl.RoleColumn,
	}
	if rl.UsernameColumn != nil && *rl.UsernameColumn != "" {
		required["username_column"] = *rl.UsernameColumn
	}
	if rl.PasswordColumn != nil && *rl.PasswordColumn != "" {
		required["password_column"] = *rl.PasswordColumn
	}
	for key, col := range required {
		if !cols[col] {
			return fmt.Errorf("jwt.role_lookup: table %s.%s has no column %q (configured as %s; set it to \"\" to skip this check if it does not apply)",
				rl.Schema, rl.Table, col, key)
		}
	}
	return nil
}

// Run is the one-call entrypoint: load config, open (retrying while the
// database/schema come up, per database.startup_wait_seconds), then serve
// until ctx ends. The config path is recorded so server.hot_reload can watch
// it.
func Run(ctx context.Context, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	gate, err := openWithRetry(ctx, cfg, WithConfigPath(configPath))
	if err != nil {
		return err
	}
	defer gate.Close()
	return gate.ListenAndServe(ctx)
}

// openWithRetry calls Open, retrying on "not ready yet" errors (database down,
// or its schema not yet populated by a seeder) until the startup-wait window
// elapses. Real errors — bad config, auth failure, a genuinely empty schema
// after the window — are returned immediately/finally. This makes the gateway
// resilient to starting before its database or seeder, with no external
// healthcheck plumbing required.
func openWithRetry(ctx context.Context, cfg *config.Config, opts ...Option) (*Gate, error) {
	deadline := time.Now().Add(startupWait(cfg))
	for attempt := 1; ; attempt++ {
		gate, err := Open(ctx, cfg, opts...)
		if err == nil {
			return gate, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !isNotReady(err) || !time.Now().Before(deadline) {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "gqlgate: database/schema not ready (attempt %d), retrying in 2s: %v\n", attempt, err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// startupWait resolves the retry window: GQLGATE_WAIT_DB (seconds) overrides
// database.startup_wait_seconds.
func startupWait(cfg *config.Config) time.Duration {
	if v := os.Getenv("GQLGATE_WAIT_DB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Second
		}
	}
	return time.Duration(cfg.Database.StartupWaitSeconds) * time.Second
}

// isNotReady reports whether an Open error is a transient "dependencies still
// coming up" condition worth retrying (vs. a real misconfiguration).
func isNotReady(err error) bool {
	msg := err.Error()
	for _, s := range []string{
		"cannot reach database",             // DB not accepting connections
		"contains no exposable base tables", // schema exists but not seeded yet
		"Unknown database",                  // target schema not created yet
		"does not exist",                    // identity table / schema not created yet
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
