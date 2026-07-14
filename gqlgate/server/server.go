// Package server exposes the per-role GraphQL schemas over HTTP, with an
// embedded GraphiQL IDE for development. The live parts (config, per-role
// schemas, JWT verifier) are read through a State accessor on every request,
// so a hot reload can swap them atomically without dropping connections.
package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/graphql-go/graphql"

	"gqlgate/auth"
	"gqlgate/config"
	"gqlgate/rbac"
	gqlschema "gqlgate/schema"
)

//go:embed graphiql.html
var graphiqlHTML []byte

// maxBodyBytes caps the request body; GraphQL documents are small.
const maxBodyBytes = 1 << 20

// State is the hot-swappable serving state for one config generation.
type State struct {
	Cfg      *config.Config
	Schemas  map[string]graphql.Schema
	Verifier *auth.Verifier
}

// New assembles the HTTP handler. Routing (path, CORS) is fixed from static;
// the config/schemas/verifier used per request come from current(), so a
// reload that swaps the State takes effect on the next request.
func New(static *config.Config, current func() *State, logger *slog.Logger) http.Handler {
	s := &srv{current: current, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc(static.Server.Path, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if s.current().Cfg.Server.GraphiQL && wantsHTML(r) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write(graphiqlHTML)
				return
			}
			auth.WriteError(w, http.StatusMethodNotAllowed, "use POST for GraphQL requests")
		case http.MethodPost:
			s.execute(w, r)
		default:
			auth.WriteError(w, http.StatusMethodNotAllowed, "use POST for GraphQL requests")
		}
	})

	if static.Server.CORS.Enabled {
		return corsMiddleware(static.Server.CORS, mux)
	}
	return mux
}

type srv struct {
	current func() *State
	logger  *slog.Logger
}

type graphqlRequest struct {
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables"`
	OperationName string         `json:"operationName"`
}

func (s *srv) execute(w http.ResponseWriter, r *http.Request) {
	st := s.current()

	// Authenticate with the current verifier and resolve the role.
	id, status, err := st.Verifier.Identify(r)
	if err != nil {
		auth.WriteError(w, status, err.Error())
		return
	}
	schema, ok := st.Schemas[id.Role]
	if !ok {
		auth.WriteError(w, http.StatusForbidden, "no schema for role "+id.Role)
		return
	}

	var req graphqlRequest
	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		auth.WriteError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Query) == "" {
		auth.WriteError(w, http.StatusBadRequest, "request has no query")
		return
	}
	if err := checkDepth(req.Query, st.Cfg.Server.MaxQueryDepth); err != nil {
		auth.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := rbac.WithIdentity(r.Context(), id)
	timeout := time.Duration(st.Cfg.Database.QueryTimeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Per-request relationship dataloaders (batch N+1 relationship queries).
	ctx = gqlschema.WithLoaders(ctx)

	start := time.Now()
	result := graphql.Do(graphql.Params{
		Schema:         schema,
		RequestString:  req.Query,
		VariableValues: req.Variables,
		OperationName:  req.OperationName,
		Context:        ctx,
	})
	if st.Cfg.Server.Debug && s.logger != nil {
		s.logger.Debug("graphql",
			"role", id.Role,
			"operation", req.OperationName,
			"duration", time.Since(start).String(),
			"errors", len(result.Errors))
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil && s.logger != nil {
		s.logger.Error("writing response", "err", err)
	}
}

func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func corsMiddleware(cfg config.CORS, next http.Handler) http.Handler {
	allowed := map[string]bool{}
	all := false
	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			all = true
		}
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (all || allowed[origin]) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
