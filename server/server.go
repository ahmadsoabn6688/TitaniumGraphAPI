// Package server exposes the per-role GraphQL schemas over HTTP, with an
// embedded GraphiQL IDE for development. The live parts (config, per-role
// schemas, JWT verifier) are read through a State accessor on every request,
// so a hot reload can swap them atomically without dropping connections.
package server

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/gqlerrors"

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
		return corsMiddleware(static.Server.CORS, static.JWT.RoleHeader, mux)
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
	// Per-request response row budget (server.max_response_rows).
	ctx = gqlschema.WithResponseLimit(ctx, st.Cfg.Server.MaxResponseRows)
	// Per-request cap on concurrently running root fields of a query.
	ctx = gqlschema.WithRootParallelism(ctx, st.Cfg.Server.MaxParallelRootFields)

	start := time.Now()
	result := graphql.Do(graphql.Params{
		Schema:         schema,
		RequestString:  req.Query,
		VariableValues: req.Variables,
		OperationName:  req.OperationName,
		Context:        ctx,
	})
	restoreExtensions(result.Errors)
	if gqlschema.ResponseLimitExceeded(ctx) {
		limitResult(result, gqlschema.MutationCommitted(ctx))
	}
	if st.Cfg.Server.Debug && s.logger != nil {
		s.logger.Debug("graphql",
			"role", id.Role,
			"operation", req.OperationName,
			"duration", time.Since(start).String(),
			"errors", len(result.Errors))
	}

	out, err := json.Marshal(result)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("encoding response", "err", err)
		}
		auth.WriteError(w, http.StatusInternalServerError, "could not encode the response")
		return
	}
	if limit := st.Cfg.Server.MaxResponseBytes; limit > 0 && len(out) > limit {
		out = tooLargeBody(len(out), limit, gqlschema.MutationCommitted(ctx))
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(append(out, '\n')); err != nil && s.logger != nil {
		s.logger.Error("writing response", "err", err)
	}
}

// restoreExtensions puts back the extensions (error codes) of errors that
// graphql-go dropped: an error returned from a deferred (batched) resolver is
// formatted without them. The code travels in the original error.
func restoreExtensions(errs []gqlerrors.FormattedError) {
	for i := range errs {
		if errs[i].Extensions != nil {
			continue
		}
		var err error = errs[i].OriginalError()
		for depth := 0; err != nil && depth < 8; depth++ {
			if ext, ok := err.(gqlerrors.ExtendedError); ok {
				errs[i].Extensions = ext.Extensions()
				break
			}
			switch e := err.(type) {
			case gqlerrors.FormattedError:
				err = e.OriginalError()
			case *gqlerrors.Error:
				err = e.OriginalError
			default:
				err = errors.Unwrap(err)
			}
		}
	}
}

// limitResult turns a request that ran over server.max_response_rows into a
// failure: the partial data is dropped (one response_too_large error stays)
// unless a mutation already committed. Then the partial result is kept, and
// every response_too_large error says the mutation was applied: rows a
// mutation's result reads after its commit (relationships under `returning`)
// can go over, and null propagation can leave data null, so the error is the
// only sign of the write — a client must not retry it.
func limitResult(result *graphql.Result, committed bool) {
	if committed {
		for i, e := range result.Errors {
			if e.Extensions["code"] != gqlschema.CodeResponseTooLarge {
				continue
			}
			ext := make(map[string]any, len(e.Extensions)+1)
			for k, v := range e.Extensions {
				ext[k] = v
			}
			ext["mutation_applied"] = true
			result.Errors[i].Extensions = ext
			result.Errors[i].Message += mutationAppliedNote
		}
		return
	}
	result.Data = nil
	var kept []gqlerrors.FormattedError
	limitSeen := false
	for _, e := range result.Errors {
		if e.Extensions["code"] == gqlschema.CodeResponseTooLarge {
			if limitSeen {
				continue
			}
			limitSeen = true
		}
		kept = append(kept, e)
	}
	result.Errors = kept
}

// mutationAppliedNote ends a response_too_large message when a mutation of
// the request has committed nonetheless.
const mutationAppliedNote = " (the mutation itself was applied; do not retry it)"

// tooLargeBody is the response sent instead of one over
// server.max_response_bytes.
func tooLargeBody(size, limit int, committed bool) []byte {
	msg := fmt.Sprintf("response too large: %d bytes exceeds server.max_response_bytes (%d); ask for fewer rows or fields", size, limit)
	ext := map[string]any{"code": gqlschema.CodeResponseTooLarge}
	if committed {
		msg += mutationAppliedNote
		ext["mutation_applied"] = true
	}
	body, _ := json.Marshal(map[string]any{
		"data": nil,
		"errors": []map[string]any{{
			"message":    msg,
			"extensions": ext,
		}},
	})
	return body
}

func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// corsMiddleware answers CORS preflights; the role header (jwt.role_header,
// fixed at startup like the rest of the routing) is an allowed request
// header so browser clients can select a role.
func corsMiddleware(cfg config.CORS, roleHeader string, next http.Handler) http.Handler {
	allowHeaders := "Authorization, Content-Type"
	if roleHeader != "" {
		allowHeaders += ", " + roleHeader
	}
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
			w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
