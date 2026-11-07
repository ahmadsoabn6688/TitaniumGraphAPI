package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gqlgate/config"
)

// The role header must pass a CORS preflight, or browser clients could not
// select a role.
func TestCORSAllowsRoleHeader(t *testing.T) {
	h := corsMiddleware(config.CORS{Enabled: true, AllowedOrigins: []string{"*"}}, "X-Role",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	r := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	r.Header.Set("Origin", "https://app.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	got := w.Header().Get("Access-Control-Allow-Headers")
	for _, want := range []string{"Authorization", "Content-Type", "X-Role"} {
		if !strings.Contains(got, want) {
			t.Errorf("Access-Control-Allow-Headers = %q, missing %s", got, want)
		}
	}
}
