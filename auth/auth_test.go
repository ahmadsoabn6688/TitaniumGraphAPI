package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gqlgate/config"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func testVerifier(t *testing.T, mutate func(*config.JWT), resolver RoleResolver) *Verifier {
	t.Helper()
	cfg := config.JWT{Algorithm: "HS256", Secret: testSecret, RoleClaim: "role", AnonymousRole: "anonymous",
		RoleHeader: config.DefaultRoleHeader}
	if mutate != nil {
		mutate(&cfg)
	}
	v, err := New(cfg, []string{"anonymous", "author", "editor", "admin"}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func token(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func request(tok, role string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	if role != "" {
		r.Header.Set("X-Gqlgate-Role", role)
	}
	return r
}

func TestIdentifyRoleHeaderWithClaim(t *testing.T) {
	v := testVerifier(t, func(c *config.JWT) { c.AllowedRolesClaim = "https://app/claims.roles" }, nil)
	tok := token(t, jwt.MapClaims{"role": "author", "sub": 1,
		"https://app/claims": map[string]any{"roles": []any{"editor", "ghost"}}})

	cases := []struct {
		name, tok, header string
		wantRole          string
		wantStatus        int
	}{
		{"no header: default role", tok, "", "author", 0},
		{"header names the default role", tok, "author", "author", 0},
		{"header picks an allowed role", tok, "editor", "editor", 0},
		{"role not in the allowed list", tok, "admin", "", http.StatusForbidden},
		{"allowed but not configured", tok, "ghost", "", http.StatusForbidden},
		{"anonymous cannot pick a role", "", "editor", "", http.StatusForbidden},
		{"anonymous may name its own role", "", "anonymous", "anonymous", 0},
		{"anonymous without header", "", "", "anonymous", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, status, err := v.Identify(request(tc.tok, tc.header))
			if tc.wantStatus != 0 {
				if err == nil || status != tc.wantStatus {
					t.Fatalf("want status %d, got %d (err %v, id %+v)", tc.wantStatus, status, err, id)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id.Role != tc.wantRole {
				t.Errorf("role = %q, want %q", id.Role, tc.wantRole)
			}
		})
	}
}

func TestIdentifyRoleHeaderWithoutAllowedRoles(t *testing.T) {
	v := testVerifier(t, nil, nil)
	tok := token(t, jwt.MapClaims{"role": "author", "roles": []any{"admin"}})
	if id, _, err := v.Identify(request(tok, "")); err != nil || id.Role != "author" {
		t.Fatalf("default role: %v %+v", err, id)
	}
	if id, _, err := v.Identify(request(tok, "author")); err != nil || id.Role != "author" {
		t.Fatalf("own role in the header: %v %+v", err, id)
	}
	// Without an allowed-roles source a claim named like one is ignored and
	// no other role can be requested.
	if _, status, err := v.Identify(request(tok, "admin")); err == nil || status != http.StatusForbidden {
		t.Fatalf("want 403 for another role, got %d %v", status, err)
	}
}

func TestIdentifyRoleHeaderCustomName(t *testing.T) {
	v := testVerifier(t, func(c *config.JWT) {
		c.AllowedRolesClaim = "roles"
		c.RoleHeader = "X-Role"
	}, nil)
	tok := token(t, jwt.MapClaims{"role": "author", "roles": "editor, admin"})
	r := request(tok, "")
	r.Header.Set("X-Role", "admin")
	if id, _, err := v.Identify(r); err != nil || id.Role != "admin" {
		t.Fatalf("comma-separated claim: %v %+v", err, id)
	}
	// The default header name means nothing once another is configured.
	if id, _, err := v.Identify(request(tok, "admin")); err != nil || id.Role != "author" {
		t.Fatalf("X-Gqlgate-Role must be ignored: %v %+v", err, id)
	}
}

func TestIdentifyRoleHeaderBadClaims(t *testing.T) {
	v := testVerifier(t, func(c *config.JWT) { c.AllowedRolesClaim = "roles" }, nil)
	for _, claims := range []jwt.MapClaims{
		{"role": "author", "roles": []any{"editor", 5}},
		{"role": "author", "roles": 7},
		{"role": "author"}, // no list: nothing extra is allowed
	} {
		if _, status, err := v.Identify(request(token(t, claims), "editor")); err == nil || status != http.StatusForbidden {
			t.Errorf("%v: want 403, got %d %v", claims, status, err)
		}
	}
	// The default role must still be valid when another role is requested.
	tok := token(t, jwt.MapClaims{"role": "nobody", "roles": []any{"editor"}})
	if _, status, err := v.Identify(request(tok, "editor")); err == nil || status != http.StatusForbidden {
		t.Errorf("invalid default role: want 403, got %d %v", status, err)
	}
}

func TestIdentifyRoleHeaderWithResolver(t *testing.T) {
	resolver := func(_ context.Context, claims map[string]any) (string, error) {
		if claims["sub"] == "gone" {
			return "", errors.New("no identity")
		}
		return "author", nil
	}
	v := testVerifier(t, nil, resolver)
	v.SetAllowedRoles(func(_ context.Context, claims map[string]any) ([]string, error) {
		return []string{"editor"}, nil
	})
	tok := token(t, jwt.MapClaims{"sub": "u1"})
	if id, _, err := v.Identify(request(tok, "editor")); err != nil || id.Role != "editor" {
		t.Fatalf("resolver + allowed list: %v %+v", err, id)
	}
	if _, status, _ := v.Identify(request(tok, "admin")); status != http.StatusForbidden {
		t.Errorf("admin is not allowed: got %d", status)
	}
	// A caller whose identity is gone is rejected even with a role header.
	if _, status, _ := v.Identify(request(token(t, jwt.MapClaims{"sub": "gone"}), "editor")); status != http.StatusForbidden {
		t.Errorf("deleted identity: got %d", status)
	}
}

func TestParseRoleList(t *testing.T) {
	for in, want := range map[string]string{
		``:                   ``,
		`editor`:             `editor`,
		` editor , admin ,`:  `editor|admin`,
		`["editor","admin"]`: `editor|admin`,
	} {
		got, err := ParseRoleList([]byte(in))
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if strings.Join(got, "|") != want {
			t.Errorf("%q = %v, want %s", in, got, want)
		}
	}
	if _, err := ParseRoleList([]byte(`["editor", 1]`)); err == nil {
		t.Error("a JSON array with a non-string must fail")
	}
}

// IdentifyHeaders authenticates a WebSocket connection from its
// connection_init headers exactly like a request, reading only the
// Authorization and role headers.
func TestIdentifyHeadersAndDeadline(t *testing.T) {
	v := testVerifier(t, func(c *config.JWT) {
		c.AllowedRolesClaim = "roles"
		c.LeewaySeconds = 30
	}, nil)
	exp := time.Now().Add(time.Hour).Unix()
	tok := token(t, jwt.MapClaims{"role": "author", "roles": []any{"editor"}, "exp": exp})
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	h.Set(config.DefaultRoleHeader, "editor")
	id, _, err := v.IdentifyHeaders(context.Background(), h)
	if err != nil || id.Role != "editor" {
		t.Fatalf("identify: %v %+v", err, id)
	}
	deadline, ok := v.Deadline(id)
	if !ok || deadline.Unix() != exp+30 {
		t.Errorf("deadline = %v %v, want exp + leeway", deadline, ok)
	}
	h.Set(config.DefaultRoleHeader, "admin")
	if _, status, err := v.IdentifyHeaders(context.Background(), h); err == nil || status != http.StatusForbidden {
		t.Errorf("a role outside the allowed list: %d %v", status, err)
	}
	// No token: the anonymous role, which has no deadline.
	id, _, err = v.IdentifyHeaders(context.Background(), http.Header{})
	if err != nil || id.Role != "anonymous" {
		t.Fatalf("anonymous: %v %+v", err, id)
	}
	if _, ok := v.Deadline(id); ok {
		t.Error("an anonymous identity has no deadline")
	}
	// An expired token is reported as such.
	h = http.Header{}
	h.Set("Authorization", "Bearer "+token(t, jwt.MapClaims{"role": "author", "exp": time.Now().Add(-time.Hour).Unix()}))
	if _, _, err := v.IdentifyHeaders(context.Background(), h); !IsExpired(err) {
		t.Errorf("expired token: %v", err)
	}
	if IsExpired(errors.New("other")) {
		t.Error("IsExpired on an unrelated error")
	}
}
