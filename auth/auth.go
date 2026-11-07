// Package auth verifies incoming JWTs and resolves the caller's role.
// It only ever *verifies* tokens — issuing them (signup/login) is the host
// application's job.
package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gqlgate/config"
	"gqlgate/rbac"
)

// Verifier validates bearer tokens according to the jwt: section of the config.
type Verifier struct {
	cfg      config.JWT
	key      any // []byte (HS*), *rsa.PublicKey (RS*) or *ecdsa.PublicKey (ES*)
	parser   *jwt.Parser
	roles    map[string]bool
	resolver RoleResolver // nil = role comes from the RoleClaim
	// allowed lists the roles a caller may select with the role header
	// (nil = only its own default role).
	allowed AllowedRolesFunc
}

// New builds a Verifier. roleNames is the set of roles defined in the config;
// a caller resolving to any other role is rejected. resolver is non-nil when
// jwt.role_lookup is configured, in which case the role claim is ignored.
func New(cfg config.JWT, roleNames []string, resolver RoleResolver) (*Verifier, error) {
	v := &Verifier{cfg: cfg, roles: map[string]bool{}, resolver: resolver}
	for _, r := range roleNames {
		v.roles[r] = true
	}
	if cfg.RoleHeader == "" {
		v.cfg.RoleHeader = config.DefaultRoleHeader
	}
	if cfg.AllowedRolesClaim != "" {
		v.allowed = ClaimAllowedRoles(cfg.AllowedRolesClaim)
	}

	if strings.HasPrefix(cfg.Algorithm, "HS") {
		v.key = []byte(cfg.Secret)
	} else {
		key, err := loadPublicKey(cfg.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("jwt.public_key_file: %w", err)
		}
		switch key.(type) {
		case *rsa.PublicKey:
			if !strings.HasPrefix(cfg.Algorithm, "RS") {
				return nil, fmt.Errorf("jwt.public_key_file holds an RSA key but jwt.algorithm is %s", cfg.Algorithm)
			}
		case *ecdsa.PublicKey:
			if !strings.HasPrefix(cfg.Algorithm, "ES") {
				return nil, fmt.Errorf("jwt.public_key_file holds an EC key but jwt.algorithm is %s", cfg.Algorithm)
			}
		default:
			return nil, fmt.Errorf("jwt.public_key_file holds an unsupported key type %T", key)
		}
		v.key = key
	}

	opts := []jwt.ParserOption{
		// Pin the accepted algorithm to exactly the configured one. This is
		// what prevents alg-confusion attacks (e.g. an HS256 token signed
		// with the RSA public key as the HMAC secret).
		jwt.WithValidMethods([]string{cfg.Algorithm}),
		// Tokens without an expiry never age out; refuse them.
		jwt.WithExpirationRequired(),
	}
	if cfg.LeewaySeconds > 0 {
		opts = append(opts, jwt.WithLeeway(time.Duration(cfg.LeewaySeconds)*time.Second))
	}
	if cfg.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(cfg.Issuer))
	}
	if cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(cfg.Audience))
	}
	v.parser = jwt.NewParser(opts...)
	return v, nil
}

func loadPublicKey(path string) (any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default: // "PUBLIC KEY" and friends
		return x509.ParsePKIXPublicKey(block.Bytes)
	}
}

// SetAllowedRoles installs the source of the roles a caller may select with
// the role header (e.g. a database lookup). Call it before serving.
func (v *Verifier) SetAllowedRoles(fn AllowedRolesFunc) { v.allowed = fn }

// Identify authenticates one request and returns the caller's identity.
//
// The role is the caller's default role (the anonymous role, the role
// resolver's or the role claim's) unless the request names another one in
// the role header. A requested role must be configured and in the caller's
// allowed roles (the default role is always allowed); anything else is
// rejected with 403 rather than silently served as the default role.
// Anonymous requests can only ever be the anonymous role.
func (v *Verifier) Identify(r *http.Request) (*rbac.Identity, int, error) {
	requested := strings.TrimSpace(r.Header.Get(v.cfg.RoleHeader))
	header := r.Header.Get("Authorization")
	if header == "" {
		if v.cfg.AnonymousRole == "" {
			return nil, http.StatusUnauthorized, fmt.Errorf("missing Authorization header")
		}
		if requested != "" && requested != v.cfg.AnonymousRole {
			return nil, http.StatusForbidden, fmt.Errorf("role %q is not allowed for unauthenticated requests", requested)
		}
		return &rbac.Identity{Role: v.cfg.AnonymousRole, Claims: map[string]any{}}, 0, nil
	}

	const prefix = "bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return nil, http.StatusUnauthorized, fmt.Errorf("Authorization header is not a Bearer token")
	}
	tokenString := strings.TrimSpace(header[len(prefix):])

	claims := jwt.MapClaims{}
	if _, err := v.parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		return v.key, nil
	}); err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("invalid token: %w", err)
	}

	role, err := v.defaultRole(r, claims)
	if err != nil {
		return nil, http.StatusForbidden, err
	}
	if requested != "" && requested != role {
		if err := v.checkRequested(r, claims, requested); err != nil {
			return nil, http.StatusForbidden, err
		}
		role = requested
	}
	return &rbac.Identity{Role: role, Claims: claims}, 0, nil
}

// IdentifyHeaders authenticates a caller from a header set instead of an
// HTTP request — a WebSocket connection's connection_init payload. Only the
// Authorization header and the role header are read; ctx bounds the role
// and allowed-roles lookups.
func (v *Verifier) IdentifyHeaders(ctx context.Context, h http.Header) (*rbac.Identity, int, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	for _, k := range []string{"Authorization", v.cfg.RoleHeader} {
		if val := h.Get(k); val != "" {
			r.Header.Set(k, val)
		}
	}
	return v.Identify(r)
}

// RoleHeader is the request header that selects one of the caller's
// allowed roles.
func (v *Verifier) RoleHeader() string { return v.cfg.RoleHeader }

// Deadline is when an identity's token stops being accepted: its exp claim
// plus the configured leeway. ok is false for an identity without a token
// expiry (the anonymous role).
func (v *Verifier) Deadline(id *rbac.Identity) (deadline time.Time, ok bool) {
	if id == nil || id.Claims == nil {
		return time.Time{}, false
	}
	exp, err := jwt.MapClaims(id.Claims).GetExpirationTime()
	if err != nil || exp == nil {
		return time.Time{}, false
	}
	return exp.Add(time.Duration(v.cfg.LeewaySeconds) * time.Second), true
}

// IsExpired reports whether an Identify error is an expired token.
func IsExpired(err error) bool { return errors.Is(err, jwt.ErrTokenExpired) }

// defaultRole resolves the role a verified caller gets without the role
// header: from the role resolver when one is set, else from the role claim.
func (v *Verifier) defaultRole(r *http.Request, claims jwt.MapClaims) (string, error) {
	if v.resolver != nil {
		role, err := v.resolver(r.Context(), claims)
		if err != nil {
			return "", err
		}
		if !v.roles[role] {
			return "", fmt.Errorf("role %q (from the identity table) is not configured", role)
		}
		return role, nil
	}

	roleValue, ok := rbac.LookupClaim(claims, v.cfg.RoleClaim)
	if !ok {
		return "", fmt.Errorf("token has no %q claim", v.cfg.RoleClaim)
	}
	role, ok := roleValue.(string)
	if !ok {
		return "", fmt.Errorf("token claim %q is not a string", v.cfg.RoleClaim)
	}
	if !v.roles[role] {
		return "", fmt.Errorf("role %q is not configured", role)
	}
	return role, nil
}

// checkRequested verifies that a caller may act as the role it requested
// with the role header.
func (v *Verifier) checkRequested(r *http.Request, claims jwt.MapClaims, requested string) error {
	if v.allowed == nil {
		return fmt.Errorf("role %q is not allowed: no allowed roles are configured, so %s may only name the caller's own role", requested, v.cfg.RoleHeader)
	}
	allowed, err := v.allowed(r.Context(), claims)
	if err != nil {
		return err
	}
	if !slices.Contains(allowed, requested) {
		return fmt.Errorf("role %q is not among the caller's allowed roles", requested)
	}
	if !v.roles[requested] {
		return fmt.Errorf("role %q is not configured", requested)
	}
	return nil
}

// Middleware authenticates the request and stores the identity in the context.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, status, err := v.Identify(r)
		if err != nil {
			WriteError(w, status, err.Error())
			return
		}
		next.ServeHTTP(w, r.WithContext(rbac.WithIdentity(r.Context(), id)))
	})
}

// WriteError writes a GraphQL-shaped error body so clients can handle auth
// failures with the same code path as query errors.
func WriteError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]any{{"message": message}},
	})
}
