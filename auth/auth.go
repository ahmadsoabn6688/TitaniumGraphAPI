// Package auth verifies incoming JWTs and resolves the caller's role.
// It only ever *verifies* tokens — issuing them (signup/login) is the host
// application's job.
package auth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
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
}

// New builds a Verifier. roleNames is the set of roles defined in the config;
// a caller resolving to any other role is rejected. resolver is non-nil when
// jwt.role_lookup is configured, in which case the role claim is ignored.
func New(cfg config.JWT, roleNames []string, resolver RoleResolver) (*Verifier, error) {
	v := &Verifier{cfg: cfg, roles: map[string]bool{}, resolver: resolver}
	for _, r := range roleNames {
		v.roles[r] = true
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

// Identify authenticates one request and returns the caller's identity.
func (v *Verifier) Identify(r *http.Request) (*rbac.Identity, int, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		if v.cfg.AnonymousRole == "" {
			return nil, http.StatusUnauthorized, fmt.Errorf("missing Authorization header")
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

	if v.resolver != nil {
		role, err := v.resolver(r.Context(), claims)
		if err != nil {
			return nil, http.StatusForbidden, err
		}
		if !v.roles[role] {
			return nil, http.StatusForbidden, fmt.Errorf("role %q (from the identity table) is not configured", role)
		}
		return &rbac.Identity{Role: role, Claims: claims}, 0, nil
	}

	roleValue, ok := rbac.LookupClaim(claims, v.cfg.RoleClaim)
	if !ok {
		return nil, http.StatusForbidden, fmt.Errorf("token has no %q claim", v.cfg.RoleClaim)
	}
	role, ok := roleValue.(string)
	if !ok {
		return nil, http.StatusForbidden, fmt.Errorf("token claim %q is not a string", v.cfg.RoleClaim)
	}
	if !v.roles[role] {
		return nil, http.StatusForbidden, fmt.Errorf("role %q is not configured", role)
	}
	return &rbac.Identity{Role: role, Claims: claims}, 0, nil
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
