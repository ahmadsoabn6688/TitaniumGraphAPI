// Command gqlgate runs the GraphQL gateway defined by a YAML config.
//
//	gqlgate -config gqlgate.yaml
//
// For development (until your own signup/token service exists) it can also
// mint test tokens with the configured HS* secret.
//
// With role_claim mode the argument is the role (and claims carry the id):
//
//	gqlgate -config gqlgate.yaml -print-token author -claims '{"sub": 1}' -ttl 24h
//
// With jwt.role_lookup configured the argument is the USER ID — the role
// comes from the identity table at request time:
//
//	gqlgate -config gqlgate.yaml -print-token 1
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gqlgate"
	"gqlgate/config"

	// Compiled-in custom hooks: every .go file in the top-level hooks/
	// directory registers itself (via gqlgate/register) when this package
	// is linked in. Drop a file there and rebuild — that's the whole flow.
	_ "gqlgate/hooks"
)

func main() {
	configPath := flag.String("config", "gqlgate.yaml", "path to the YAML config")
	printToken := flag.String("print-token", "", "print a signed dev JWT and exit (HS* only); the value is the role, or the user id when jwt.role_lookup is configured")
	claimsJSON := flag.String("claims", "{}", "extra claims for -print-token, as a JSON object")
	ttl := flag.Duration("ttl", 24*time.Hour, "token lifetime for -print-token")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}

	if *printToken != "" {
		token, err := mintToken(cfg, *printToken, *claimsJSON, *ttl)
		if err != nil {
			fatal(err)
		}
		fmt.Println(token)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// gqlgate.Run retries startup while the database/schema come up (see
	// database.startup_wait_seconds / GQLGATE_WAIT_DB).
	if err := gqlgate.Run(ctx, *configPath); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gqlgate:", err)
	os.Exit(1)
}

// mintToken signs a development token equivalent to what the (user-provided)
// signup service would issue. subject is the role name in role_claim mode, or
// the user id when jwt.role_lookup is configured.
func mintToken(cfg *config.Config, subject, claimsJSON string, ttl time.Duration) (string, error) {
	if !strings.HasPrefix(cfg.JWT.Algorithm, "HS") {
		return "", fmt.Errorf("-print-token requires an HS* algorithm (the config uses %s, whose private key gqlgate does not have)", cfg.JWT.Algorithm)
	}

	claims := jwt.MapClaims{}
	if err := json.Unmarshal([]byte(claimsJSON), &claims); err != nil {
		return "", fmt.Errorf("-claims must be a JSON object: %w", err)
	}

	if cfg.JWT.RoleLookup.Enabled() {
		// The token carries only the user id; the role is read from the
		// identity table when the request arrives.
		var id any = subject
		if n, err := strconv.ParseInt(subject, 10, 64); err == nil {
			id = n
		}
		setClaimPath(claims, cfg.JWT.RoleLookup.IDClaim, id)
	} else {
		if _, ok := cfg.Roles[subject]; !ok {
			return "", fmt.Errorf("role %q is not defined in the config", subject)
		}
		setClaimPath(claims, cfg.JWT.RoleClaim, subject)
	}
	now := time.Now()
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(ttl).Unix()
	if cfg.JWT.Issuer != "" {
		claims["iss"] = cfg.JWT.Issuer
	}
	if cfg.JWT.Audience != "" {
		claims["aud"] = cfg.JWT.Audience
	}

	method := jwt.GetSigningMethod(cfg.JWT.Algorithm)
	return jwt.NewWithClaims(method, claims).SignedString([]byte(cfg.JWT.Secret))
}

// setClaimPath writes a value at a dot path, creating nested maps as needed
// (mirrors how rbac.LookupClaim resolves the role claim).
func setClaimPath(claims jwt.MapClaims, path string, value any) {
	parts := strings.Split(path, ".")
	m := map[string]any(claims)
	for i, p := range parts {
		if i == len(parts)-1 {
			m[p] = value
			return
		}
		next, ok := m[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[p] = next
		}
		m = next
	}
}
