package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"gqlgate/config"
	"gqlgate/rbac"
)

// RoleResolver turns verified JWT claims into a role name.
type RoleResolver func(ctx context.Context, claims map[string]any) (string, error)

func quoteIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

type cacheEntry struct {
	role    string
	expires time.Time
}

// NewDBRoleResolver builds a RoleResolver that reads the role from the
// configured identity table: the token's id claim is matched against the id
// column and the role column's value becomes the caller's role. The id value
// is always bound as a SQL parameter.
func NewDBRoleResolver(db *sql.DB, cfg config.RoleLookup) RoleResolver {
	query := fmt.Sprintf("SELECT %s FROM %s.%s WHERE %s = ? LIMIT 1",
		quoteIdent(cfg.RoleColumn),
		quoteIdent(cfg.Schema), quoteIdent(cfg.Table),
		quoteIdent(cfg.IDColumn))

	ttl := time.Duration(cfg.CacheSeconds) * time.Second
	var mu sync.Mutex
	cache := map[string]cacheEntry{}

	return func(ctx context.Context, claims map[string]any) (string, error) {
		idValue, ok := rbac.LookupClaim(claims, cfg.IDClaim)
		if !ok {
			return "", fmt.Errorf("token has no %q claim to look the role up with", cfg.IDClaim)
		}
		switch v := idValue.(type) {
		case string:
			if v == "" {
				return "", fmt.Errorf("token claim %q is empty", cfg.IDClaim)
			}
		case float64:
			// JSON numbers arrive as float64; integral ids bind cleaner as ints.
			if v == float64(int64(v)) {
				idValue = int64(v)
			}
		default:
			return "", fmt.Errorf("token claim %q must be a string or number", cfg.IDClaim)
		}

		key := fmt.Sprintf("%v", idValue)
		if ttl > 0 {
			mu.Lock()
			e, hit := cache[key]
			mu.Unlock()
			if hit && time.Now().Before(e.expires) {
				return e.role, nil
			}
		}

		var role sql.NullString
		err := db.QueryRowContext(ctx, query, idValue).Scan(&role)
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("no identity found for token %s %q", cfg.IDClaim, key)
		}
		if err != nil {
			return "", fmt.Errorf("role lookup failed: %w", err)
		}
		if !role.Valid || role.String == "" {
			return "", fmt.Errorf("identity %q has no role assigned", key)
		}

		if ttl > 0 {
			mu.Lock()
			cache[key] = cacheEntry{role: role.String, expires: time.Now().Add(ttl)}
			mu.Unlock()
		}
		return role.String, nil
	}
}
