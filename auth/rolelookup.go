package auth

import (
	"context"
	"database/sql"
	"encoding/json"
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
		idValue, key, err := lookupID(claims, cfg.IDClaim)
		if err != nil {
			return "", err
		}
		if ttl > 0 {
			mu.Lock()
			e, hit := cache[key]
			mu.Unlock()
			if hit && time.Now().Before(e.expires) {
				return e.role, nil
			}
		}

		var role sql.NullString
		err = db.QueryRowContext(ctx, query, idValue).Scan(&role)
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

// lookupID reads the user id claim used for identity-table lookups and
// returns it as a bindable value plus its cache key.
func lookupID(claims map[string]any, idClaim string) (any, string, error) {
	idValue, ok := rbac.LookupClaim(claims, idClaim)
	if !ok {
		return nil, "", fmt.Errorf("token has no %q claim to look the role up with", idClaim)
	}
	switch v := idValue.(type) {
	case string:
		if v == "" {
			return nil, "", fmt.Errorf("token claim %q is empty", idClaim)
		}
	case float64:
		// JSON numbers arrive as float64; integral ids bind cleaner as ints.
		if v == float64(int64(v)) {
			idValue = int64(v)
		}
	default:
		return nil, "", fmt.Errorf("token claim %q must be a string or number", idClaim)
	}
	return idValue, fmt.Sprintf("%v", idValue), nil
}

// AllowedRolesFunc returns the roles a verified caller may select with the
// role header (its default role is always allowed besides these).
type AllowedRolesFunc func(ctx context.Context, claims map[string]any) ([]string, error)

// ClaimAllowedRoles reads the allowed roles from a claim: a JSON array of
// role names, or one string of comma-separated names. A missing claim
// allows no extra role.
func ClaimAllowedRoles(path string) AllowedRolesFunc {
	return func(_ context.Context, claims map[string]any) ([]string, error) {
		v, ok := rbac.LookupClaim(claims, path)
		if !ok || v == nil {
			return nil, nil
		}
		switch x := v.(type) {
		case string:
			return splitRoleList(x), nil
		case []any:
			out := make([]string, 0, len(x))
			for _, e := range x {
				s, ok := e.(string)
				if !ok {
					return nil, fmt.Errorf("token claim %q must list role names as strings", path)
				}
				out = append(out, s)
			}
			return out, nil
		}
		return nil, fmt.Errorf("token claim %q must be an array of role names or a comma-separated string", path)
	}
}

// splitRoleList splits "a, b,c" into its non-empty, trimmed names.
func splitRoleList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ParseRoleList decodes an allowed-roles column value: a JSON array of role
// names, or a comma-separated string. NULL/empty means no extra role.
func ParseRoleList(raw []byte) ([]string, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return nil, nil
	}
	if strings.HasPrefix(s, "[") {
		var out []string
		if err := json.Unmarshal([]byte(s), &out); err != nil {
			return nil, fmt.Errorf("allowed roles column is not a JSON array of role names")
		}
		return out, nil
	}
	return splitRoleList(s), nil
}

// maxAllowedRoles bounds the rows an allowed-roles table lookup reads.
const maxAllowedRoles = 1000

type rolesEntry struct {
	roles   []string
	expires time.Time
}

// NewDBAllowedRoles builds an AllowedRolesFunc over the identity database:
// either role_lookup.allowed_roles_column on the identity table, or one row
// per role in role_lookup.allowed_roles_table. The id claim value is bound
// as a SQL parameter; role_lookup.cache_seconds caches the result.
func NewDBAllowedRoles(db *sql.DB, cfg config.RoleLookup) AllowedRolesFunc {
	var query string
	column := cfg.AllowedRolesColumn != ""
	if column {
		query = fmt.Sprintf("SELECT %s FROM %s.%s WHERE %s = ? LIMIT 1",
			quoteIdent(cfg.AllowedRolesColumn),
			quoteIdent(cfg.Schema), quoteIdent(cfg.Table),
			quoteIdent(cfg.IDColumn))
	} else {
		at := cfg.AllowedRolesTable
		query = fmt.Sprintf("SELECT %s FROM %s.%s WHERE %s = ? LIMIT %d",
			quoteIdent(at.RoleColumn),
			quoteIdent(at.Schema), quoteIdent(at.Table),
			quoteIdent(at.IDColumn), maxAllowedRoles)
	}

	ttl := time.Duration(cfg.CacheSeconds) * time.Second
	var mu sync.Mutex
	cache := map[string]rolesEntry{}

	return func(ctx context.Context, claims map[string]any) ([]string, error) {
		idValue, key, err := lookupID(claims, cfg.IDClaim)
		if err != nil {
			return nil, err
		}
		if ttl > 0 {
			mu.Lock()
			e, hit := cache[key]
			mu.Unlock()
			if hit && time.Now().Before(e.expires) {
				return e.roles, nil
			}
		}

		var roles []string
		if column {
			var raw []byte
			err := db.QueryRowContext(ctx, query, idValue).Scan(&raw)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("no identity found for token %s %q", cfg.IDClaim, key)
			}
			if err != nil {
				return nil, fmt.Errorf("allowed roles lookup failed: %w", err)
			}
			if roles, err = ParseRoleList(raw); err != nil {
				return nil, err
			}
		} else {
			rows, err := db.QueryContext(ctx, query, idValue)
			if err != nil {
				return nil, fmt.Errorf("allowed roles lookup failed: %w", err)
			}
			defer rows.Close()
			for rows.Next() {
				var r sql.NullString
				if err := rows.Scan(&r); err != nil {
					return nil, fmt.Errorf("allowed roles lookup failed: %w", err)
				}
				if r.Valid && r.String != "" {
					roles = append(roles, r.String)
				}
			}
			if err := rows.Err(); err != nil {
				return nil, fmt.Errorf("allowed roles lookup failed: %w", err)
			}
		}

		if ttl > 0 {
			mu.Lock()
			cache[key] = rolesEntry{roles: roles, expires: time.Now().Add(ttl)}
			mu.Unlock()
		}
		return roles, nil
	}
}
