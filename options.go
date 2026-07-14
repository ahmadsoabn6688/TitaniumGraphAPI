package gqlgate

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gqlgate/auth"
	"gqlgate/config"
	"gqlgate/register"
	"gqlgate/schema"
)

// Public re-exports for hook files (via gqlgate/register) and tooling.
type (
	// MutationEvent describes one write passed to a lifecycle hook.
	MutationEvent = schema.MutationEvent
	// MutationHookFunc is a before/after lifecycle hook.
	MutationHookFunc = schema.MutationHookFunc
	// CustomField is a developer-provided root query/mutation field.
	CustomField = schema.CustomField
	// MutationOp identifies a write operation.
	MutationOp = schema.MutationOp
	// RoleResolver maps verified JWT claims to a role name.
	RoleResolver = auth.RoleResolver
)

const (
	OpInsert = schema.OpInsert
	OpUpdate = schema.OpUpdate
	OpDelete = schema.OpDelete
)

// options accumulates the functional options passed to Open.
type options struct {
	configPath string
}

// Option customizes a Gate at Open time.
type Option func(*options)

// WithConfigPath records the config file path so the Gate can hot-reload it
// (when server.hot_reload is on) and so Reload() knows what to re-read. Run
// sets this automatically.
func WithConfigPath(path string) Option {
	return func(o *options) { o.configPath = path }
}

// buildHooks resolves the YAML hook wiring against the compile-time registry
// (the hooks/ directory; files there register themselves via gqlgate/register)
// into the schema.Hooks the builder consumes. A hook name referenced in YAML
// with no registered implementation, and malformed custom-field registrations,
// are startup errors.
func buildHooks(cfg *config.Config) (*schema.Hooks, error) {
	registeredHooks, registeredFields, _ := register.Registered()

	before := map[string][]schema.MutationHookFunc{}
	after := map[string][]schema.MutationHookFunc{}
	for table, th := range cfg.Hooks.Tables {
		if th == nil {
			continue
		}
		specs := []struct {
			op     schema.MutationOp
			names  []string
			dst    map[string][]schema.MutationHookFunc
			timing string
		}{
			{schema.OpInsert, th.BeforeInsert, before, "before_insert"},
			{schema.OpInsert, th.AfterInsert, after, "after_insert"},
			{schema.OpUpdate, th.BeforeUpdate, before, "before_update"},
			{schema.OpUpdate, th.AfterUpdate, after, "after_update"},
			{schema.OpDelete, th.BeforeDelete, before, "before_delete"},
			{schema.OpDelete, th.AfterDelete, after, "after_delete"},
		}
		for _, s := range specs {
			for _, name := range s.names {
				fn, ok := registeredHooks[name]
				if !ok {
					return nil, fmt.Errorf("hooks.tables.%s.%s references hook %q, which no file in the hooks/ directory registers (register.MutationHook)", table, s.timing, name)
				}
				key := schema.HookKey(table, s.op)
				s.dst[key] = append(s.dst[key], fn)
			}
		}
	}

	for _, cf := range registeredFields {
		if err := validateCustomField(cfg, cf.Name, cf.Operation, cf.AllowedRoles); err != nil {
			return nil, err
		}
	}
	return schema.NewHooks(before, after, registeredFields), nil
}

func validateCustomField(cfg *config.Config, name, operation string, roles []string) error {
	if operation != "query" && operation != "mutation" {
		return fmt.Errorf("custom field %q: operation must be \"query\" or \"mutation\", got %q", name, operation)
	}
	for _, r := range roles {
		if _, ok := cfg.Roles[r]; !ok {
			return fmt.Errorf("custom field %q allows role %q, which is not defined under roles:", name, r)
		}
	}
	return nil
}

// signHelper returns a JWT signer bound to the config's HS* secret. It fills
// in iat/exp (24h default) and iss/aud when configured. Exposed to hook files
// through Gate.SignToken.
func signHelper(cfg config.JWT) func(map[string]any) (string, error) {
	return func(claims map[string]any) (string, error) {
		if !strings.HasPrefix(cfg.Algorithm, "HS") {
			return "", fmt.Errorf("sign requires an HS* jwt.algorithm (config uses %s, whose private key is not held here)", cfg.Algorithm)
		}
		m := jwt.MapClaims{}
		for k, v := range claims {
			m[k] = v
		}
		now := time.Now()
		if _, ok := m["iat"]; !ok {
			m["iat"] = now.Unix()
		}
		if _, ok := m["exp"]; !ok {
			m["exp"] = now.Add(24 * time.Hour).Unix()
		}
		if cfg.Issuer != "" {
			m["iss"] = cfg.Issuer
		}
		if cfg.Audience != "" {
			m["aud"] = cfg.Audience
		}
		return jwt.NewWithClaims(jwt.GetSigningMethod(cfg.Algorithm), m).SignedString([]byte(cfg.Secret))
	}
}
