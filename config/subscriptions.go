package config

import (
	"fmt"
	"sort"
	"time"
)

// Subscriptions configures live queries over WebSocket (the
// graphql-transport-ws protocol on server.path). A subscription re-runs its
// query on an interval and pushes the result only when it changed; which
// tables a role may subscribe to is set per role with select.subscribe.
//
//	server:
//	  subscriptions:
//	    enabled: true                 # default true (nothing is subscribable until a role grants subscribe)
//	    poll_interval_ms: 1000        # default interval
//	    min_poll_interval_ms: 250     # bounds for every interval in the config
//	    max_poll_interval_ms: 60000
//	    max_connections: 1000         # open sockets per gateway (-1 = unlimited)
//	    max_subscriptions_per_connection: 100
//	    connection_init_timeout_seconds: 10
//	    keepalive_seconds: 30         # WebSocket ping interval (-1 = off)
//	    ping_timeout_seconds: 10      # a ping unanswered this long closes the socket
//	    reauth_interval_seconds: 10   # re-verify the token / role lookup this often
type Subscriptions struct {
	// Enabled turns the WebSocket endpoint and the Subscription root on.
	// nil (unset) = on.
	Enabled *bool `yaml:"enabled"`
	// PollIntervalMS is the default polling interval of a subscription.
	// Default 1000.
	PollIntervalMS int `yaml:"poll_interval_ms"`
	// MinPollIntervalMS and MaxPollIntervalMS bound every interval set in
	// the config (the default and the per-table overrides). Defaults 250
	// and 60000.
	MinPollIntervalMS int `yaml:"min_poll_interval_ms"`
	MaxPollIntervalMS int `yaml:"max_poll_interval_ms"`
	// MaxConnections caps the open WebSocket connections of the gateway.
	// Default 1000; -1 = unlimited.
	MaxConnections int `yaml:"max_connections"`
	// MaxPerConnection caps the operations running at once on one socket.
	// Default 100.
	MaxPerConnection int `yaml:"max_subscriptions_per_connection"`
	// ConnectionInitTimeoutSeconds is how long a client has to send
	// connection_init after the upgrade. Default 10.
	ConnectionInitTimeoutSeconds int `yaml:"connection_init_timeout_seconds"`
	// KeepAliveSeconds is the interval of WebSocket ping frames. Default 30;
	// -1 = no pings.
	KeepAliveSeconds int `yaml:"keepalive_seconds"`
	// PingTimeoutSeconds closes a socket whose ping is not answered in
	// time. Default 10.
	PingTimeoutSeconds int `yaml:"ping_timeout_seconds"`
	// ReauthIntervalSeconds is how often an open socket re-verifies its
	// token and re-resolves its role (jwt.role_lookup, allowed roles); a
	// failure closes the socket. Default 10.
	ReauthIntervalSeconds int `yaml:"reauth_interval_seconds"`
}

// On reports whether subscriptions are enabled.
func (s Subscriptions) On() bool { return s.Enabled == nil || *s.Enabled }

// DefaultPollInterval is server.subscriptions.poll_interval_ms's default.
const DefaultPollInterval = time.Second

// PollInterval is the default polling interval (DefaultPollInterval when
// unset, as in a Config built in code without Parse).
func (s Subscriptions) PollInterval() time.Duration {
	if s.PollIntervalMS <= 0 {
		return DefaultPollInterval
	}
	return time.Duration(s.PollIntervalMS) * time.Millisecond
}

// SubscriptionPolling overrides the polling interval of one table's (or
// native query's) subscription fields:
//
//	tables:
//	  posts:
//	    subscriptions:
//	      poll_interval_ms: 2000      # every subscription field of posts
//	      root_fields:                # per field kind; wins over the above
//	        aggregate: 10000
//	        by_pk: 500
//
// Table kinds: by_pk, connection, aggregate, list and unique (every
// <t>_by_<unique key> field). Native query kinds: list and connection.
type SubscriptionPolling struct {
	PollIntervalMS int            `yaml:"poll_interval_ms"`
	RootFields     map[string]int `yaml:"root_fields"`
}

// Subscription field kinds a SubscriptionPolling may set besides the
// RootField kinds.
const SubscriptionUnique = "unique"

// tableSubscriptionKinds / nativeSubscriptionKinds are the kinds accepted
// under subscriptions.root_fields.
var (
	tableSubscriptionKinds  = []string{RootByPK, RootConnection, RootAggregate, RootList, SubscriptionUnique}
	nativeSubscriptionKinds = []string{"list", "connection"}
)

// Interval resolves the interval of one field kind: the kind's own entry,
// else the poll_interval_ms of the entry, else def. A nil receiver = def.
func (p *SubscriptionPolling) Interval(kind string, def time.Duration) time.Duration {
	if p == nil {
		return def
	}
	if ms := p.RootFields[kind]; ms > 0 {
		return time.Duration(ms) * time.Millisecond
	}
	if p.PollIntervalMS > 0 {
		return time.Duration(p.PollIntervalMS) * time.Millisecond
	}
	return def
}

func (s *Subscriptions) applyDefaults() {
	if s.PollIntervalMS == 0 {
		s.PollIntervalMS = int(DefaultPollInterval / time.Millisecond)
	}
	if s.MinPollIntervalMS == 0 {
		s.MinPollIntervalMS = 250
	}
	if s.MaxPollIntervalMS == 0 {
		s.MaxPollIntervalMS = 60000
	}
	if s.MaxConnections == 0 {
		s.MaxConnections = 1000
	}
	if s.MaxPerConnection == 0 {
		s.MaxPerConnection = 100
	}
	if s.ConnectionInitTimeoutSeconds == 0 {
		s.ConnectionInitTimeoutSeconds = 10
	}
	if s.KeepAliveSeconds == 0 {
		s.KeepAliveSeconds = 30
	}
	if s.PingTimeoutSeconds == 0 {
		s.PingTimeoutSeconds = 10
	}
	if s.ReauthIntervalSeconds == 0 {
		s.ReauthIntervalSeconds = 10
	}
}

// validateSubscriptions checks server.subscriptions, the per-table and
// per-native-query polling overrides, and that subscribe is only granted on
// select.
func (c *Config) validateSubscriptions() error {
	s := c.Server.Subscriptions
	const w = "server.subscriptions"
	if s.MinPollIntervalMS < 1 {
		return fmt.Errorf("%s.min_poll_interval_ms must be >= 1", w)
	}
	if s.MaxPollIntervalMS < s.MinPollIntervalMS {
		return fmt.Errorf("%s.max_poll_interval_ms (%d) is below min_poll_interval_ms (%d)", w, s.MaxPollIntervalMS, s.MinPollIntervalMS)
	}
	if err := s.checkInterval(w+".poll_interval_ms", s.PollIntervalMS); err != nil {
		return err
	}
	if s.MaxConnections < -1 {
		return fmt.Errorf("%s.max_connections must be > 0 (or -1 = unlimited)", w)
	}
	for key, v := range map[string]int{
		"max_subscriptions_per_connection": s.MaxPerConnection,
		"connection_init_timeout_seconds":  s.ConnectionInitTimeoutSeconds,
		"ping_timeout_seconds":             s.PingTimeoutSeconds,
		"reauth_interval_seconds":          s.ReauthIntervalSeconds,
	} {
		if v < 1 {
			return fmt.Errorf("%s.%s must be >= 1", w, key)
		}
	}
	if s.KeepAliveSeconds < -1 {
		return fmt.Errorf("%s.keepalive_seconds must be > 0 (or -1 = no pings)", w)
	}

	tables := make([]string, 0, len(c.Tables))
	for tn := range c.Tables {
		tables = append(tables, tn)
	}
	sort.Strings(tables)
	for _, tn := range tables {
		if tc := c.Tables[tn]; tc != nil {
			if err := s.checkPolling("tables."+tn+".subscriptions", tc.Subscriptions, tableSubscriptionKinds); err != nil {
				return err
			}
		}
	}
	natives := make([]string, 0, len(c.NativeQueries))
	for qn := range c.NativeQueries {
		natives = append(natives, qn)
	}
	sort.Strings(natives)
	for _, qn := range natives {
		if nq := c.NativeQueries[qn]; nq != nil {
			if err := s.checkPolling("native_queries."+qn+".subscriptions", nq.Subscriptions, nativeSubscriptionKinds); err != nil {
				return err
			}
		}
	}

	for roleName, role := range c.Roles {
		if role == nil {
			continue
		}
		for tableName, tp := range role.Tables {
			if tp == nil {
				continue
			}
			for opName, perm := range map[string]*OpPerm{"insert": tp.Insert, "update": tp.Update, "delete": tp.Delete} {
				if perm != nil && perm.Subscribe {
					return fmt.Errorf("role %q, table %q: subscribe applies to select only, not %s", roleName, tableName, opName)
				}
			}
		}
	}
	return nil
}

func (s Subscriptions) checkInterval(where string, ms int) error {
	if ms < s.MinPollIntervalMS || ms > s.MaxPollIntervalMS {
		return fmt.Errorf("%s (%d) must be between server.subscriptions.min_poll_interval_ms (%d) and max_poll_interval_ms (%d)",
			where, ms, s.MinPollIntervalMS, s.MaxPollIntervalMS)
	}
	return nil
}

func (s Subscriptions) checkPolling(where string, p *SubscriptionPolling, kinds []string) error {
	if p == nil {
		return nil
	}
	if p.PollIntervalMS != 0 {
		if err := s.checkInterval(where+".poll_interval_ms", p.PollIntervalMS); err != nil {
			return err
		}
	}
	keys := make([]string, 0, len(p.RootFields))
	for k := range p.RootFields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !containsString(kinds, k) {
			return fmt.Errorf("%s.root_fields: unknown field kind %q (one of %v)", where, k, kinds)
		}
		if err := s.checkInterval(where+".root_fields."+k, p.RootFields[k]); err != nil {
			return err
		}
	}
	return nil
}
