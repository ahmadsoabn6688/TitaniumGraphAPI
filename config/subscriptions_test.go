package config

import (
	"strings"
	"testing"
	"time"
)

func TestSubscriptionDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Server.Subscriptions
	if !s.On() || s.PollIntervalMS != 1000 || s.MinPollIntervalMS != 250 || s.MaxPollIntervalMS != 60000 ||
		s.MaxConnections != 1000 || s.MaxPerConnection != 100 || s.ConnectionInitTimeoutSeconds != 10 ||
		s.KeepAliveSeconds != 30 || s.PingTimeoutSeconds != 10 || s.ReauthIntervalSeconds != 10 {
		t.Errorf("defaults: %+v", s)
	}
	if perm := cfg.Roles["admin"].Tables["*"].Select; perm.Subscribe {
		t.Error("select: true must not grant subscribe")
	}
}

func TestSubscriptionConfig(t *testing.T) {
	parse := func(server, tables, perm string) (*Config, error) {
		y := strings.Replace(minimalYAML, "select: true", perm, 1)
		if server != "" {
			y += "server:\n  subscriptions:\n" + server
		}
		if tables != "" {
			y += "tables:\n" + tables
		}
		return Parse([]byte(y))
	}
	cfg, err := parse("    enabled: false\n    poll_interval_ms: 500\n", `  posts:
    subscriptions:
      poll_interval_ms: 2000
      root_fields: {aggregate: 10000, unique: 300}
`, "select: {allow: true, subscribe: true}")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.Subscriptions.On() || cfg.Server.Subscriptions.PollInterval() != 500*time.Millisecond {
		t.Errorf("server.subscriptions: %+v", cfg.Server.Subscriptions)
	}
	if !cfg.Roles["admin"].Tables["*"].Select.Subscribe {
		t.Error("select.subscribe not decoded")
	}
	p := cfg.Tables["posts"].Subscriptions
	def := time.Second
	for kind, want := range map[string]time.Duration{
		RootAggregate: 10 * time.Second, SubscriptionUnique: 300 * time.Millisecond,
		RootConnection: 2 * time.Second, RootByPK: 2 * time.Second,
	} {
		if got := p.Interval(kind, def); got != want {
			t.Errorf("interval of %s = %s, want %s", kind, got, want)
		}
	}
	var none *SubscriptionPolling
	if none.Interval(RootByPK, def) != def {
		t.Error("no override must yield the default")
	}

	for _, tc := range []struct{ server, tables, perm, want string }{
		{"    poll_interval_ms: 100\n", "", "select: true", "server.subscriptions.poll_interval_ms (100) must be between"},
		{"    min_poll_interval_ms: 5000\n    max_poll_interval_ms: 1000\n", "", "select: true", "is below min_poll_interval_ms"},
		{"    max_connections: -2\n", "", "select: true", "max_connections"},
		{"    max_subscriptions_per_connection: -1\n", "", "select: true", "max_subscriptions_per_connection"},
		{"    keepalive_seconds: -5\n", "", "select: true", "keepalive_seconds"},
		{"", "  posts:\n    subscriptions: {poll_interval_ms: 70000}\n", "select: true", "tables.posts.subscriptions.poll_interval_ms (70000)"},
		{"", "  posts:\n    subscriptions: {root_fields: {nearest: 1000}}\n", "select: true", `unknown field kind "nearest"`},
		{"", "  posts:\n    subscriptions: {root_fields: {by_pk: 10}}\n", "select: true", "root_fields.by_pk (10)"},
		{"", "", "select: true\n        update: {allow: true, subscribe: true}", "subscribe applies to select only, not update"},
	} {
		if _, err := parse(tc.server, tc.tables, tc.perm); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q %q %q: got %v, want %q", tc.server, tc.tables, tc.perm, err, tc.want)
		}
	}
	// Unlimited connections and no keepalive pings are allowed.
	if _, err := parse("    max_connections: -1\n    keepalive_seconds: -1\n", "", "select: true"); err != nil {
		t.Errorf("unlimited/no pings: %v", err)
	}
}
