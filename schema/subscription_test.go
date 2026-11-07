package schema

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/graphql-go/graphql"

	"gqlgate/config"
)

func subscriptionFieldNames(s graphql.Schema) []string {
	if s.SubscriptionType() == nil {
		return nil
	}
	var out []string
	for name := range s.SubscriptionType().Fields() {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func buildSubscriptions(t *testing.T, tablesYAML, rolesYAML string, mutate ...func(*config.Config)) (*Built, error) {
	t.Helper()
	cfg := modelConfig(t, tablesYAML, rolesYAML)
	for _, m := range mutate {
		m(cfg)
	}
	return Build(Options{Catalog: modelCatalog(), Config: cfg})
}

func TestSubscriptionRootMirrorsGrantedReads(t *testing.T) {
	tables := `
users:
  subscriptions:
    poll_interval_ms: 2000
    root_fields: {aggregate: 5000, unique: 700}
`
	roles := `
r:
  tables:
    users: {select: {allow: true, subscribe: true}}
    posts: {select: true, insert: true}
    events: {select: {allow: true, subscribe: true}}
plain:
  tables:
    users: {select: true}
`
	built, err := buildSubscriptions(t, tables, roles, func(c *config.Config) {
		c.Server.Subscriptions.PollIntervalMS = 1500
	})
	if err != nil {
		t.Fatal(err)
	}
	s := built.Schemas["r"]
	got := strings.Join(subscriptionFieldNames(s), " ")
	want := "events_aggregate events_list users_aggregate users_by_email users_by_pk users_connection"
	if got != want {
		t.Errorf("subscription fields = %s, want %s", got, want)
	}
	// Queries are unchanged; posts (select without subscribe) is query-only.
	for _, f := range []string{"posts_connection", "users_connection", "events_list"} {
		if !hasQueryField(s, f) {
			t.Errorf("query field %s missing", f)
		}
	}
	// The subscription field is the query field: same type, same arguments.
	q := s.QueryType().Fields()["users_connection"]
	sub := s.SubscriptionType().Fields()["users_connection"]
	if q.Type.String() != sub.Type.String() || len(q.Args) != len(sub.Args) {
		t.Errorf("users_connection differs: %s(%d) vs %s(%d)", q.Type, len(q.Args), sub.Type, len(sub.Args))
	}
	if !strings.Contains(sub.Description, "Live query: re-run every 2s") || strings.Contains(q.Description, "Live query") {
		t.Errorf("descriptions: query %q, subscription %q", q.Description, sub.Description)
	}
	for field, every := range map[string]time.Duration{
		"users_aggregate":  5 * time.Second,
		"users_by_email":   700 * time.Millisecond,
		"users_by_pk":      2 * time.Second,
		"users_connection": 2 * time.Second,
		"events_list":      1500 * time.Millisecond, // no override: the server default
		"events_aggregate": 1500 * time.Millisecond,
	} {
		if got := built.PollIntervals["r"][field]; got != every {
			t.Errorf("interval of %s = %s, want %s", field, got, every)
		}
	}
	// A role without subscribe has no Subscription root at all.
	plain := built.Schemas["plain"]
	if plain.SubscriptionType() != nil || built.PollIntervals["plain"] != nil {
		t.Error("a role without subscribe must have no Subscription root")
	}
}

func TestSubscriptionRespectsColumnPermissions(t *testing.T) {
	built, err := buildSubscriptions(t, "", `
r:
  tables:
    users: {select: {allow: true, columns: [id, name], subscribe: true}}
`)
	if err != nil {
		t.Fatal(err)
	}
	s := built.Schemas["r"]
	// email is not readable: no unique lookup by it, and no email field on
	// the row type the subscription returns.
	if got := strings.Join(subscriptionFieldNames(s), " "); got != "users_aggregate users_by_pk users_connection" {
		t.Errorf("subscription fields = %s", got)
	}
	row := s.SubscriptionType().Fields()["users_by_pk"].Type.(*graphql.Object)
	if _, ok := row.Fields()["email"]; ok {
		t.Error("a hidden column must not be selectable through a subscription")
	}
	// Without a readable key there is no by_pk/connection, only the list.
	built, err = buildSubscriptions(t, "", `
r:
  tables:
    users: {select: {allow: true, columns: [name], subscribe: true}}
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(subscriptionFieldNames(built.Schemas["r"]), " "); got != "users_aggregate users_list" {
		t.Errorf("keyless subscription fields = %s", got)
	}
}

func TestSubscriptionsDisabledAndTypeClash(t *testing.T) {
	roles := `
r:
  tables:
    users: {select: {allow: true, subscribe: true}}
    posts: {select: true}
`
	off := false
	built, err := buildSubscriptions(t, "", roles, func(c *config.Config) { c.Server.Subscriptions.Enabled = &off })
	if err != nil {
		t.Fatal(err)
	}
	if r := built.Schemas["r"]; r.SubscriptionType() != nil {
		t.Error("server.subscriptions.enabled: false must drop the Subscription root")
	}

	// A table type named Subscription only matters to roles that subscribe.
	clash := "posts:\n  type_name: Subscription\n"
	if _, err := buildSubscriptions(t, clash, roles); err == nil || !strings.Contains(err.Error(), "type name Subscription") {
		t.Errorf("clash with a subscribing role: %v", err)
	}
	if _, err := buildSubscriptions(t, clash, "r:\n  tables:\n    posts: {select: true}\n"); err != nil {
		t.Errorf("no subscribing role, no clash: %v", err)
	}
}
