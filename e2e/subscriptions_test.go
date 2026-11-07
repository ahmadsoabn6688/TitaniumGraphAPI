package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// End-to-end tests for subscriptions (live queries over graphql-transport-ws):
// per-role Subscription roots gated by select.subscribe, change-only pushes,
// RBAC on every poll, relationship batching inside live selections, token
// expiry and role re-checks closing the socket, limits, hot reload and
// shutdown.

const wait = 10 * time.Second

// subsTemplate is the default config with fast polling and re-checks, plus
// extra lines under server.subscriptions.
func subsTemplate(extra string) string {
	return strings.Replace(DefaultConfigTemplate, "  graphiql: false\n",
		"  graphiql: false\n  subscriptions:\n    poll_interval_ms: 100\n    min_poll_interval_ms: 50\n    reauth_interval_seconds: 1\n"+extra, 1)
}

const subsRolesYAML = `roles:
  admin:
    tables:
      "*":
        select: {allow: true, subscribe: true}
        insert: true
        update: true
        delete: true
  author:
    tables:
      users:
        select: {allow: true, columns: [id, name]}
      posts:
        select:
          allow: true
          columns: [id, author_id, title, published]
          filter: "author_id = :jwt.sub"
          subscribe: true
        update:
          allow: true
          columns: [title]
          filter: "author_id = :jwt.sub"
      comments:
        select: true
  anonymous:
    tables:
      posts:
        select:
          allow: true
          columns: [id, title]
          filter: "published = 1"
          filterable_columns: [id, title]
          subscribe: true
      users:
        select: {allow: true, columns: [id, name]}
`

func TestSubscriptionLiveQueriesPerRole(t *testing.T) {
	t.Parallel()
	env := New(t, WithConfigTemplate(subsTemplate("")), WithRolesYAML(subsRolesYAML))
	admin := env.Token(t, "admin", 4)
	grace := env.Token(t, "author", 2)

	// Author 2 sees only her own posts, with the author relationship
	// (batched per poll) — users is readable but not subscribable.
	author := env.DialWS(t, AuthPayload(grace))
	author.Subscribe(t, "feed", `subscription { posts_connection { nodes { id title author { name } } } }`, nil)
	r := author.Next(t, "feed", wait).Result(t).MustOK(t)
	if ids := r.IDs(t, "posts_connection.nodes"); fmt.Sprint(ids) != "[3]" {
		t.Fatalf("author's first push: %s", r.Raw)
	}
	if r.String(t, "posts_connection.nodes.0.author.name") != "Grace Hopper" {
		t.Fatalf("relationship in a live query: %s", r.Raw)
	}

	// Anonymous: a live count of published posts.
	anon := env.DialWS(t, AuthPayload(""))
	anon.Subscribe(t, "count", `subscription { posts_aggregate { count } }`, nil)
	if n := anon.Next(t, "count", wait).Result(t).MustOK(t).Int(t, "posts_aggregate.count"); n != 3 {
		t.Fatalf("published posts = %d", n)
	}

	// A draft by author 2: pushed to her, not to anonymous (its count did
	// not change, and nothing is pushed when nothing changed).
	env.MustGQL(t, admin, `mutation { insert_posts_one(object: {author_id: 2, title: "Draft", published: false}) { id } }`, nil)
	r = author.Next(t, "feed", wait).Result(t).MustOK(t)
	if got := len(r.List(t, "posts_connection.nodes")); got != 2 {
		t.Fatalf("after insert: %s", r.Raw)
	}
	draftID := r.Int(t, "posts_connection.nodes.1.id")
	anon.Quiet(t, 700*time.Millisecond)

	// Publishing it changes the anonymous count; the author's selection
	// (id, title, author) is unchanged, so she gets nothing.
	env.MustGQL(t, admin, `mutation($id: BigInt!) { update_posts_by_pk(id: $id, _set: {published: true}) { id } }`, map[string]any{"id": draftID})
	if n := anon.Next(t, "count", wait).Result(t).MustOK(t).Int(t, "posts_aggregate.count"); n != 4 {
		t.Fatalf("published posts after publishing = %d", n)
	}
	author.Quiet(t, 700*time.Millisecond)

	// A write through the author's own mutation shows up in her by-pk
	// subscription.
	author.Subscribe(t, "one", `subscription($id: BigInt!) { posts_by_pk(id: $id) { title } }`, map[string]any{"id": draftID})
	if r := author.Next(t, "one", wait).Result(t).MustOK(t); r.String(t, "posts_by_pk.title") != "Draft" {
		t.Fatalf("by_pk: %s", r.Raw)
	}
	env.MustGQL(t, grace, `mutation($id: BigInt!) { update_posts_by_pk(id: $id, _set: {title: "Final"}) { id } }`, map[string]any{"id": draftID})
	seen := map[string]bool{}
	for len(seen) < 2 { // both of her subscriptions see the new title
		m := author.Read(t, wait)
		r := m.Result(t).MustOK(t)
		switch m.ID {
		case "one":
			if r.String(t, "posts_by_pk.title") != "Final" {
				t.Fatalf("by_pk after update: %s", r.Raw)
			}
		case "feed":
			if r.String(t, "posts_connection.nodes.1.title") != "Final" {
				t.Fatalf("feed after update: %s", r.Raw)
			}
		default:
			t.Fatalf("unexpected message %+v", m)
		}
		seen[m.ID] = true
	}

	// complete stops an operation: no more pushes for it.
	author.Complete(t, "one")
	author.Complete(t, "feed")
	env.MustGQL(t, admin, `mutation($id: BigInt!) { update_posts_by_pk(id: $id, _set: {title: "Again"}) { id } }`, map[string]any{"id": draftID})
	author.Quiet(t, 700*time.Millisecond)

	// Queries over the socket: next + complete.
	anon.Subscribe(t, "q", `{ posts_connection(first: 1) { nodes { id } } }`, nil)
	if r := anon.Next(t, "q", wait).Result(t).MustOK(t); fmt.Sprint(r.IDs(t, "posts_connection.nodes")) != "[1]" {
		t.Fatalf("query over websocket: %s", r.Raw)
	}
	if m := anon.Next(t, "q", wait); m.Type != "complete" {
		t.Fatalf("expected complete, got %+v", m)
	}
	// Mutations over the socket, as the admin.
	adminWS := env.DialWS(t, AuthPayload(admin))
	adminWS.Subscribe(t, "m", `mutation { insert_posts_one(object: {author_id: 1, title: "Via socket", published: true}) { title } }`, nil)
	if r := adminWS.Next(t, "m", wait).Result(t).MustOK(t); r.String(t, "insert_posts_one.title") != "Via socket" {
		t.Fatalf("mutation over websocket: %s", r.Raw)
	}
	if n := anon.Next(t, "count", wait).Result(t).MustOK(t).Int(t, "posts_aggregate.count"); n != 5 {
		t.Fatalf("published posts after the socket insert = %d", n)
	}
}

func TestSubscriptionRBACNegative(t *testing.T) {
	t.Parallel()
	env := New(t, WithConfigTemplate(subsTemplate("")), WithRolesYAML(subsRolesYAML))
	grace := env.Token(t, "author", 2)
	anon := env.DialWS(t, AuthPayload(""))
	author := env.DialWS(t, AuthPayload(grace))

	expectError := func(c *WSClient, id, query, substr string) {
		t.Helper()
		c.Subscribe(t, id, query, nil)
		m := c.Next(t, id, wait)
		if m.Type != "error" {
			t.Fatalf("%s: expected an error message, got %+v %s", id, m, m.Payload)
		}
		errs := m.Errors(t)
		for _, e := range errs {
			if strings.Contains(e.Message, substr) {
				return
			}
		}
		t.Fatalf("%s: no error contains %q: %s", id, substr, m.Payload)
	}
	// A hidden column, in the selection and in where.
	expectError(anon, "col", `subscription { posts_connection { nodes { id published } } }`, "published")
	expectError(anon, "where", `subscription { posts_aggregate(where: {author_id: {_eq: 1}}) { count } }`, "author_id")
	// Readable but not subscribable tables have no subscription field.
	expectError(anon, "users", `subscription { users_connection { nodes { id } } }`, "users_connection")
	expectError(author, "comments", `subscription { comments_aggregate { count } }`, "comments_aggregate")
	// No mutations for anonymous, over the socket either.
	expectError(anon, "mut", `mutation { delete_posts(where: {}) { affected_rows } }`, "no mutations")
	// One root field per subscription.
	expectError(anon, "two", `subscription { a: posts_aggregate { count } b: posts_connection { nodes { id } } }`, "exactly one root field")

	// The author's live query never shows another author's rows, even
	// through where.
	author.Subscribe(t, "others", `subscription { posts_connection(where: {author_id: {_eq: 1}}) { nodes { id } } }`, nil)
	if r := author.Next(t, "others", wait).Result(t).MustOK(t); len(r.List(t, "posts_connection.nodes")) != 0 {
		t.Fatalf("author 2 sees author 1's posts: %s", r.Raw)
	}
	// Anonymous never sees the unpublished post 2, even by key.
	anon.Subscribe(t, "draft", `subscription { posts_by_pk(id: 2) { id title } }`, nil)
	if r := anon.Next(t, "draft", wait).Result(t).MustOK(t); r.Get("posts_by_pk") != nil {
		t.Fatalf("anonymous sees a draft: %s", r.Raw)
	}
	// A role without any subscribable table has no Subscription root, and
	// so cannot hold a socket at all: its connection_init is refused.
	env2 := New(t, WithConfigTemplate(subsTemplate("")))
	expectInitRefused(t, env2, AuthPayload(""), 4403, "no subscriptions")
	r := env2.MustGQL(t, "", `{ __schema { subscriptionType { name } } }`, nil)
	if r.Get("__schema.subscriptionType") != nil {
		t.Fatalf("subscriptionType without grants: %s", r.Raw)
	}
}

func TestSubscriptionProtocolErrors(t *testing.T) {
	t.Parallel()
	env := New(t, WithConfigTemplate(subsTemplate("")), WithRolesYAML(subsRolesYAML))

	// subscribe before connection_init: 4401.
	c, _, err := env.DialWSRaw(t, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	c.Subscribe(t, "1", `subscription { posts_aggregate { count } }`, nil)
	if code, _ := c.WaitClose(t, wait); code != 4401 {
		t.Fatalf("subscribe before ack: close %d", code)
	}

	// A bad token in connection_init: 4403.
	c, _, err = env.DialWSRaw(t, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	c.Send(t, map[string]any{"type": "connection_init", "payload": map[string]any{"Authorization": "Bearer not.a.jwt"}})
	if code, _ := c.WaitClose(t, wait); code != 4403 {
		t.Fatalf("bad token: close %d", code)
	}
	// A token for an unknown role: 4403.
	c, _, _ = env.DialWSRaw(t, nil, "")
	c.Send(t, map[string]any{"type": "connection_init", "payload": AuthPayload(env.Token(t, "superuser", 9))})
	if code, _ := c.WaitClose(t, wait); code != 4403 {
		t.Fatalf("unknown role: close %d", code)
	}

	// A duplicate operation id: 4409.
	ws := env.DialWS(t, AuthPayload(""))
	ws.Subscribe(t, "dup", `subscription { posts_aggregate { count } }`, nil)
	ws.Next(t, "dup", wait)
	ws.Subscribe(t, "dup", `subscription { posts_aggregate { count } }`, nil)
	if code, _ := ws.WaitClose(t, wait); code != 4409 {
		t.Fatalf("duplicate id: close %d", code)
	}

	// A second connection_init: 4429; ping is answered with pong.
	ws = env.DialWS(t, AuthPayload(""))
	ws.Send(t, map[string]any{"type": "ping"})
	if m := ws.Read(t, wait); m.Type != "pong" {
		t.Fatalf("ping: %+v", m)
	}
	ws.Send(t, map[string]any{"type": "connection_init"})
	if code, _ := ws.WaitClose(t, wait); code != 4429 {
		t.Fatalf("second init: close %d", code)
	}

	// Garbage: 4400. Wrong subprotocol: 4406.
	ws = env.DialWS(t, AuthPayload(""))
	if err := ws.conn.Write(context.Background(), websocket.MessageText, []byte("{nope")); err != nil {
		t.Fatal(err)
	}
	if code, _ := ws.WaitClose(t, wait); code != 4400 {
		t.Fatalf("invalid JSON: close %d", code)
	}
	c, _, err = env.DialWSRaw(t, nil, "graphql-ws")
	if err == nil {
		if code, _ := c.WaitClose(t, wait); code != 4406 {
			t.Fatalf("legacy subprotocol: close %d", code)
		}
	}

	// The token may come from the upgrade request's headers instead (for
	// non-browser clients), and from a nested headers object.
	grace := env.Token(t, "author", 2)
	c, _, err = env.DialWSRaw(t, http.Header{"Authorization": {"Bearer " + grace}}, "")
	if err != nil {
		t.Fatal(err)
	}
	c.Send(t, map[string]any{"type": "connection_init"})
	if m := c.Read(t, wait); m.Type != "connection_ack" {
		t.Fatalf("upgrade header auth: %+v", m)
	}
	c.Subscribe(t, "q", `{ _role }`, nil)
	if r := c.Next(t, "q", wait).Result(t).MustOK(t); r.String(t, "_role") != "author" {
		t.Fatalf("upgrade header auth: %s", r.Raw)
	}
	nested := env.DialWS(t, map[string]any{"headers": map[string]any{"authorization": "Bearer " + grace}})
	nested.Subscribe(t, "q", `{ _role }`, nil)
	if r := nested.Next(t, "q", wait).Result(t).MustOK(t); r.String(t, "_role") != "author" {
		t.Fatalf("nested headers auth: %s", r.Raw)
	}
}

func TestSubscriptionTokenExpiryClosesSocket(t *testing.T) {
	t.Parallel()
	env := New(t, WithConfigTemplate(subsTemplate("")), WithRolesYAML(subsRolesYAML))
	// The harness verifies with leeway_seconds: 5, so the token stops being
	// accepted 5s after exp.
	tok := env.Token(t, "author", 2, map[string]any{"exp": time.Now().Add(1 * time.Second).Unix()})
	ws := env.DialWS(t, AuthPayload(tok))
	ws.Subscribe(t, "feed", `subscription { posts_aggregate { count } }`, nil)
	if n := ws.Next(t, "feed", wait).Result(t).MustOK(t).Int(t, "posts_aggregate.count"); n != 1 {
		t.Fatalf("author 2's posts = %d", n)
	}
	start := time.Now()
	code, reason := ws.WaitClose(t, 15*time.Second)
	if code != 4401 || !strings.Contains(reason, "expired") {
		t.Fatalf("expired token: close %d %q", code, reason)
	}
	if time.Since(start) < 3*time.Second {
		t.Fatalf("closed too early (%s): the leeway was not honoured", time.Since(start))
	}
}

func TestSubscriptionRoleLookupRecheck(t *testing.T) {
	t.Parallel()
	tmpl := strings.Replace(subsTemplate(""), "  role_claim: role\n", "  role_lookup:\n    table: users\n", 1)
	env := New(t, WithConfigTemplate(tmpl), WithRolesYAML(subsRolesYAML))
	tok := env.Token(t, "", 2) // the role comes from users.role
	ws := env.DialWS(t, AuthPayload(tok))
	ws.Subscribe(t, "feed", `subscription { posts_aggregate { count } }`, nil)
	if n := ws.Next(t, "feed", wait).Result(t).MustOK(t).Int(t, "posts_aggregate.count"); n != 1 {
		t.Fatalf("author 2's posts = %d", n)
	}
	// Another socket for a user whose role changes to another valid role.
	tok3 := env.Token(t, "", 1)
	ws3 := env.DialWS(t, AuthPayload(tok3))
	ws3.Subscribe(t, "feed", `subscription { posts_aggregate { count } }`, nil)
	ws3.Next(t, "feed", wait)

	env.Exec(t, "UPDATE users SET role = 'banned' WHERE id = 2")
	env.Exec(t, "UPDATE users SET role = 'admin' WHERE id = 1")
	if code, reason := ws.WaitClose(t, wait); code != 4403 {
		t.Fatalf("role no longer valid: close %d %q", code, reason)
	}
	if code, reason := ws3.WaitClose(t, wait); code != 4403 || !strings.Contains(reason, "role changed") {
		t.Fatalf("role changed: close %d %q", code, reason)
	}
}

func TestSubscriptionHotReloadRevalidates(t *testing.T) {
	t.Parallel()
	env := New(t, WithConfigTemplate(subsTemplate("")), WithRolesYAML(subsRolesYAML))
	anon := env.DialWS(t, AuthPayload(""))
	anon.Subscribe(t, "count", `subscription { posts_aggregate { count } }`, nil)
	anon.Next(t, "count", wait)
	anon.Subscribe(t, "titles", `subscription { posts_connection { nodes { title } } }`, nil)
	anon.Next(t, "titles", wait)

	// Reload: anonymous keeps subscribe on posts but loses the title column.
	roles := strings.Replace(subsRolesYAML, "          columns: [id, title]\n          filter: \"published = 1\"\n          filterable_columns: [id, title]\n",
		"          columns: [id]\n          filter: \"published = 1\"\n          filterable_columns: [id]\n", 1)
	if roles == subsRolesYAML {
		t.Fatal("role edit did not apply")
	}
	if err := env.Reload(t, roles); err != nil {
		t.Fatal(err)
	}
	// The titles subscription is re-validated against the new schema and
	// ends with an error; the count keeps running (unchanged: no push).
	m := anon.Next(t, "titles", wait)
	if m.Type != "error" || !strings.Contains(string(m.Payload), "title") {
		t.Fatalf("after reload: %+v %s", m, m.Payload)
	}
	anon.Quiet(t, 700*time.Millisecond)
	admin := env.Token(t, "admin", 4)
	env.MustGQL(t, admin, `mutation { update_posts_by_pk(id: 2, _set: {published: true}) { id } }`, nil)
	if n := anon.Next(t, "count", wait).Result(t).MustOK(t).Int(t, "posts_aggregate.count"); n != 4 {
		t.Fatalf("count after reload = %d", n)
	}

	// Revoking subscribe ends the remaining subscription too.
	if err := env.Reload(t, strings.ReplaceAll(roles, "          subscribe: true\n", "")); err != nil {
		t.Fatal(err)
	}
	if m := anon.Next(t, "count", wait); m.Type != "error" || !strings.Contains(string(m.Payload), "no subscriptions") {
		t.Fatalf("after revoking subscribe: %+v %s", m, m.Payload)
	}
}

func TestSubscriptionLimitsAndShutdown(t *testing.T) {
	t.Parallel()
	env := New(t, WithConfigTemplate(subsTemplate("    max_connections: 2\n    max_subscriptions_per_connection: 2\n")), WithRolesYAML(subsRolesYAML))
	ws := env.DialWS(t, AuthPayload(""))
	ws.Subscribe(t, "a", `subscription { posts_aggregate { count } }`, nil)
	ws.Next(t, "a", wait)
	ws.Subscribe(t, "b", `subscription { posts_connection { nodes { id } } }`, nil)
	ws.Next(t, "b", wait)
	ws.Subscribe(t, "c", `subscription { posts_by_pk(id: 1) { id } }`, nil)
	if m := ws.Next(t, "c", wait); m.Type != "error" || !strings.Contains(string(m.Payload), "too many operations") {
		t.Fatalf("third subscription: %+v %s", m, m.Payload)
	}
	// Completing one frees a slot.
	ws.Complete(t, "a")
	time.Sleep(200 * time.Millisecond)
	ws.Subscribe(t, "c", `subscription { posts_by_pk(id: 1) { id } }`, nil)
	if m := ws.Next(t, "c", wait); m.Type != "next" {
		t.Fatalf("after complete: %+v %s", m, m.Payload)
	}

	ws2 := env.DialWS(t, AuthPayload(env.Token(t, "author", 2)))
	// max_connections counts initialised sockets: a third one upgrades but
	// its connection_init is turned away with 1013 (try again later).
	expectInitRefused(t, env, AuthPayload(env.Token(t, "admin", 4)), websocket.StatusTryAgainLater, "max_connections")

	// Shutdown closes every socket with 1001.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		env.Gate.Close()
		close(done)
	}()
	for _, c := range []*WSClient{ws, ws2} {
		if code, _ := c.WaitClose(t, wait); code != websocket.StatusGoingAway {
			t.Fatalf("shutdown: close %d", code)
		}
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("Gate.Close did not return")
	}
}

func TestSubscriptionPollIntervalOverride(t *testing.T) {
	t.Parallel()
	extra := `tables:
  posts:
    subscriptions:
      poll_interval_ms: 60000
      root_fields:
        aggregate: 100
`
	env := New(t, WithConfigTemplate(subsTemplate("    max_poll_interval_ms: 60000\n")), WithRolesYAML(subsRolesYAML), WithExtraYAML(extra))
	admin := env.Token(t, "admin", 4)
	ws := env.DialWS(t, AuthPayload(""))
	ws.Subscribe(t, "agg", `subscription { posts_aggregate { count } }`, nil)
	ws.Next(t, "agg", wait)
	ws.Subscribe(t, "conn", `subscription { posts_connection { nodes { id } } }`, nil)
	ws.Next(t, "conn", wait)
	env.MustGQL(t, admin, `mutation { update_posts_by_pk(id: 2, _set: {published: true}) { id } }`, nil)
	// The aggregate polls every 100ms; the connection only every minute.
	if n := ws.Next(t, "agg", wait).Result(t).MustOK(t).Int(t, "posts_aggregate.count"); n != 4 {
		t.Fatalf("count = %d", n)
	}
	ws.Quiet(t, time.Second)
	r := env.MustGQL(t, "", `{ __type(name: "Subscription") { fields { name description } } }`, nil)
	if !strings.Contains(string(r.Raw), "re-run every 1m0s") || !strings.Contains(string(r.Raw), "re-run every 100ms") {
		t.Fatalf("intervals in the descriptions: %s", r.Raw)
	}
}

func TestSubscriptionNativeQuery(t *testing.T) {
	t.Parallel()
	native := `native_queries:
  my_posts:
    sql: "SELECT p.id AS post_id, p.title, p.views FROM posts p WHERE p.author_id = :author"
    arguments:
      author: BigInt!
    key: [post_id]
    subscriptions: {poll_interval_ms: 100}
`
	roles := `roles:
  admin:
    tables:
      "*": {select: true, update: true}
  author:
    tables:
      posts: {select: true}
    native_queries:
      my_posts:
        allow: true
        columns: [post_id, title]
        presets: {author: ":jwt.sub"}
        subscribe: true
  anonymous:
    tables:
      posts: {select: true}
    native_queries:
      my_posts: {allow: true, subscribe: false}
`
	env := New(t, WithConfigTemplate(subsTemplate("")), WithRolesYAML(roles), WithExtraYAML(native))
	admin := env.Token(t, "admin", 4)
	ws := env.DialWS(t, AuthPayload(env.Token(t, "author", 1)))
	ws.Subscribe(t, "mine", `subscription { my_posts_connection { nodes { post_id title } } }`, nil)
	if r := ws.Next(t, "mine", wait).Result(t).MustOK(t); len(r.List(t, "my_posts_connection.nodes")) != 2 {
		t.Fatalf("author 1's posts: %s", r.Raw)
	}
	env.MustGQL(t, admin, `mutation { update_posts_by_pk(id: 1, _set: {title: "Renamed"}) { id } }`, nil)
	if r := ws.Next(t, "mine", wait).Result(t).MustOK(t); r.String(t, "my_posts_connection.nodes.0.title") != "Renamed" {
		t.Fatalf("after rename: %s", r.Raw)
	}
	// The preset argument cannot be set by the client, and hidden result
	// columns stay hidden.
	for id, q := range map[string]string{
		"args":  `subscription { my_posts(args: {author: 2}) { post_id } }`,
		"views": `subscription { my_posts { views } }`,
	} {
		ws.Subscribe(t, id, q, nil)
		if m := ws.Next(t, id, wait); m.Type != "error" {
			t.Fatalf("%s: %+v %s", id, m, m.Payload)
		}
	}
	// Anonymous may query it but not subscribe to it: with nothing
	// subscribable it cannot even open a socket.
	expectInitRefused(t, env, AuthPayload(""), 4403, "no subscriptions")
}

// expectInitRefused dials, sends connection_init with payload and expects
// the socket to close with code (and a reason containing substr).
func expectInitRefused(t *testing.T, env *Env, payload map[string]any, code websocket.StatusCode, substr string) {
	t.Helper()
	c, _, err := env.DialWSRaw(t, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	c.Send(t, map[string]any{"type": "connection_init", "payload": payload})
	if got, reason := c.WaitClose(t, wait); got != code || !strings.Contains(reason, substr) {
		t.Fatalf("connection_init: close %d %q, want %d %q", got, reason, code, substr)
	}
}

// Unauthenticated sockets only fill the pending pool, never the
// initialised connections; one caller (a token's sub, or the anonymous role
// per client address) cannot take every slot; polls still run with
// max_concurrent_polls 1; and disabling subscriptions by a reload closes
// the open sockets.
func TestSubscriptionCallerLimits(t *testing.T) {
	t.Parallel()
	limits := "    max_connections: 3\n    max_pending_connections: 2\n    max_connections_per_identity: 1\n" +
		"    max_subscriptions_per_identity: 2\n    max_concurrent_polls: 1\n"
	env := New(t, WithConfigTemplate(subsTemplate(limits)), WithRolesYAML(subsRolesYAML))
	grace := env.Token(t, "author", 2)
	admin := env.Token(t, "admin", 4)

	// Two sockets that never send connection_init fill the pending pool.
	var idle []*WSClient
	for range 2 {
		c, _, err := env.DialWSRaw(t, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	if _, resp, err := env.DialWSRaw(t, nil, ""); err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("third pending socket: err %v, resp %+v", err, resp)
	}
	for _, c := range idle {
		c.Close()
	}
	// They never held one of the 3 initialised slots.
	var author *WSClient
	deadline := time.Now().Add(wait)
	for author == nil {
		c, _, err := env.DialWSRaw(t, nil, "")
		if err == nil {
			c.Send(t, map[string]any{"type": "connection_init", "payload": AuthPayload(grace)})
			if m := c.Read(t, wait); m.Type == "connection_ack" {
				author = c
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending slots not freed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// One socket per caller: a second one of author 2 is turned away, other
	// callers are not.
	expectInitRefused(t, env, AuthPayload(grace), websocket.StatusTryAgainLater, "max_connections_per_identity")
	anon := env.DialWS(t, AuthPayload(""))
	// Anonymous callers share one identity per client address.
	expectInitRefused(t, env, AuthPayload(""), websocket.StatusTryAgainLater, "max_connections_per_identity")
	adminWS := env.DialWS(t, AuthPayload(admin))
	// The 3 initialised slots are taken.
	expectInitRefused(t, env, AuthPayload(env.Token(t, "author", 1)), websocket.StatusTryAgainLater, "(server.subscriptions.max_connections)")

	// Two operations per caller (over all its sockets); with one poll at a
	// time they all still run, each with its own role's permissions.
	author.Subscribe(t, "a", `subscription { posts_connection { nodes { id } } }`, nil)
	author.Subscribe(t, "b", `subscription { posts_aggregate { count } }`, nil)
	for range 2 { // in either order
		m := author.Read(t, wait)
		r := m.Result(t).MustOK(t)
		switch m.ID {
		case "a":
			if fmt.Sprint(r.IDs(t, "posts_connection.nodes")) != "[3]" {
				t.Fatalf("author's own posts only: %s", r.Raw)
			}
		case "b":
			if n := r.Int(t, "posts_aggregate.count"); n != 1 {
				t.Fatalf("author's count = %d", n)
			}
		default:
			t.Fatalf("unexpected message %+v", m)
		}
	}
	author.Subscribe(t, "c", `subscription { posts_by_pk(id: 3) { id } }`, nil)
	if m := author.Next(t, "c", wait); m.Type != "error" || !strings.Contains(string(m.Payload), "max_subscriptions_per_identity") {
		t.Fatalf("third operation of author 2: %+v %s", m, m.Payload)
	}
	adminWS.Subscribe(t, "a", `subscription { posts_aggregate { count } }`, nil)
	if n := adminWS.Next(t, "a", wait).Result(t).MustOK(t).Int(t, "posts_aggregate.count"); n != 4 {
		t.Fatalf("admin's count = %d", n)
	}
	anon.Subscribe(t, "a", `subscription { posts_aggregate { count } }`, nil)
	if n := anon.Next(t, "a", wait).Result(t).MustOK(t).Int(t, "posts_aggregate.count"); n != 3 {
		t.Fatalf("anonymous count = %d", n)
	}

	// A reload that disables subscriptions closes every open socket (idle
	// ones too) and the endpoint.
	env.settings.template = subsTemplate(limits + "    enabled: false\n")
	if err := env.Reload(t, subsRolesYAML); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*WSClient{author, adminWS, anon} {
		if code, _ := c.WaitClose(t, wait); code != websocket.StatusGoingAway {
			t.Fatalf("after disabling: close %d", code)
		}
	}
	if _, resp, err := env.DialWSRaw(t, nil, ""); err == nil || resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("disabled endpoint: err %v, resp %+v", err, resp)
	}
}

// The upgrade's Origin must match server.cors.allowed_origins exactly,
// scheme included.
func TestSubscriptionOriginCheck(t *testing.T) {
	t.Parallel()
	tmpl := strings.Replace(subsTemplate(""), "  graphiql: false\n",
		"  graphiql: false\n  cors:\n    enabled: true\n    allowed_origins: [\"https://app.example.com\"]\n", 1)
	env := New(t, WithConfigTemplate(tmpl), WithRolesYAML(subsRolesYAML))
	for origin, want := range map[string]int{
		"http://app.example.com":  http.StatusForbidden,
		"https://evil.example":    http.StatusForbidden,
		"https://app.example.com": http.StatusSwitchingProtocols,
	} {
		c, resp, _ := env.DialWSRaw(t, http.Header{"Origin": {origin}}, "")
		if resp == nil || resp.StatusCode != want {
			t.Fatalf("Origin %s: resp %+v, want %d", origin, resp, want)
		}
		if c != nil {
			c.Send(t, map[string]any{"type": "connection_init", "payload": AuthPayload(env.Token(t, "author", 1))})
			if m := c.Read(t, wait); m.Type != "connection_ack" {
				t.Fatalf("allowed origin: %+v", m)
			}
			c.Close()
		}
	}
}
