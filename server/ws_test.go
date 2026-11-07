package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/golang-jwt/jwt/v5"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"

	"gqlgate/auth"
	"gqlgate/config"
	"gqlgate/rbac"
)

// Protocol tests for the graphql-transport-ws endpoint over an in-memory
// schema (no database): a Subscription root whose `tick` field reads a
// counter the test controls.

const wsTestSecret = "0123456789abcdef0123456789abcdef"

type wsFixture struct {
	t       *testing.T
	ts      *httptest.Server
	srv     *Server
	cur     atomic.Pointer[State]
	counter atomic.Int64
}

func wsConfig(t *testing.T, subs string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`
database:
  schema: appdb
jwt:
  algorithm: HS256
  secret: "` + wsTestSecret + `"
  anonymous_role: anonymous
server:
  subscriptions:
` + subs + `
roles:
  viewer:
    tables:
      "*": {select: true}
  anonymous:
    tables:
      "*": {select: true}
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// testSchemas builds the viewer schema (with a Subscription root carrying
// the given fields) and the anonymous one (queries only).
func (f *wsFixture) testSchemas(subFields ...string) map[string]graphql.Schema {
	query := graphql.NewObject(graphql.ObjectConfig{Name: "Query", Fields: graphql.Fields{
		"role": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) {
			id, _ := rbac.IdentityFrom(p.Context)
			return id.Role, nil
		}},
	}})
	all := graphql.Fields{
		"tick": &graphql.Field{Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (any, error) {
			return int(f.counter.Load()), nil
		}},
		"other": &graphql.Field{Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (any, error) { return 1, nil }},
	}
	sub := graphql.Fields{}
	for _, n := range subFields {
		sub[n] = all[n]
	}
	viewer, err := graphql.NewSchema(graphql.SchemaConfig{
		Query:        query,
		Subscription: graphql.NewObject(graphql.ObjectConfig{Name: "Subscription", Fields: sub}),
	})
	if err != nil {
		f.t.Fatal(err)
	}
	anon, err := graphql.NewSchema(graphql.SchemaConfig{Query: query})
	if err != nil {
		f.t.Fatal(err)
	}
	return map[string]graphql.Schema{"viewer": viewer, "anonymous": anon}
}

func newWSFixture(t *testing.T, subs string) *wsFixture {
	t.Helper()
	f := &wsFixture{t: t}
	cfg := wsConfig(t, subs)
	f.cur.Store(f.state(cfg, "tick", "other"))
	f.srv = NewServer(cfg, func() *State { return f.cur.Load() }, nil)
	f.ts = httptest.NewServer(f.srv)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = f.srv.Shutdown(ctx)
		f.ts.Close()
	})
	return f
}

func (f *wsFixture) state(cfg *config.Config, subFields ...string) *State {
	v, err := auth.New(cfg.JWT, []string{"viewer", "anonymous"}, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return &State{
		Cfg: cfg, Schemas: f.testSchemas(subFields...), Verifier: v,
		PollIntervals: map[string]map[string]time.Duration{"viewer": {"tick": 20 * time.Millisecond}},
	}
}

func (f *wsFixture) token(role string, exp time.Time) string {
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"role": role, "sub": "1", "exp": exp.Unix()}).SignedString([]byte(wsTestSecret))
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

type testWS struct {
	t      *testing.T
	c      *websocket.Conn
	msgs   chan wsMessage
	closed chan struct{}
	code   websocket.StatusCode
}

func (f *wsFixture) dial(subprotocol string) *testWS {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.ts.URL, "http")+"/graphql",
		&websocket.DialOptions{Subprotocols: []string{subprotocol}})
	if err != nil {
		f.t.Fatalf("dial: %v", err)
	}
	w := &testWS{t: f.t, c: c, msgs: make(chan wsMessage, 64), closed: make(chan struct{}), code: -1}
	go func() {
		defer close(w.closed)
		for {
			_, data, err := c.Read(context.Background())
			if err != nil {
				w.code = websocket.CloseStatus(err)
				close(w.msgs)
				return
			}
			var m wsMessage
			_ = json.Unmarshal(data, &m)
			w.msgs <- m
		}
	}()
	f.t.Cleanup(func() { c.CloseNow() })
	return w
}

// init dials, sends connection_init and expects the ack.
func (f *wsFixture) init(token string) *testWS {
	f.t.Helper()
	w := f.dial(wsSubprotocol)
	payload := map[string]any{}
	if token != "" {
		payload["Authorization"] = "Bearer " + token
	}
	w.send(map[string]any{"type": "connection_init", "payload": payload})
	if m := w.read(); m.Type != "connection_ack" {
		f.t.Fatalf("expected connection_ack, got %+v", m)
	}
	return w
}

func (w *testWS) send(msg any) {
	w.t.Helper()
	data, _ := json.Marshal(msg)
	if err := w.c.Write(context.Background(), websocket.MessageText, data); err != nil {
		w.t.Fatalf("write: %v", err)
	}
}

func (w *testWS) subscribe(id, query string) {
	w.t.Helper()
	w.send(map[string]any{"id": id, "type": "subscribe", "payload": map[string]any{"query": query}})
}

func (w *testWS) read() wsMessage {
	w.t.Helper()
	select {
	case m, ok := <-w.msgs:
		if !ok {
			w.t.Fatalf("socket closed (%d) while waiting for a message", w.code)
		}
		return m
	case <-time.After(5 * time.Second):
		w.t.Fatal("no message within 5s")
	}
	return wsMessage{}
}

func (w *testWS) quiet(d time.Duration) {
	w.t.Helper()
	select {
	case m, ok := <-w.msgs:
		if ok {
			w.t.Fatalf("expected silence, got %+v %s", m, m.Payload)
		}
		w.t.Fatalf("socket closed (%d)", w.code)
	case <-time.After(d):
	}
}

func (w *testWS) waitClose(d time.Duration) websocket.StatusCode {
	w.t.Helper()
	select {
	case <-w.closed:
		return w.code
	case <-time.After(d):
		w.t.Fatalf("socket not closed within %s", d)
	}
	return 0
}

func payloadString(m wsMessage) string { return string(m.Payload) }

func TestWSLiveQueryPushesOnlyChanges(t *testing.T) {
	f := newWSFixture(t, "    poll_interval_ms: 1000\n")
	w := f.init(f.token("viewer", time.Now().Add(time.Hour)))
	w.subscribe("s", `subscription { tick }`)
	if m := w.read(); m.ID != "s" || m.Type != "next" || payloadString(m) != `{"data":{"tick":0}}` {
		t.Fatalf("first push: %+v %s", m, m.Payload)
	}
	w.quiet(200 * time.Millisecond) // ~10 polls, nothing changed
	f.counter.Store(7)
	if m := w.read(); payloadString(m) != `{"data":{"tick":7}}` {
		t.Fatalf("after change: %+v %s", m, m.Payload)
	}
	w.send(map[string]any{"id": "s", "type": "complete"})
	time.Sleep(50 * time.Millisecond)
	f.counter.Store(8)
	w.quiet(200 * time.Millisecond)

	// A query runs once: next + complete.
	w.subscribe("q", `{ role }`)
	if m := w.read(); m.ID != "q" || payloadString(m) != `{"data":{"role":"viewer"}}` {
		t.Fatalf("query: %+v %s", m, m.Payload)
	}
	if m := w.read(); m.ID != "q" || m.Type != "complete" {
		t.Fatalf("query end: %+v", m)
	}
	// Validation errors end the operation with an error message.
	for query, want := range map[string]string{
		`subscription { tick other }`: "exactly one root field",
		`subscription { nope }`:       "nope",
		`subscription { tick`:         "Syntax Error",
		`mutation { x }`:              "no mutations",
	} {
		w.subscribe("bad", query)
		m := w.read()
		if m.ID != "bad" || m.Type != "error" || !strings.Contains(payloadString(m), want) {
			t.Fatalf("%s: %+v %s", query, m, m.Payload)
		}
	}
	// ping → pong.
	w.send(map[string]any{"type": "ping"})
	if m := w.read(); m.Type != "pong" {
		t.Fatalf("ping: %+v", m)
	}
}

func TestWSAuthentication(t *testing.T) {
	f := newWSFixture(t, "")
	// No token: the anonymous role, which has no Subscription root.
	w := f.init("")
	w.subscribe("q", `{ role }`)
	if m := w.read(); payloadString(m) != `{"data":{"role":"anonymous"}}` {
		t.Fatalf("anonymous: %s", m.Payload)
	}
	w.read() // complete
	w.subscribe("s", `subscription { tick }`)
	if m := w.read(); m.Type != "error" || !strings.Contains(payloadString(m), "no subscriptions") {
		t.Fatalf("anonymous subscription: %+v %s", m, m.Payload)
	}

	// A bad or expired token, or an unknown role: 4403 at connection_init.
	for _, tok := range []string{"garbage", f.token("viewer", time.Now().Add(-time.Hour)), f.token("root", time.Now().Add(time.Hour))} {
		w := f.dial(wsSubprotocol)
		w.send(map[string]any{"type": "connection_init", "payload": map[string]any{"Authorization": "Bearer " + tok}})
		if code := w.waitClose(5 * time.Second); code != closeForbidden {
			t.Errorf("token %.20s…: close %d", tok, code)
		}
	}

	// subscribe before connection_init: 4401.
	w = f.dial(wsSubprotocol)
	w.subscribe("s", `subscription { tick }`)
	if code := w.waitClose(5 * time.Second); code != closeUnauthorized {
		t.Errorf("subscribe before init: close %d", code)
	}

	// The token expires while the socket is open: 4401.
	w = f.init(f.token("viewer", time.Now().Add(2500*time.Millisecond)))
	w.subscribe("s", `subscription { tick }`)
	w.read()
	start := time.Now()
	if code := w.waitClose(5 * time.Second); code != closeUnauthorized {
		t.Errorf("expiry: close %d", code)
	}
	if time.Since(start) < time.Second {
		t.Errorf("closed after %s, before the token expired", time.Since(start))
	}
}

func TestWSProtocolViolations(t *testing.T) {
	f := newWSFixture(t, "    connection_init_timeout_seconds: 1\n    max_subscriptions_per_connection: 1\n")
	tok := f.token("viewer", time.Now().Add(time.Hour))

	w := f.dial(wsSubprotocol) // never initialises
	if code := w.waitClose(5 * time.Second); code != closeInitTimeout {
		t.Errorf("init timeout: close %d", code)
	}
	w = f.dial("graphql-ws") // the legacy protocol is not spoken
	if code := w.waitClose(5 * time.Second); code != closeSubprotocol {
		t.Errorf("legacy subprotocol: close %d", code)
	}
	w = f.init(tok)
	w.send(map[string]any{"type": "connection_init"})
	if code := w.waitClose(5 * time.Second); code != closeTooManyInits {
		t.Errorf("second init: close %d", code)
	}
	w = f.init(tok)
	w.send(map[string]any{"type": "bogus"})
	if code := w.waitClose(5 * time.Second); code != closeBadRequest {
		t.Errorf("unknown type: close %d", code)
	}
	w = f.init(tok)
	w.subscribe("a", `subscription { tick }`)
	w.read()
	w.subscribe("b", `subscription { tick }`)
	if m := w.read(); m.ID != "b" || m.Type != "error" || !strings.Contains(payloadString(m), "too many operations") {
		t.Errorf("over the per-connection limit: %+v %s", m, m.Payload)
	}
	w.subscribe("a", `subscription { tick }`)
	if code := w.waitClose(5 * time.Second); code != closeDuplicateID {
		t.Errorf("duplicate id: close %d", code)
	}
}

func TestWSHotReloadRevalidates(t *testing.T) {
	f := newWSFixture(t, "")
	w := f.init(f.token("viewer", time.Now().Add(time.Hour)))
	w.subscribe("s", `subscription { tick }`)
	w.read()
	w.subscribe("o", `subscription { other }`)
	w.read()
	// The new generation drops tick: that subscription ends with an error,
	// the other keeps running (and, unchanged, stays silent).
	f.cur.Store(f.state(f.cur.Load().Cfg, "other"))
	m := w.read()
	if m.ID != "s" || m.Type != "error" || !strings.Contains(payloadString(m), "tick") {
		t.Fatalf("after reload: %+v %s", m, m.Payload)
	}
	w.quiet(1500 * time.Millisecond)
	// A generation whose verifier no longer accepts the token closes the
	// socket with 4403.
	cfg := *f.cur.Load().Cfg
	cfg.JWT.Secret = strings.Repeat("x", 40)
	f.cur.Store(f.state(&cfg, "other"))
	if code := w.waitClose(5 * time.Second); code != closeForbidden {
		t.Errorf("token no longer verifies: close %d", code)
	}
}

func TestWSDisabledAndShutdown(t *testing.T) {
	f := newWSFixture(t, "    enabled: false\n")
	_, resp, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(f.ts.URL, "http")+"/graphql",
		&websocket.DialOptions{Subprotocols: []string{wsSubprotocol}})
	if err == nil || resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("disabled: err %v resp %v", err, resp)
	}

	f = newWSFixture(t, "")
	w := f.init(f.token("viewer", time.Now().Add(time.Hour)))
	w.subscribe("s", `subscription { tick }`)
	w.read()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if code := w.waitClose(5 * time.Second); code != websocket.StatusGoingAway {
		t.Errorf("shutdown: close %d", code)
	}
	_, resp, err = websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(f.ts.URL, "http")+"/graphql",
		&websocket.DialOptions{Subprotocols: []string{wsSubprotocol}})
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("after shutdown: err %v resp %v", err, resp)
	}
}

func TestInitHeaders(t *testing.T) {
	upgrade := http.Header{"Authorization": {"Bearer from-upgrade"}, "X-Gqlgate-Role": {"up"}}
	for _, tc := range []struct {
		payload    string
		auth, role string
		err        string
	}{
		{`{"Authorization": "Bearer a"}`, "Bearer a", "up", ""},
		{`{"authorization": "Bearer a", "x-gqlgate-role": "editor"}`, "Bearer a", "editor", ""},
		{`{"headers": {"Authorization": "Bearer n", "X-Gqlgate-Role": "r"}}`, "Bearer n", "r", ""},
		{`null`, "Bearer from-upgrade", "up", ""},
		{``, "Bearer from-upgrade", "up", ""},
		{`{"Authorization": 5}`, "", "", "must be a string"},
		{`[1]`, "", "", "must be an object"},
	} {
		h, err := initHeaders(json.RawMessage(tc.payload), upgrade, config.DefaultRoleHeader)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err %v, want %q", tc.payload, err, tc.err)
			}
			continue
		}
		if err != nil || h.Get("Authorization") != tc.auth || h.Get(config.DefaultRoleHeader) != tc.role {
			t.Errorf("%s: %v %v", tc.payload, h, err)
		}
	}
	// Nothing else from the payload is used.
	h, _ := initHeaders(json.RawMessage(`{"Cookie": "x", "Authorization": "Bearer a"}`), http.Header{}, config.DefaultRoleHeader)
	if len(h) != 1 {
		t.Errorf("only auth headers are taken: %v", h)
	}
}

func TestRootFieldNames(t *testing.T) {
	parse := func(q string) (*ast.OperationDefinition, map[string]*ast.FragmentDefinition) {
		doc, err := parser.Parse(parser.ParseParams{Source: source.NewSource(&source.Source{Body: []byte(q)})})
		if err != nil {
			t.Fatal(err)
		}
		op, err := findOperation(doc, "")
		if err != nil {
			t.Fatal(err)
		}
		return op, fragmentsOf(doc)
	}
	for q, want := range map[string]int{
		`subscription { a }`:         1,
		`subscription { a a }`:       1,
		`subscription { a b }`:       2,
		`subscription { x: a y: a }`: 2,
		`subscription { ... on S { a } ...F } fragment F on S { a }`: 1,
		`subscription { ...F } fragment F on S { a b }`:              2,
	} {
		op, frags := parse(q)
		if got := len(rootFieldNames(op.SelectionSet, frags)); got != want {
			t.Errorf("%s: %d root fields, want %d", q, got, want)
		}
	}
	doc, _ := parser.Parse(parser.ParseParams{Source: source.NewSource(&source.Source{Body: []byte(`query A { a } query B { b }`)})})
	if _, err := findOperation(doc, ""); err == nil {
		t.Error("two operations without a name must be rejected")
	}
	if op, err := findOperation(doc, "B"); err != nil || op.Name.Value != "B" {
		t.Errorf("by name: %v", err)
	}
	if _, err := findOperation(doc, "C"); err == nil {
		t.Error("an unknown operation name must be rejected")
	}
}

func TestOriginPatternsAndUpgrade(t *testing.T) {
	if p := originPatterns(config.CORS{Enabled: false, AllowedOrigins: []string{"*"}}); p != nil {
		t.Errorf("CORS off: same origin only, got %v", p)
	}
	if p := originPatterns(config.CORS{Enabled: true, AllowedOrigins: []string{"http://localhost:3000", "https://app.example.com"}}); strings.Join(p, ",") != "localhost:3000,app.example.com" {
		t.Errorf("patterns = %v", p)
	}
	if p := originPatterns(config.CORS{Enabled: true, AllowedOrigins: []string{"https://a.example", "*"}}); strings.Join(p, ",") != "*" {
		t.Errorf("wildcard = %v", p)
	}
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	r.Header.Set("Connection", "keep-alive, Upgrade")
	r.Header.Set("Upgrade", "websocket")
	if !isWebSocketUpgrade(r) {
		t.Error("upgrade not detected")
	}
	r.Header.Set("Connection", "keep-alive")
	if isWebSocketUpgrade(r) {
		t.Error("no Connection: upgrade, no upgrade")
	}
}

// A client that stops answering WebSocket pings is disconnected.
func TestWSPingTimeout(t *testing.T) {
	f := newWSFixture(t, "    keepalive_seconds: 1\n    ping_timeout_seconds: 1\n")
	ctx := context.Background()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.ts.URL, "http")+"/graphql",
		&websocket.DialOptions{Subprotocols: []string{wsSubprotocol}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	if err := c.Write(ctx, websocket.MessageText, []byte(`{"type":"connection_init"}`)); err != nil {
		t.Fatal(err)
	}
	if _, data, err := c.Read(ctx); err != nil || !strings.Contains(string(data), "connection_ack") {
		t.Fatalf("ack: %s %v", data, err)
	}
	// Not reading means pings go unanswered.
	time.Sleep(2500 * time.Millisecond)
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, _, err = c.Read(rctx)
	if code := websocket.CloseStatus(err); code != websocket.StatusPolicyViolation {
		t.Fatalf("unanswered ping: %v (close %d)", err, code)
	}
}
