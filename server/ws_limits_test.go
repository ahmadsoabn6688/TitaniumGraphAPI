package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"gqlgate/rbac"
)

// Tests for the WebSocket endpoint's limits and its reactions to a reload:
// pending vs initialised connection caps, per-caller caps, the concurrent
// poll cap, the Origin check, the init timeout and disabling by reload.

// The handshake compares the whole Origin with server.cors.allowed_origins:
// an http page is not let in where only the https one is configured.
func TestWSOriginSchemeEnforced(t *testing.T) {
	cfg := wsConfigWith(t, "  cors:\n    enabled: true\n    allowed_origins: [\"https://app.example.com\"]\n", "")
	f := newWSFixtureWith(t, cfg, nil)
	for origin, want := range map[string]int{
		"https://app.example.com": http.StatusSwitchingProtocols,
		"http://app.example.com":  http.StatusForbidden,
		"https://evil.com":        http.StatusForbidden,
		f.ts.URL:                  http.StatusSwitchingProtocols, // same origin
		"":                        http.StatusSwitchingProtocols, // not a browser
	} {
		h := http.Header{}
		if origin != "" {
			h.Set("Origin", origin)
		}
		c, resp, err := f.dialRaw(wsSubprotocol, h)
		if resp == nil || resp.StatusCode != want {
			t.Errorf("Origin %q: resp %v err %v, want %d", origin, resp, err, want)
		}
		if c != nil {
			c.CloseNow()
		}
	}
}

// Unauthenticated sockets count towards max_pending_connections only; the
// max_connections cap is taken at connection_init, so they cannot lock
// authenticated callers out.
func TestWSConnectionLimits(t *testing.T) {
	f := newWSFixture(t, "    max_connections: 1\n    max_pending_connections: 2\n")
	tok := func(sub string) string { return f.tokenFor("viewer", sub, time.Now().Add(time.Hour)) }

	a := f.dial(wsSubprotocol)
	b := f.dial(wsSubprotocol)
	// A third socket that has not initialised is one too many.
	if _, resp, err := f.dialRaw(wsSubprotocol, nil); err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("third pending socket: err %v resp %v", err, resp)
	}
	a.sendInit(tok("1"))
	if m := a.read(); m.Type != "connection_ack" {
		t.Fatalf("first init: %+v", m)
	}
	// a left the pending pool: a new socket may upgrade again.
	c := f.dial(wsSubprotocol)
	// max_connections (1) is taken by a: b's init is turned away with 1013.
	b.sendInit(tok("2"))
	if code := b.waitClose(5 * time.Second); code != websocket.StatusTryAgainLater {
		t.Fatalf("over max_connections: close %d", code)
	}
	// An anonymous socket never gets that far (no Subscription root).
	c.sendInit("")
	if code := c.waitClose(5 * time.Second); code != closeForbidden {
		t.Fatalf("anonymous: close %d", code)
	}
	// Closing a frees its slot.
	a.c.Close(websocket.StatusNormalClosure, "")
	a.waitClose(5 * time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for {
		d := f.dial(wsSubprotocol)
		d.sendInit(tok("2"))
		m, ok := <-d.msgs
		if ok && m.Type == "connection_ack" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("slot not freed after close: %+v (close %d)", m, d.code)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestWSPerIdentityLimits(t *testing.T) {
	f := newWSFixture(t, "    max_connections_per_identity: 1\n    max_subscriptions_per_identity: 1\n")
	exp := time.Now().Add(time.Hour)
	one := f.init(f.tokenFor("viewer", "1", exp))
	// Another socket of the same caller: 1013.
	w := f.dial(wsSubprotocol)
	w.sendInit(f.tokenFor("viewer", "1", exp))
	if code := w.waitClose(5 * time.Second); code != websocket.StatusTryAgainLater {
		t.Fatalf("second socket of sub 1: close %d", code)
	}
	two := f.init(f.tokenFor("viewer", "2", exp)) // another caller is fine

	one.subscribe("a", `subscription { tick }`)
	if m := one.read(); m.Type != "next" {
		t.Fatalf("first subscription: %+v", m)
	}
	one.subscribe("b", `subscription { other }`)
	if m := one.read(); m.ID != "b" || m.Type != "error" || !strings.Contains(payloadString(m), "max_subscriptions_per_identity") {
		t.Fatalf("over the per-caller limit: %+v %s", m, m.Payload)
	}
	two.subscribe("b", `subscription { other }`)
	if m := two.read(); m.Type != "next" {
		t.Fatalf("other caller: %+v %s", m, m.Payload)
	}
	// Completing frees the caller's slot.
	one.send(map[string]any{"id": "a", "type": "complete"})
	time.Sleep(100 * time.Millisecond)
	one.subscribe("c", `subscription { other }`)
	if m := one.read(); m.ID != "c" || m.Type != "next" {
		t.Fatalf("after complete: %+v %s", m, m.Payload)
	}
}

func TestIdentityKey(t *testing.T) {
	for _, tc := range []struct {
		id   *rbac.Identity
		addr string
		want string
	}{
		{&rbac.Identity{Role: "viewer", Claims: map[string]any{"sub": "42"}}, "10.0.0.1:5555", "sub:42"},
		{&rbac.Identity{Role: "editor", Claims: map[string]any{"sub": float64(42)}}, "10.0.0.2:1", "sub:42"},
		{&rbac.Identity{Role: "anonymous", Claims: map[string]any{}}, "10.0.0.1:5555", "addr:anonymous@10.0.0.1"},
		{&rbac.Identity{Role: "anonymous", Claims: map[string]any{}}, "10.0.0.1:6666", "addr:anonymous@10.0.0.1"},
		{&rbac.Identity{Role: "svc", Claims: map[string]any{"sub": ""}}, "[::1]:80", "addr:svc@::1"},
	} {
		if got := identityKey(tc.id, tc.addr); got != tc.want {
			t.Errorf("%+v %s: %q, want %q", tc.id, tc.addr, got, tc.want)
		}
	}
}

// max_concurrent_polls bounds the executions running at once.
func TestWSConcurrentPolls(t *testing.T) {
	for _, tc := range []struct {
		limit   string
		wantMax func(int64) bool
	}{
		{"1", func(n int64) bool { return n == 1 }},
		{"-1", func(n int64) bool { return n > 1 }}, // control: the test does see overlap
	} {
		f := newWSFixture(t, "    max_concurrent_polls: "+tc.limit+"\n")
		w := f.init(f.token("viewer", time.Now().Add(time.Hour)))
		for i := range 4 {
			w.subscribe(fmt.Sprintf("s%d", i), `subscription { slow }`)
		}
		for range 4 {
			if m := w.read(); m.Type != "next" {
				t.Fatalf("limit %s: %+v %s", tc.limit, m, m.Payload)
			}
		}
		if n := f.maxInflight.Load(); !tc.wantMax(n) {
			t.Errorf("max_concurrent_polls %s: %d executions at once", tc.limit, n)
		}
	}
}

func TestWSLimiter(t *testing.T) {
	var l wsLimiter
	limit := 2
	lim := func() int { return limit }
	ctx := context.Background()
	if n, ok := l.acquire(ctx, 1, lim); !ok || n != 1 {
		t.Fatal(n, ok)
	}
	// A weight above the limit is capped at it, and waits for the slot held.
	got := make(chan int, 1)
	go func() {
		n, _ := l.acquire(ctx, 5, lim)
		got <- n
	}()
	select {
	case <-got:
		t.Fatal("acquired while a slot is held")
	case <-time.After(50 * time.Millisecond):
	}
	l.release(1)
	if n := <-got; n != 2 {
		t.Fatalf("capped weight = %d", n)
	}
	// Waiting ends with the context.
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if _, ok := l.acquire(cctx, 1, lim); ok {
		t.Fatal("acquired over the limit")
	}
	l.release(2)
	// <= 0 is unlimited.
	limit = 0
	for range 10 {
		if _, ok := l.acquire(ctx, 1, lim); !ok {
			t.Fatal("unlimited")
		}
	}
}

// Disabling GraphQL over WebSocket by a reload closes the open sockets,
// idle ones included, instead of letting them keep running operations.
func TestWSDisabledByReload(t *testing.T) {
	f := newWSFixture(t, "")
	tok := f.token("viewer", time.Now().Add(time.Hour))
	on := f.cur.Load()
	busy := f.init(tok)
	busy.subscribe("s", `subscription { tick }`)
	busy.read()
	idle := f.init(tok)

	off := f.state(wsConfig(t, "    enabled: false\n"), "tick", "other", "slow")
	f.cur.Store(off)
	for name, w := range map[string]*testWS{"busy": busy, "idle": idle} {
		if code := w.waitClose(5 * time.Second); code != websocket.StatusGoingAway {
			t.Errorf("%s socket: close %d", name, code)
		}
	}

	// The review's probe: a query sent right after the reload on a socket
	// opened before it gets no data.
	f.cur.Store(on)
	w := f.init(tok)
	f.cur.Store(off)
	w.subscribe("q", `{ role }`)
	for m := range w.msgs {
		if m.Type == "next" {
			t.Fatalf("operation ran after subscriptions were disabled: %s", m.Payload)
		}
	}
	if w.code != websocket.StatusGoingAway {
		t.Errorf("probe socket: close %d", w.code)
	}
}

// A connection_init that arrived in time is not cut off by the init timeout
// while its role lookup is still running.
func TestWSInitTimeoutWhileAuthenticating(t *testing.T) {
	slow := func(ctx context.Context, claims map[string]any) (string, error) {
		select {
		case <-time.After(1500 * time.Millisecond):
		case <-ctx.Done():
			return "", ctx.Err()
		}
		role, _ := claims["role"].(string)
		return role, nil
	}
	f := newWSFixtureWith(t, wsConfig(t, "    connection_init_timeout_seconds: 1\n"), slow)
	w := f.dial(wsSubprotocol)
	time.Sleep(500 * time.Millisecond)
	w.sendInit(f.token("viewer", time.Now().Add(time.Hour)))
	if m := w.read(); m.Type != "connection_ack" {
		t.Fatalf("expected connection_ack, got %+v (close %d)", m, w.code)
	}
	// Without connection_init the timeout still applies.
	w = f.dial(wsSubprotocol)
	if code := w.waitClose(5 * time.Second); code != closeInitTimeout {
		t.Errorf("no init: close %d", code)
	}
}
