package server

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// Operation lifecycle and fairness: the FIFO execution limiter, re-checks
// inside it, ids reused after complete, completed operations that are still
// running, and shutdown with clients that never finish the close handshake.

// serverConn returns the gateway side of the fixture's only connection.
func (f *wsFixture) serverConn() *wsConn {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.srv.hub.mu.Lock()
		for c := range f.srv.hub.conns {
			f.srv.hub.mu.Unlock()
			return c
		}
		f.srv.hub.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatal("no server-side connection")
	return nil
}

// A request for several slots is granted in arrival order: later
// single-slot requests queue behind it instead of overtaking it forever.
func TestWSLimiterFIFO(t *testing.T) {
	var l wsLimiter
	lim := func() int { return 5 }
	ctx := context.Background()
	for range 5 {
		if _, ok := l.acquire(ctx, 1, lim); !ok {
			t.Fatal("initial slots")
		}
	}
	big := make(chan int, 1)
	go func() {
		n, _ := l.acquire(ctx, 4, lim)
		big <- n
	}()
	waitQueued(t, &l, 1)
	// A stream of single-slot requests arriving after the big one: each
	// must wait behind it.
	small := make(chan int, 10)
	for range 3 {
		go func() {
			n, _ := l.acquire(ctx, 1, lim)
			small <- n
		}()
	}
	waitQueued(t, &l, 4)
	// Free slots one by one: the big request is granted once 4 are free
	// (used drops to 1), before any small one.
	for range 4 {
		l.release(1)
	}
	select {
	case n := <-big:
		if n != 4 {
			t.Fatalf("big request got %d slots", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the weight-4 request was overtaken / starved")
	}
	select {
	case <-small:
		t.Fatal("a later single-slot request overtook the queue")
	default:
	}
	// used = 5 now (1 + 4): releasing the big one lets the small ones in.
	l.release(4)
	for range 3 {
		select {
		case <-small:
		case <-time.After(2 * time.Second):
			t.Fatal("small requests not granted")
		}
	}

	// A waiter whose context ends leaves the queue, and the one behind it
	// moves up.
	var l2 wsLimiter
	l2.acquire(ctx, 2, func() int { return 2 })
	cctx, cancel := context.WithCancel(ctx)
	gone := make(chan bool, 1)
	go func() {
		_, ok := l2.acquire(cctx, 2, func() int { return 2 })
		gone <- ok
	}()
	waitQueued(t, &l2, 1)
	next := make(chan bool, 1)
	go func() {
		_, ok := l2.acquire(ctx, 1, func() int { return 2 })
		next <- ok
	}()
	waitQueued(t, &l2, 2)
	cancel()
	if ok := <-gone; ok {
		t.Fatal("a cancelled waiter must not be granted")
	}
	l2.release(1)
	if ok := <-next; !ok {
		t.Fatal("the waiter behind a cancelled one must be granted")
	}
}

func waitQueued(t *testing.T, l *wsLimiter, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		q := len(l.queue)
		l.mu.Unlock()
		if q == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("queue never reached %d waiters", n)
}

// A query sent over a socket takes one slot per root field (capped at
// max_parallel_root_fields), and waits for slots no longer than the query
// timeout: then it ends with a "server busy" error instead of hanging.
func TestWSQueryWeightAndBusy(t *testing.T) {
	f := newWSFixture(t, "    max_concurrent_polls: 2\n")
	st := f.cur.Load()
	st.Cfg.Server.MaxParallelRootFields = 4
	st.Cfg.Database.QueryTimeoutSeconds = 1
	w := f.init(f.token("viewer", time.Now().Add(time.Hour)))
	// Hold one of the two slots: a one-field query (weight 1) still runs.
	n, _ := f.srv.hub.polls.acquire(context.Background(), 1, f.srv.hub.pollLimit)
	w.subscribe("q1", `{ role }`)
	if m := w.read(); m.ID != "q1" || m.Type != "next" {
		t.Fatalf("one-field query with a free slot: %+v %s", m, m.Payload)
	}
	w.read() // complete
	// A two-field query needs both slots: it waits, then gives up.
	start := time.Now()
	w.subscribe("q2", `{ a: role b: role }`)
	m := w.read()
	if m.ID != "q2" || m.Type != "error" || !strings.Contains(payloadString(m), "server busy") {
		t.Fatalf("two-field query without slots: %+v %s", m, m.Payload)
	}
	if d := time.Since(start); d < 900*time.Millisecond || d > 4*time.Second {
		t.Errorf("busy after %s, want about the 1s query timeout", d)
	}
	f.srv.hub.polls.release(n)
	w.subscribe("q3", `{ a: role b: role }`)
	if m := w.read(); m.ID != "q3" || m.Type != "next" {
		t.Fatalf("two-field query with both slots free: %+v %s", m, m.Payload)
	}
}

// A re-check that looks the role up takes a max_concurrent_polls slot, so
// a reload cannot make every socket hit the database at once; a re-check
// that times out is retried (nothing runs meanwhile) instead of closing the
// socket.
func TestWSReauthInsideLimiter(t *testing.T) {
	var calls atomic.Int64
	resolver := func(ctx context.Context, claims map[string]any) (string, error) {
		calls.Add(1)
		role, _ := claims["role"].(string)
		return role, nil
	}
	old := wsAuthTimeout
	wsAuthTimeout = 300 * time.Millisecond
	defer func() { wsAuthTimeout = old }()

	cfg := wsConfig(t, "    max_concurrent_polls: 1\n")
	f := newWSFixtureWith(t, cfg, resolver)
	w := f.init(f.token("viewer", time.Now().Add(time.Hour)))
	w.subscribe("s", `subscription { tick }`)
	if m := w.read(); m.Type != "next" {
		t.Fatalf("first poll: %+v", m)
	}
	before := calls.Load()

	// Take the only slot, then reload: the re-check cannot look the role
	// up until the slot is free.
	n, _ := f.srv.hub.polls.acquire(context.Background(), 1, f.srv.hub.pollLimit)
	f.cur.Store(f.state(cfg, "tick", "other", "slow"))
	f.counter.Add(1)
	time.Sleep(800 * time.Millisecond) // more than one wsAuthTimeout: retried, not closed
	if got := calls.Load(); got != before {
		t.Errorf("role lookups ran without a slot: %d -> %d", before, got)
	}
	w.quiet(50 * time.Millisecond) // still open, nothing sent on an unconfirmed identity
	f.srv.hub.polls.release(n)
	if m := w.read(); m.Type != "next" || !strings.Contains(payloadString(m), `"tick":1`) {
		t.Fatalf("after the slot frees: %+v %s", m, m.Payload)
	}
	if calls.Load() == before {
		t.Error("the re-check never looked the role up")
	}
}

// Once the server has processed a client's complete, nothing more is sent
// under that id — even when a message of the old operation was being
// written at that moment and the client reuses the id at once.
func TestWSNoSendAfterComplete(t *testing.T) {
	f := newWSFixture(t, "")
	w := f.init(f.token("viewer", time.Now().Add(time.Hour)))
	w.subscribe("x", `subscription { tick }`)
	if m := w.read(); m.Type != "next" {
		t.Fatalf("first poll: %+v", m)
	}
	c := f.serverConn()
	c.mu.Lock()
	old := c.ops["x"]
	c.mu.Unlock()
	// Pretend the old operation is mid-write: complete must wait for it.
	old.sendMu.Lock()
	w.send(map[string]any{"id": "x", "type": "complete"})
	w.subscribe("x", `subscription { other }`)
	time.Sleep(100 * time.Millisecond)
	c.mu.Lock()
	_, reused := c.ops["x"]
	c.mu.Unlock()
	if reused {
		t.Fatal("the reused id was accepted before the old operation's write finished")
	}
	old.sendMu.Unlock()
	m := w.read()
	if m.ID != "x" || m.Type != "next" || !strings.Contains(payloadString(m), `"other"`) {
		t.Fatalf("first message after the reuse: %+v %s", m, m.Payload)
	}
	old.sendMu.Lock()
	done := old.done
	old.sendMu.Unlock()
	if !done {
		t.Error("the completed operation may still send")
	}
	if c.sendLive(old, wsMessage{ID: "x", Type: "next", Payload: json.RawMessage(`{}`)}) {
		t.Error("sendLive sent for a completed operation")
	}
	f.counter.Add(1)
	w.quiet(150 * time.Millisecond) // the old tick subscription is gone
}

// max_subscriptions_per_connection counts operations whose goroutine is
// still running after the client completed them, so subscribe/complete
// loops cannot pile up goroutines on one socket (here with the per-caller
// limit off, as behind a reverse proxy).
func TestWSPerConnectionCountsRunningOps(t *testing.T) {
	f := newWSFixture(t, "    max_subscriptions_per_connection: 1\n    max_subscriptions_per_identity: -1\n")
	w := f.init(f.token("viewer", time.Now().Add(time.Hour)))
	c := f.serverConn()
	c.authMu.Lock() // a slow re-authentication: new operations wait on it
	w.subscribe("a", `subscription { tick }`)
	w.send(map[string]any{"id": "a", "type": "complete"})
	w.subscribe("b", `subscription { tick }`)
	m := w.read()
	if m.ID != "b" || m.Type != "error" || !strings.Contains(payloadString(m), "max_subscriptions_per_connection") {
		t.Fatalf("second operation while the completed one still runs: %+v %s", m, m.Payload)
	}
	c.authMu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.mu.Lock()
		running := c.running
		c.mu.Unlock()
		if running == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d operations still running", running)
		}
		time.Sleep(10 * time.Millisecond)
	}
	w.subscribe("c", `subscription { tick }`)
	if m := w.read(); m.ID != "c" || m.Type != "next" {
		t.Fatalf("after the completed operation stopped: %+v %s", m, m.Payload)
	}
}

// Shutdown honours its context even when clients never answer the close
// handshake: it cuts their sockets, stops their operations and returns
// promptly, with nothing left running.
func TestWSShutdownCutsStuckClients(t *testing.T) {
	f := newWSFixture(t, "")
	tok := f.token("viewer", time.Now().Add(time.Hour))
	for i := range 3 {
		c, _, err := f.dialRaw(wsSubprotocol, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.CloseNow() })
		ctx := context.Background()
		send := func(v any) {
			data, _ := json.Marshal(v)
			if err := c.Write(ctx, websocket.MessageText, data); err != nil {
				t.Fatal(err)
			}
		}
		send(map[string]any{"type": "connection_init", "payload": map[string]any{"Authorization": "Bearer " + tok}})
		if _, data, err := c.Read(ctx); err != nil || !strings.Contains(string(data), "connection_ack") {
			t.Fatalf("client %d init: %v %s", i, err, data)
		}
		send(map[string]any{"id": "s", "type": "subscribe", "payload": map[string]any{"query": `subscription { tick }`}})
		// ...and never read again.
	}
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_ = f.srv.Shutdown(ctx)
	if d := time.Since(start); d > 2500*time.Millisecond {
		t.Errorf("Shutdown took %s with a 500ms context", d)
	}
	f.srv.hub.mu.Lock()
	left := len(f.srv.hub.conns)
	f.srv.hub.mu.Unlock()
	if left != 0 {
		t.Errorf("%d connections still running after Shutdown", left)
	}
}
