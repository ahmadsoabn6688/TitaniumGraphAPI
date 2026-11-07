package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/gqlerrors"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"

	"gqlgate/auth"
	"gqlgate/config"
	"gqlgate/rbac"
)

// GraphQL over WebSocket: the graphql-transport-ws protocol (the one the
// graphql-ws client library speaks; the legacy subscriptions-transport-ws
// "graphql-ws" subprotocol is not supported) on the GraphQL path.
//
//	client                         server
//	connection_init {payload} ──►  verify the token in the payload → role
//	                          ◄──  connection_ack            (or close 4403)
//	subscribe {id, payload}   ──►  validate against the role's schema
//	                          ◄──  next {id, payload}        (each changed result)
//	                          ◄──  error {id, payload}       (invalid operation)
//	complete {id}             ──►  stop that operation
//	ping / pong               ◄─►  answered / ignored
//
// A subscription operation is a live query: it is re-executed every polling
// interval with a fresh request context and pushed only when the encoded
// result differs from the last one sent (SHA-256 of the JSON). Query and
// mutation operations run once (next + complete).
//
// Authentication comes from the connection_init payload — browsers cannot
// set headers on a WebSocket — as {"Authorization": "Bearer <jwt>"} or
// {"headers": {"Authorization": …}}, plus the role header the same way; the
// upgrade request's own headers are the fallback for non-browser clients.
// The socket is closed with 4401 when the token expires and with 4403 when
// a periodic re-check (server.subscriptions.reauth_interval_seconds) no
// longer accepts the caller: the token stops verifying, the role lookup
// fails or yields another role, or the role is gone after a reload.
//
// Limits: a socket counts towards max_pending_connections from the upgrade
// until connection_init succeeds, and from then on towards max_connections
// and its caller's max_connections_per_identity — so unauthenticated sockets
// cannot crowd out authenticated ones. A role with no Subscription root is
// refused at connection_init. Every execution (a poll, or a query or
// mutation sent over a socket) takes a slot of max_concurrent_polls, so
// live queries cannot take every pooled connection from HTTP requests.
//
// Hot reload: every poll re-reads the serving state. When it changed, the
// connection re-authenticates against the new verifier, and each operation
// is re-validated against its role's new schema before it runs again (an
// operation the new schema rejects ends with an error message; its interval
// follows the new config). A subscription never keeps running on
// permissions a reload has withdrawn.

const wsSubprotocol = "graphql-transport-ws"

// graphql-transport-ws close codes.
const (
	closeBadRequest    websocket.StatusCode = 4400
	closeUnauthorized  websocket.StatusCode = 4401
	closeForbidden     websocket.StatusCode = 4403
	closeSubprotocol   websocket.StatusCode = 4406
	closeInitTimeout   websocket.StatusCode = 4408
	closeDuplicateID   websocket.StatusCode = 4409
	closeTooManyInits  websocket.StatusCode = 4429
	closeInternalError websocket.StatusCode = 4500
)

// wsWriteTimeout bounds one message write to a slow client.
const wsWriteTimeout = 10 * time.Second

// wsAuthTimeout bounds one (re-)authentication (role lookups).
const wsAuthTimeout = 10 * time.Second

func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// wsHub owns the open WebSocket connections of one Server.
type wsHub struct {
	s       *srv
	origins wsOrigins

	mu      sync.Mutex
	conns   map[*wsConn]struct{}
	pending int                 // sockets not (yet) past connection_init, upgrades in progress included
	active  int                 // sockets past connection_init
	callers map[string]*wsUsage // per identityKey
	closing bool
	wg      sync.WaitGroup

	polls wsLimiter // max_concurrent_polls
}

// wsUsage is what one caller (identityKey) holds open.
type wsUsage struct {
	conns int // initialised sockets
	ops   int // running operations over all of them
}

func newWSHub(s *srv, static *config.Config) *wsHub {
	return &wsHub{s: s, origins: newWSOrigins(static.Server.CORS), conns: map[*wsConn]struct{}{}, callers: map[string]*wsUsage{}}
}

// wsOrigins is the set of browser origins allowed to open a WebSocket
// besides the gateway's own: server.cors.allowed_origins when CORS is
// enabled, compared as whole origins (scheme, host and port) exactly like
// the HTTP CORS middleware does, "*" allowing any.
type wsOrigins struct {
	all     bool
	allowed map[string]bool
}

func newWSOrigins(cors config.CORS) wsOrigins {
	o := wsOrigins{allowed: map[string]bool{}}
	if !cors.Enabled {
		return o
	}
	for _, v := range cors.AllowedOrigins {
		if v == "*" {
			o.all = true
		}
		o.allowed[v] = true
	}
	return o
}

// allow reports whether an upgrade request's Origin may connect: no Origin
// (a non-browser client), an allowed origin, or the same host as the
// request (the gateway's own pages).
func (o wsOrigins) allow(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || o.all || o.allowed[origin] {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// identityKey is the caller a connection counts against for the
// per-identity limits: the token's sub claim, or — for a caller without one,
// such as the anonymous role — the role plus the client address (behind a
// reverse proxy that is the proxy's address).
func identityKey(id *rbac.Identity, remoteAddr string) string {
	if sub, ok := id.Claims["sub"]; ok && sub != nil {
		if s := fmt.Sprint(sub); s != "" {
			return "sub:" + s
		}
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return "addr:" + id.Role + "@" + host
}

// admit moves an authenticated connection from the pending count to the
// initialised ones, unless that would exceed max_connections or its
// caller's max_connections_per_identity.
func (h *wsHub) admit(c *wsConn, key string, sc config.Subscriptions) (websocket.StatusCode, string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	u := h.callers[key]
	switch {
	case h.closing:
		return websocket.StatusGoingAway, "server shutting down", false
	case sc.MaxConnections > 0 && h.active >= sc.MaxConnections:
		return websocket.StatusTryAgainLater, "too many WebSocket connections (server.subscriptions.max_connections)", false
	case u != nil && sc.MaxConnectionsPerIdentity > 0 && u.conns >= sc.MaxConnectionsPerIdentity:
		return websocket.StatusTryAgainLater, "too many WebSocket connections for this caller (server.subscriptions.max_connections_per_identity)", false
	}
	if u == nil {
		u = &wsUsage{}
		h.callers[key] = u
	}
	u.conns++
	h.pending--
	h.active++
	c.key, c.admitted = key, true
	return 0, "", true
}

// release forgets a connection that ended (under h.mu).
func (h *wsHub) release(c *wsConn) {
	delete(h.conns, c)
	if !c.admitted {
		h.pending--
		return
	}
	h.active--
	if u := h.callers[c.key]; u != nil {
		u.conns--
		if u.conns <= 0 && u.ops <= 0 {
			delete(h.callers, c.key)
		}
	}
}

// reserveOp counts one more running operation for a caller unless that
// exceeds max (<= 0 = unlimited).
func (h *wsHub) reserveOp(key string, max int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	u := h.callers[key]
	if u == nil {
		u = &wsUsage{}
		h.callers[key] = u
	}
	if max > 0 && u.ops >= max {
		return false
	}
	u.ops++
	return true
}

func (h *wsHub) releaseOp(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if u := h.callers[key]; u != nil {
		u.ops--
		if u.conns <= 0 && u.ops <= 0 {
			delete(h.callers, key)
		}
	}
}

// wsLimiter is a counting semaphore whose size is read on every acquire, so
// a reload that changes max_concurrent_polls applies to the next poll.
type wsLimiter struct {
	mu   sync.Mutex
	used int
	wake chan struct{} // closed (and dropped) on every release
}

// acquire takes n slots of limit() (<= 0 = unlimited), waiting until they
// are free or ctx ends (ok false). n is capped at the limit, and a request
// is granted whenever nothing else holds a slot, so a shrunken limit never
// deadlocks. It returns the number of slots taken, for release.
func (l *wsLimiter) acquire(ctx context.Context, n int, limit func() int) (int, bool) {
	for {
		l.mu.Lock()
		max := limit()
		if max > 0 && n > max {
			n = max
		}
		if max <= 0 || l.used == 0 || l.used+n <= max {
			l.used += n
			l.mu.Unlock()
			return n, true
		}
		if l.wake == nil {
			l.wake = make(chan struct{})
		}
		wake := l.wake
		l.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			return 0, false
		}
	}
}

func (l *wsLimiter) release(n int) {
	l.mu.Lock()
	l.used -= n
	if l.wake != nil {
		close(l.wake)
		l.wake = nil
	}
	l.mu.Unlock()
}

// serve upgrades one request and runs the connection until it closes.
func (h *wsHub) serve(w http.ResponseWriter, r *http.Request) {
	sc := h.s.current().Cfg.Server.Subscriptions
	if !sc.On() {
		auth.WriteError(w, http.StatusBadRequest, "GraphQL over WebSocket is disabled (server.subscriptions.enabled)")
		return
	}
	if !h.origins.allow(r) {
		auth.WriteError(w, http.StatusForbidden, "WebSocket Origin not allowed (server.cors.allowed_origins)")
		return
	}
	h.mu.Lock()
	switch {
	case h.closing:
		h.mu.Unlock()
		auth.WriteError(w, http.StatusServiceUnavailable, "server is shutting down")
		return
	case sc.MaxPendingConnections > 0 && h.pending >= sc.MaxPendingConnections:
		h.mu.Unlock()
		auth.WriteError(w, http.StatusServiceUnavailable, "too many WebSocket connections awaiting connection_init (server.subscriptions.max_pending_connections)")
		return
	}
	h.pending++
	h.wg.Add(1)
	h.mu.Unlock()
	defer h.wg.Done()

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{wsSubprotocol},
		// The Origin was checked above against whole origins (the
		// library's OriginPatterns compare hosts only).
		InsecureSkipVerify: true,
	})
	if err != nil {
		h.mu.Lock()
		h.pending--
		h.mu.Unlock()
		return // Accept already answered the request
	}
	ctx, cancel := context.WithCancel(r.Context())
	c := &wsConn{hub: h, ws: ws, ctx: ctx, cancel: cancel, ops: map[string]*wsOp{}, upgrade: r.Header.Clone(),
		remoteAddr: r.RemoteAddr, closeDone: make(chan struct{})}

	h.mu.Lock()
	closing := h.closing
	h.conns[c] = struct{}{}
	h.mu.Unlock()
	if closing {
		c.closeWith(websocket.StatusGoingAway, "server shutting down")
	}
	defer func() {
		h.mu.Lock()
		h.release(c)
		h.mu.Unlock()
	}()
	if ws.Subprotocol() != wsSubprotocol {
		c.closeWith(closeSubprotocol, "Subprotocol not acceptable")
	}
	c.run()
}

// shutdown closes every connection with 1001 and waits for them.
func (h *wsHub) shutdown(ctx context.Context) error {
	h.mu.Lock()
	h.closing = true
	conns := make([]*wsConn, 0, len(h.conns))
	for c := range h.conns {
		conns = append(conns, c)
	}
	h.mu.Unlock()
	for _, c := range conns {
		c.closeWith(websocket.StatusGoingAway, "server shutting down")
	}
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		for _, c := range conns {
			c.ws.CloseNow()
		}
		return ctx.Err()
	}
}

// wsConn is one WebSocket connection.
type wsConn struct {
	hub     *wsHub
	ws      *websocket.Conn
	ctx     context.Context // ends when the connection does
	cancel  context.CancelFunc
	upgrade http.Header // the upgrade request's headers (auth fallback)

	remoteAddr string
	// Set by wsHub.admit, under wsHub.mu: the connection counts towards
	// max_connections and its caller's limits under key.
	admitted bool
	key      string

	initSeen atomic.Bool // connection_init received (it may still be authenticating)
	acked    atomic.Bool // connection_ack sent: operations allowed
	closing  atomic.Bool // closeWith was called: run nothing more

	// Authentication state, refreshed by authorize.
	authMu  sync.Mutex
	headers http.Header // Authorization + role header used to authenticate
	st      *State
	id      *rbac.Identity
	authAt  time.Time
	expiry  *time.Timer

	mu  sync.Mutex
	ops map[string]*wsOp
	wg  sync.WaitGroup // running operations

	closeOnce sync.Once
	closeDone chan struct{} // closed when the close handshake closeWith started is over
}

// wsOp is one running operation (subscribe message) of a connection.
type wsOp struct {
	id      string
	query   string
	vars    map[string]any
	opName  string
	ctx     context.Context
	cancel  context.CancelFunc
	removed bool // under wsConn.mu: completed by the client
}

// wsMessage is one graphql-transport-ws message.
type wsMessage struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

func (c *wsConn) run() {
	defer func() {
		if c.closing.Load() {
			// Let the close frame (with its status code) go out before
			// the connection is torn down.
			select {
			case <-c.closeDone:
			case <-time.After(15 * time.Second):
			}
		}
		c.cancel()
		c.wg.Wait()
		c.authMu.Lock()
		if c.expiry != nil {
			c.expiry.Stop()
		}
		c.authMu.Unlock()
		c.ws.CloseNow()
	}()
	sc := c.hub.s.current().Cfg.Server.Subscriptions
	c.ws.SetReadLimit(maxBodyBytes)

	// 4408 means no connection_init arrived in time; one that did is still
	// authenticating (bounded by wsAuthTimeout) and settles the socket itself.
	initTimer := time.AfterFunc(time.Duration(sc.ConnectionInitTimeoutSeconds)*time.Second, func() {
		if !c.initSeen.Load() {
			c.closeWith(closeInitTimeout, "Connection initialisation timeout")
		}
	})
	defer initTimer.Stop()
	if sc.KeepAliveSeconds > 0 {
		go c.keepAlive(time.Duration(sc.KeepAliveSeconds)*time.Second, time.Duration(sc.PingTimeoutSeconds)*time.Second)
	}
	go c.watchEnabled()

	for {
		typ, data, err := c.ws.Read(c.ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			c.closeWith(closeBadRequest, "Invalid message received: binary frames are not supported")
			return
		}
		if !c.handle(data) {
			return
		}
	}
}

// keepAlive pings the client; an unanswered ping closes the connection.
func (c *wsConn) keepAlive(every, timeout time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(c.ctx, timeout)
			err := c.ws.Ping(ctx)
			cancel()
			if err != nil {
				if c.ctx.Err() == nil {
					c.closeWith(websocket.StatusPolicyViolation, "ping timeout")
				}
				return
			}
		}
	}
}

// wsEnabledCheck is how often an open socket checks that a reload has not
// turned server.subscriptions.enabled off.
const wsEnabledCheck = time.Second

const wsDisabledReason = "GraphQL over WebSocket is disabled (server.subscriptions.enabled)"

// watchEnabled closes the connection (1001) once a reload disables GraphQL
// over WebSocket, idle sockets included.
func (c *wsConn) watchEnabled() {
	t := time.NewTicker(wsEnabledCheck)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			if !c.hub.s.current().Cfg.Server.Subscriptions.On() {
				c.closeWith(websocket.StatusGoingAway, wsDisabledReason)
				return
			}
		}
	}
}

// closeWith starts closing the connection with a status code (once); the
// read loop then ends and every operation stops.
func (c *wsConn) closeWith(code websocket.StatusCode, reason string) {
	c.closeOnce.Do(func() {
		c.closing.Store(true)
		if len(reason) > 123 { // the limit of a close frame's reason
			reason = reason[:120] + "..."
		}
		go func() {
			defer close(c.closeDone)
			_ = c.ws.Close(code, reason)
			c.cancel()
		}()
	})
}

// handle processes one client message; false ends the read loop.
func (c *wsConn) handle(data []byte) bool {
	var msg wsMessage
	if err := json.Unmarshal(data, &msg); err != nil || msg.Type == "" {
		c.closeWith(closeBadRequest, "Invalid message received")
		return false
	}
	switch msg.Type {
	case "connection_init":
		if c.initSeen.Swap(true) {
			c.closeWith(closeTooManyInits, "Too many initialisation requests")
			return false
		}
		return c.connectionInit(msg.Payload)
	case "ping":
		c.send(wsMessage{Type: "pong"})
	case "pong":
	case "subscribe":
		if !c.acked.Load() {
			c.closeWith(closeUnauthorized, "Unauthorized")
			return false
		}
		return c.subscribe(msg)
	case "complete":
		c.mu.Lock()
		op := c.ops[msg.ID]
		if op != nil {
			op.removed = true
			delete(c.ops, msg.ID)
		}
		c.mu.Unlock()
		if op != nil {
			op.cancel()
		}
	default:
		c.closeWith(closeBadRequest, "Invalid message received: unknown type "+msg.Type)
		return false
	}
	return true
}

// connectionInit authenticates the connection from the connection_init
// payload and acknowledges it.
func (c *wsConn) connectionInit(payload json.RawMessage) bool {
	st := c.hub.s.current()
	if !st.Cfg.Server.Subscriptions.On() {
		c.closeWith(websocket.StatusGoingAway, wsDisabledReason)
		return false
	}
	headers, err := initHeaders(payload, c.upgrade, st.Verifier.RoleHeader())
	if err != nil {
		c.closeWith(closeBadRequest, "Invalid message received: "+err.Error())
		return false
	}
	ctx, cancel := context.WithTimeout(c.ctx, wsAuthTimeout)
	id, _, err := st.Verifier.IdentifyHeaders(ctx, headers)
	cancel()
	if err == nil {
		if schema, ok := st.Schemas[id.Role]; !ok {
			err = fmt.Errorf("no schema for role %s", id.Role)
		} else if schema.SubscriptionType() == nil {
			// Nothing to subscribe to: such a caller has no reason to hold
			// a socket (its queries go over HTTP).
			err = fmt.Errorf("role %s has no subscriptions", id.Role)
		}
	}
	if err != nil {
		c.logDebug("websocket connection_init rejected", "err", err)
		c.closeWith(closeForbidden, "Forbidden: "+err.Error())
		return false
	}
	if code, reason, ok := c.hub.admit(c, identityKey(id, c.remoteAddr), st.Cfg.Server.Subscriptions); !ok {
		c.logDebug("websocket connection_init over a limit", "reason", reason)
		c.closeWith(code, reason)
		return false
	}

	c.authMu.Lock()
	c.headers, c.st, c.id, c.authAt = headers, st, id, time.Now()
	if deadline, ok := st.Verifier.Deadline(id); ok {
		c.expiry = time.AfterFunc(time.Until(deadline), func() {
			c.closeWith(closeUnauthorized, "Token expired")
		})
	}
	c.authMu.Unlock()

	c.acked.Store(true)
	c.send(wsMessage{Type: "connection_ack"})
	return true
}

// initHeaders reads the Authorization and role headers from a
// connection_init payload: top-level keys or a nested "headers" object,
// matched case-insensitively. A header the payload does not carry falls back
// to the upgrade request's.
func initHeaders(payload json.RawMessage, upgrade http.Header, roleHeader string) (http.Header, error) {
	var fields map[string]any
	if len(payload) > 0 && string(payload) != "null" {
		if err := json.Unmarshal(payload, &fields); err != nil {
			return nil, fmt.Errorf("connection_init payload must be an object")
		}
	}
	nested, _ := fields["headers"].(map[string]any)
	out := http.Header{}
	for _, name := range []string{"Authorization", roleHeader} {
		val, found, err := payloadHeader(fields, nested, name)
		if err != nil {
			return nil, err
		}
		if !found {
			val = upgrade.Get(name)
		}
		if val != "" {
			out.Set(name, val)
		}
	}
	return out, nil
}

func payloadHeader(fields, nested map[string]any, name string) (string, bool, error) {
	for _, m := range []map[string]any{fields, nested} {
		for k, v := range m {
			if !strings.EqualFold(k, name) {
				continue
			}
			s, ok := v.(string)
			if !ok {
				return "", false, fmt.Errorf("connection_init payload %s must be a string", name)
			}
			return s, true, nil
		}
	}
	return "", false, nil
}

// subscribe starts one operation.
func (c *wsConn) subscribe(msg wsMessage) bool {
	if msg.ID == "" {
		c.closeWith(closeBadRequest, "Invalid message received: subscribe without id")
		return false
	}
	var req graphqlRequest
	if err := json.Unmarshal(msg.Payload, &req); err != nil {
		c.closeWith(closeBadRequest, "Invalid message received: "+err.Error())
		return false
	}
	sc := c.hub.s.current().Cfg.Server.Subscriptions
	max := sc.MaxPerConnection
	c.mu.Lock()
	if _, dup := c.ops[msg.ID]; dup {
		c.mu.Unlock()
		c.closeWith(closeDuplicateID, "Subscriber for "+msg.ID+" already exists")
		return false
	}
	if len(c.ops) >= max {
		c.mu.Unlock()
		c.sendErrors(msg.ID, []gqlerrors.FormattedError{gqlerrors.NewFormattedError(
			fmt.Sprintf("too many operations on this connection (server.subscriptions.max_subscriptions_per_connection is %d)", max))})
		return true
	}
	if !c.hub.reserveOp(c.key, sc.MaxPerIdentity) {
		c.mu.Unlock()
		c.sendErrors(msg.ID, []gqlerrors.FormattedError{gqlerrors.NewFormattedError(
			fmt.Sprintf("too many operations for this caller (server.subscriptions.max_subscriptions_per_identity is %d)", sc.MaxPerIdentity))})
		return true
	}
	ctx, cancel := context.WithCancel(c.ctx)
	op := &wsOp{id: msg.ID, query: req.Query, vars: req.Variables, opName: req.OperationName, ctx: ctx, cancel: cancel}
	c.ops[msg.ID] = op
	c.wg.Add(1)
	c.mu.Unlock()
	go c.runOp(op)
	return true
}

// finishOp forgets an operation that ended on the server side. It reports
// whether the client had not completed it already (so a final message may
// still be sent for it).
func (c *wsConn) finishOp(op *wsOp) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if op.removed {
		return false
	}
	op.removed = true
	delete(c.ops, op.id)
	return true
}

// prepared is an operation parsed and validated against one role's schema.
type prepared struct {
	st       *State
	role     string
	schema   graphql.Schema
	doc      *ast.Document
	opType   string
	interval time.Duration
}

// prepare parses and validates an operation for the role in st, the way an
// HTTP request is checked (depth limit, schema validation), and for a
// subscription also requires a single root field and looks up its interval.
func prepare(st *State, role string, op *wsOp) (*prepared, []gqlerrors.FormattedError) {
	schema, ok := st.Schemas[role]
	if !ok {
		return nil, []gqlerrors.FormattedError{gqlerrors.NewFormattedError("no schema for role " + role)}
	}
	if strings.TrimSpace(op.query) == "" {
		return nil, []gqlerrors.FormattedError{gqlerrors.NewFormattedError("request has no query")}
	}
	if err := checkDepth(op.query, st.Cfg.Server.MaxQueryDepth); err != nil {
		return nil, []gqlerrors.FormattedError{gqlerrors.NewFormattedError(err.Error())}
	}
	doc, err := parser.Parse(parser.ParseParams{Source: source.NewSource(&source.Source{
		Body: []byte(op.query),
		Name: "GraphQL request",
	})})
	if err != nil {
		return nil, gqlerrors.FormatErrors(err)
	}
	if vr := graphql.ValidateDocument(&schema, doc, nil); !vr.IsValid {
		return nil, vr.Errors
	}
	operation, err := findOperation(doc, op.opName)
	if err != nil {
		return nil, []gqlerrors.FormattedError{gqlerrors.NewFormattedError(err.Error())}
	}
	p := &prepared{st: st, role: role, schema: schema, doc: doc, opType: operation.Operation}
	// Validation does not reject an operation whose root type the schema
	// lacks (the executor would, with a vaguer message).
	if p.opType == ast.OperationTypeSubscription && schema.SubscriptionType() == nil {
		return nil, []gqlerrors.FormattedError{gqlerrors.NewFormattedError(
			"role " + role + " has no subscriptions (grant select.subscribe on a table)")}
	}
	if p.opType == ast.OperationTypeMutation && schema.MutationType() == nil {
		return nil, []gqlerrors.FormattedError{gqlerrors.NewFormattedError("role " + role + " has no mutations")}
	}
	if p.opType == ast.OperationTypeSubscription {
		names := rootFieldNames(operation.SelectionSet, fragmentsOf(doc))
		if len(names) != 1 {
			return nil, []gqlerrors.FormattedError{gqlerrors.NewFormattedError(
				fmt.Sprintf("a subscription must select exactly one root field (got %d)", len(names)))}
		}
		p.interval = st.PollIntervals[role][names[0]]
		if p.interval <= 0 {
			p.interval = st.Cfg.Server.Subscriptions.PollInterval()
		}
	}
	return p, nil
}

// findOperation picks the operation to run, as the executor does.
func findOperation(doc *ast.Document, name string) (*ast.OperationDefinition, error) {
	var found *ast.OperationDefinition
	for _, def := range doc.Definitions {
		op, ok := def.(*ast.OperationDefinition)
		if !ok {
			continue
		}
		if name == "" {
			if found != nil {
				return nil, errors.New("Must provide operation name if query contains multiple operations.")
			}
			found = op
		} else if op.Name != nil && op.Name.Value == name {
			found = op
		}
	}
	if found == nil {
		if name != "" {
			return nil, fmt.Errorf("Unknown operation named %q.", name)
		}
		return nil, errors.New("Must provide an operation.")
	}
	return found, nil
}

func fragmentsOf(doc *ast.Document) map[string]*ast.FragmentDefinition {
	out := map[string]*ast.FragmentDefinition{}
	for _, def := range doc.Definitions {
		if f, ok := def.(*ast.FragmentDefinition); ok && f.Name != nil {
			out[f.Name.Value] = f
		}
	}
	return out
}

// rootFieldNames lists the distinct root fields (by field name, not alias)
// of a selection set, following fragments (cycles are rejected by
// validation before this runs; seen guards anyway).
func rootFieldNames(set *ast.SelectionSet, frags map[string]*ast.FragmentDefinition) []string {
	var names []string
	seenName := map[string]bool{}
	seenFrag := map[string]bool{}
	var walk func(*ast.SelectionSet)
	walk = func(set *ast.SelectionSet) {
		if set == nil {
			return
		}
		for _, s := range set.Selections {
			switch n := s.(type) {
			case *ast.Field:
				if n.Name == nil {
					continue
				}
				key := n.Name.Value
				if n.Alias != nil {
					key += " as " + n.Alias.Value
				}
				if !seenName[key] {
					seenName[key] = true
					names = append(names, n.Name.Value)
				}
			case *ast.InlineFragment:
				walk(n.SelectionSet)
			case *ast.FragmentSpread:
				if n.Name == nil || seenFrag[n.Name.Value] {
					continue
				}
				seenFrag[n.Name.Value] = true
				if f := frags[n.Name.Value]; f != nil {
					walk(f.SelectionSet)
				}
			}
		}
	}
	walk(set)
	return names
}

// runOp runs one operation: once for a query or mutation, on an interval
// for a subscription.
func (c *wsConn) runOp(op *wsOp) {
	defer c.wg.Done()
	defer c.hub.releaseOp(c.key)
	defer op.cancel()

	st, id, ok := c.authorize()
	if !ok {
		return
	}
	p, errs := prepare(st, id.Role, op)
	if errs != nil {
		if c.finishOp(op) {
			c.sendErrors(op.id, errs)
		}
		return
	}
	if p.opType != ast.OperationTypeSubscription {
		out, ok := c.execute(op, p, id)
		if ok && c.finishOp(op) {
			c.send(wsMessage{ID: op.id, Type: "next", Payload: out})
			c.send(wsMessage{ID: op.id, Type: "complete"})
		}
		return
	}

	var last [sha256.Size]byte
	sent := false
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-op.ctx.Done():
			return
		case <-timer.C:
		}
		st, id, ok := c.authorize()
		if !ok {
			return
		}
		if st != p.st {
			// A reload swapped the serving state: re-validate against the
			// role's new schema (and pick up its new interval).
			np, errs := prepare(st, id.Role, op)
			if errs != nil {
				if c.finishOp(op) {
					c.sendErrors(op.id, errs)
				}
				return
			}
			p = np
		}
		out, ok := c.execute(op, p, id)
		if !ok {
			return
		}
		if sum := sha256.Sum256(out); !sent || sum != last {
			c.mu.Lock()
			live := !op.removed
			c.mu.Unlock()
			if !live {
				return
			}
			if !c.send(wsMessage{ID: op.id, Type: "next", Payload: out}) {
				return
			}
			last, sent = sum, true
		}
		timer.Reset(p.interval)
	}
}

// execute runs a prepared operation once and encodes its result. ok is false
// when the operation (or the connection) ended meanwhile.
func (c *wsConn) execute(op *wsOp, p *prepared, id *rbac.Identity) (json.RawMessage, bool) {
	// A query may run its root fields in parallel, each on its own pooled
	// connection: it takes that many slots of max_concurrent_polls.
	weight := 1
	if p.opType == ast.OperationTypeQuery && p.st.Cfg.Server.MaxParallelRootFields > 1 {
		weight = p.st.Cfg.Server.MaxParallelRootFields
	}
	n, ok := c.hub.polls.acquire(op.ctx, weight, func() int {
		return c.hub.s.current().Cfg.Server.Subscriptions.MaxConcurrentPolls
	})
	if !ok {
		return nil, false
	}
	defer c.hub.polls.release(n)
	ctx, cancel := requestContext(op.ctx, p.st, id)
	defer cancel()
	start := time.Now()
	result := graphql.Execute(graphql.ExecuteParams{
		Schema:        p.schema,
		AST:           p.doc,
		OperationName: op.opName,
		Args:          op.vars,
		Context:       ctx,
	})
	if op.ctx.Err() != nil {
		return nil, false
	}
	out, err := c.hub.s.encodeResult(ctx, p.st, result, id.Role, op.opName, start)
	if err != nil {
		c.closeWith(closeInternalError, "could not encode the response")
		return nil, false
	}
	return out, true
}

// authorize returns the state and identity to run the next execution with.
// It re-authenticates when the serving state changed (hot reload) or the
// re-check interval passed, closing the connection when the caller is no
// longer accepted (4401 for an expired token, 4403 otherwise).
func (c *wsConn) authorize() (*State, *rbac.Identity, bool) {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	if c.ctx.Err() != nil || c.closing.Load() {
		return nil, nil, false
	}
	st := c.hub.s.current()
	if !st.Cfg.Server.Subscriptions.On() {
		c.closeWith(websocket.StatusGoingAway, wsDisabledReason)
		return nil, nil, false
	}
	every := time.Duration(st.Cfg.Server.Subscriptions.ReauthIntervalSeconds) * time.Second
	if st == c.st && time.Since(c.authAt) < every {
		return c.st, c.id, true
	}
	ctx, cancel := context.WithTimeout(c.ctx, wsAuthTimeout)
	id, _, err := st.Verifier.IdentifyHeaders(ctx, c.headers)
	cancel()
	if err != nil {
		if c.ctx.Err() != nil {
			return nil, nil, false
		}
		c.logDebug("websocket re-authentication failed", "err", err)
		if auth.IsExpired(err) {
			c.closeWith(closeUnauthorized, "Token expired")
		} else {
			c.closeWith(closeForbidden, "Forbidden: "+err.Error())
		}
		return nil, nil, false
	}
	if id.Role != c.id.Role {
		c.closeWith(closeForbidden, fmt.Sprintf("Forbidden: the role changed from %s to %s; reconnect", c.id.Role, id.Role))
		return nil, nil, false
	}
	if _, ok := st.Schemas[id.Role]; !ok {
		c.closeWith(closeForbidden, "Forbidden: no schema for role "+id.Role)
		return nil, nil, false
	}
	c.st, c.id, c.authAt = st, id, time.Now()
	return st, id, true
}

// send writes one message; false when the connection is gone.
func (c *wsConn) send(msg wsMessage) bool {
	data, err := json.Marshal(msg)
	if err != nil {
		c.closeWith(closeInternalError, "could not encode a message")
		return false
	}
	ctx, cancel := context.WithTimeout(c.ctx, wsWriteTimeout)
	defer cancel()
	if err := c.ws.Write(ctx, websocket.MessageText, data); err != nil {
		c.closeWith(websocket.StatusInternalError, "write failed")
		return false
	}
	return true
}

func (c *wsConn) sendErrors(id string, errs []gqlerrors.FormattedError) {
	payload, err := json.Marshal(errs)
	if err != nil {
		c.closeWith(closeInternalError, "could not encode a message")
		return
	}
	c.send(wsMessage{ID: id, Type: "error", Payload: payload})
}

func (c *wsConn) logDebug(msg string, args ...any) {
	if l := c.hub.s.logger; l != nil {
		l.Debug(msg, args...)
	}
}
