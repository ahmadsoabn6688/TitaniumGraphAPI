package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// WebSocket client for the graphql-transport-ws endpoint (subscriptions).
//
//	ws := env.DialWS(t, map[string]any{"Authorization": "Bearer " + tok}) // init + ack
//	ws.Subscribe(t, "1", `subscription { posts_aggregate { count } }`, nil)
//	r := ws.Next(t, "1", 5*time.Second).Result(t)
//	code := ws.WaitClose(t, 10*time.Second)

// WSSubprotocol is the subprotocol the gateway speaks.
const WSSubprotocol = "graphql-transport-ws"

// WSMessage is one graphql-transport-ws message.
type WSMessage struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Result decodes a next message's payload as a GraphQL result.
func (m WSMessage) Result(t testing.TB) *Result {
	t.Helper()
	r := &Result{Status: http.StatusOK, Raw: m.Payload}
	var decoded struct {
		Data   map[string]any `json:"data"`
		Errors []GQLError     `json:"errors"`
	}
	if err := json.Unmarshal(m.Payload, &decoded); err != nil {
		t.Fatalf("decode %s payload: %v\n%s", m.Type, err, m.Payload)
	}
	r.Data, r.Errors = decoded.Data, decoded.Errors
	return r
}

// Errors decodes an error message's payload.
func (m WSMessage) Errors(t testing.TB) []GQLError {
	t.Helper()
	var errs []GQLError
	if err := json.Unmarshal(m.Payload, &errs); err != nil {
		t.Fatalf("decode error payload: %v\n%s", err, m.Payload)
	}
	return errs
}

// WSClient is one WebSocket connection to the gateway.
type WSClient struct {
	conn   *websocket.Conn
	msgs   chan WSMessage
	closed chan struct{}
	status websocket.StatusCode // close status once closed (-1 = not a close frame)
	reason string
}

// WSURL is the ws:// URL of the GraphQL endpoint.
func (e *Env) WSURL() string {
	return "ws" + strings.TrimPrefix(e.Server.URL, "http") + e.Config.Server.Path
}

// DialWSRaw opens a WebSocket without sending connection_init. headers go on
// the upgrade request; subprotocol "" offers graphql-transport-ws.
func (e *Env) DialWSRaw(t testing.TB, headers http.Header, subprotocol string) (*WSClient, *http.Response, error) {
	t.Helper()
	if subprotocol == "" {
		subprotocol = WSSubprotocol
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, e.WSURL(), &websocket.DialOptions{
		Subprotocols: []string{subprotocol},
		HTTPHeader:   headers,
	})
	if err != nil {
		return nil, resp, err
	}
	c := &WSClient{conn: conn, msgs: make(chan WSMessage, 256), closed: make(chan struct{}), status: -1}
	go c.readLoop()
	t.Cleanup(func() { c.conn.CloseNow() })
	return c, resp, nil
}

// DialWS opens a WebSocket, sends connection_init with payload and waits for
// connection_ack.
func (e *Env) DialWS(t testing.TB, payload map[string]any) *WSClient {
	t.Helper()
	c, _, err := e.DialWSRaw(t, nil, "")
	if err != nil {
		t.Fatalf("dial %s: %v", e.WSURL(), err)
	}
	c.Send(t, map[string]any{"type": "connection_init", "payload": payload})
	if m := c.Read(t, 10*time.Second); m.Type != "connection_ack" {
		t.Fatalf("expected connection_ack, got %+v", m)
	}
	return c
}

// AuthPayload is the connection_init payload carrying a bearer token ("" =
// anonymous).
func AuthPayload(token string) map[string]any {
	if token == "" {
		return map[string]any{}
	}
	return map[string]any{"Authorization": "Bearer " + token}
}

func (c *WSClient) readLoop() {
	defer close(c.closed)
	defer close(c.msgs)
	for {
		_, data, err := c.conn.Read(context.Background())
		if err != nil {
			c.status = websocket.CloseStatus(err)
			var ce websocket.CloseError
			if errors.As(err, &ce) {
				c.reason = ce.Reason
			}
			return
		}
		var m WSMessage
		if json.Unmarshal(data, &m) == nil {
			c.msgs <- m
		}
	}
}

// Send writes one message.
func (c *WSClient) Send(t testing.TB, msg map[string]any) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("websocket write: %v", err)
	}
}

// Subscribe starts an operation.
func (c *WSClient) Subscribe(t testing.TB, id, query string, vars map[string]any) {
	t.Helper()
	c.Send(t, map[string]any{"id": id, "type": "subscribe", "payload": map[string]any{"query": query, "variables": vars}})
}

// Complete stops an operation.
func (c *WSClient) Complete(t testing.TB, id string) {
	t.Helper()
	c.Send(t, map[string]any{"id": id, "type": "complete"})
}

// Read returns the next message (of any operation), failing the test when
// none arrives in time or the socket closes.
func (c *WSClient) Read(t testing.TB, timeout time.Duration) WSMessage {
	t.Helper()
	select {
	case m, ok := <-c.msgs:
		if !ok {
			t.Fatalf("websocket closed (status %d %q) while waiting for a message", c.status, c.reason)
		}
		return m
	case <-time.After(timeout):
		t.Fatalf("no websocket message within %s", timeout)
	}
	return WSMessage{}
}

// Next returns the next message for operation id, failing on a message for
// another operation.
func (c *WSClient) Next(t testing.TB, id string, timeout time.Duration) WSMessage {
	t.Helper()
	m := c.Read(t, timeout)
	if m.ID != id {
		t.Fatalf("expected a message for %q, got %+v (payload %s)", id, m, m.Payload)
	}
	return m
}

// Quiet asserts that no message arrives within d.
func (c *WSClient) Quiet(t testing.TB, d time.Duration) {
	t.Helper()
	select {
	case m, ok := <-c.msgs:
		if ok {
			t.Fatalf("expected no message, got %+v (payload %s)", m, m.Payload)
		}
		t.Fatalf("websocket closed (status %d %q) unexpectedly", c.status, c.reason)
	case <-time.After(d):
	}
}

// WaitClose waits for the server to close the socket and returns the close
// status and reason. Messages arriving meanwhile are discarded.
func (c *WSClient) WaitClose(t testing.TB, timeout time.Duration) (websocket.StatusCode, string) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case <-c.msgs:
		case <-c.closed:
			return c.status, c.reason
		case <-deadline:
			t.Fatalf("websocket not closed within %s", timeout)
		}
	}
}

// Close closes the client side.
func (c *WSClient) Close() { _ = c.conn.Close(websocket.StatusNormalClosure, "") }
