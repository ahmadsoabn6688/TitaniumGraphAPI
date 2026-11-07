package schema

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strconv"
)

// Cursor pagination on TiDB uses the KEYSET (seek) method on the clustered
// primary key: each page is `WHERE <filter> AND (pk...) > (cursor...) ORDER BY
// pk LIMIT n`. Because TiDB stores rows in clustered-PK order, this is a range
// scan with no sort and no offset scan — O(page) regardless of how deep the
// client has paged, which is what makes it viable over billions of rows.
//
// The cursor carries the primary-key values of the last row of the previous
// page (as strings, to avoid float64 precision loss on large BIGINT ids;
// raw-byte keys base64-encoded, so they survive JSON exactly) plus
// a "shape" hash of the table+filter, so a cursor can't be misapplied to a
// different query (that is rejected rather than silently mispaging).

type cursorData struct {
	Keys []string `json:"k"`
	// Bin lists the positions in Keys holding raw bytes (a BINARY /
	// VARBINARY / BLOB key), base64-encoded: JSON strings must be valid
	// UTF-8, and encoding/json would otherwise replace every invalid byte
	// with U+FFFD — seeking after a different key than the one read.
	Bin   []int  `json:"b,omitempty"`
	Shape string `json:"s"`
}

// encodeCursor builds the opaque token from the last row's key values, as
// cursorKey renders them (string or []byte).
func encodeCursor(keys []any, shape string) string {
	c := cursorData{Keys: make([]string, len(keys)), Shape: shape}
	for i, k := range keys {
		switch v := k.(type) {
		case []byte:
			c.Keys[i] = base64.StdEncoding.EncodeToString(v)
			c.Bin = append(c.Bin, i)
		case string:
			c.Keys[i] = v
		default:
			c.Keys[i] = stringifyKey(v)
		}
	}
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor parses a cursor and verifies it belongs to the current query
// shape, returning the key values to seek after: strings, and []byte for
// raw-byte keys (bound as bytes, so the comparison stays binary-exact).
func decodeCursor(cursor, shape string, keyLen int) ([]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor")
	}
	var c cursorData
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("invalid cursor")
	}
	if c.Shape != shape {
		return nil, fmt.Errorf("cursor does not match this query's filter; start a fresh page without `after`")
	}
	if len(c.Keys) != keyLen {
		return nil, fmt.Errorf("invalid cursor")
	}
	out := make([]any, len(c.Keys))
	for i, k := range c.Keys {
		out[i] = k
	}
	for _, i := range c.Bin {
		if i < 0 || i >= len(c.Keys) {
			return nil, fmt.Errorf("invalid cursor")
		}
		b, err := base64.StdEncoding.DecodeString(c.Keys[i])
		if err != nil {
			return nil, fmt.Errorf("invalid cursor")
		}
		out[i] = b
	}
	return out, nil
}

// cursorShape hashes the table name and filter so cursors are scoped to one
// query. Ordering is always by primary key, so it isn't part of the shape.
func cursorShape(table string, where map[string]any) string {
	b, _ := json.Marshal(struct {
		T string         `json:"t"`
		W map[string]any `json:"w"`
	}{table, where})
	h := fnv.New64a()
	_, _ = h.Write(b)
	return strconv.FormatUint(h.Sum64(), 36)
}

// cursorKey renders a scanned key value for the cursor: raw bytes stay
// bytes (encodeCursor carries them losslessly), anything else becomes an
// exact string (stringifyKey).
func cursorKey(v any) any {
	if b, ok := v.([]byte); ok {
		return append([]byte{}, b...)
	}
	return stringifyKey(v)
}

// stringifyKey renders a scanned PK value as an exact string for the cursor.
// Values come from convertValue (int64, string, float64, bool, ...), so fmt
// is exact for integers and strings — no float rounding of large ids.
func stringifyKey(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(t)
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}
