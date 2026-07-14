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
// page (as strings, to avoid float64 precision loss on large BIGINT ids) plus
// a "shape" hash of the table+filter, so a cursor can't be misapplied to a
// different query (that is rejected rather than silently mispaging).

type cursorData struct {
	Keys  []string `json:"k"`
	Shape string   `json:"s"`
}

// encodeCursor builds the opaque token from the last row's PK values.
func encodeCursor(keys []string, shape string) string {
	b, _ := json.Marshal(cursorData{Keys: keys, Shape: shape})
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeCursor parses a cursor and verifies it belongs to the current query
// shape, returning the PK values to seek after.
func decodeCursor(cursor, shape string, keyLen int) ([]string, error) {
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
	return c.Keys, nil
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

// stringifyKey renders a scanned PK value as an exact string for the cursor.
// Values come from convertValue (int64, string, float64, bool, []byte-as-...),
// so fmt is exact for integers and strings — no float rounding of large ids.
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
