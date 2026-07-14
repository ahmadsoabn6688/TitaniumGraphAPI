package schema

import "testing"

func TestCursorRoundTrip(t *testing.T) {
	shape := cursorShape("posts", nil)
	keys, err := decodeCursor(encodeCursor([]string{"42"}, shape), shape, 1)
	if err != nil || len(keys) != 1 || keys[0] != "42" {
		t.Errorf("round trip = (%v, %v), want ([42], nil)", keys, err)
	}
	// Composite key round trip.
	shape2 := cursorShape("t", nil)
	keys2, err := decodeCursor(encodeCursor([]string{"7", "abc"}, shape2), shape2, 2)
	if err != nil || len(keys2) != 2 || keys2[0] != "7" || keys2[1] != "abc" {
		t.Errorf("composite round trip = (%v, %v)", keys2, err)
	}
}

func TestCursorShapeMismatchRejected(t *testing.T) {
	c := encodeCursor([]string{"5"}, cursorShape("posts", nil))
	if _, err := decodeCursor(c, cursorShape("users", nil), 1); err == nil {
		t.Error("a cursor from a different table must be rejected")
	}
	// Same table but a different filter is a different shape.
	c2 := encodeCursor([]string{"5"}, cursorShape("posts", map[string]any{"a": 1}))
	if _, err := decodeCursor(c2, cursorShape("posts", nil), 1); err == nil {
		t.Error("a cursor from a different filter must be rejected")
	}
}

func TestCursorInvalid(t *testing.T) {
	shape := cursorShape("t", nil)
	if _, err := decodeCursor("!!not-base64!!", shape, 1); err == nil {
		t.Error("garbage cursor must be rejected")
	}
	// Wrong key arity (composite cursor used where a single key is expected).
	c := encodeCursor([]string{"1", "2"}, shape)
	if _, err := decodeCursor(c, shape, 1); err == nil {
		t.Error("mismatched key length must be rejected")
	}
}

func TestCursorShapeStable(t *testing.T) {
	w := map[string]any{"a": 1, "b": 2}
	if cursorShape("t", w) != cursorShape("t", w) {
		t.Error("cursorShape must be deterministic for the same inputs")
	}
}

// keysetPage mirrors the connection resolver's post-fetch logic (fetch
// first+1, trim, guard empty) so the has_next_page/end_cursor invariant can be
// checked without a DB: has_next_page=true must always come with an end_cursor.
func keysetPage(first, fetched int) (hasNext bool, endCursor any) {
	rows := fetched
	hasNext = rows > first
	if hasNext {
		rows = first
	}
	if rows == 0 {
		hasNext = false
	}
	if rows > 0 {
		endCursor = "cursor"
	}
	return
}

func TestConnectionPageInfoInvariant(t *testing.T) {
	cases := []struct {
		name           string
		first, fetched int
	}{
		{"full page, more follow", 10, 11},
		{"exact last page", 10, 10},
		{"partial last page", 10, 4},
		{"empty result", 10, 0},
		{"first:0 on non-empty", 0, 1},
		{"first:0 on empty", 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hasNext, endCursor := keysetPage(c.first, c.fetched)
			if hasNext && endCursor == nil {
				t.Errorf("has_next_page=true but end_cursor=nil (first=%d fetched=%d)", c.first, c.fetched)
			}
		})
	}
	if hasNext, _ := keysetPage(0, 1); hasNext {
		t.Error("first:0 must report has_next_page=false")
	}
	if hasNext, _ := keysetPage(10, 11); !hasNext {
		t.Error("a full page with an extra row must report has_next_page=true")
	}
}

func TestStringifyKey(t *testing.T) {
	// Large BIGINT ids must stay exact (no float rounding).
	if got := stringifyKey(int64(9007199254740993)); got != "9007199254740993" {
		t.Errorf("stringifyKey(bigint) = %q, want exact", got)
	}
	if got := stringifyKey([]byte("uid-7")); got != "uid-7" {
		t.Errorf("stringifyKey([]byte) = %q", got)
	}
	if got := stringifyKey("abc"); got != "abc" {
		t.Errorf("stringifyKey(string) = %q", got)
	}
}
