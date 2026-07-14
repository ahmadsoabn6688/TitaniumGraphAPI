package server

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCheckDepth(t *testing.T) {
	shallow := `query { posts { id title } }`
	if err := checkDepth(shallow, 3); err != nil {
		t.Errorf("depth-2 query rejected at limit 3: %v", err)
	}
	deep := `query { posts { author { posts { author { posts { id } } } } } }`
	if err := checkDepth(deep, 3); err == nil {
		t.Error("depth-6 query accepted at limit 3")
	}
	if err := checkDepth(deep, -1); err != nil {
		t.Errorf("-1 must disable the check: %v", err)
	}
}

func TestCheckDepthFragments(t *testing.T) {
	q := `
	query { posts { ...postFields } }
	fragment postFields on posts { author { posts { author { id } } } }`
	if err := checkDepth(q, 3); err == nil {
		t.Error("fragment nesting must count toward depth")
	}
	// Cyclic fragments must not hang the checker.
	cyclic := `
	query { posts { ...a } }
	fragment a on posts { author { ...b } }
	fragment b on users { posts { ...a } }`
	if err := checkDepth(cyclic, 100); err != nil {
		t.Errorf("cyclic fragments should terminate quietly, got %v", err)
	}
}

// TestCheckDepthFanOut guards against the exponential-blowup DoS: a document
// whose N fragments each spread the next one twice is legal and non-cyclic,
// but a naive (non-memoized) traversal would visit ~2^N nodes. Each fragment
// nests one field so it also accrues real depth. This must return quickly
// (not hang) AND still measure the true depth through the fan-out.
func TestCheckDepthFanOut(t *testing.T) {
	var b strings.Builder
	const n = 60
	b.WriteString("query { ...f0 }\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "fragment f%d on T { child { ...f%d ...f%d } }\n", i, i+1, i+1)
	}
	fmt.Fprintf(&b, "fragment f%d on T { id }\n", n)

	done := make(chan error, 1)
	go func() { done <- checkDepth(b.String(), 5) }()
	select {
	case err := <-done:
		// Real depth is ~n+1 through the nested `child` fields, well over the
		// limit of 5 — and the point is it returns a verdict fast, not hangs.
		if err == nil {
			t.Error("deep fan-out document should exceed the depth limit")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("checkDepth did not terminate on a fan-out document (exponential blowup)")
	}
}
