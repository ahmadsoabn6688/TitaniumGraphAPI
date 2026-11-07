package schema

import (
	"context"
	"fmt"
	"sync/atomic"
)

// Per-request response accounting. server.max_response_rows bounds how many
// rows one GraphQL request may read for its response: aliases and nested
// relationships multiply rows (200 posts x 200 comments x ...), and every
// list is only clamped on its own. The budget is shared by every read path
// that returns rows to the client — connection pages, _by_pk / unique-key
// lookups, relationship batches, vector search and mutation `returning` —
// and the request fails with code response_too_large once it is exceeded.

type responseKey struct{}

// responseTracker is installed per request by WithResponseLimit.
type responseTracker struct {
	maxRows   int64 // 0 = unlimited
	rows      atomic.Int64
	exceeded  atomic.Bool
	committed atomic.Bool // a mutation of this request has committed
}

// WithResponseLimit returns a context carrying a fresh response tracker that
// allows at most maxRows rows (0 = unlimited). The server installs it per
// request; without it nothing is limited.
func WithResponseLimit(ctx context.Context, maxRows int) context.Context {
	return context.WithValue(ctx, responseKey{}, &responseTracker{maxRows: int64(maxRows)})
}

func trackerFrom(ctx context.Context) *responseTracker {
	t, _ := ctx.Value(responseKey{}).(*responseTracker)
	return t
}

// ResponseLimitExceeded reports whether a request ran over its row budget.
func ResponseLimitExceeded(ctx context.Context) bool {
	t := trackerFrom(ctx)
	return t != nil && t.exceeded.Load()
}

// MutationCommitted reports whether a mutation of this request committed (so
// a response-limit failure must not hide that the write happened).
func MutationCommitted(ctx context.Context) bool {
	t := trackerFrom(ctx)
	return t != nil && t.committed.Load()
}

// noteCommit records that a mutation committed.
func noteCommit(ctx context.Context) {
	if t := trackerFrom(ctx); t != nil {
		t.committed.Store(true)
	}
}

// countRows charges n rows against the request's budget and fails with
// response_too_large once the budget is exceeded (and for every later read).
func countRows(ctx context.Context, n int) error {
	t := trackerFrom(ctx)
	if t == nil || t.maxRows <= 0 {
		return nil
	}
	if t.rows.Add(int64(n)) > t.maxRows || t.exceeded.Load() {
		t.exceeded.Store(true)
		return ResponseTooLarge(t.maxRows)
	}
	return nil
}

// ResponseTooLarge is the error of a request over server.max_response_rows.
func ResponseTooLarge(maxRows int64) error {
	return &CodedError{
		Code: CodeResponseTooLarge,
		Message: fmt.Sprintf("response row limit exceeded: the request reads more than %d rows (server.max_response_rows); "+
			"ask for fewer rows with first/limit/where or split the request", maxRows),
	}
}
