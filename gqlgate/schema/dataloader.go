package schema

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// The dataloader defeats the N+1 pattern on relationship fields. graphql-go
// resolves every field (placing a thunk for any resolver that returns a
// func() (interface{}, error)) before it "dethunks" the tree breadth-first
// (see the executor's dethunkMapWithBreadthFirstTraversal). So every
// relationship resolver in a query runs — and can register its parent key —
// before any thunk fires. Each relationship resolver therefore:
//
//  1. enqueues its parent key into a request-scoped loader, and
//  2. returns a thunk that, on first call, issues ONE `… WHERE fk IN (keys)`
//     query for every enqueued key, then hands each parent its slice.
//
// Result: `posts { author }` over N posts runs 2 queries, not N+1.

type loaderSetKey struct{}

// loaderSet holds every relationship loader for one GraphQL request, keyed by
// a stable string (relationship identity + argument signature).
type loaderSet struct {
	mu      sync.Mutex
	loaders map[string]*relLoader
}

// WithLoaders returns a context carrying a fresh per-request loader set. The
// server installs this before executing each GraphQL request; resolvers that
// run without it degrade gracefully to unbatched (one query per parent).
func WithLoaders(ctx context.Context) context.Context {
	return context.WithValue(ctx, loaderSetKey{}, &loaderSet{loaders: map[string]*relLoader{}})
}

func loadersFrom(ctx context.Context) *loaderSet {
	if ls, ok := ctx.Value(loaderSetKey{}).(*loaderSet); ok {
		return ls
	}
	// No shared set (e.g. a relationship resolved outside a request): give an
	// ephemeral one so the same code path still works, just unbatched.
	return &loaderSet{loaders: map[string]*relLoader{}}
}

// getOrCreate returns the loader for key, creating it via make on first use.
func (s *loaderSet) getOrCreate(key string, make func() *relLoader) *relLoader {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.loaders[key]; ok {
		return l
	}
	l := make()
	s.loaders[key] = l
	return l
}

// relLoader batches one relationship. It is a MULTI-ROUND batcher: keys
// enqueued between flushes form one batch, and it can flush more than once.
// This is essential for recursive/self-referential relationships (org charts,
// category trees, threaded comments): the same field — hence the same loader
// key — runs at every nesting depth, and graphql-go fires each depth's thunks
// in its own breadth-first wave. A latch-once loader would serve level 2 from
// level 1's results (silently dropping rows); instead, each wave's freshly
// enqueued keys are flushed on first access at that depth.
type relLoader struct {
	mu      sync.Mutex
	seen    map[string]bool             // every key ever enqueued (dedup)
	pending [][]any                     // enqueued but not yet loaded
	loaded  map[string]bool             // key sigs already fetched
	byKey   map[string][]map[string]any // grouped results, accumulated
	err     error                       // sticky: a batch error fails the field
	loadFn  func(ctx context.Context, keys [][]any) (map[string][]map[string]any, error)
}

func newRelLoader(loadFn func(ctx context.Context, keys [][]any) (map[string][]map[string]any, error)) *relLoader {
	return &relLoader{
		seen:   map[string]bool{},
		loaded: map[string]bool{},
		byKey:  map[string][]map[string]any{},
		loadFn: loadFn,
	}
}

// enqueue registers a parent key for the next batch (deduplicated across the
// whole loader lifetime, so a key seen at one depth isn't refetched later).
func (l *relLoader) enqueue(key []any) {
	sig := keySig(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.seen[sig] {
		l.seen[sig] = true
		l.pending = append(l.pending, key)
	}
}

// fetch returns the rows for one key. If the key hasn't been loaded yet, it
// flushes ALL currently-pending keys in one query first (so callers within the
// same wave share a single batch), then serves from the grouped result.
func (l *relLoader) fetch(ctx context.Context, key []any) ([]map[string]any, error) {
	sig := keySig(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	if !l.loaded[sig] && len(l.pending) > 0 {
		batch := l.pending
		l.pending = nil
		res, err := l.loadFn(ctx, batch)
		if err != nil {
			l.err = err
			return nil, err
		}
		for _, k := range batch {
			l.loaded[keySig(k)] = true
		}
		for s, rows := range res {
			l.byKey[s] = rows
		}
	}
	return l.byKey[sig], nil
}

// keySig is a stable, type-tagged signature for a key tuple. Parent and child
// values for an FK come from the same column type through convertValue, so
// their signatures match; JSON encoding keeps ints/strings unambiguous.
func keySig(key []any) string {
	b, err := json.Marshal(key)
	if err != nil {
		// Fall back to a coarse representation; correctness over compactness.
		return fmt.Sprintf("%#v", key)
	}
	return string(b)
}

// groupByColumns buckets rows by the signature of their joinCols values,
// preserving input (SQL ORDER BY) order within each bucket.
func groupByColumns(rows []map[string]any, joinCols []string) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, row := range rows {
		key := make([]any, len(joinCols))
		for i, c := range joinCols {
			key[i] = row[c]
		}
		sig := keySig(key)
		out[sig] = append(out[sig], row)
	}
	return out
}

// argsSignature identifies a to-many relationship loader. It includes
// where/order_by AND limit/offset: the batch is bounded per parent to
// limit+offset rows (see runSelectByKeys), so two call sites with different
// page sizes must not share one capped batch.
func argsSignature(la listArgs) string {
	b, err := json.Marshal(struct {
		Where   map[string]any `json:"w"`
		OrderBy []any          `json:"o"`
		Limit   *int           `json:"l"`
		Offset  *int           `json:"f"`
	}{la.where, la.orderBy, la.limit, la.offset})
	if err != nil {
		return fmt.Sprintf("%#v|%#v|%v|%v", la.where, la.orderBy, la.limit, la.offset)
	}
	return string(b)
}

// columnsReadable reports whether every one of cols is in the role's readable
// set for ti — the precondition for batching, since the loader groups results
// by those columns and they must appear in the projection.
func columnsReadable(ti *tableInfo, cols []string) bool {
	if ti.access.Select == nil {
		return false
	}
	for _, c := range cols {
		if !ti.access.Select.ColumnSet[c] {
			return false
		}
	}
	return true
}

// loaderKey namespaces a loader by direction, constraint and argument sig.
func loaderKey(direction, constraint, argSig string) string {
	return strings.Join([]string{direction, constraint, argSig}, "\x00")
}
