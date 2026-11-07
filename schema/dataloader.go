package schema

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"

	"gqlgate/introspect"
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
//
// Mutations are the exception. graphql-go runs a mutation's root fields one
// after another but fires thunks only once all of them have run, and a
// loader deduplicates keys for the whole request. Batched relationship (and
// <rel>_aggregate) fields under `mutation { a: … b: … }` would therefore all
// read the database as it is after the LAST mutation, and a's response would
// show b's changes. Under a mutation with more than one root field the
// relationship resolvers resolve immediately instead (one query per parent
// row, see serialMutation), so every root field's returned subtree is read
// before the next mutation runs. A single-mutation request keeps batching:
// the end of the request is the state after its one mutation.

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

// serialMutation reports whether a resolver runs inside a mutation operation
// with more than one root field, where relationship fields must not defer to
// a batched thunk (see the package comment above).
func serialMutation(info graphql.ResolveInfo) bool {
	op, ok := info.Operation.(*ast.OperationDefinition)
	if !ok || op.Operation != ast.OperationTypeMutation {
		return false
	}
	return countRootFields(op.SelectionSet, info.Fragments) > 1
}

// countRootFields counts the fields of a selection set, following inline
// fragments and fragment spreads. Fields skipped by @skip/@include still
// count, which can only make a request resolve eagerly (slower), never wrong.
func countRootFields(set *ast.SelectionSet, frags map[string]ast.Definition) int {
	if set == nil {
		return 0
	}
	n := 0
	for _, s := range set.Selections {
		switch node := s.(type) {
		case *ast.Field:
			n++
		case *ast.InlineFragment:
			n += countRootFields(node.SelectionSet, frags)
		case *ast.FragmentSpread:
			if node.Name != nil {
				if def, ok := frags[node.Name.Value].(*ast.FragmentDefinition); ok {
					n += countRootFields(def.GetSelectionSet(), frags)
				}
			}
		}
	}
	return n
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

// Collation-aware key matching.
//
// A batch fetches the rows of every parent key with SQL equality
// (`col IN (…)`), which for character columns follows the column's
// collation: under a *_ci collation 'ABC' = 'abc', and under a PAD SPACE
// collation (every *_bin and *_ci one except the utf8mb4_0900_* family)
// 'abc ' = 'abc'. The value a matching row carries can therefore differ from
// the key that fetched it, and bucketing rows by their exact bytes would drop
// them (or, for a GROUP BY, whole groups, since the value reported for a
// group is an arbitrary member). keyIndex instead compares character key
// columns by WEIGHT_STRING — the collation's sort key, equal exactly when the
// values compare equal — computed by the database for both the fetched rows
// and the batch's keys. Other columns (integers, dates, binary strings)
// compare by value as before, at no extra cost.

// sqlNamePattern guards collation/charset names before they are inlined.
var sqlNamePattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// weightedKeyCol reports whether a join column is matched by collation
// weight: every character column except the byte-exact binary charset.
func weightedKeyCol(c *introspect.Column) bool {
	return c != nil && c.Collation != "" && c.Collation != "binary" &&
		sqlNamePattern.MatchString(c.Collation) && sqlNamePattern.MatchString(c.Charset)
}

// maxWeightExprs bounds the WEIGHT_STRING expressions per key-weight query.
const maxWeightExprs = 500

// keyIndex maps rows fetched for a batch back to the batch's key tuples.
type keyIndex struct {
	keys     [][]any
	cols     []string // join column names of the queried table
	weighted []bool   // per join column: compared by collation weight
	bySig    map[string][]int
}

// newKeyIndex indexes keys for matching rows of ti on joinCols. When a join
// column is a character column it runs one small query per maxWeightExprs
// key values to learn their collation weights.
func (b *builder) newKeyIndex(ctx context.Context, ti *tableInfo, joinCols []string, keys [][]any) (*keyIndex, error) {
	ki := &keyIndex{keys: keys, cols: joinCols, weighted: make([]bool, len(joinCols)), bySig: make(map[string][]int, len(keys))}
	var cols []*introspect.Column
	weighted := false
	for i, name := range joinCols {
		c := ti.table.ColumnMap[name]
		cols = append(cols, c)
		if weightedKeyCol(c) {
			ki.weighted[i] = true
			weighted = true
		}
	}
	canon := keys
	if weighted {
		var err error
		if canon, err = b.keyWeights(ctx, cols, ki.weighted, keys); err != nil {
			return nil, err
		}
	}
	for i, k := range canon {
		sig := keySig(k)
		ki.bySig[sig] = append(ki.bySig[sig], i)
	}
	return ki, nil
}

// weightCount is the number of WEIGHT_STRING values each fetched row carries.
func (ki *keyIndex) weightCount() int {
	n := 0
	for _, w := range ki.weighted {
		if w {
			n++
		}
	}
	return n
}

// weightExprs are the extra SELECT expressions a fetch adds: the collation
// weight of each weighted join column, in join-column order.
func (ki *keyIndex) weightExprs() []string {
	var out []string
	for i, w := range ki.weighted {
		if w {
			out = append(out, "WEIGHT_STRING("+quoteIdent(ki.cols[i])+")")
		}
	}
	return out
}

// match returns the indices (into keys) of the keys equal to a fetched row:
// vals are the row's join-column values (only read at unweighted positions)
// and weights its weightExprs results.
func (ki *keyIndex) match(vals, weights []any) []int {
	parts := make([]any, len(ki.weighted))
	w := 0
	for i, isW := range ki.weighted {
		if isW {
			h := weightHex(weights[w])
			if h == "" {
				return nil // NULL weight: matches no key
			}
			parts[i] = h
			w++
			continue
		}
		parts[i] = vals[i]
	}
	return ki.bySig[keySig(parts)]
}

// group buckets fetched rows under the signature of every key they match,
// preserving input (SQL ORDER BY) order within each bucket. On a to-one
// relationship several keys of a batch ('ABC', 'abc') can match one row.
func (ki *keyIndex) group(rows []map[string]any, weights [][]any) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	vals := make([]any, len(ki.cols))
	for r, row := range rows {
		for i, c := range ki.cols {
			vals[i] = row[c]
		}
		var ws []any
		if weights != nil {
			ws = weights[r]
		}
		for _, k := range ki.match(vals, ws) {
			sig := keySig(ki.keys[k])
			out[sig] = append(out[sig], row)
		}
	}
	return out
}

// keyWeights returns a copy of keys whose weighted positions hold the hex
// collation weight of the value under the column's charset and collation —
// the form match compares fetched rows' weights in.
func (b *builder) keyWeights(ctx context.Context, cols []*introspect.Column, weighted []bool, keys [][]any) ([][]any, error) {
	out := make([][]any, len(keys))
	type slot struct{ key, col int }
	var exprs []string
	var args []any
	var slots []slot
	flush := func() error {
		if len(exprs) == 0 {
			return nil
		}
		query := "SELECT " + strings.Join(exprs, ", ")
		b.logSQL(query, args)
		vals := make([]any, len(exprs))
		ptrs := make([]any, len(exprs))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := b.opt.DB.QueryRowContext(ctx, query, args...).Scan(ptrs...); err != nil {
			return b.dbErr(err)
		}
		for i, s := range slots {
			out[s.key][s.col] = weightHex(vals[i])
		}
		exprs, args, slots = exprs[:0], args[:0], slots[:0]
		return nil
	}
	for k, key := range keys {
		out[k] = append([]any(nil), key...)
		for j, isW := range weighted {
			if !isW {
				continue
			}
			c := cols[j]
			exprs = append(exprs, "WEIGHT_STRING(CONVERT(? USING "+c.Charset+") COLLATE "+c.Collation+")")
			args = append(args, key[j])
			slots = append(slots, slot{k, j})
			if len(exprs) >= maxWeightExprs {
				if err := flush(); err != nil {
					return nil, err
				}
			}
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

// weightHex renders a WEIGHT_STRING result as hex (weights are raw bytes,
// which JSON-based key signatures would mangle).
func weightHex(v any) string {
	switch w := v.(type) {
	case []byte:
		return "w" + hex.EncodeToString(w)
	case string:
		return "w" + hex.EncodeToString([]byte(w))
	}
	return "" // NULL
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
