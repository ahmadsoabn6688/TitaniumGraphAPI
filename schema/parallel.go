package schema

import (
	"context"
	"fmt"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
)

// Concurrent root fields.
//
// graphql-go resolves the root fields of a query one after another on a
// single goroutine, then "dethunks" the result tree breadth-first. A root
// field whose resolver starts its work on a goroutine and returns a thunk
// that waits for it therefore overlaps with the root fields resolved after
// it: `{ a: users_aggregate {…} b: posts_connection {…} }` costs the slower
// of the two queries instead of their sum.
//
// Only query root fields are wrapped; graphql-go runs mutation root fields
// serially and they stay that way. The wrapper runs the field's original
// resolver — generated or a custom field's — on its own goroutine, bounded
// per request by server.max_parallel_root_fields (a semaphore; the resolver
// waits for a free slot before starting the next goroutine). Everything
// below the root still resolves on graphql-go's goroutine when the thunk is
// completed, so relationship dataloaders batch exactly as before (across
// all root fields, since every root's children are collected before any
// relationship thunk fires).
//
// Each root field reads through its own pooled connection, so concurrent
// root fields read at their own snapshot: they are not mutually consistent
// (they never were across requests either). A request with one root field,
// or a limit of 1, runs inline as before.

type rootLimiterKey struct{}

// rootLimiter bounds the root fields of one request running at once.
type rootLimiter struct {
	sem chan struct{}
}

// WithRootParallelism returns a context allowing up to n concurrently running
// root fields per query (n <= 1 = serial). The server installs it per request.
func WithRootParallelism(ctx context.Context, n int) context.Context {
	if n <= 1 {
		return ctx
	}
	return context.WithValue(ctx, rootLimiterKey{}, &rootLimiter{sem: make(chan struct{}, n)})
}

func rootLimiterFrom(ctx context.Context) *rootLimiter {
	l, _ := ctx.Value(rootLimiterKey{}).(*rootLimiter)
	return l
}

// rootResult is what a root field's goroutine hands to its thunk.
type rootResult struct {
	val any
	err error
}

// concurrentRootFields wraps the resolver of every query root field except
// the trivial ones (no database work) to run concurrently. Each wrapped field
// is a copy: a custom field's *graphql.Field is shared by every role's schema
// and every hot-reload generation, and must never be wrapped twice.
func concurrentRootFields(fields graphql.Fields) {
	for name, f := range fields {
		if f == nil || f.Resolve == nil || name == "_role" {
			continue
		}
		wrapped := *f
		wrapped.Resolve = concurrentRoot(name, f.Resolve)
		fields[name] = &wrapped
	}
}

// concurrentRoot runs orig on a goroutine when the request allows parallel
// root fields and the operation has more than one, returning a thunk that
// waits for its result.
func concurrentRoot(name string, orig graphql.FieldResolveFn) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		lim := rootLimiterFrom(p.Context)
		if lim == nil || !multipleRootFields(p.Info) {
			return orig(p)
		}
		ctx := p.Context
		select {
		case lim.sem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		done := make(chan rootResult, 1)
		go func() {
			res := rootResult{}
			defer func() {
				if r := recover(); r != nil {
					res = rootResult{err: fmt.Errorf("field %s: internal error: %v", name, r)}
				}
				<-lim.sem
				done <- res
			}()
			res.val, res.err = orig(p)
		}()
		return func() (any, error) {
			var res rootResult
			select {
			case res = <-done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if res.err != nil {
				return nil, res.err
			}
			// A resolver that itself deferred its work (a custom field
			// returning a thunk) completes here, on graphql-go's goroutine.
			if thunk, ok := res.val.(func() (any, error)); ok {
				return thunk()
			}
			return res.val, nil
		}, nil
	}
}

// multipleRootFields reports whether the operation selects more than one
// root field (fragments followed); with a single one there is nothing to
// overlap.
func multipleRootFields(info graphql.ResolveInfo) bool {
	op, ok := info.Operation.(*ast.OperationDefinition)
	if !ok || op.Operation != ast.OperationTypeQuery {
		return false
	}
	return countRootFields(op.SelectionSet, info.Fragments) > 1
}
