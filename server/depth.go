package server

import (
	"fmt"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"
)

// checkDepth parses the query and rejects it when any operation's selection
// nesting exceeds maxDepth. Fragment spreads are followed (with cycle
// protection; actual cycle rejection is the validator's job).
func checkDepth(query string, maxDepth int) error {
	if maxDepth < 0 {
		return nil
	}
	doc, err := parser.Parse(parser.ParseParams{
		Source: source.NewSource(&source.Source{Body: []byte(query)}),
	})
	if err != nil {
		// Let the executor produce its own (better) syntax error.
		return nil
	}

	fragments := map[string]*ast.FragmentDefinition{}
	for _, def := range doc.Definitions {
		if f, ok := def.(*ast.FragmentDefinition); ok && f.Name != nil {
			fragments[f.Name.Value] = f
		}
	}

	// Each fragment's depth is independent of where it is spread, so memoize
	// it: this makes the whole scan linear in the document size. Without
	// memoization a document whose fragments each spread the next one twice
	// (a legal, non-cyclic fan-out) forces ~2^N recursive visits — a tiny
	// request that would peg a CPU. `computing` breaks cycles (a self-
	// referential fragment is an invalid query graphql-go rejects later; here
	// it simply contributes 0 rather than looping forever).
	fragDepth := map[string]int{}
	computing := map[string]bool{}

	var depthOfSet func(ss *ast.SelectionSet) int
	var fragmentDepth func(name string) int

	depthOfSet = func(ss *ast.SelectionSet) int {
		if ss == nil {
			return 0
		}
		max := 0
		for _, sel := range ss.Selections {
			d := 0
			switch node := sel.(type) {
			case *ast.Field:
				d = 1 + depthOfSet(node.SelectionSet)
			case *ast.InlineFragment:
				d = depthOfSet(node.SelectionSet)
			case *ast.FragmentSpread:
				if node.Name != nil {
					d = fragmentDepth(node.Name.Value)
				}
			}
			if d > max {
				max = d
			}
		}
		return max
	}

	fragmentDepth = func(name string) int {
		if d, ok := fragDepth[name]; ok {
			return d
		}
		if computing[name] {
			return 0 // cycle
		}
		frag, ok := fragments[name]
		if !ok {
			return 0
		}
		computing[name] = true
		d := depthOfSet(frag.SelectionSet)
		delete(computing, name)
		fragDepth[name] = d
		return d
	}

	for _, def := range doc.Definitions {
		op, ok := def.(*ast.OperationDefinition)
		if !ok {
			continue
		}
		if d := depthOfSet(op.SelectionSet); d > maxDepth {
			return fmt.Errorf("query depth %d exceeds the configured maximum of %d", d, maxDepth)
		}
	}
	return nil
}
