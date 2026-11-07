package schema

import (
	"fmt"
	"math"
	"sort"

	"github.com/graphql-go/graphql"

	"gqlgate/config"
	"gqlgate/introspect"
)

// Typed JSON columns (json_types + tables.<t>.columns.<c>.json_type).
//
// A JSON column with a declared shape is exposed as a GraphQL object type
// (or a list of one) instead of the opaque JSON scalar, so clients select
// sub-fields and introspection shows the shape. The column is still read
// whole and decoded in Go (as for the JSON scalar); each field then reads its
// key from the decoded object. The database does not enforce the shape, so
// every field is nullable: a missing key is null, and a value of the wrong
// kind (a string where an Int is declared, an array where an object is) is
// null with a json_shape_mismatch error on that field — the rest of the
// response is unaffected.
//
// The object types are built per role, and only when a column the role can
// read uses them, so a role that cannot read the column does not even see
// the type. Writes and `where` keep taking the JSON scalar.

// typedJSONColumn is the output field of a JSON column with a declared shape.
func (b *builder) typedJSONColumn(ti *tableInfo, col *introspect.Column, expr string) *graphql.Field {
	ref, _ := config.ParseJSONTypeRef(expr) // validated with the config
	where := ti.typeName + "." + ti.colToField[col.Name]
	return &graphql.Field{
		Type:              b.jsonOutput(ref),
		Description:       b.shared.model.columnDescription(ti.model, col),
		DeprecationReason: ti.model.colDeprecated[col.Name],
		Resolve: func(p graphql.ResolveParams) (any, error) {
			row, _ := p.Source.(map[string]any)
			return coerceJSON(ref, row[col.Name], where)
		},
	}
}

// jsonOutput is the GraphQL output type of a JSON type expression.
func (b *builder) jsonOutput(ref config.JSONTypeRef) graphql.Output {
	var t graphql.Output
	switch ref.Name {
	case "String":
		t = graphql.String
	case "Int":
		t = graphql.Int
	case "Float":
		t = graphql.Float
	case "Boolean":
		t = graphql.Boolean
	case "JSON":
		t = jsonScalar
	default:
		t = b.jsonObject(ref.Name)
	}
	for i := 0; i < ref.Lists; i++ {
		t = graphql.NewList(t)
	}
	return t
}

// jsonObject returns (building on first use) the role's object type of one
// declared JSON shape. Fields are a thunk, so shapes may refer to each other
// (or themselves, e.g. a tree of nodes).
func (b *builder) jsonObject(name string) *graphql.Object {
	if o := b.jsonObjs[name]; o != nil {
		return o
	}
	jt := b.shared.model.jsonTypes[name]
	o := graphql.NewObject(graphql.ObjectConfig{
		Name:        name,
		Description: jt.Description,
		Fields: (graphql.FieldsThunk)(func() graphql.Fields {
			fields := graphql.Fields{}
			names := make([]string, 0, len(jt.Fields))
			for fn := range jt.Fields {
				names = append(names, fn)
			}
			sort.Strings(names)
			for _, fn := range names {
				f := jt.Fields[fn]
				ref, _ := config.ParseJSONTypeRef(f.Type)
				key := f.JSONKey(fn)
				where := name + "." + fn
				fields[fn] = &graphql.Field{
					Type:              b.jsonOutput(ref),
					Description:       f.Description,
					DeprecationReason: f.Deprecated,
					Resolve: func(p graphql.ResolveParams) (any, error) {
						obj, _ := p.Source.(map[string]any)
						return coerceJSON(ref, obj[key], where)
					},
				}
			}
			return fields
		}),
	})
	b.jsonObjs[name] = o
	return o
}

// coerceJSON checks a decoded JSON value against a declared type and returns
// it in the form the GraphQL type serializes. Objects are only checked to be
// objects (their fields check themselves when selected); lists are checked
// element by element. A mismatch is a json_shape_mismatch error.
func coerceJSON(ref config.JSONTypeRef, v any, where string) (any, error) {
	if v == nil {
		return nil, nil
	}
	if ref.Lists > 0 {
		list, ok := v.([]any)
		if !ok {
			return nil, shapeMismatch(where, ref, v)
		}
		inner := ref
		inner.Lists--
		out := make([]any, len(list))
		for i, e := range list {
			c, err := coerceJSON(inner, e, fmt.Sprintf("%s[%d]", where, i))
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	}
	switch ref.Name {
	case "JSON":
		return v, nil
	case "String":
		if s, ok := v.(string); ok {
			return s, nil
		}
	case "Boolean":
		if bv, ok := v.(bool); ok {
			return bv, nil
		}
	case "Float":
		if f, ok := jsonNumber(v); ok {
			return f, nil
		}
	case "Int":
		if f, ok := jsonNumber(v); ok && f == math.Trunc(f) && f >= math.MinInt32 && f <= math.MaxInt32 {
			return int(f), nil
		}
	default: // a declared object type
		if m, ok := v.(map[string]any); ok {
			return m, nil
		}
	}
	return nil, shapeMismatch(where, ref, v)
}

// jsonNumber reads a decoded JSON number (float64; other numeric kinds are
// accepted for values that did not come through encoding/json).
func jsonNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// shapeMismatch is the error of a stored JSON value that does not fit its
// declared type.
func shapeMismatch(where string, ref config.JSONTypeRef, v any) error {
	return &CodedError{
		Code:    CodeJSONShapeMismatch,
		Message: fmt.Sprintf("%s: the stored JSON holds %s where %s is declared", where, jsonKind(v), describeJSONRef(ref)),
	}
}

func describeJSONRef(ref config.JSONTypeRef) string {
	s := ref.Name
	for i := 0; i < ref.Lists; i++ {
		s = "[" + s + "]"
	}
	switch {
	case ref.Lists > 0:
		return "a list " + s
	case ref.Name == "Int":
		return "an Int"
	case config.JSONScalars[ref.Name]:
		return "a " + s
	}
	return "an object " + s
}

// jsonKind names the kind of a decoded JSON value for error messages (never
// the value itself).
func jsonKind(v any) string {
	switch n := v.(type) {
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case map[string]any:
		return "an object"
	case []any:
		return "an array"
	case float64:
		if n != math.Trunc(n) {
			return "a fractional number"
		}
		if n < math.MinInt32 || n > math.MaxInt32 {
			return "a number outside the 32-bit Int range"
		}
		return "a number"
	}
	return fmt.Sprintf("a %T", v)
}
