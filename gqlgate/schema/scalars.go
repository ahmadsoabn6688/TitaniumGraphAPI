package schema

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"

	"gqlgate/introspect"
)

// Custom scalars covering MySQL/TiDB types that GraphQL's builtins can't
// represent faithfully. graphql-go treats a nil return from ParseValue /
// ParseLiteral as a coercion failure, which surfaces as an input error.

// bigIntScalar carries 64-bit integers. Values are serialized as JSON numbers
// (exact in the JSON text; JavaScript clients should treat ids > 2^53 with
// care). Inputs may be numbers or strings.
var bigIntScalar = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "BigInt",
	Description: "64-bit integer, accepted as a number or a numeric string.",
	Serialize: func(value any) any {
		switch v := value.(type) {
		case int64, uint64, int, int32, uint32:
			return v
		case []byte:
			return string(v)
		case string:
			return v
		}
		return nil
	},
	ParseValue:   coerceBigInt,
	ParseLiteral: func(v ast.Value) any { return coerceBigInt(literalToGo(v)) },
})

func coerceBigInt(value any) any {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		if v == float64(int64(v)) {
			return int64(v)
		}
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return n
		}
	}
	return nil
}

// decimalScalar keeps DECIMAL/NUMERIC values as strings to preserve exactness.
var decimalScalar = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "Decimal",
	Description: "Arbitrary-precision decimal, represented as a string.",
	Serialize: func(value any) any {
		switch v := value.(type) {
		case []byte:
			return string(v)
		case string:
			return v
		case float64, int64, int:
			return fmt.Sprintf("%v", v)
		}
		return nil
	},
	ParseValue:   coerceDecimal,
	ParseLiteral: func(v ast.Value) any { return coerceDecimal(literalToGo(v)) },
})

func coerceDecimal(value any) any {
	switch v := value.(type) {
	case string:
		if _, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return strings.TrimSpace(v)
		}
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	}
	return nil
}

var dateTimeFormats = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

// dateTimeScalar maps DATETIME/TIMESTAMP columns. Outputs RFC 3339.
var dateTimeScalar = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "DateTime",
	Description: "Timestamp, RFC 3339 on output; accepts RFC 3339 or 'YYYY-MM-DD hh:mm:ss' on input.",
	Serialize: func(value any) any {
		switch v := value.(type) {
		case time.Time:
			return v.Format(time.RFC3339)
		case []byte:
			return string(v)
		case string:
			return v
		}
		return nil
	},
	ParseValue:   coerceDateTime,
	ParseLiteral: func(v ast.Value) any { return coerceDateTime(literalToGo(v)) },
})

func coerceDateTime(value any) any {
	s, ok := value.(string)
	if !ok {
		if t, isTime := value.(time.Time); isTime {
			return t
		}
		return nil
	}
	for _, f := range dateTimeFormats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return nil
}

// dateScalar maps DATE columns; represented as "YYYY-MM-DD" strings and bound
// to SQL as strings so no fake midnight time part is introduced.
var dateScalar = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "Date",
	Description: "Calendar date in YYYY-MM-DD form.",
	Serialize: func(value any) any {
		switch v := value.(type) {
		case time.Time:
			return v.Format("2006-01-02")
		case []byte:
			return string(v)
		case string:
			return v
		}
		return nil
	},
	ParseValue:   coerceDate,
	ParseLiteral: func(v ast.Value) any { return coerceDate(literalToGo(v)) },
})

func coerceDate(value any) any {
	s, ok := value.(string)
	if !ok {
		return nil
	}
	if _, err := time.Parse("2006-01-02", s); err != nil {
		return nil
	}
	return s
}

// jsonScalar maps JSON columns; any JSON value passes through untouched.
var jsonScalar = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "JSON",
	Description: "Arbitrary JSON value.",
	Serialize:   func(value any) any { return value },
	ParseValue:  func(value any) any { return value },
	ParseLiteral: func(v ast.Value) any {
		return literalToGo(v)
	},
})

// bytesScalar maps binary columns as base64 strings.
var bytesScalar = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "Bytes",
	Description: "Binary data, base64-encoded.",
	Serialize: func(value any) any {
		switch v := value.(type) {
		case []byte:
			return base64.StdEncoding.EncodeToString(v)
		case string:
			return base64.StdEncoding.EncodeToString([]byte(v))
		}
		return nil
	},
	ParseValue:   coerceBytes,
	ParseLiteral: func(v ast.Value) any { return coerceBytes(literalToGo(v)) },
})

func coerceBytes(value any) any {
	s, ok := value.(string)
	if !ok {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// vectorScalar maps TiDB VECTOR columns. Represented as the bracketed string
// form TiDB uses, e.g. "[1,2,3]"; stored and bound as that string.
var vectorScalar = graphql.NewScalar(graphql.ScalarConfig{
	Name:        "Vector",
	Description: "TiDB vector (fixed-length float array), e.g. \"[1,2,3]\".",
	Serialize: func(value any) any {
		switch v := value.(type) {
		case []byte:
			return string(v)
		case string:
			return v
		}
		return nil
	},
	ParseValue:   coerceVector,
	ParseLiteral: func(v ast.Value) any { return coerceVector(literalToGo(v)) },
})

func coerceVector(value any) any {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	}
	return nil
}

// literalToGo converts a GraphQL AST literal into plain Go values.
func literalToGo(v ast.Value) any {
	switch node := v.(type) {
	case *ast.StringValue:
		return node.Value
	case *ast.BooleanValue:
		return node.Value
	case *ast.IntValue:
		if n, err := strconv.ParseInt(node.Value, 10, 64); err == nil {
			return n
		}
		return node.Value
	case *ast.FloatValue:
		if f, err := strconv.ParseFloat(node.Value, 64); err == nil {
			return f
		}
		return node.Value
	case *ast.EnumValue:
		return node.Value
	case *ast.ListValue:
		out := make([]any, 0, len(node.Values))
		for _, item := range node.Values {
			out = append(out, literalToGo(item))
		}
		return out
	case *ast.ObjectValue:
		out := map[string]any{}
		for _, f := range node.Fields {
			out[f.Name.Value] = literalToGo(f.Value)
		}
		return out
	}
	return nil
}

// scalarFor maps an introspected column to its GraphQL scalar.
func scalarFor(col *introspect.Column) *graphql.Scalar {
	unsigned := strings.Contains(col.ColumnType, "unsigned")
	switch col.DataType {
	case "tinyint":
		if strings.HasPrefix(col.ColumnType, "tinyint(1)") {
			return graphql.Boolean
		}
		return graphql.Int
	case "smallint", "mediumint", "year":
		return graphql.Int
	case "int", "integer":
		if unsigned {
			return bigIntScalar // unsigned int exceeds GraphQL's 32-bit Int
		}
		return graphql.Int
	case "bigint":
		return bigIntScalar
	case "float", "double", "real":
		return graphql.Float
	case "decimal", "numeric":
		return decimalScalar
	case "date":
		return dateScalar
	case "datetime", "timestamp":
		return dateTimeScalar
	case "json":
		return jsonScalar
	case "binary", "varbinary", "blob", "tinyblob", "mediumblob", "longblob", "bit":
		return bytesScalar
	case "vector":
		return vectorScalar
	default:
		// char, varchar, *text, enum, set, time, ...
		return graphql.String
	}
}

// convertValue normalizes a raw driver value for the column's scalar so that
// Serialize always sees a type it understands.
func convertValue(col *introspect.Column, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch scalarFor(col).Name() {
	case "Int":
		switch n := v.(type) {
		case int64:
			return int(n), nil
		case []byte:
			i, err := strconv.Atoi(string(n))
			if err != nil {
				return nil, fmt.Errorf("column %s: %w", col.Name, err)
			}
			return i, nil
		}
	case "BigInt":
		switch n := v.(type) {
		case int64, uint64:
			return n, nil
		case []byte:
			if i, err := strconv.ParseInt(string(n), 10, 64); err == nil {
				return i, nil
			}
			return string(n), nil
		}
	case "Float":
		switch n := v.(type) {
		case float64:
			return n, nil
		case float32:
			return float64(n), nil
		case []byte:
			f, err := strconv.ParseFloat(string(n), 64)
			if err != nil {
				return nil, fmt.Errorf("column %s: %w", col.Name, err)
			}
			return f, nil
		}
	case "Boolean":
		switch n := v.(type) {
		case int64:
			return n != 0, nil
		case bool:
			return n, nil
		case []byte:
			return string(n) != "0" && len(n) > 0, nil
		}
	case "String", "Decimal", "Vector":
		if b, ok := v.([]byte); ok {
			return string(b), nil
		}
	case "DateTime", "Date":
		return v, nil // time.Time or []byte; Serialize handles both
	case "JSON":
		if b, ok := v.([]byte); ok {
			var out any
			if err := json.Unmarshal(b, &out); err != nil {
				return nil, fmt.Errorf("column %s holds invalid JSON: %w", col.Name, err)
			}
			return out, nil
		}
	case "Bytes":
		return v, nil
	}
	return v, nil
}

// bindValue normalizes a coerced GraphQL input value for the SQL driver.
func bindValue(col *introspect.Column, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	if scalarFor(col).Name() == "JSON" {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("column %s: cannot encode JSON value: %w", col.Name, err)
		}
		return string(raw), nil
	}
	return v, nil
}
