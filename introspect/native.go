package introspect

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// NativeAlias is the alias a native query runs under as a derived table.
const NativeAlias = "__gqlgate_nq"

// QueryColumns describes the result columns of a read-only query (a native
// query's SQL with "?" placeholders) by running it as a derived table with
// LIMIT 0 and the given placeholder values, then reading the driver's column
// metadata. A second LIMIT 0 query reads the collation and charset of
// character columns (COLLATION() of a column is a property of its type, so
// a NULL-extended outer-join row is enough).
//
// The database reports a derived table's columns without reliable
// nullability, so every column is nullable; MySQL's wire protocol carries no
// display width either, so TINYINT(1) is reported as a plain TINYINT.
func QueryColumns(ctx context.Context, db *sql.DB, query string, args []any) ([]*Column, error) {
	rows, err := db.QueryContext(ctx, "SELECT * FROM ("+query+"\n) AS `"+NativeAlias+"` LIMIT 0", args...)
	if err != nil {
		return nil, err
	}
	cts, err := rows.ColumnTypes()
	if cerr := rows.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	var cols []*Column
	seen := map[string]bool{}
	var charCols []*Column
	for i, ct := range cts {
		name := ct.Name()
		if name == "" {
			return nil, fmt.Errorf("result column %d has no name (give it an alias)", i+1)
		}
		if seen[strings.ToLower(name)] {
			return nil, fmt.Errorf("result column %q appears twice (give each column a distinct alias)", name)
		}
		seen[strings.ToLower(name)] = true
		prec, scale, hasDec := ct.DecimalSize()
		c := ColumnFromDriverType(name, ct.DatabaseTypeName(), prec, scale, hasDec)
		c.Ordinal = i
		cols = append(cols, c)
		if c.Charset == "?" {
			charCols = append(charCols, c)
		}
	}
	if len(charCols) > 0 {
		parts := make([]string, 0, 2*len(charCols))
		for _, c := range charCols {
			ref := "`" + NativeAlias + "`.`" + strings.ReplaceAll(c.Name, "`", "``") + "`"
			parts = append(parts, "COLLATION("+ref+")", "CHARSET("+ref+")")
		}
		// LIMIT 0 inside keeps the statement from being evaluated; the
		// outer join still yields one (NULL-extended) row to read from.
		q := "SELECT " + strings.Join(parts, ", ") + " FROM (SELECT 1) AS `__gqlgate_one` LEFT JOIN (SELECT * FROM (" +
			query + "\n) AS `__gqlgate_inner` LIMIT 0) AS `" + NativeAlias + "` ON 1 = 0"
		vals := make([]sql.NullString, len(parts))
		ptrs := make([]any, len(parts))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := db.QueryRowContext(ctx, q, args...).Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("reading result column collations: %w", err)
		}
		for i, c := range charCols {
			c.Collation = strings.ToLower(vals[2*i].String)
			c.Charset = strings.ToLower(vals[2*i+1].String)
			if c.Collation == "binary" {
				c.Collation, c.Charset = "", ""
			}
		}
	}
	return cols, nil
}

// ColumnFromDriverType maps the driver's DatabaseTypeName of a result column
// ("BIGINT", "UNSIGNED INT", "VARCHAR", "DECIMAL", …) to a Column as
// information_schema would describe it. Character columns get Charset "?"
// (to be read separately); an unknown type keeps an empty DataType.
func ColumnFromDriverType(name, dbType string, prec, scale int64, hasDec bool) *Column {
	c := &Column{Name: name, Nullable: true}
	t := strings.ToLower(strings.TrimSpace(dbType))
	unsigned := false
	if rest, ok := strings.CutPrefix(t, "unsigned "); ok {
		t, unsigned = rest, true
	}
	c.DataType = t
	c.ColumnType = t
	switch t {
	case "decimal":
		if hasDec && prec > 0 {
			c.ColumnType = fmt.Sprintf("decimal(%d,%d)", prec, scale)
		}
	case "char", "varchar", "tinytext", "text", "mediumtext", "longtext", "enum", "set":
		c.Charset = "?"
	case "null":
		// SELECT NULL AS x: no type at all; a nullable string is the most
		// honest reading (declare a type under columns: to change it).
		c.DataType, c.ColumnType = "varchar", "varchar"
	}
	if unsigned {
		c.ColumnType += " unsigned"
	}
	return c
}
