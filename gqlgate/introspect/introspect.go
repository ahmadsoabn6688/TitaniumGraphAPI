// Package introspect reads table/column/key metadata for one schema out of
// information_schema on TiDB (or any MySQL-compatible server).
package introspect

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// Catalog is the introspected shape of one database schema.
type Catalog struct {
	SchemaName string
	Tables     map[string]*Table
	TableOrder []string // stable iteration order
}

// Table describes one base table.
type Table struct {
	Name        string
	Columns     []*Column
	ColumnMap   map[string]*Column
	PrimaryKey  []string      // column names, in key order; empty if no PK
	ForeignKeys []*ForeignKey // FKs declared on this table (outgoing)
	IncomingFKs []*ForeignKey // FKs on other tables referencing this one
}

// Column describes one column.
type Column struct {
	Name          string
	Ordinal       int    // 0-based position in the table
	DataType      string // e.g. "int", "varchar", "datetime"
	ColumnType    string // e.g. "tinyint(1)", "int(11) unsigned"
	Nullable      bool
	IsPrimary     bool
	AutoIncrement bool
	HasDefault    bool
	// Generated is true for STORED/VIRTUAL generated columns. The database
	// computes their value and rejects any client-supplied one, so they are
	// never writable and never required on insert.
	Generated bool
}

// ForeignKey is a (possibly composite) foreign key relationship.
type ForeignKey struct {
	ConstraintName string
	Table          string
	Columns        []string
	RefTable       string
	RefColumns     []string
}

// HasColumn reports whether the table has a column with the given name.
func (t *Table) HasColumn(name string) bool {
	_, ok := t.ColumnMap[name]
	return ok
}

// TableColumns returns the column names of one table (empty map if the table
// does not exist). Unlike Load it works for tables outside the exposed
// catalog, e.g. an identity table that is deliberately not published.
func TableColumns(ctx context.Context, db *sql.DB, schema, table string) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT column_name FROM information_schema.columns
		 WHERE table_schema = ? AND table_name = ?`, schema, table)
	if err != nil {
		return nil, fmt.Errorf("introspect columns of %s.%s: %w", schema, table, err)
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

// Load introspects the given schema. include/exclude filter table names;
// an empty include list means every base table in the schema.
func Load(ctx context.Context, db *sql.DB, schema string, include, exclude []string) (*Catalog, error) {
	cat := &Catalog{SchemaName: schema, Tables: map[string]*Table{}}

	includeSet := map[string]bool{}
	for _, t := range include {
		includeSet[t] = true
	}
	excludeSet := map[string]bool{}
	for _, t := range exclude {
		excludeSet[t] = true
	}

	rows, err := db.QueryContext(ctx,
		`SELECT table_name FROM information_schema.tables
		 WHERE table_schema = ? AND table_type = 'BASE TABLE'
		 ORDER BY table_name`, schema)
	if err != nil {
		return nil, fmt.Errorf("list tables of schema %q: %w", schema, err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if excludeSet[name] {
			continue
		}
		if len(includeSet) > 0 && !includeSet[name] {
			continue
		}
		cat.Tables[name] = &Table{Name: name, ColumnMap: map[string]*Column{}}
		cat.TableOrder = append(cat.TableOrder, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cat.Tables) == 0 {
		return nil, fmt.Errorf("schema %q contains no exposable base tables (check database.schema and schema_gen.tables filters)", schema)
	}

	for _, name := range cat.TableOrder {
		if err := loadColumns(ctx, db, schema, cat.Tables[name]); err != nil {
			return nil, err
		}
	}
	if err := loadForeignKeys(ctx, db, schema, cat); err != nil {
		return nil, err
	}
	return cat, nil
}

func loadColumns(ctx context.Context, db *sql.DB, schema string, t *Table) error {
	rows, err := db.QueryContext(ctx,
		`SELECT column_name, data_type, column_type, is_nullable, column_key, extra,
		        column_default IS NOT NULL
		 FROM information_schema.columns
		 WHERE table_schema = ? AND table_name = ?
		 ORDER BY ordinal_position`, schema, t.Name)
	if err != nil {
		return fmt.Errorf("introspect columns of %s: %w", t.Name, err)
	}
	defer rows.Close()
	for rows.Next() {
		var c Column
		var nullable, key, extra string
		var hasDefault bool
		if err := rows.Scan(&c.Name, &c.DataType, &c.ColumnType, &nullable, &key, &extra, &hasDefault); err != nil {
			return err
		}
		c.DataType = strings.ToLower(c.DataType)
		c.ColumnType = strings.ToLower(c.ColumnType)
		c.Nullable = strings.EqualFold(nullable, "YES")
		c.IsPrimary = strings.EqualFold(key, "PRI")
		extraLower := strings.ToLower(extra)
		c.AutoIncrement = strings.Contains(extraLower, "auto_increment")
		// "STORED GENERATED" / "VIRTUAL GENERATED" mark computed columns.
		// (Guard against matching "default_generated", which is unrelated.)
		c.Generated = strings.Contains(extraLower, "stored generated") ||
			strings.Contains(extraLower, "virtual generated")
		c.HasDefault = hasDefault || c.AutoIncrement || c.Generated ||
			strings.Contains(extraLower, "default_generated")
		c.Ordinal = len(t.Columns)
		t.Columns = append(t.Columns, &c)
		t.ColumnMap[c.Name] = &c
		if c.IsPrimary {
			t.PrimaryKey = append(t.PrimaryKey, c.Name)
		}
	}
	return rows.Err()
}

func loadForeignKeys(ctx context.Context, db *sql.DB, schema string, cat *Catalog) error {
	// referenced_table_schema is pinned to the same schema: gqlgate only
	// exposes one schema and always qualifies joins with it, so a cross-schema
	// FK to a same-named table elsewhere must not be treated as a local
	// relationship (it would silently join against the wrong table).
	rows, err := db.QueryContext(ctx,
		`SELECT constraint_name, table_name, column_name, referenced_table_name, referenced_column_name
		 FROM information_schema.key_column_usage
		 WHERE table_schema = ? AND referenced_table_schema = ? AND referenced_table_name IS NOT NULL
		 ORDER BY table_name, constraint_name, ordinal_position`, schema, schema)
	if err != nil {
		return fmt.Errorf("introspect foreign keys: %w", err)
	}
	defer rows.Close()

	byConstraint := map[string]*ForeignKey{}
	var order []string
	for rows.Next() {
		var constraint, table, col, refTable, refCol string
		if err := rows.Scan(&constraint, &table, &col, &refTable, &refCol); err != nil {
			return err
		}
		// Only keep FKs where both ends are exposed tables.
		if _, ok := cat.Tables[table]; !ok {
			continue
		}
		if _, ok := cat.Tables[refTable]; !ok {
			continue
		}
		key := table + "\x00" + constraint
		fk, ok := byConstraint[key]
		if !ok {
			fk = &ForeignKey{ConstraintName: constraint, Table: table, RefTable: refTable}
			byConstraint[key] = fk
			order = append(order, key)
		}
		fk.Columns = append(fk.Columns, col)
		fk.RefColumns = append(fk.RefColumns, refCol)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	sort.Strings(order)
	for _, key := range order {
		fk := byConstraint[key]
		cat.Tables[fk.Table].ForeignKeys = append(cat.Tables[fk.Table].ForeignKeys, fk)
		cat.Tables[fk.RefTable].IncomingFKs = append(cat.Tables[fk.RefTable].IncomingFKs, fk)
	}
	return nil
}
