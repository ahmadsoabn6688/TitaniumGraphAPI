// Package introspect reads table/column/key metadata for one schema out of
// information_schema on TiDB (or any MySQL-compatible server).
package introspect

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// Catalog is the introspected shape of one database schema.
type Catalog struct {
	SchemaName string
	Tables     map[string]*Table
	TableOrder []string // stable iteration order
}

// Table describes one base table or view.
type Table struct {
	Name string
	// IsView marks a view: read-only, without keys or foreign keys of its
	// own (a logical key and relationships can be declared in the config).
	IsView bool
	// Comment is the table COMMENT ("" for none, and always for views).
	Comment     string
	Columns     []*Column
	ColumnMap   map[string]*Column
	PrimaryKey  []string      // column names, in key order; empty if no PK
	ForeignKeys []*ForeignKey // FKs declared on this table (outgoing)
	IncomingFKs []*ForeignKey // FKs on other tables referencing this one
	// UniqueKeys are the table's UNIQUE indexes usable as row lookups: every
	// column NOT NULL and indexed in full (no prefix or expression parts),
	// and not the primary key's column set again. Ordered by index name.
	UniqueKeys []*UniqueKey
}

// UniqueKey is one UNIQUE index whose columns identify at most one row.
type UniqueKey struct {
	Name    string
	Columns []string // in index order
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
	// AutoRandom marks a TiDB AUTO_RANDOM primary key column: the database
	// generates its value (reported through LAST_INSERT_ID like
	// AUTO_INCREMENT), so it is optional on insert.
	AutoRandom bool
	HasDefault bool
	// Generated is true for STORED/VIRTUAL generated columns. The database
	// computes their value and rejects any client-supplied one, so they are
	// never writable and never required on insert.
	Generated bool
	// Charset and Collation of character columns ("" for other types), e.g.
	// "utf8mb4" / "utf8mb4_bin". The string filter operators use them to
	// pick a case-(in)sensitive comparison that can still use an index.
	Charset   string
	Collation string
	// Comment is the column COMMENT ("" for none).
	Comment string
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

// Options selects what Load introspects.
type Options struct {
	// Include/Exclude filter table names; an empty include list means every
	// base table in the schema. Exclude wins.
	Include, Exclude []string
	// Views lists the views that may be loaded (subject to Include/Exclude
	// like tables). A view not listed here is never loaded, so exposing views
	// is opt-in by name.
	Views []string
}

// Load introspects the given schema's base tables. include/exclude filter
// table names; an empty include list means every base table in the schema.
func Load(ctx context.Context, db *sql.DB, schema string, include, exclude []string) (*Catalog, error) {
	return LoadWith(ctx, db, schema, Options{Include: include, Exclude: exclude})
}

// LoadWith introspects the given schema: its base tables and the views named
// in opt.Views, filtered by opt.Include/opt.Exclude.
func LoadWith(ctx context.Context, db *sql.DB, schema string, opt Options) (*Catalog, error) {
	cat := &Catalog{SchemaName: schema, Tables: map[string]*Table{}}

	includeSet := map[string]bool{}
	for _, t := range opt.Include {
		includeSet[t] = true
	}
	excludeSet := map[string]bool{}
	for _, t := range opt.Exclude {
		excludeSet[t] = true
	}
	viewSet := map[string]bool{}
	for _, t := range opt.Views {
		viewSet[t] = true
	}

	rows, err := db.QueryContext(ctx,
		`SELECT table_name, table_type, IFNULL(table_comment, '') FROM information_schema.tables
		 WHERE table_schema = ? AND table_type IN ('BASE TABLE', 'VIEW')
		 ORDER BY table_name`, schema)
	if err != nil {
		return nil, fmt.Errorf("list tables of schema %q: %w", schema, err)
	}
	defer rows.Close()
	baseTables := 0
	for rows.Next() {
		var name, kind, comment string
		if err := rows.Scan(&name, &kind, &comment); err != nil {
			return nil, err
		}
		isView := strings.EqualFold(kind, "VIEW")
		if excludeSet[name] || (isView && !viewSet[name]) {
			continue
		}
		if len(includeSet) > 0 && !includeSet[name] {
			continue
		}
		t := &Table{Name: name, IsView: isView, ColumnMap: map[string]*Column{}}
		if isView {
			comment = "" // TiDB/MySQL report the literal "VIEW" here
		} else {
			baseTables++
		}
		t.Comment = comment
		cat.Tables[name] = t
		cat.TableOrder = append(cat.TableOrder, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if baseTables == 0 {
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
	if err := loadAutoRandom(ctx, db, schema, cat); err != nil {
		return nil, err
	}
	if err := loadUniqueKeys(ctx, db, schema, cat); err != nil {
		return nil, err
	}
	return cat, nil
}

// loadAutoRandom marks AUTO_RANDOM primary key columns. TiDB reports them
// only in information_schema.tables.tidb_row_id_sharding_info
// ("PK_AUTO_RANDOM_BITS=<n>"), not in columns.extra. On plain MySQL the
// column does not exist, which simply means no AUTO_RANDOM keys.
func loadAutoRandom(ctx context.Context, db *sql.DB, schema string, cat *Catalog) error {
	rows, err := db.QueryContext(ctx,
		`SELECT table_name, IFNULL(tidb_row_id_sharding_info, '')
		 FROM information_schema.tables WHERE table_schema = ?`, schema)
	if err != nil {
		var me *mysql.MySQLError
		if errors.As(err, &me) && me.Number == 1054 { // unknown column: not TiDB
			return nil
		}
		return fmt.Errorf("introspect auto_random keys: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, info string
		if err := rows.Scan(&name, &info); err != nil {
			return err
		}
		markAutoRandom(cat.Tables[name], info)
	}
	return rows.Err()
}

// markAutoRandom applies one table's sharding info: an AUTO_RANDOM table has
// a single-column primary key whose value the database generates.
func markAutoRandom(t *Table, shardingInfo string) {
	if t == nil || len(t.PrimaryKey) != 1 || !strings.HasPrefix(shardingInfo, "PK_AUTO_RANDOM_BITS=") {
		return
	}
	c := t.ColumnMap[t.PrimaryKey[0]]
	c.AutoRandom = true
	c.HasDefault = true
}

// StatRow is one row of information_schema.statistics for a unique index.
type StatRow struct {
	Table, Index string
	Column       sql.NullString // NULL for an expression part
	SubPart      sql.NullInt64  // non-NULL for a prefix part
}

func loadUniqueKeys(ctx context.Context, db *sql.DB, schema string, cat *Catalog) error {
	rows, err := db.QueryContext(ctx,
		`SELECT table_name, index_name, column_name, sub_part
		 FROM information_schema.statistics
		 WHERE table_schema = ? AND non_unique = 0 AND index_name <> 'PRIMARY'
		 ORDER BY table_name, index_name, seq_in_index`, schema)
	if err != nil {
		return fmt.Errorf("introspect unique keys: %w", err)
	}
	defer rows.Close()
	var stats []StatRow
	for rows.Next() {
		var r StatRow
		if err := rows.Scan(&r.Table, &r.Index, &r.Column, &r.SubPart); err != nil {
			return err
		}
		stats = append(stats, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	ApplyUniqueKeys(cat, stats)
	return nil
}

// ApplyUniqueKeys sets Table.UniqueKeys from unique-index statistics rows
// (ordered by table, index, position). An index is kept only when it
// identifies one row by plain equality on its columns: no expression or
// prefix parts (those don't compare whole column values), no nullable
// column (a UNIQUE index admits any number of NULLs), not the primary key's
// column set again, and not a column set an earlier index already covers.
func ApplyUniqueKeys(cat *Catalog, stats []StatRow) {
	type idx struct {
		table, name string
		cols        []string
		ok          bool
	}
	var order []*idx
	byKey := map[string]*idx{}
	for _, r := range stats {
		t := cat.Tables[r.Table]
		if t == nil {
			continue
		}
		key := r.Table + "\x00" + r.Index
		ix := byKey[key]
		if ix == nil {
			ix = &idx{table: r.Table, name: r.Index, ok: true}
			byKey[key] = ix
			order = append(order, ix)
		}
		if !r.Column.Valid || r.SubPart.Valid {
			ix.ok = false
			continue
		}
		c := t.ColumnMap[r.Column.String]
		if c == nil || c.Nullable {
			ix.ok = false
			continue
		}
		ix.cols = append(ix.cols, c.Name)
	}
	seen := map[string]bool{}
	for _, t := range cat.Tables {
		t.UniqueKeys = nil
		if len(t.PrimaryKey) > 0 {
			seen[t.Name+"\x00"+colSetKey(t.PrimaryKey)] = true
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].table != order[j].table {
			return order[i].table < order[j].table
		}
		return order[i].name < order[j].name
	})
	for _, ix := range order {
		if !ix.ok || len(ix.cols) == 0 {
			continue
		}
		k := ix.table + "\x00" + colSetKey(ix.cols)
		if seen[k] {
			continue
		}
		seen[k] = true
		t := cat.Tables[ix.table]
		t.UniqueKeys = append(t.UniqueKeys, &UniqueKey{Name: ix.name, Columns: ix.cols})
	}
}

// colSetKey identifies a set of columns regardless of their order.
func colSetKey(cols []string) string {
	s := append([]string{}, cols...)
	sort.Strings(s)
	return strings.Join(s, "\x00")
}

func loadColumns(ctx context.Context, db *sql.DB, schema string, t *Table) error {
	rows, err := db.QueryContext(ctx,
		`SELECT column_name, data_type, column_type, is_nullable, column_key, extra,
		        column_default IS NOT NULL,
		        IFNULL(character_set_name, ''), IFNULL(collation_name, ''),
		        IFNULL(column_comment, '')
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
		if err := rows.Scan(&c.Name, &c.DataType, &c.ColumnType, &nullable, &key, &extra, &hasDefault, &c.Charset, &c.Collation, &c.Comment); err != nil {
			return err
		}
		c.DataType = strings.ToLower(c.DataType)
		c.ColumnType = strings.ToLower(c.ColumnType)
		c.Charset = strings.ToLower(c.Charset)
		c.Collation = strings.ToLower(c.Collation)
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
		if c.IsPrimary && !t.IsView {
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
