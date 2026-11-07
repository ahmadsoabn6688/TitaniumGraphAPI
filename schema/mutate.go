package schema

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"gqlgate/introspect"
	"gqlgate/rbac"
)

// Writes.
//
// TiDB has no RETURNING clause, so everything a mutation reports back — the
// rows for `returning`, the input of the role's write check — is read inside
// the mutation's own transaction, which sees its uncommitted writes:
//
//   - insert runs one INSERT per object and records each row's primary key
//     (the supplied values, or LAST_INSERT_ID for an AUTO_INCREMENT /
//     AUTO_RANDOM column: one row per statement, so the id is that row's
//     even when AUTO_RANDOM values are not contiguous);
//   - update and delete first lock the rows they will touch with
//     `SELECT <key> … WHERE <where> AND <update/delete filter> FOR UPDATE`
//     and then write exactly those keys, so the rows written, checked and
//     returned are the same rows.
//
// The write check (insert.check / update.check) then counts the written rows
// that do not satisfy it — `(<check>) IS NOT TRUE`, so a check that comes out
// NULL fails too — and any such row rolls the whole mutation back. It runs
// after the before-hooks and the write but before the after-hooks, so an
// after-hook never sees rows that are about to be rolled back.
//
// `returning` rows are re-read through the role's SELECT permission (its
// columns and row filter): a written row the role cannot read is written but
// not returned. Which rows a delete removes depends only on the DELETE
// permission; the rows are read for `returning` before they are deleted.
//
// Without `returning` and without a check, update and delete keep running as
// one plain statement (no key list in memory, however many rows match).

// queryer is the read side shared by *sql.DB and *sql.Tx.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// writeOpts tunes one update or delete.
type writeOpts struct {
	// returning collects the written rows, as the role may read them.
	returning bool
	// keyCols identify one row: the unique key a _by_<key> mutation
	// addresses, or nil for the primary key.
	keyCols []string
}

// keyChunkParams bounds the parameters of one `(key) IN (…)` statement.
const keyChunkParams = 1000

// chunkKeys splits key tuples into groups small enough for one statement.
func chunkKeys(keys [][]any, width int) [][][]any {
	size := keyChunkParams
	if width > 1 {
		size = keyChunkParams / width
	}
	if size < 1 {
		size = 1
	}
	var out [][][]any
	for len(keys) > 0 {
		n := min(size, len(keys))
		out = append(out, keys[:n])
		keys = keys[n:]
	}
	return out
}

func quotedList(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = quoteIdent(c)
	}
	return strings.Join(q, ", ")
}

// inTx runs fn in a transaction, committing on success (and recording the
// commit for the response-limit accounting) and rolling back on error.
func (b *builder) inTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := b.opt.DB.BeginTx(ctx, nil)
	if err != nil {
		return b.dbErr(err)
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return b.dbErr(err)
	}
	noteCommit(ctx)
	return nil
}

// runInsert inserts the given objects in one transaction and returns the
// number of inserted rows, plus the inserted rows as the role may read them
// when returning is set.
func (b *builder) runInsert(ctx context.Context, ti *tableInfo, id *rbac.Identity, objects []any, returning bool) (int64, []map[string]any, error) {
	oa := ti.access.Insert
	if oa == nil {
		return 0, nil, fmt.Errorf("insert into %q is not permitted for role %q", ti.table.Name, b.role)
	}
	if len(objects) == 0 {
		return 0, nil, fmt.Errorf("objects must not be empty")
	}
	pk := ti.table.PrimaryKey
	if oa.Check != nil && len(pk) == 0 {
		return 0, nil, fmt.Errorf("insert into %q: the role's insert check needs a primary key to find the inserted rows", ti.table.Name)
	}
	returning = returning && ti.access.Select != nil && len(pk) > 0
	needKeys := returning || oa.Check != nil

	// Resolve every object's columns/values first, so lifecycle hooks see the
	// full batch (with presets applied) before anything is written.
	type mergedRow struct {
		cols []*introspect.Column
		vals []any
	}
	merged := make([]mergedRow, 0, len(objects))
	eventValues := make([]map[string]any, 0, len(objects))
	for _, item := range objects {
		obj, ok := item.(map[string]any)
		if !ok {
			return 0, nil, fmt.Errorf("insert objects must be objects")
		}
		cols, vals, err := mergedRowValues(ti, oa, obj, id)
		if err != nil {
			return 0, nil, err
		}
		if len(cols) == 0 {
			return 0, nil, fmt.Errorf("insert object for %q has no columns", ti.table.Name)
		}
		merged = append(merged, mergedRow{cols, vals})
		rowMap := make(map[string]any, len(cols))
		for i, c := range cols {
			rowMap[c.Name] = vals[i]
		}
		eventValues = append(eventValues, rowMap)
	}

	var affected int64
	var out []map[string]any
	err := b.inTx(ctx, func(tx *sql.Tx) error {
		ev := &MutationEvent{Op: OpInsert, Table: ti.table.Name, Role: b.role, Claims: id.Claims, Values: eventValues, Tx: tx}
		if err := b.opt.Hooks.runBefore(ctx, ev); err != nil {
			return err
		}
		var keys [][]any
		for _, m := range merged {
			names := make([]string, len(m.cols))
			for i, c := range m.cols {
				names[i] = quoteIdent(c.Name)
			}
			query := "INSERT INTO " + b.qualifiedTable(ti.table) +
				" (" + strings.Join(names, ", ") + ") VALUES (" +
				strings.TrimSuffix(strings.Repeat("?, ", len(m.cols)), ", ") + ")"
			b.logSQL(query, m.vals)
			res, err := tx.ExecContext(ctx, query, m.vals...)
			if err != nil {
				return b.dbErr(err)
			}
			n, _ := res.RowsAffected()
			affected += n
			if !needKeys {
				continue
			}
			lastID, _ := res.LastInsertId()
			key, ok := insertedKey(ti.table, m.cols, m.vals, lastID)
			if !ok {
				if oa.Check != nil {
					return fmt.Errorf("insert into %q: the role's insert check needs each inserted row's primary key, "+
						"but it is generated by a column default here; supply the key explicitly", ti.table.Name)
				}
				continue // cannot be found again: left out of returning
			}
			keys = append(keys, key)
		}
		if oa.Check != nil {
			if err := b.verifyCheck(ctx, tx, ti, id, oa.Check, pk, keys, "insert"); err != nil {
				return err
			}
		}
		ev.Affected = int(affected)
		if err := b.opt.Hooks.runAfter(ctx, ev); err != nil {
			return err
		}
		if returning {
			var err error
			if out, err = b.readRows(ctx, tx, ti, id, pk, keys); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return affected, out, nil
}

// insertedKey works out the primary key of a row one INSERT just wrote: the
// supplied (or preset) value of each key column, or the statement's
// LAST_INSERT_ID for an AUTO_INCREMENT / AUTO_RANDOM column left to the
// database. ok is false when a key column was filled by a column default.
func insertedKey(t *introspect.Table, cols []*introspect.Column, vals []any, lastID int64) ([]any, bool) {
	byCol := make(map[string]any, len(cols))
	for i, c := range cols {
		byCol[c.Name] = vals[i]
	}
	key := make([]any, len(t.PrimaryKey))
	for i, name := range t.PrimaryKey {
		c := t.ColumnMap[name]
		v, supplied := byCol[name]
		generated := c.AutoIncrement || c.AutoRandom
		if supplied && v != nil && !(generated && isZeroNumber(v)) {
			key[i] = v
			continue
		}
		if generated && lastID != 0 {
			if strings.Contains(c.ColumnType, "unsigned") {
				key[i] = uint64(lastID)
			} else {
				key[i] = lastID
			}
			continue
		}
		return nil, false
	}
	return key, true
}

// isZeroNumber reports a numeric zero, which an AUTO_INCREMENT column treats
// like NULL (it generates the next id).
func isZeroNumber(v any) bool {
	switch n := v.(type) {
	case int:
		return n == 0
	case int64:
		return n == 0
	case float64:
		return n == 0
	case string:
		return n == "0"
	}
	return false
}

// verifyCheck fails with a permission error when any of the written rows
// (identified by keyCols/keys) does not satisfy the role's write check.
func (b *builder) verifyCheck(ctx context.Context, tx *sql.Tx, ti *tableInfo, id *rbac.Identity, check *rbac.Filter, keyCols []string, keys [][]any, op string) error {
	csql, cargs, err := check.SQL(id.Claims)
	if err != nil {
		return err
	}
	for _, chunk := range chunkKeys(keys, len(keyCols)) {
		in := inCondition(keyCols, chunk)
		query := "SELECT COUNT(*) FROM " + b.qualifiedTable(ti.table) +
			" WHERE " + in.sql + " AND (" + csql + ") IS NOT TRUE"
		args := append(append([]any{}, in.args...), cargs...)
		b.logSQL(query, args)
		var bad int64
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&bad); err != nil {
			return b.dbErr(err)
		}
		if bad > 0 {
			return checkFailed(op, ti.table.Name)
		}
	}
	return nil
}

// lockKeys selects (and, in a pessimistic transaction, locks) the key of
// every row matching cond, in key order. OF limits the locks to the target
// table: rows a filter's subquery reads elsewhere are not locked.
func (b *builder) lockKeys(ctx context.Context, tx *sql.Tx, ti *tableInfo, keyCols []string, cond *condition) ([][]any, error) {
	cols := quotedList(keyCols)
	query := "SELECT " + cols + " FROM " + b.qualifiedTable(ti.table) +
		" WHERE " + cond.sql + " ORDER BY " + cols + " FOR UPDATE OF " + quoteIdent(ti.table.Name)
	b.logSQL(query, cond.args)
	rows, err := tx.QueryContext(ctx, query, cond.args...)
	if err != nil {
		return nil, b.dbErr(err)
	}
	defer rows.Close()
	var keys [][]any
	for rows.Next() {
		key := make([]any, len(keyCols))
		ptrs := make([]any, len(key))
		for i := range key {
			ptrs[i] = &key[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, b.dbErr(err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, b.dbErr(err)
	}
	return keys, nil
}

// readRows reads the rows with the given keys as the role may see them (its
// select columns and row filter) through q — the mutation's transaction. Rows
// come back in the order of keys; rows the role cannot read are left out.
// They count against the request's response row budget.
func (b *builder) readRows(ctx context.Context, q queryer, ti *tableInfo, id *rbac.Identity, keyCols []string, keys [][]any) ([]map[string]any, error) {
	out := []map[string]any{}
	sel := ti.access.Select
	if sel == nil || len(keys) == 0 {
		return out, nil
	}
	filterCond, err := rbacCond(sel, id)
	if err != nil {
		return nil, err
	}
	for _, chunk := range chunkKeys(keys, len(keyCols)) {
		where := combineConds(inCondition(keyCols, chunk), filterCond)
		// The key columns ride along raw (they may be unreadable for the
		// role) to put the rows back in key order.
		query := "SELECT " + selectList(sel.Columns) + ", " + quotedList(keyCols) +
			" FROM " + b.qualifiedTable(ti.table) + " WHERE " + where.sql
		rows, rawKeys, err := b.scanRowsOn(ctx, q, sel.Columns, len(keyCols), query, where.args)
		if err != nil {
			return nil, err
		}
		if err := countRows(ctx, len(rows)); err != nil {
			return nil, err
		}
		out = append(out, orderByKeys(chunk, rows, rawKeys)...)
	}
	return out, nil
}

// orderByKeys orders rows (whose raw key values are rawKeys) like keys. Rows
// whose key text matches no key (an unusual type mismatch) keep their place
// after the matched ones, so no row is ever dropped.
func orderByKeys(keys [][]any, rows []map[string]any, rawKeys [][]any) []map[string]any {
	pos := make(map[string]int, len(keys))
	for i, k := range keys {
		if _, dup := pos[keyText(k)]; !dup {
			pos[keyText(k)] = i
		}
	}
	idx := make([]int, len(rows))
	for i := range rows {
		p, ok := pos[keyText(rawKeys[i])]
		if !ok {
			p = len(keys) + i
		}
		idx[i] = p
	}
	order := make([]int, len(rows))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return idx[order[a]] < idx[order[b]] })
	out := make([]map[string]any, len(rows))
	for i, o := range order {
		out[i] = rows[o]
	}
	return out
}

// keyText renders a key tuple so that a bound input value and the raw value
// the driver scans for the same key compare equal (5 / int64(5) / "5").
func keyText(key []any) string {
	parts := make([]string, len(key))
	for i, v := range key {
		switch x := v.(type) {
		case nil:
			parts[i] = "\x01null"
		case []byte:
			parts[i] = string(x)
		case string:
			parts[i] = x
		case int:
			parts[i] = strconv.Itoa(x)
		case int64:
			parts[i] = strconv.FormatInt(x, 10)
		case uint64:
			parts[i] = strconv.FormatUint(x, 10)
		case float64:
			if x == float64(int64(x)) {
				parts[i] = strconv.FormatInt(int64(x), 10)
			} else {
				parts[i] = strconv.FormatFloat(x, 'g', -1, 64)
			}
		case time.Time:
			parts[i] = x.Format("2006-01-02 15:04:05.999999999")
		default:
			parts[i] = fmt.Sprint(x)
		}
	}
	return strings.Join(parts, "\x00")
}

// movedKeys applies an update's _set to the locked keys: a key column the
// update assigns now holds the assigned value in every updated row.
func movedKeys(keyCols []string, keys [][]any, setValues map[string]any) [][]any {
	moved := false
	for _, c := range keyCols {
		if _, ok := setValues[c]; ok {
			moved = true
		}
	}
	if !moved {
		return keys
	}
	out := make([][]any, len(keys))
	for i, k := range keys {
		nk := append([]any{}, k...)
		for j, c := range keyCols {
			if v, ok := setValues[c]; ok {
				nk[j] = v
			}
		}
		out[i] = nk
	}
	return out
}

// identityCols resolves the columns that identify one row for a write.
func identityCols(ti *tableInfo, opts writeOpts) []string {
	if opts.keyCols != nil {
		return opts.keyCols
	}
	return ti.table.PrimaryKey
}

// runUpdate updates the rows matching where (and the role's update filter)
// and returns how many matched, plus the updated rows as the role may read
// them when opts.returning is set.
func (b *builder) runUpdate(ctx context.Context, ti *tableInfo, id *rbac.Identity, set map[string]any, where *condition, opts writeOpts) (int64, []map[string]any, error) {
	oa := ti.access.Update
	if oa == nil {
		return 0, nil, fmt.Errorf("update on %q is not permitted for role %q", ti.table.Name, b.role)
	}
	setSQL, setArgs, setValues, err := setClause(ti, oa, set, id)
	if err != nil {
		return 0, nil, err
	}
	filterCond, err := rbacCond(oa, id)
	if err != nil {
		return 0, nil, err
	}
	cond := combineConds(where, filterCond)
	keyCols := identityCols(ti, opts)
	needKeys := opts.returning || oa.Check != nil
	if needKeys && len(keyCols) == 0 {
		return 0, nil, fmt.Errorf("update on %q: returning and the update check need a primary key", ti.table.Name)
	}

	var n int64
	var out []map[string]any
	err = b.inTx(ctx, func(tx *sql.Tx) error {
		// Values matches the insert path's contract: SQL column names, presets
		// applied, values bound — so a hook sees what is actually written.
		ev := &MutationEvent{Op: OpUpdate, Table: ti.table.Name, Role: b.role, Claims: id.Claims, Values: []map[string]any{setValues}, Tx: tx}
		if err := b.opt.Hooks.runBefore(ctx, ev); err != nil {
			return err
		}
		var keys [][]any
		if !needKeys {
			query := "UPDATE " + b.qualifiedTable(ti.table) + " SET " + setSQL + " WHERE " + cond.sql
			args := append(append([]any{}, setArgs...), cond.args...)
			b.logSQL(query, args)
			res, err := tx.ExecContext(ctx, query, args...)
			if err != nil {
				return b.dbErr(err)
			}
			n, _ = res.RowsAffected()
		} else {
			if keys, err = b.lockKeys(ctx, tx, ti, keyCols, cond); err != nil {
				return err
			}
			for _, chunk := range chunkKeys(keys, len(keyCols)) {
				in := inCondition(keyCols, chunk)
				query := "UPDATE " + b.qualifiedTable(ti.table) + " SET " + setSQL + " WHERE " + in.sql
				args := append(append([]any{}, setArgs...), in.args...)
				b.logSQL(query, args)
				res, err := tx.ExecContext(ctx, query, args...)
				if err != nil {
					return b.dbErr(err)
				}
				c, _ := res.RowsAffected()
				n += c
			}
			keys = movedKeys(keyCols, keys, setValues)
			if oa.Check != nil {
				if err := b.verifyCheck(ctx, tx, ti, id, oa.Check, keyCols, keys, "update"); err != nil {
					return err
				}
			}
		}
		ev.Affected = int(n)
		if err := b.opt.Hooks.runAfter(ctx, ev); err != nil {
			return err
		}
		if opts.returning {
			var err error
			if out, err = b.readRows(ctx, tx, ti, id, keyCols, keys); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, nil, err
	}
	return n, out, nil
}

// runDelete deletes the rows matching where (and the role's delete filter)
// and returns how many were deleted, plus — when opts.returning is set — the
// deleted rows the role may read, as they were before the delete. Which rows
// are deleted never depends on the select permission.
func (b *builder) runDelete(ctx context.Context, ti *tableInfo, id *rbac.Identity, where *condition, opts writeOpts) (int64, []map[string]any, error) {
	oa := ti.access.Delete
	if oa == nil {
		return 0, nil, fmt.Errorf("delete on %q is not permitted for role %q", ti.table.Name, b.role)
	}
	filterCond, err := rbacCond(oa, id)
	if err != nil {
		return 0, nil, err
	}
	cond := combineConds(where, filterCond)
	keyCols := identityCols(ti, opts)
	if opts.returning && len(keyCols) == 0 {
		return 0, nil, fmt.Errorf("delete on %q: returning needs a primary key", ti.table.Name)
	}

	var n int64
	var out []map[string]any
	err = b.inTx(ctx, func(tx *sql.Tx) error {
		ev := &MutationEvent{Op: OpDelete, Table: ti.table.Name, Role: b.role, Claims: id.Claims, Tx: tx}
		if err := b.opt.Hooks.runBefore(ctx, ev); err != nil {
			return err
		}
		if !opts.returning {
			query := "DELETE FROM " + b.qualifiedTable(ti.table) + " WHERE " + cond.sql
			b.logSQL(query, cond.args)
			res, err := tx.ExecContext(ctx, query, cond.args...)
			if err != nil {
				return b.dbErr(err)
			}
			n, _ = res.RowsAffected()
		} else {
			// The DELETE permission alone decides the rows (locked here);
			// the SELECT permission only decides which of them are shown.
			keys, err := b.lockKeys(ctx, tx, ti, keyCols, cond)
			if err != nil {
				return err
			}
			if out, err = b.readRows(ctx, tx, ti, id, keyCols, keys); err != nil {
				return err
			}
			for _, chunk := range chunkKeys(keys, len(keyCols)) {
				in := inCondition(keyCols, chunk)
				query := "DELETE FROM " + b.qualifiedTable(ti.table) + " WHERE " + in.sql
				b.logSQL(query, in.args)
				res, err := tx.ExecContext(ctx, query, in.args...)
				if err != nil {
					return b.dbErr(err)
				}
				c, _ := res.RowsAffected()
				n += c
			}
		}
		ev.Affected = int(n)
		return b.opt.Hooks.runAfter(ctx, ev)
	})
	if err != nil {
		return 0, nil, err
	}
	return n, out, nil
}

// keyCond builds the equality condition on the given key columns from field
// arguments (by_pk and _by_<unique key> fields).
func (b *builder) keyCond(ti *tableInfo, cols []string, args map[string]any) (*condition, error) {
	var parts []string
	var vals []any
	for _, name := range cols {
		col := ti.table.ColumnMap[name]
		v, ok := args[ti.colToField[name]]
		if !ok || v == nil {
			return nil, fmt.Errorf("missing key argument %q", ti.colToField[name])
		}
		bound, err := bindValue(col, v)
		if err != nil {
			return nil, err
		}
		parts = append(parts, quoteIdent(col.Name)+" = ?")
		vals = append(vals, bound)
	}
	return &condition{sql: strings.Join(parts, " AND "), args: vals}, nil
}

// pkCond builds the primary-key equality condition from by_pk arguments.
func (b *builder) pkCond(ti *tableInfo, args map[string]any) (*condition, error) {
	return b.keyCond(ti, ti.table.PrimaryKey, args)
}
