package introspect

import (
	"database/sql"
	"reflect"
	"strings"
	"testing"
)

func uniqueCatalog() *Catalog {
	mk := func(name string, nullable bool) *Column { return &Column{Name: name, Nullable: nullable} }
	cols := []*Column{mk("id", false), mk("email", false), mk("tenant", false), mk("slug", false), mk("nick", true), mk("code", false)}
	t := &Table{Name: "users", ColumnMap: map[string]*Column{}, PrimaryKey: []string{"id"}}
	for _, c := range cols {
		t.Columns = append(t.Columns, c)
		t.ColumnMap[c.Name] = c
	}
	other := &Table{Name: "tags", ColumnMap: map[string]*Column{"id": mk("id", false)}}
	return &Catalog{Tables: map[string]*Table{"users": t, "tags": other}, TableOrder: []string{"tags", "users"}}
}

func stat(table, index, col string, sub int64) StatRow {
	r := StatRow{Table: table, Index: index}
	if col != "" {
		r.Column = sql.NullString{String: col, Valid: true}
	}
	if sub > 0 {
		r.SubPart = sql.NullInt64{Int64: sub, Valid: true}
	}
	return r
}

func TestApplyUniqueKeys(t *testing.T) {
	cat := uniqueCatalog()
	ApplyUniqueKeys(cat, []StatRow{
		stat("users", "uq_email", "email", 0),
		stat("users", "uq_tenant_slug", "tenant", 0), stat("users", "uq_tenant_slug", "slug", 0),
		stat("users", "uq_nick", "nick", 0),                                                      // nullable: many NULLs allowed
		stat("users", "uq_code_prefix", "code", 8),                                               // prefix: not whole-value unique
		stat("users", "uq_expr", "", 0),                                                          // expression index
		stat("users", "uq_id_again", "id", 0),                                                    // the primary key's column set
		stat("users", "uq_email_dup", "email", 0),                                                // same columns as uq_email
		stat("users", "uq_slug_tenant", "slug", 0), stat("users", "uq_slug_tenant", "tenant", 0), // same set, other order
		stat("missing", "uq", "x", 0), // table not exposed
	})
	var got [][]string
	for _, uk := range cat.Tables["users"].UniqueKeys {
		got = append(got, append([]string{uk.Name}, uk.Columns...))
	}
	want := [][]string{{"uq_email", "email"}, {"uq_slug_tenant", "slug", "tenant"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unique keys = %v, want %v", got, want)
	}
	if len(cat.Tables["tags"].UniqueKeys) != 0 {
		t.Errorf("tags has no unique index, got %v", cat.Tables["tags"].UniqueKeys)
	}
}

func TestMarkAutoRandom(t *testing.T) {
	cat := uniqueCatalog()
	markAutoRandom(cat.Tables["users"], "PK_AUTO_RANDOM_BITS=5")
	id := cat.Tables["users"].ColumnMap["id"]
	if !id.AutoRandom || !id.HasDefault {
		t.Errorf("AUTO_RANDOM key not marked: %+v", id)
	}
	cat = uniqueCatalog()
	markAutoRandom(cat.Tables["users"], "NOT_SHARDED(PK_IS_HANDLE)")
	markAutoRandom(cat.Tables["tags"], "PK_AUTO_RANDOM_BITS=5") // no primary key
	markAutoRandom(nil, "PK_AUTO_RANDOM_BITS=5")
	if cat.Tables["users"].ColumnMap["id"].AutoRandom {
		t.Error("only PK_AUTO_RANDOM_BITS marks a key")
	}
}

func TestCheckHasColumns(t *testing.T) {
	if err := checkHasColumns(&Table{Name: "t", Columns: []*Column{{Name: "id"}}}); err != nil {
		t.Errorf("table with columns: %v", err)
	}
	err := checkHasColumns(&Table{Name: "vx", IsView: true})
	if err == nil || !strings.Contains(err.Error(), `view "vx" has no columns`) || !strings.Contains(err.Error(), "dropped") {
		t.Errorf("invalid view: err = %v", err)
	}
	if err := checkHasColumns(&Table{Name: "t"}); err == nil {
		t.Error("table without columns: want an error")
	}
}

func TestColumnFromDriverType(t *testing.T) {
	cases := []struct {
		db                string
		prec, scale       int64
		hasDec            bool
		dataType, colType string
		charset           string
	}{
		{"BIGINT", 0, 0, false, "bigint", "bigint", ""},
		{"UNSIGNED INT", 0, 0, false, "int", "int unsigned", ""},
		{"DECIMAL", 10, 2, true, "decimal", "decimal(10,2)", ""},
		{"VARCHAR", 0, 0, false, "varchar", "varchar", "?"},
		{"TEXT", 0, 0, false, "text", "text", "?"},
		{"JSON", 0, 0, false, "json", "json", ""},
		{"NULL", 0, 0, false, "varchar", "varchar", ""},
		{"", 0, 0, false, "", "", ""},
	}
	for _, c := range cases {
		col := ColumnFromDriverType("x", c.db, c.prec, c.scale, c.hasDec)
		if col.DataType != c.dataType || col.ColumnType != c.colType || col.Charset != c.charset || !col.Nullable {
			t.Errorf("%q -> %+v", c.db, col)
		}
	}
}
