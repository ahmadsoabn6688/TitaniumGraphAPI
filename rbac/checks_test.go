package rbac

import (
	"strings"
	"testing"

	"gqlgate/config"
	"gqlgate/introspect"
)

func checksCatalog() *introspect.Catalog {
	id := &introspect.Column{Name: "id", IsPrimary: true}
	org := &introspect.Column{Name: "org_id", Ordinal: 1}
	t := &introspect.Table{
		Name: "projects", Columns: []*introspect.Column{id, org},
		ColumnMap: map[string]*introspect.Column{"id": id, "org_id": org}, PrimaryKey: []string{"id"},
	}
	return &introspect.Catalog{SchemaName: "appdb", Tables: map[string]*introspect.Table{"projects": t}, TableOrder: []string{"projects"}}
}

func resolveOne(t *testing.T, perm *config.TablePerm) (*TableAccess, error) {
	t.Helper()
	acc, err := Resolve("r", &config.Role{Tables: map[string]*config.TablePerm{"projects": perm}}, checksCatalog())
	if err != nil {
		return nil, err
	}
	return acc.Table("projects"), nil
}

func TestWriteChecksCompiled(t *testing.T) {
	ta, err := resolveOne(t, &config.TablePerm{
		Insert: &config.OpPerm{Allow: true, Check: "org_id IN (:jwt.orgs)"},
		Update: &config.OpPerm{Allow: true, Filter: "org_id IN (:jwt.orgs)", Check: "org_id IN (:jwt.orgs)"},
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"orgs": []any{float64(1), float64(2)}}
	for name, oa := range map[string]*OpAccess{"insert": ta.Insert, "update": ta.Update} {
		if oa.Check == nil {
			t.Fatalf("%s check not compiled", name)
		}
		sql, args, err := oa.Check.SQL(claims)
		if err != nil || sql != "org_id IN (?, ?)" || len(args) != 2 {
			t.Errorf("%s check = %q %v %v", name, sql, args, err)
		}
	}
	if ta.Insert.CheckFromFilter || ta.Insert.Filter != nil {
		t.Error("an explicit insert check must not be marked as coming from filter")
	}
	if ta.Update.Filter == nil {
		t.Error("the update filter must stay the update's row filter")
	}
}

// An insert filter used to be accepted and silently ignored; it is enforced
// as the insert check now, never left as an unused row filter.
func TestInsertFilterBecomesCheck(t *testing.T) {
	ta, err := resolveOne(t, &config.TablePerm{Insert: &config.OpPerm{Allow: true, Filter: "org_id = :jwt.org"}})
	if err != nil {
		t.Fatal(err)
	}
	if ta.Insert.Check == nil || !ta.Insert.CheckFromFilter || ta.Insert.Filter != nil {
		t.Errorf("insert filter not turned into the check: %+v", ta.Insert)
	}
}

func TestCheckRejectedOnSelectAndDelete(t *testing.T) {
	for name, perm := range map[string]*config.TablePerm{
		"select": {Select: &config.OpPerm{Allow: true, Check: "1 = 1"}},
		"delete": {Delete: &config.OpPerm{Allow: true, Check: "1 = 1"}},
		"both":   {Insert: &config.OpPerm{Allow: true, Filter: "1 = 1", Check: "2 = 2"}},
	} {
		if _, err := resolveOne(t, perm); err == nil || !strings.Contains(err.Error(), "check") {
			t.Errorf("%s: got %v, want a check error", name, err)
		}
	}
}
