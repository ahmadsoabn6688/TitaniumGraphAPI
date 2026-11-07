package e2e

import (
	"fmt"
	"strings"
	"testing"

	"gqlgate/config"
)

// Regression tests for the mutation review findings: keys stored in another
// form than sent, row limits hit after a commit, and legacy insert.filter
// configs that must keep booting.

// Keys the database stores in another form than the one sent (DECIMAL
// rounding, DATETIME fractional seconds, FLOAT precision, a key column
// changed by ON UPDATE) must never let a written row escape the write check:
// the rows are found again by their stored form, and a row that cannot be
// found fails the check.
const keyFormFixture = `
CREATE TABLE ledger (id DECIMAL(10,2) PRIMARY KEY, owner BIGINT NOT NULL);
CREATE TABLE slots (at DATETIME PRIMARY KEY, owner BIGINT NOT NULL);
CREATE TABLE floats (k FLOAT PRIMARY KEY, owner BIGINT NOT NULL);
CREATE TABLE stamps (
	id INT NOT NULL,
	at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
	owner BIGINT NOT NULL,
	note VARCHAR(20) NOT NULL DEFAULT '',
	PRIMARY KEY (id, at)
);
INSERT INTO ledger VALUES (5, 1), (7, 2);
INSERT INTO stamps (id, at, owner) VALUES (1, '2024-01-01 00:00:00', 1);
`

const keyFormRolesYAML = `roles:
  admin:
    tables:
      "*":
        select: true
        insert: true
        update: true
        delete: true
  owner:
    tables:
      "*":
        select:
          allow: true
          filter: "owner = :jwt.sub"
        insert:
          allow: true
          check: "owner = :jwt.sub"
        update:
          allow: true
          filter: "owner = :jwt.sub"
          check: "owner = :jwt.sub"
  anonymous:
    tables:
      slots:
        select: true
`

func TestWriteCheckStoredKeyForms(t *testing.T) {
	t.Parallel()
	env := New(t, WithFixtures(keyFormFixture), WithRolesYAML(keyFormRolesYAML))
	one, two := env.Token(t, "owner", 1), env.Token(t, "owner", 2)
	admin := env.Token(t, "admin", 99)
	str := func(r *Result, path string) string { return fmt.Sprint(r.Get(path)) }

	// DECIMAL: "1.005" is stored as 1.01. Giving the row to owner 2 must
	// fail the check (the lookup by "1.005" used to find nothing and pass).
	wantCode(t, env.GQL(t, one, `mutation { insert_ledger(objects: [{id: "1.005", owner: 2}]) { affected_rows returning { id } } }`, nil), "permission_error")
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM ledger WHERE owner = 2"); n != 1 {
		t.Fatalf("a rejected insert committed a row: %d rows of owner 2", n)
	}
	// The own row goes in and comes back in its stored form.
	r := env.MustGQL(t, one, `mutation { insert_ledger(objects: [{id: "1.005", owner: 1}]) { affected_rows returning { id owner } } }`, nil)
	if got := str(r, "insert_ledger.returning.0.id"); got != "1.01" {
		t.Errorf("returning id = %s, want 1.01 (%s)", got, r.Raw)
	}
	r = env.MustGQL(t, one, `mutation { insert_ledger_one(object: {id: "2.004", owner: 1}) { id } }`, nil)
	if got := str(r, "insert_ledger_one.id"); got != "2.00" {
		t.Errorf("insert_ledger_one = %s", r.Raw)
	}

	// An update moving the key: handing the row to owner 2 fails, keeping
	// it works and returns the new stored key.
	wantCode(t, env.GQL(t, one, `mutation { update_ledger(where: {id: {_eq: "5"}}, _set: {id: "6.005", owner: 2}) { affected_rows returning { id } } }`, nil), "permission_error")
	wantCode(t, env.GQL(t, one, `mutation { update_ledger_by_pk(id: "5", _set: {id: "6.005", owner: 2}) { id } }`, nil), "permission_error")
	if got := env.QueryInt(t, "SELECT owner FROM ledger WHERE id = 5"); got != 1 {
		t.Fatalf("a rejected update moved row 5 to owner %d", got)
	}
	r = env.MustGQL(t, one, `mutation { update_ledger(where: {id: {_eq: "5"}}, _set: {id: "6.005"}) { affected_rows returning { id owner } } }`, nil)
	if got := str(r, "update_ledger.returning.0.id"); got != "6.01" {
		t.Errorf("update returning = %s", r.Raw)
	}
	r = env.MustGQL(t, one, `mutation { update_ledger_by_pk(id: "6.01", _set: {id: "6.5"}) { id } }`, nil)
	if got := str(r, "update_ledger_by_pk.id"); got != "6.50" {
		t.Errorf("update_ledger_by_pk = %s", r.Raw)
	}
	// Negative RBAC: owner 1 cannot touch (or see) owner 2's row 7.
	wantInt(t, env.MustGQL(t, one, `mutation { update_ledger(where: {id: {_eq: "7"}}, _set: {owner: 1}) { affected_rows } }`, nil), "update_ledger.affected_rows", 0)
	r = env.MustGQL(t, two, `{ ledger_connection(first: 10) { nodes { id owner } } }`, nil)
	if nodes := r.List(t, "ledger_connection.nodes"); len(nodes) != 1 || str(r, "ledger_connection.nodes.0.id") != "7.00" {
		t.Errorf("owner 2 sees %s", r.Raw)
	}

	// DATETIME: .7 seconds rounds up to the next second.
	wantCode(t, env.GQL(t, one, `mutation { insert_slots_one(object: {at: "2024-01-01T00:00:00.7Z", owner: 2}) { at } }`, nil), "permission_error")
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM slots"); n != 0 {
		t.Fatalf("a rejected insert committed %d slots", n)
	}
	r = env.MustGQL(t, one, `mutation { insert_slots_one(object: {at: "2024-01-01T00:00:00.7Z", owner: 1}) { at owner } }`, nil)
	if r.Get("insert_slots_one") == nil {
		t.Errorf("insert_slots_one must return the row: %s", r.Raw)
	}

	// FLOAT 0.1 is stored as a nearby value that no lookup by 0.1 finds: the
	// check cannot be verified, so the insert fails closed.
	wantCode(t, env.GQL(t, one, `mutation { insert_floats_one(object: {k: 0.1, owner: 1}) { k } }`, nil), "permission_error")
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM floats"); n != 0 {
		t.Fatalf("an unverifiable insert committed %d rows", n)
	}
	env.MustGQL(t, one, `mutation { insert_floats_one(object: {k: 0.5, owner: 1}) { k } }`, nil)

	// ON UPDATE CURRENT_TIMESTAMP changes a key column the update does not
	// set: the row cannot be found again, so a checked update fails closed.
	wantCode(t, env.GQL(t, one, `mutation { update_stamps(where: {id: {_eq: 1}}, _set: {note: "x"}) { affected_rows } }`, nil), "permission_error")
	if got := env.QueryString(t, "SELECT note FROM stamps WHERE id = 1"); got != "" {
		t.Errorf("a rejected update committed note %q", got)
	}

	// A role without a check is unaffected, and returning finds the stored form.
	r = env.MustGQL(t, admin, `mutation { insert_ledger(objects: [{id: "3.005", owner: 2}]) { returning { id owner } } }`, nil)
	if got := str(r, "insert_ledger.returning.0.id"); got != "3.01" {
		t.Errorf("admin returning = %s", r.Raw)
	}
	wantInt(t, env.MustGQL(t, admin, `mutation { update_stamps(where: {id: {_eq: 1}}, _set: {note: "y"}) { affected_rows } }`, nil), "update_stamps.affected_rows", 1)
}

// Relationship rows under `returning` are read after the commit. When they
// push the request over server.max_response_rows, data can come back null;
// the error must then say the mutation was applied, so it is not retried.
func TestResponseRowLimitAfterCommit(t *testing.T) {
	t.Parallel()
	env := New(t, WithConfig(func(c *config.Config) { c.Server.MaxResponseRows = 3 }))
	admin := env.Token(t, "admin", 4)
	r := env.GQL(t, admin, `mutation { update_users(where: {id: {_eq: 1}}, _set: {name: "Ada2"}) { returning { id posts { id comments { id } } } } }`, nil)
	wantCode(t, r, "response_too_large")
	r.MustFail(t, "the mutation itself was applied")
	applied := false
	for _, e := range r.Errors {
		applied = applied || e.Extensions["mutation_applied"] == true
	}
	if !applied {
		t.Errorf("the limit error must carry extensions.mutation_applied: %s", r.Raw)
	}
	if got := env.QueryString(t, "SELECT name FROM users WHERE id = 1"); got != "Ada2" {
		t.Fatalf("the update must have committed, name = %q", got)
	}
	// A query over the limit (nothing written) does not claim a write.
	r = env.GQL(t, admin, `{ posts_connection(first: 10) { nodes { id } } }`, nil)
	wantCode(t, r, "response_too_large")
	if strings.Contains(string(r.Raw), "applied") {
		t.Errorf("a read must not claim a write: %s", r.Raw)
	}
	// Top-level returning over the limit still rolls the mutation back.
	r = env.GQL(t, admin, `mutation { update_posts(where: {}, _set: {views: 7}) { returning { id } } }`, nil)
	wantCode(t, r, "response_too_large")
	if strings.Contains(string(r.Raw), "applied") {
		t.Errorf("a rolled-back mutation must not claim a write: %s", r.Raw)
	}
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM posts WHERE views = 7"); n != 0 {
		t.Errorf("an over-limit returning must roll the update back, %d rows updated", n)
	}
	// Second role: anonymous over the limit, no write claimed either.
	r = env.GQL(t, "", `{ posts_connection(first: 10) { nodes { id comments { id } } } }`, nil)
	wantCode(t, r, "response_too_large")
}

// A legacy insert.filter that earlier versions ignored must not stop such a
// config from booting (or reloading): where it cannot be enforced — a table
// without a primary key, a "*" rule naming a column the table lacks — it is
// skipped with a warning; elsewhere it is enforced as the insert check.
func TestLegacyInsertFilterCompat(t *testing.T) {
	t.Parallel()
	const legacy = `roles:
  admin:
    tables:
      "*":
        select: true
        insert: true
        update: true
        delete: true
  writer:
    tables:
      "*":
        select: true
        insert:
          allow: true
          filter: "user_id = :jwt.sub"
  anonymous:
    tables:
      posts:
        select: true
`
	env := New(t, WithSQL("CREATE TABLE nopk (a INT, b INT)"), WithRolesYAML(legacy))
	writer := env.Token(t, "writer", 3)
	admin := env.Token(t, "admin", 4)

	// No primary key: inserts work as before.
	wantInt(t, env.MustGQL(t, writer, `mutation { insert_nopk(objects: [{a: 1, b: 2}]) { affected_rows } }`, nil), "insert_nopk.affected_rows", 1)
	// posts has no user_id: the rule is skipped there, as before.
	env.MustGQL(t, writer, `mutation { insert_posts_one(object: {author_id: 1, title: "legacy"}) { id } }`, nil)
	// comments has user_id: enforced, so writer 3 cannot comment as user 1.
	wantCode(t, env.GQL(t, writer, `mutation { insert_comments_one(object: {post_id: 1, user_id: 1, body: "as ada"}) { id } }`, nil), "permission_error")
	env.MustGQL(t, writer, `mutation { insert_comments_one(object: {post_id: 1, user_id: 3, body: "as alan"}) { id } }`, nil)
	// A role without any write permission gets no mutations at all.
	env.GQL(t, "", `mutation { insert_comments_one(object: {post_id: 1, user_id: 1, body: "anon"}) { id } }`, nil).MustFail(t, "not configured for mutations")
	// admin has no filter.
	env.MustGQL(t, admin, `mutation { insert_comments_one(object: {post_id: 1, user_id: 1, body: "admin"}) { id } }`, nil)

	// Hot reload accepts the same config.
	if err := env.Reload(t, legacy); err != nil {
		t.Fatalf("reload with a legacy insert.filter: %v", err)
	}
	wantInt(t, env.MustGQL(t, writer, `mutation { insert_nopk(objects: [{a: 3, b: 4}]) { affected_rows } }`, nil), "insert_nopk.affected_rows", 1)
}
