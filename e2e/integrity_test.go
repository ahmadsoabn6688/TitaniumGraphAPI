package e2e

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gqlgate/config"
	"gqlgate/register"
)

// End-to-end tests for data integrity edge cases: relationships through
// foreign keys that share a constraint name, keyset paging on raw-byte keys,
// mutations racing a concurrent writer, after-hooks and the response row
// limit, legacy insert filters on default-generated keys, and the shared
// mutation_response shape.

// sameFKRoles: admin reads everything; r sees only b row 1 and not a.secret.
const sameFKRoles = `roles:
  admin:
    tables:
      "*": {select: true}
  r:
    tables:
      a: {select: {allow: true, columns: [id, name]}}
      b: {select: {allow: true, filter: "id = 1"}}
      c: {select: true}
      d: {select: true}
  anonymous:
    tables:
      b: {select: true}
`

// Two foreign keys may share a constraint name on different tables (TiDB
// only requires uniqueness per table). Each relationship must still read its
// own target table through that table's permission — not whichever table's
// loader was created first in the request.
func TestSameNamedForeignKeys(t *testing.T) {
	t.Parallel()
	env := New(t, WithRolesYAML(sameFKRoles), WithSQL(
		"CREATE TABLE a (id BIGINT PRIMARY KEY, name VARCHAR(20) NOT NULL, secret VARCHAR(20) NOT NULL)",
		"CREATE TABLE b (id BIGINT PRIMARY KEY, name VARCHAR(20) NOT NULL)",
		"CREATE TABLE c (id BIGINT PRIMARY KEY, x_id BIGINT NOT NULL, CONSTRAINT fk_x FOREIGN KEY (x_id) REFERENCES a (id))",
		"CREATE TABLE d (id BIGINT PRIMARY KEY, x_id BIGINT NOT NULL, CONSTRAINT fk_x FOREIGN KEY (x_id) REFERENCES b (id))",
		"INSERT INTO a VALUES (1, 'A-one', 's1'), (2, 'A-two', 's2')",
		"INSERT INTO b VALUES (1, 'B-one'), (2, 'B-two')",
		"INSERT INTO c VALUES (1, 1), (2, 2)",
		"INSERT INTO d VALUES (10, 1), (20, 2)",
	))
	type want struct{ cName, dName [2]string } // x.name of c rows 1,2 and d rows 10,20 ("" = null)
	objects := func(t *testing.T, token string, cFirst bool, w want) {
		t.Helper()
		cq := `c_connection { nodes { id x { id name } } }`
		dq := `d_connection { nodes { id x { id name } } }`
		q := "{ " + cq + " " + dq + " }"
		if !cFirst {
			q = "{ " + dq + " " + cq + " }"
		}
		r := env.MustGQL(t, token, q, nil)
		for i := range 2 {
			for _, side := range []struct {
				root string
				name string
			}{{"c_connection", w.cName[i]}, {"d_connection", w.dName[i]}} {
				p := side.root + ".nodes." + strconv.Itoa(i) + ".x"
				if side.name == "" {
					wantNull(t, r, p)
					continue
				}
				if got := r.String(t, p+".name"); got != side.name {
					t.Errorf("cFirst=%v %s = %q, want %q: %s", cFirst, p, got, side.name, r.Raw)
				}
			}
		}
	}
	arrays := func(t *testing.T, token string, aFirst bool, aIDs [][]int64, bIDs [][]int64) {
		t.Helper()
		aq := `a_connection { nodes { id c { id } } }`
		bq := `b_connection { nodes { id d { id } } }`
		q := "{ " + aq + " " + bq + " }"
		if !aFirst {
			q = "{ " + bq + " " + aq + " }"
		}
		r := env.MustGQL(t, token, q, nil)
		for i, w := range aIDs {
			if got := r.IDs(t, "a_connection.nodes."+strconv.Itoa(i)+".c"); !equalIDs(got, w) {
				t.Errorf("aFirst=%v a[%d].c = %v, want %v", aFirst, i, got, w)
			}
		}
		if n := len(r.List(t, "b_connection.nodes")); n != len(bIDs) {
			t.Fatalf("b rows = %d, want %d: %s", n, len(bIDs), r.Raw)
		}
		for i, w := range bIDs {
			if got := r.IDs(t, "b_connection.nodes."+strconv.Itoa(i)+".d"); !equalIDs(got, w) {
				t.Errorf("aFirst=%v b[%d].d = %v, want %v", aFirst, i, got, w)
			}
		}
	}
	admin := env.Token(t, "admin", 1)
	r := env.Token(t, "r", 1)
	for _, first := range []bool{true, false} {
		objects(t, admin, first, want{[2]string{"A-one", "A-two"}, [2]string{"B-one", "B-two"}})
		// r: b's row filter hides b 2, so d 20's x is null — never a's row 2.
		objects(t, r, first, want{[2]string{"A-one", "A-two"}, [2]string{"B-one", ""}})
		arrays(t, admin, first, [][]int64{{1}, {2}}, [][]int64{{10}, {20}})
		arrays(t, r, first, [][]int64{{1}, {2}}, [][]int64{{10}})
	}
	// Negative: r still cannot read a.secret through the relationship.
	env.GQL(t, r, `{ c_connection { nodes { x { secret } } } }`, nil).MustFail(t, "secret")
}

// bkRoles: admin reads everything; viewer never sees n = 4; anonymous
// cannot read the key, so it gets no connection at all.
const bkRoles = `roles:
  admin:
    tables:
      "*": {select: true}
      bkv: {select: true} # views are exposed by name only
  viewer:
    tables:
      bk: {select: {allow: true, filter: "n <> 4"}}
      bkv: {select: {allow: true, filter: "n <> 4"}}
  anonymous:
    tables:
      bk: {select: {allow: true, columns: [n]}}
`

// Keyset cursors on BINARY keys (a real primary key, and a view's declared
// key) must carry the raw bytes exactly: bytes that are not valid UTF-8 used
// to be mangled into U+FFFD, and the next page then skipped rows silently.
func TestBinaryKeyCursors(t *testing.T) {
	t.Parallel()
	env := New(t, WithRolesYAML(bkRoles),
		WithExtraYAML("tables:\n  bkv:\n    primary_key: [uid]\n"),
		WithSQL(
			"CREATE TABLE bk (uid BINARY(2) PRIMARY KEY, n INT NOT NULL)",
			"INSERT INTO bk VALUES (0x1000, 1), (0x9F00, 2), (0xA000, 3), (0xC000, 4), (0xEFBF, 5), (0xF000, 6)",
			"CREATE VIEW bkv AS SELECT uid, n FROM bk",
		))
	page := func(t *testing.T, token, root string) []int64 {
		t.Helper()
		q := fmt.Sprintf(`query($after: String) { %s(first: 1, after: $after) { nodes { n } page_info { has_next_page end_cursor } } }`, root)
		var out []int64
		var after any
		for range 10 {
			r := env.MustGQL(t, token, q, map[string]any{"after": after})
			for i := range r.List(t, root+".nodes") {
				out = append(out, r.Int(t, root+".nodes."+strconv.Itoa(i)+".n"))
			}
			if r.Get(root+".page_info.has_next_page") != true {
				return out
			}
			after = r.String(t, root+".page_info.end_cursor")
		}
		t.Fatalf("%s: paging did not end: %v", root, out)
		return nil
	}
	admin := env.Token(t, "admin", 1)
	viewer := env.Token(t, "viewer", 2)
	for _, root := range []string{"bk_connection", "bkv_connection"} {
		if got := page(t, admin, root); !equalIDs(got, []int64{1, 2, 3, 4, 5, 6}) {
			t.Errorf("admin %s pages = %v", root, got)
		}
		if got := page(t, viewer, root); !equalIDs(got, []int64{1, 2, 3, 5, 6}) {
			t.Errorf("viewer %s pages = %v", root, got)
		}
	}
	// Negative: a role that cannot read the key cannot page on it.
	env.GQL(t, "", `{ bk_connection { nodes { n } } }`, nil).MustFail(t, "bk_connection")
}

// raceRoles: own reads only its rows, may update any row's name but must
// leave it owned by itself (check), and may delete any row.
const raceRoles = `roles:
  admin:
    tables:
      "*": {select: true, insert: true, update: true, delete: true}
  own:
    tables:
      r:
        select: {allow: true, filter: "owner = :jwt.sub"}
        update: {allow: true, columns: [name, owner], check: "owner = :jwt.sub"}
        delete: true
  anonymous:
    tables:
      r: {select: {allow: true, columns: [id]}}
`

// whileLocked runs stmts in a pessimistic transaction on its own connection,
// starts request while that transaction holds its row locks, and commits a
// moment later — so the gateway's mutation, which started before the commit,
// has to wait for the locks and then sees the committed change.
func whileLocked(t *testing.T, env *Env, stmts []string, request func() *Result) *Result {
	t.Helper()
	ctx := context.Background()
	conn, err := env.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, s := range append([]string{"BEGIN PESSIMISTIC"}, stmts...) {
		if _, err := conn.ExecContext(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	done := make(chan *Result, 1)
	go func() { done <- request() }()
	time.Sleep(1500 * time.Millisecond) // the mutation is now waiting for the lock
	select {
	case r := <-done:
		t.Fatalf("the mutation did not wait for the row lock: %s", r.Raw)
	default:
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		return r
	case <-time.After(30 * time.Second):
		t.Fatal("the mutation never finished")
	}
	return nil
}

// A mutation that waited for a row lock must read `returning` and evaluate
// its write check on the row as the other transaction committed it — not on
// the snapshot from when it started.
func TestMutationsReadLockedRowsCurrent(t *testing.T) {
	t.Parallel()
	env := New(t, WithRolesYAML(raceRoles), WithSQL(
		"CREATE TABLE r (id BIGINT PRIMARY KEY, name VARCHAR(20) NOT NULL, owner BIGINT NOT NULL)",
		"INSERT INTO r VALUES (1, 'old', 1), (2, 'old', 1), (3, 'old', 1), (4, 'old', 1), (5, 'old', 1), (6, 'old', 2)",
	))
	admin := env.Token(t, "admin", 9)
	own := env.Token(t, "own", 1)
	gql := func(token, q string) func() *Result {
		return func() *Result { return env.GQL(t, token, q, nil) }
	}

	// delete returning shows the row as it was when deleted.
	r := whileLocked(t, env, []string{"UPDATE r SET name = 'new', owner = 2 WHERE id = 1"},
		gql(admin, `mutation { delete_r_by_pk(id: 1) { id name owner } }`)).MustOK(t)
	if got := r.String(t, "delete_r_by_pk.name"); got != "new" || r.Int(t, "delete_r_by_pk.owner") != 2 {
		t.Errorf("delete returned a stale row: %s", r.Raw)
	}

	// An update that leaves the row's values unchanged still returns the
	// committed name.
	r = whileLocked(t, env, []string{"UPDATE r SET name = 'new' WHERE id = 2"},
		gql(admin, `mutation { update_r_by_pk(id: 2, _set: {owner: 1}) { id name owner } }`)).MustOK(t)
	if got := r.String(t, "update_r_by_pk.name"); got != "new" {
		t.Errorf("update returned a stale row: %s", r.Raw)
	}

	// Negative (own, sub 1): the row moved to owner 2 while the update
	// waited. The update leaves it unchanged (same name), so only a current
	// read sees the move: the check must refuse, not pass on owner 1.
	r = whileLocked(t, env, []string{"UPDATE r SET owner = 2 WHERE id = 3"},
		gql(own, `mutation { update_r_by_pk(id: 3, _set: {name: "old"}) { id } }`))
	wantCode(t, r, "permission_error")
	if got := env.QueryInt(t, "SELECT owner FROM r WHERE id = 3"); got != 2 {
		t.Errorf("row 3 owner = %d, want 2", got)
	}

	// Negative: own may delete row 5, but it now belongs to owner 2, which
	// own's select filter hides — so it is deleted but not returned.
	r = whileLocked(t, env, []string{"UPDATE r SET owner = 2 WHERE id = 5"},
		gql(own, `mutation { delete_r_by_pk(id: 5) { id name } }`)).MustOK(t)
	wantNull(t, r, "delete_r_by_pk")
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM r WHERE id = 5"); n != 0 {
		t.Errorf("row 5 not deleted")
	}

	// A row that came to match the where while the delete waited is
	// deleted and returned: affected_rows and returning agree.
	r = whileLocked(t, env, []string{"UPDATE r SET owner = 1 WHERE id = 6", "UPDATE r SET name = 'moved' WHERE id = 4",
		"INSERT INTO r VALUES (7, 'fresh', 1)"},
		gql(admin, `mutation { delete_r(where: {owner: {_eq: 1}}) { affected_rows returning { id name } } }`)).MustOK(t)
	if n := r.Int(t, "delete_r.affected_rows"); n != int64(len(r.List(t, "delete_r.returning"))) {
		t.Errorf("affected_rows %d but %d returned: %s", n, len(r.List(t, "delete_r.returning")), r.Raw)
	}
	if got := r.IDs(t, "delete_r.returning"); !equalIDs(got, []int64{2, 4, 6, 7}) {
		t.Errorf("deleted rows = %v, want [2 4 6 7]: %s", got, r.Raw)
	}
	if got := r.String(t, "delete_r.returning.1.name"); got != "moved" {
		t.Errorf("row 4 returned as %q, want moved", got)
	}
}

var (
	returningHookOnce  sync.Once
	returningHookCalls atomic.Int64
)

// `returning` is read (and counted against max_response_rows) before the
// after-hooks run: a mutation rolled back for going over the limit has not
// triggered any after-hook.
func TestReturningReadBeforeAfterHooks(t *testing.T) {
	t.Parallel()
	returningHookOnce.Do(func() {
		register.MutationHook("e2e_returning_after", func(ctx context.Context, ev *register.MutationEvent) error {
			returningHookCalls.Add(1)
			return nil
		})
	})
	env := New(t,
		WithSQL("CREATE TABLE hooked (id BIGINT AUTO_INCREMENT PRIMARY KEY, body VARCHAR(20) NOT NULL)"),
		WithExtraYAML("hooks:\n  tables:\n    hooked:\n      after_insert: [e2e_returning_after]\n      after_update: [e2e_returning_after]\n"),
		WithConfig(func(c *config.Config) { c.Server.MaxResponseRows = 2 }),
		WithRolesYAML(`roles:
  admin:
    tables:
      hooked: {select: true, insert: true, update: true}
  writer:
    tables:
      hooked: {insert: true}
  anonymous:
    tables:
      hooked: {select: true}
`))
	admin := env.Token(t, "admin", 1)
	start := returningHookCalls.Load()
	three := `[{body: "a"}, {body: "b"}, {body: "c"}]`

	wantCode(t, env.GQL(t, admin, `mutation { insert_hooked(objects: `+three+`) { returning { id } } }`, nil), "response_too_large")
	if n := returningHookCalls.Load() - start; n != 0 {
		t.Errorf("after_insert ran %d times for a rolled-back insert", n)
	}
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM hooked"); n != 0 {
		t.Fatalf("the over-limit insert must roll back, %d rows", n)
	}
	wantInt(t, env.MustGQL(t, admin, `mutation { insert_hooked(objects: `+three+`) { affected_rows } }`, nil), "insert_hooked.affected_rows", 3)
	if n := returningHookCalls.Load() - start; n != 1 {
		t.Errorf("after_insert ran %d times, want 1", n)
	}
	wantCode(t, env.GQL(t, admin, `mutation { update_hooked(where: {}, _set: {body: "z"}) { returning { id } } }`, nil), "response_too_large")
	if n := returningHookCalls.Load() - start; n != 1 {
		t.Errorf("after_update ran for a rolled-back update (%d calls)", n)
	}
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM hooked WHERE body = 'z'"); n != 0 {
		t.Errorf("the over-limit update must roll back, %d rows", n)
	}

	// writer cannot read the table: no returning, and its insert runs the
	// after-hook once.
	writer := env.Token(t, "writer", 2)
	env.GQL(t, writer, `mutation { insert_hooked(objects: [{body: "w"}]) { returning { id } } }`, nil).MustFail(t, "returning")
	env.MustGQL(t, writer, `mutation { insert_hooked(objects: [{body: "w"}]) { affected_rows } }`, nil)
	if n := returningHookCalls.Load() - start; n != 2 {
		t.Errorf("after_insert calls = %d, want 2", n)
	}
}

// A legacy insert.filter is not enforced where an inserted row's key may
// be unknown (a DEFAULT (UUID()) key the role cannot write): such inserts
// keep working as they did while the filter was ignored. Where the key is
// always known it is still enforced.
func TestLegacyInsertFilterDefaultKey(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(
		"CREATE TABLE notes (id VARCHAR(36) NOT NULL DEFAULT (UUID()) PRIMARY KEY, user_id BIGINT NOT NULL, body VARCHAR(50) NOT NULL)",
	), WithRolesYAML(`roles:
  admin:
    tables:
      "*": {select: true, insert: true}
  noter:
    tables:
      notes:
        select: true
        insert: {allow: true, columns: [user_id, body], filter: "user_id = :jwt.sub"}
      comments:
        select: true
        insert: {allow: true, columns: [post_id, user_id, body], filter: "user_id = :jwt.sub"}
  anonymous:
    tables:
      notes: {select: {allow: true, columns: [body]}}
`))
	noter := env.Token(t, "noter", 1)
	wantInt(t, env.MustGQL(t, noter, `mutation { insert_notes(objects: [{user_id: 1, body: "mine"}]) { affected_rows } }`, nil),
		"insert_notes.affected_rows", 1)
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM notes WHERE body = 'mine' AND id <> ''"); n != 1 {
		t.Errorf("note not inserted with a generated key")
	}
	// Negative: the role still cannot set the key it may not write.
	env.GQL(t, noter, `mutation { insert_notes(objects: [{id: "x", user_id: 1, body: "k"}]) { affected_rows } }`, nil).MustFail(t, "id")
	// comments has an AUTO_INCREMENT key: the legacy filter stays enforced.
	wantCode(t, env.GQL(t, noter, `mutation { insert_comments_one(object: {post_id: 1, user_id: 2, body: "as grace"}) { id } }`, nil), "permission_error")
	env.MustGQL(t, noter, `mutation { insert_comments_one(object: {post_id: 1, user_id: 1, body: "as ada"}) { id } }`, nil)
	// admin has no filter.
	env.MustGQL(t, env.Token(t, "admin", 4), `mutation { insert_notes(objects: [{user_id: 2, body: "admin"}]) { affected_rows } }`, nil)
}

// schema_gen.mutation_response: shared keeps the single mutation_response
// object (affected_rows only) that clients generated against earlier
// versions depend on.
func TestSharedMutationResponse(t *testing.T) {
	t.Parallel()
	env := New(t, WithConfig(func(c *config.Config) { c.SchemaGen.MutationResponse = config.MutationResponseShared }))
	for _, tok := range []string{env.Token(t, "admin", 4), env.Token(t, "author", 1)} {
		r := env.MustGQL(t, tok, `mutation { update_posts(where: {id: {_eq: 1}}, _set: {title: "T"}) { __typename affected_rows } }`, nil)
		if got := r.String(t, "update_posts.__typename"); got != "mutation_response" {
			t.Errorf("__typename = %q, want mutation_response", got)
		}
		env.GQL(t, tok, `mutation { update_posts(where: {id: {_eq: 1}}, _set: {title: "U"}) { returning { id } } }`, nil).
			MustFail(t, "returning")
		if k := typeKind(t, env, tok, "mutation_response"); k != "OBJECT" {
			t.Errorf("mutation_response kind = %s, want OBJECT", k)
		}
	}
	// Negative: the author's update filter still applies (grace's post 3).
	r := env.MustGQL(t, env.Token(t, "author", 1), `mutation { update_posts(where: {id: {_eq: 3}}, _set: {title: "hijack"}) { affected_rows } }`, nil)
	wantInt(t, r, "update_posts.affected_rows", 0)
}

func typeKind(t *testing.T, env *Env, token, name string) string {
	t.Helper()
	r := env.MustGQL(t, token, `query($n: String!) { __type(name: $n) { kind } }`, map[string]any{"n": name})
	return r.String(t, "__type.kind")
}
