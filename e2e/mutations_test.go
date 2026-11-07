package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"gqlgate/config"
	"gqlgate/register"
)

// End-to-end tests for the mutation features: write checks, `returning` on
// bulk mutations, structured database errors, response limits and unique-key
// root fields. Fixture recap (testdata/blog.sql): users 1-3 are authors (3
// inactive), 4 is admin; posts 1,2 by ada (1; 2 unpublished), 3 by grace (2),
// 4 by alan (3). Comments: 1,2 on post 1 (by grace, alan), 3 on post 3 (ada),
// 4 on post 4 (ada), 5 on post 4 (grace).

// wantCode fails unless the response carries an error with extensions.code.
func wantCode(t *testing.T, r *Result, code string) {
	t.Helper()
	for _, e := range r.Errors {
		if e.Extensions["code"] == code {
			return
		}
	}
	t.Fatalf("expected an error with code %q, got HTTP %d: %s", code, r.Status, r.Raw)
}

const checkRolesYAML = `roles:
  admin:
    tables:
      "*":
        select: true
        insert: true
        update: true
        delete: true
  author:
    tables:
      users:
        select:
          allow: true
          columns: [id, name]
      posts:
        select: true
        insert:
          allow: true
          columns: [title, body, published]
          presets:
            author_id: ":jwt.sub"
          check: "published = 0 OR CHAR_LENGTH(title) >= 5"
        update:
          allow: true
          columns: [title, body, published, author_id]
          filter: "author_id = :jwt.sub"
          check: "author_id = :jwt.sub"
      comments:
        select: true
        insert:
          allow: true
          columns: [post_id, body]
          presets:
            user_id: ":jwt.sub"
          check: "post_id IN (SELECT id FROM posts WHERE published = 1 OR author_id = :jwt.sub)"
  legacy:
    tables:
      comments:
        select: true
        insert:
          allow: true
          filter: "user_id = :jwt.sub"
  anonymous:
    tables:
      posts:
        select:
          allow: true
          filter: "published = 1"
`

func TestWriteCheckInsert(t *testing.T) {
	t.Parallel()
	env := New(t, WithRolesYAML(checkRolesYAML))
	ada, grace := env.Token(t, "author", 1), env.Token(t, "author", 2)
	admin := env.Token(t, "admin", 4)
	comments := func() int64 { return env.QueryInt(t, "SELECT COUNT(*) FROM comments") }
	before := comments()

	// Negative: grace may not comment on ada's unpublished post 2.
	r := env.GQL(t, grace, `mutation { insert_comments_one(object: {post_id: 2, body: "sneaky"}) { id } }`, nil)
	wantCode(t, r, "permission_error")
	r.MustFail(t, "insert check")
	// One bad row rolls back the whole batch.
	r = env.GQL(t, grace, `mutation { insert_comments(objects: [{post_id: 1, body: "ok"}, {post_id: 2, body: "bad"}]) { affected_rows } }`, nil)
	wantCode(t, r, "permission_error")
	if got := comments(); got != before {
		t.Fatalf("rejected inserts wrote rows: %d -> %d", before, got)
	}

	// Positive: published posts, and the author's own draft.
	r = env.MustGQL(t, grace, `mutation { insert_comments(objects: [{post_id: 1, body: "a"}, {post_id: 3, body: "b"}]) { affected_rows } }`, nil)
	wantInt(t, r, "insert_comments.affected_rows", 2)
	env.MustGQL(t, ada, `mutation { insert_comments_one(object: {post_id: 2, body: "note to self"}) { id } }`, nil)
	// A role without a check (admin) is not restricted.
	env.MustGQL(t, admin, `mutation { insert_comments_one(object: {post_id: 2, user_id: 2, body: "admin"}) { id } }`, nil)
	if got := comments(); got != before+4 {
		t.Errorf("comments = %d, want %d", got, before+4)
	}

	// The check sees the row as written, presets included: a published post
	// needs a title of at least 5 characters; a draft does not.
	wantCode(t, env.GQL(t, grace, `mutation { insert_posts_one(object: {title: "abc", published: true}) { id } }`, nil), "permission_error")
	env.MustGQL(t, grace, `mutation { insert_posts_one(object: {title: "abc", published: false}) { id } }`, nil)
	env.MustGQL(t, grace, `mutation { insert_posts_one(object: {title: "abcde", published: true}) { id } }`, nil)

	// A legacy insert.filter is enforced as the insert check (it used to be
	// silently ignored).
	legacy := env.Token(t, "legacy", 3)
	wantCode(t, env.GQL(t, legacy, `mutation { insert_comments_one(object: {post_id: 1, user_id: 1, body: "as ada"}) { id } }`, nil), "permission_error")
	env.MustGQL(t, legacy, `mutation { insert_comments_one(object: {post_id: 1, user_id: 3, body: "as alan"}) { id } }`, nil)
}

func TestWriteCheckUpdate(t *testing.T) {
	t.Parallel()
	env := New(t, WithRolesYAML(checkRolesYAML))
	grace := env.Token(t, "author", 2)
	admin := env.Token(t, "admin", 4)

	// The filter lets grace touch post 3; the check stops her from handing
	// it to ada (moving it out of her own rows).
	for _, q := range []string{
		`mutation { update_posts(where: {id: {_eq: 3}}, _set: {author_id: 1, title: "gift"}) { affected_rows } }`,
		`mutation { update_posts_by_pk(id: 3, _set: {author_id: 1}) { id } }`,
	} {
		wantCode(t, env.GQL(t, grace, q, nil), "permission_error")
	}
	if a := env.QueryInt(t, "SELECT author_id FROM posts WHERE id = 3"); a != 2 {
		t.Errorf("post 3 author = %d after rejected updates, want 2", a)
	}
	if title := env.QueryString(t, "SELECT title FROM posts WHERE id = 3"); title != "Compilers for humans" {
		t.Errorf("rolled-back update changed the title to %q", title)
	}
	// Updates that keep the row inside the check pass (also by filter).
	r := env.MustGQL(t, grace, `mutation { update_posts(where: {}, _set: {title: "Compilers, again"}) { affected_rows } }`, nil)
	wantInt(t, r, "update_posts.affected_rows", 1)
	env.MustGQL(t, grace, `mutation { update_posts_by_pk(id: 3, _set: {author_id: 2, body: "same owner"}) { id } }`, nil)
	// Admin has no check.
	env.MustGQL(t, admin, `mutation { update_posts_by_pk(id: 3, _set: {author_id: 1}) { id } }`, nil)
	if a := env.QueryInt(t, "SELECT author_id FROM posts WHERE id = 3"); a != 1 {
		t.Errorf("admin update not applied: author %d", a)
	}
}

var (
	afterHookOnce  sync.Once
	afterHookCalls atomic.Int64
)

// A failed check rolls back before the after-hooks run: they never see rows
// that are about to disappear. Before-hooks still run first.
func TestWriteCheckBeforeAfterHooks(t *testing.T) {
	t.Parallel()
	afterHookOnce.Do(func() {
		register.MutationHook("e2e_check_after", func(ctx context.Context, ev *register.MutationEvent) error {
			afterHookCalls.Add(1)
			return nil
		})
	})
	env := New(t,
		WithSQL("CREATE TABLE notes (id BIGINT AUTO_INCREMENT PRIMARY KEY, owner BIGINT NOT NULL, body VARCHAR(50) NOT NULL)"),
		WithExtraYAML("hooks:\n  tables:\n    notes:\n      after_insert: [e2e_check_after]\n"),
		WithRolesYAML(`roles:
  author:
    tables:
      notes:
        select: true
        insert:
          allow: true
          check: "owner = :jwt.sub"
  anonymous:
    tables:
      notes:
        select: true
`))
	// Only this test writes notes; count calls relative to the start (the
	// hook stays registered across -count runs).
	start := afterHookCalls.Load()
	ada := env.Token(t, "author", 1)
	wantCode(t, env.GQL(t, ada, `mutation { insert_notes(objects: [{owner: 2, body: "x"}]) { affected_rows } }`, nil), "permission_error")
	if n := afterHookCalls.Load() - start; n != 0 {
		t.Errorf("after_insert ran %d times for a rolled-back insert", n)
	}
	env.MustGQL(t, ada, `mutation { insert_notes(objects: [{owner: 1, body: "x"}]) { affected_rows } }`, nil)
	if n := afterHookCalls.Load() - start; n != 1 {
		t.Errorf("after_insert ran %d times, want 1", n)
	}
}

const returningRolesYAML = `roles:
  admin:
    tables:
      "*":
        select: true
        insert: true
        update: true
        delete: true
  author:
    tables:
      users:
        select:
          allow: true
          columns: [id, name]
      posts:
        select:
          allow: true
          columns: [id, author_id, title, body, published]
        insert:
          allow: true
          columns: [title, body, published]
          presets:
            author_id: ":jwt.sub"
        update:
          allow: true
          columns: [title, body, published]
          filter: "author_id = :jwt.sub"
  moderator:
    tables:
      users:
        select:
          allow: true
          columns: [id, name]
      posts:
        select:
          allow: true
          filter: "published = 1"
        insert: true
      comments:
        select:
          allow: true
          filter: "user_id = :jwt.sub"
        delete: true
  writer:
    tables:
      comments:
        insert: true
  anonymous:
    tables:
      posts:
        select:
          allow: true
          filter: "published = 1"
`

func TestReturningInsert(t *testing.T) {
	t.Parallel()
	env := New(t, WithRolesYAML(returningRolesYAML))
	admin, grace := env.Token(t, "admin", 4), env.Token(t, "author", 2)

	r := env.MustGQL(t, admin, `mutation {
		insert_posts(objects: [{author_id: 3, title: "zeta"}, {author_id: 1, title: "alpha"}, {author_id: 2, title: "mid"}]) {
			affected_rows
			returning { id title author { name } }
		}
	}`, nil)
	wantInt(t, r, "insert_posts.affected_rows", 3)
	rows := r.List(t, "insert_posts.returning")
	if len(rows) != 3 {
		t.Fatalf("returning has %d rows: %s", len(rows), r.Raw)
	}
	// Input order, real ids, relationships resolved.
	for i, want := range []struct{ title, author string }{{"zeta", "Alan Turing"}, {"alpha", "Ada Lovelace"}, {"mid", "Grace Hopper"}} {
		p := fmt.Sprintf("insert_posts.returning.%d.", i)
		if got := r.String(t, p+"title"); got != want.title {
			t.Errorf("row %d title = %q, want %q", i, got, want.title)
		}
		if got := r.String(t, p+"author.name"); got != want.author {
			t.Errorf("row %d author = %q, want %q", i, got, want.author)
		}
		if id := r.Int(t, p+"id"); env.QueryString(t, "SELECT title FROM posts WHERE id = ?", id) != want.title {
			t.Errorf("row %d id %d does not hold %q in the database", i, id, want.title)
		}
	}

	// Second role: the author's preset is visible in returning.
	r = env.MustGQL(t, grace, `mutation { insert_posts(objects: [{title: "mine"}]) { affected_rows returning { author_id title } } }`, nil)
	wantInt(t, r, "insert_posts.returning.0.author_id", 2)

	// Rows the role's select filter hides are written but not returned.
	mod := env.Token(t, "moderator", 2)
	r = env.MustGQL(t, mod, `mutation { insert_posts(objects: [{author_id: 2, title: "draft", published: false}, {author_id: 2, title: "live", published: true}]) {
		affected_rows returning { title } } }`, nil)
	wantInt(t, r, "insert_posts.affected_rows", 2)
	if rows := r.List(t, "insert_posts.returning"); len(rows) != 1 || r.String(t, "insert_posts.returning.0.title") != "live" {
		t.Errorf("returning must only show the published row: %s", r.Raw)
	}

	// Negative RBAC: no select permission, no returning field; hidden
	// columns cannot be returned.
	writer := env.Token(t, "writer", 2)
	env.GQL(t, writer, `mutation { insert_comments(objects: [{post_id: 1, user_id: 2, body: "x"}]) { returning { id } } }`, nil).MustFail(t, "returning")
	env.MustGQL(t, writer, `mutation { insert_comments(objects: [{post_id: 1, user_id: 2, body: "x"}]) { affected_rows } }`, nil)
	env.GQL(t, grace, `mutation { insert_posts(objects: [{title: "v"}]) { returning { views } } }`, nil).MustFail(t, "views")

	// The old shape (and fragments on mutation_response) keeps working.
	r = env.MustGQL(t, admin, `mutation { insert_posts(objects: [{author_id: 1, title: "f"}]) { ...R } } fragment R on mutation_response { affected_rows }`, nil)
	wantInt(t, r, "insert_posts.affected_rows", 1)
}

func TestReturningUpdateDelete(t *testing.T) {
	t.Parallel()
	env := New(t, WithRolesYAML(returningRolesYAML))
	grace := env.Token(t, "author", 2)

	// Update by filter: the update filter decides the rows (grace's post 3).
	r := env.MustGQL(t, grace, `mutation { update_posts(where: {}, _set: {body: "edited"}) { affected_rows returning { id body author { name } } } }`, nil)
	wantInt(t, r, "update_posts.affected_rows", 1)
	wantInt(t, r, "update_posts.returning.0.id", 3)
	if got := r.String(t, "update_posts.returning.0.body"); got != "edited" {
		t.Errorf("returning shows %q, want the updated body", got)
	}
	if got := r.String(t, "update_posts.returning.0.author.name"); got != "Grace Hopper" {
		t.Errorf("relationship in returning = %q", got)
	}

	// Delete by filter: the moderator may delete every comment but can only
	// read its own (user 2). Both comments on post 1 are deleted; only
	// grace's comes back. The select filter must not change what is deleted.
	mod := env.Token(t, "moderator", 2)
	r = env.MustGQL(t, mod, `mutation { delete_comments(where: {post_id: {_eq: 1}}) { affected_rows returning { id body user_id } } }`, nil)
	wantInt(t, r, "delete_comments.affected_rows", 2)
	if got := r.IDs(t, "delete_comments.returning"); !slices.Equal(got, []int64{1}) {
		t.Errorf("returning ids = %v, want only the readable comment [1]", got)
	}
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM comments WHERE post_id = 1"); n != 0 {
		t.Errorf("%d comments on post 1 survived; the delete must not depend on the select filter", n)
	}
	// Same through delete_by_pk: comment 4 (ada's) is deleted, shown as null.
	r = env.MustGQL(t, mod, `mutation { delete_comments_by_pk(id: 4) { id } }`, nil)
	wantNull(t, r, "delete_comments_by_pk")
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM comments WHERE id = 4"); n != 0 {
		t.Error("comment 4 must be deleted even though the moderator cannot read it")
	}
	r = env.MustGQL(t, mod, `mutation { delete_comments_by_pk(id: 5) { id body } }`, nil)
	wantInt(t, r, "delete_comments_by_pk.id", 5)

	// Without returning the old single-statement path still reports counts.
	admin := env.Token(t, "admin", 4)
	r = env.MustGQL(t, admin, `mutation { delete_comments(where: {}) { affected_rows } }`, nil)
	wantInt(t, r, "delete_comments.affected_rows", 1)
}

// Natural and AUTO_RANDOM primary keys: returning finds the rows by their
// supplied key, by LAST_INSERT_ID (non-contiguous AUTO_RANDOM values, one
// statement per row), and after an update that changes the key itself.
func TestReturningKeys(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(
		"CREATE TABLE events (id BIGINT PRIMARY KEY AUTO_RANDOM, name VARCHAR(20) NOT NULL)",
		"CREATE TABLE codes (code VARCHAR(10) PRIMARY KEY, label VARCHAR(20) NOT NULL)",
		"INSERT INTO codes VALUES ('a', 'first'), ('b', 'second')",
	))
	admin := env.Token(t, "admin", 4)

	// AUTO_RANDOM ids exceed 2^53: compare them exactly (json.Number).
	exact := func(r *Result) map[string]any {
		var out struct{ Data map[string]any }
		dec := json.NewDecoder(bytes.NewReader(r.Raw))
		dec.UseNumber()
		if err := dec.Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out.Data
	}
	r := env.MustGQL(t, admin, `mutation { insert_events(objects: [{name: "one"}, {name: "two"}, {name: "three"}]) { affected_rows returning { id name } } }`, nil)
	rows := exact(r)["insert_events"].(map[string]any)["returning"].([]any)
	if len(rows) != 3 {
		t.Fatalf("returning = %s", r.Raw)
	}
	for i, name := range []string{"one", "two", "three"} {
		row := rows[i].(map[string]any)
		if row["name"] != name {
			t.Errorf("row %d = %v, want %q", i, row["name"], name)
		}
		if id, want := row["id"].(json.Number).String(), env.QueryString(t, "SELECT CAST(id AS CHAR) FROM events WHERE name = ?", name); id != want {
			t.Errorf("%s: returned id %s, database id %s", name, id, want)
		}
	}
	// AUTO_RANDOM keys are optional on insert, and insert_one returns the row.
	r = env.MustGQL(t, admin, `mutation { insert_events_one(object: {name: "four"}) { id name } }`, nil)
	one := exact(r)["insert_events_one"].(map[string]any)
	if id := one["id"].(json.Number).String(); id != env.QueryString(t, "SELECT CAST(id AS CHAR) FROM events WHERE name = 'four'") {
		t.Errorf("insert_events_one returned id %s", id)
	}

	r = env.MustGQL(t, admin, `mutation { update_codes(where: {code: {_eq: "a"}}, _set: {code: "z"}) { affected_rows returning { code label } } }`, nil)
	if got := r.String(t, "update_codes.returning.0.code"); got != "z" {
		t.Errorf("returning after a key change = %s", r.Raw)
	}
	r = env.MustGQL(t, admin, `mutation { update_codes_by_pk(code: "z", _set: {code: "y"}) { code label } }`, nil)
	if got := r.String(t, "update_codes_by_pk.code"); got != "y" {
		t.Errorf("update_codes_by_pk after a key change = %s", r.Raw)
	}
}

func TestStructuredDBErrors(t *testing.T) {
	t.Parallel()
	env := New(t)
	admin, grace := env.Token(t, "admin", 4), env.Token(t, "author", 2)

	tests := []struct {
		name, token, query, code string
	}{
		{"duplicate", admin, `mutation { insert_users_one(object: {username: "ada", password: "x", name: "A", email: "new@example.com"}) { id } }`, "constraint_violation"},
		{"missing parent", admin, `mutation { insert_posts_one(object: {author_id: 999, title: "orphan"}) { id } }`, "foreign_key_violation"},
		{"still referenced", admin, `mutation { delete_users_by_pk(id: 1) { id } }`, "foreign_key_violation"},
		{"too long", admin, `mutation { insert_posts_one(object: {author_id: 1, title: "` + strings.Repeat("x", 300) + `"}) { id } }`, "data_too_long"},
		{"author missing parent", grace, `mutation { insert_comments_one(object: {post_id: 999, body: "x"}) { id } }`, "foreign_key_violation"},
		{"author too long", grace, `mutation { update_posts_by_pk(id: 3, _set: {title: "` + strings.Repeat("y", 300) + `"}) { id } }`, "data_too_long"},
	}
	for _, tc := range tests {
		r := env.GQL(t, tc.token, tc.query, nil)
		wantCode(t, r, tc.code)
		// Without server.debug no database text reaches the client: no SQL,
		// no key names, no conflicting values.
		for _, e := range r.Errors {
			for _, leak := range []string{"Duplicate entry", "ada", "INSERT", "UPDATE", "DELETE", "fk_", "Error 1"} {
				if strings.Contains(e.Message, leak) {
					t.Errorf("%s: message leaks %q: %s", tc.name, leak, e.Message)
				}
			}
		}
	}
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM users WHERE id = 1 AND name = 'Ada Lovelace'"); n != 1 {
		t.Error("a failed update changed user 1")
	}
	// NOT NULL: a preset whose claim is null writes NULL (GraphQL itself
	// cannot send a null for a non-null input field).
	nullEnv := New(t, WithRolesYAML(DefaultRolesYAML+`
  nullish:
    tables:
      comments:
        select: true
        insert:
          allow: true
          columns: [post_id, body]
          presets:
            user_id: ":jwt.uid"
`))
	nullish := nullEnv.Token(t, "nullish", 7, map[string]any{"uid": nil})
	wantCode(t, nullEnv.GQL(t, nullish, `mutation { insert_comments_one(object: {post_id: 1, body: "x"}) { id } }`, nil), "not_null_violation")

	// server.debug passes the database's own message through, with the code.
	dbg := New(t, WithDebug())
	r := dbg.GQL(t, dbg.Token(t, "admin", 4), tests[0].query, nil)
	wantCode(t, r, "constraint_violation")
	r.MustFail(t, "Duplicate entry")
}

func TestResponseRowLimit(t *testing.T) {
	t.Parallel()
	env := New(t, WithConfig(func(c *config.Config) { c.Server.MaxResponseRows = 3 }))
	admin := env.Token(t, "admin", 4)

	env.MustGQL(t, admin, `{ posts_connection(first: 3) { nodes { id } } }`, nil)
	r := env.GQL(t, admin, `{ posts_connection(first: 10) { nodes { id } } }`, nil)
	wantCode(t, r, "response_too_large")
	if r.Data != nil {
		t.Errorf("a query over the limit must return no data: %s", r.Raw)
	}
	if len(r.Errors) != 1 {
		t.Errorf("want one limit error, got %s", r.Raw)
	}
	// Relationship rows count too (batched: the code survives the loader):
	// 2 posts + 2 comments of post 1.
	r = env.GQL(t, admin, `{ posts_connection(first: 2) { nodes { id comments { id } } } }`, nil)
	wantCode(t, r, "response_too_large")
	// Aliases share one budget.
	wantCode(t, env.GQL(t, admin, `{ a: posts_connection(first: 2) { nodes { id } } b: posts_connection(first: 2) { nodes { id } } }`, nil), "response_too_large")

	// Anonymous sees 3 published posts: exactly at the limit.
	r = env.MustGQL(t, "", `{ posts_connection(first: 10) { nodes { id } } }`, nil)
	if n := len(r.List(t, "posts_connection.nodes")); n != 3 {
		t.Errorf("anonymous got %d posts", n)
	}

	// returning counts, and a mutation over the limit is rolled back.
	before := env.QueryInt(t, "SELECT COUNT(*) FROM posts")
	r = env.GQL(t, admin, `mutation { insert_posts(objects: [{author_id: 1, title: "a"}, {author_id: 1, title: "b"}, {author_id: 1, title: "c"}, {author_id: 1, title: "d"}]) {
		affected_rows returning { id } } }`, nil)
	wantCode(t, r, "response_too_large")
	if after := env.QueryInt(t, "SELECT COUNT(*) FROM posts"); after != before {
		t.Errorf("an over-limit returning must roll the insert back: %d -> %d", before, after)
	}
	// Without returning the same insert is fine.
	r = env.MustGQL(t, admin, `mutation { insert_posts(objects: [{author_id: 1, title: "a"}, {author_id: 1, title: "b"}, {author_id: 1, title: "c"}, {author_id: 1, title: "d"}]) { affected_rows } }`, nil)
	wantInt(t, r, "insert_posts.affected_rows", 4)
}

func TestResponseByteLimit(t *testing.T) {
	t.Parallel()
	env := New(t, WithConfig(func(c *config.Config) { c.Server.MaxResponseBytes = 200 }))
	admin := env.Token(t, "admin", 4)
	env.MustGQL(t, admin, `{ posts_by_pk(id: 1) { id } }`, nil)
	r := env.GQL(t, admin, `{ posts_connection(first: 10) { nodes { id title body } } }`, nil)
	wantCode(t, r, "response_too_large")
	r.MustFail(t, "max_response_bytes")
	if r.Data != nil {
		t.Errorf("an oversized response must carry no data: %s", r.Raw)
	}
	// A committed mutation says so.
	r = env.GQL(t, admin, `mutation { update_posts(where: {}, _set: {views: 1}) { returning { id title body } } }`, nil)
	r.MustFail(t, "the mutation itself was applied")
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM posts WHERE views = 1"); n != 4 {
		t.Errorf("the update must have committed, %d rows updated", n)
	}
	// Second role, same limit.
	wantCode(t, env.GQL(t, "", `{ posts_connection(first: 10) { nodes { id title body } } }`, nil), "response_too_large")
}

const uniqueRolesYAML = `roles:
  admin:
    tables:
      "*":
        select: true
        insert: true
        update: true
        delete: true
      users:
        select:
          allow: true
          columns: [id, username, role, name, email, is_active, balance, metadata, created_at]
        insert: true
        update: true
        delete: true
  author:
    tables:
      users:
        select:
          allow: true
          columns: [id, name, is_active, created_at]
  reader:
    tables:
      users:
        select:
          allow: true
          columns: [id, name, email]
          filter: "is_active = 1"
  tagger:
    tables:
      tags:
        select: true
        update:
          allow: true
          columns: [slug, label, owner_id]
          filter: "owner_id = :jwt.sub"
          check: "owner_id = :jwt.sub"
        delete:
          allow: true
          filter: "owner_id = :jwt.sub"
  anonymous:
    tables:
      users:
        select:
          allow: true
          columns: [id, name, email]
          filterable_columns: [id, name]
`

func TestUniqueKeyRootFields(t *testing.T) {
	t.Parallel()
	env := New(t, WithRolesYAML(uniqueRolesYAML), WithSQL(
		`CREATE TABLE tags (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			owner_id BIGINT NOT NULL,
			slug VARCHAR(30) NOT NULL,
			label VARCHAR(30) NOT NULL,
			nick VARCHAR(10) NULL,
			UNIQUE KEY uq_owner_slug (owner_id, slug),
			UNIQUE KEY uq_nick (nick),
			UNIQUE KEY uq_label_prefix (label(4))
		)`,
		"INSERT INTO tags (id, owner_id, slug, label) VALUES (1, 1, 'go', 'Go lang'), (2, 2, 'go', 'Gopher'), (3, 1, 'sql', 'SQL')",
	))
	admin := env.Token(t, "admin", 4)

	r := env.MustGQL(t, admin, `{ users_by_email(email: "grace@example.com") { id name } users_by_username(username: "alan") { id } }`, nil)
	wantInt(t, r, "users_by_email.id", 2)
	wantInt(t, r, "users_by_username.id", 3)
	wantNull(t, env.MustGQL(t, admin, `{ users_by_email(email: "nobody@example.com") { id } }`, nil), "users_by_email")
	r = env.MustGQL(t, admin, `{ tags_by_owner_id_and_slug(owner_id: 2, slug: "go") { id label } }`, nil)
	wantInt(t, r, "tags_by_owner_id_and_slug.id", 2)
	// Nullable and prefix unique indexes give no lookup.
	env.GQL(t, admin, `{ tags_by_nick(nick: "x") { id } }`, nil).MustFail(t, "tags_by_nick")
	env.GQL(t, admin, `{ tags_by_label(label: "SQL") { id } }`, nil).MustFail(t, "tags_by_label")

	// Negative RBAC: the author cannot read email/username, so has no
	// lookup by them; anonymous reads email but may not filter on it.
	ada := env.Token(t, "author", 1)
	env.GQL(t, ada, `{ users_by_email(email: "grace@example.com") { id } }`, nil).MustFail(t, "users_by_email")
	env.GQL(t, ada, `{ users_by_username(username: "grace") { id } }`, nil).MustFail(t, "users_by_username")
	env.GQL(t, "", `{ users_by_email(email: "grace@example.com") { id } }`, nil).MustFail(t, "users_by_email")
	// The reader's row filter applies: inactive alan is hidden.
	reader := env.Token(t, "reader", 1)
	wantInt(t, env.MustGQL(t, reader, `{ users_by_email(email: "grace@example.com") { id } }`, nil), "users_by_email.id", 2)
	wantNull(t, env.MustGQL(t, reader, `{ users_by_email(email: "alan@example.com") { id } }`, nil), "users_by_email")
	env.GQL(t, reader, `mutation { update_users_by_email(email: "grace@example.com", _set: {name: "x"}) { id } }`, nil).MustFail(t, "")

	// Point mutations by unique key, including one that changes the key.
	r = env.MustGQL(t, admin, `mutation { update_users_by_email(email: "grace@example.com", _set: {email: "hopper@example.com"}) { id email } }`, nil)
	if got := r.String(t, "update_users_by_email.email"); got != "hopper@example.com" {
		t.Errorf("update_users_by_email returned %s", r.Raw)
	}
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM users WHERE id = 2 AND email = 'hopper@example.com'"); n != 1 {
		t.Error("email not updated")
	}
	env.Exec(t, "INSERT INTO users (id, username, password, name, email) VALUES (9, 'temp', 'x', 'Temp', 'temp@example.com')")
	r = env.MustGQL(t, admin, `mutation { delete_users_by_username(username: "temp") { id name } }`, nil)
	wantInt(t, r, "delete_users_by_username.id", 9)
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM users WHERE id = 9"); n != 0 {
		t.Error("user 9 not deleted")
	}

	// tagger (sub 1): its filter hides user 2's tag from update and delete,
	// and its check stops it from giving a tag away.
	tagger := env.Token(t, "tagger", 1)
	wantNull(t, env.MustGQL(t, tagger, `mutation { update_tags_by_owner_id_and_slug(owner_id: 2, slug: "go", _set: {label: "mine"}) { id } }`, nil), "update_tags_by_owner_id_and_slug")
	wantNull(t, env.MustGQL(t, tagger, `mutation { delete_tags_by_owner_id_and_slug(owner_id: 2, slug: "go") { id } }`, nil), "delete_tags_by_owner_id_and_slug")
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM tags WHERE id = 2 AND label = 'Gopher'"); n != 1 {
		t.Error("tag 2 was changed or deleted by a role whose filter hides it")
	}
	wantCode(t, env.GQL(t, tagger, `mutation { update_tags_by_owner_id_and_slug(owner_id: 1, slug: "sql", _set: {owner_id: 2}) { id } }`, nil), "permission_error")
	if n := env.QueryInt(t, "SELECT owner_id FROM tags WHERE id = 3"); n != 1 {
		t.Errorf("tag 3 owner = %d after a rejected update, want 1", n)
	}
	r = env.MustGQL(t, tagger, `mutation { update_tags_by_owner_id_and_slug(owner_id: 1, slug: "go", _set: {slug: "golang"}) { id slug } }`, nil)
	if got := r.String(t, "update_tags_by_owner_id_and_slug.slug"); got != "golang" {
		t.Errorf("key change through the unique key = %s", r.Raw)
	}
	r = env.MustGQL(t, tagger, `mutation { delete_tags_by_owner_id_and_slug(owner_id: 1, slug: "sql") { id } }`, nil)
	wantInt(t, r, "delete_tags_by_owner_id_and_slug.id", 3)
}

// The demo roles (mirrored by DefaultRolesYAML) carry an insert check on
// comments: an author may only comment on posts it can see.
func TestDemoCommentCheck(t *testing.T) {
	t.Parallel()
	env := New(t)
	grace, ada := env.Token(t, "author", 2), env.Token(t, "author", 1)
	const q = `mutation($p: BigInt!) { insert_comments_one(object: {post_id: $p, body: "hi"}) { id user_id } }`
	wantCode(t, env.GQL(t, grace, q, map[string]any{"p": 2}), "permission_error") // ada's draft
	wantInt(t, env.MustGQL(t, grace, q, map[string]any{"p": 1}), "insert_comments_one.user_id", 2)
	env.MustGQL(t, ada, q, map[string]any{"p": 2}) // her own draft
}
