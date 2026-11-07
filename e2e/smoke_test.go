package e2e

import (
	"net/http"
	"slices"
	"testing"
)

// Smoke tests for existing behaviour, proving the harness end to end. Fixture
// recap (testdata/blog.sql): users 1-3 are authors, 4 is admin; posts 1,2 by
// user 1 (2 is unpublished), post 3 by user 2, post 4 by user 3.

func TestSmokeAnonymousRowFilter(t *testing.T) {
	t.Parallel()
	env := New(t)

	const q = `{ posts_connection(first: 10) { nodes { id title author_id } total_count } }`
	anon := env.MustGQL(t, "", q, nil)
	if got := anon.IDs(t, "posts_connection.nodes"); !slices.Equal(got, []int64{1, 3, 4}) {
		t.Errorf("anonymous sees posts %v, want only published [1 3 4]", got)
	}
	if n := anon.Int(t, "posts_connection.total_count"); n != 3 {
		t.Errorf("anonymous total_count = %d, want 3", n)
	}

	admin := env.MustGQL(t, env.Token(t, "admin", 4), q, nil)
	if got := admin.IDs(t, "posts_connection.nodes"); !slices.Equal(got, []int64{1, 2, 3, 4}) {
		t.Errorf("admin sees posts %v, want [1 2 3 4]", got)
	}

	// The unpublished post is invisible by primary key too.
	if r := env.MustGQL(t, "", `{ posts_by_pk(id: 2) { id } }`, nil); r.Get("posts_by_pk") != nil {
		t.Errorf("anonymous read hidden post 2: %s", r.Raw)
	}

	// Negative RBAC: hidden columns can be neither selected nor filtered on.
	env.GQL(t, "", `{ posts_connection { nodes { id published } } }`, nil).MustFail(t, "published")
	env.GQL(t, "", `{ posts_connection(where: {published: {_eq: false}}) { nodes { id } } }`, nil).MustFail(t, "published")
	env.GQL(t, "", `{ users_connection { nodes { id email } } }`, nil).MustFail(t, "email")
}

func TestSmokeAuthorInsertPreset(t *testing.T) {
	t.Parallel()
	env := New(t)
	grace := env.Token(t, "author", 2)

	r := env.MustGQL(t, grace, `mutation($t: String!) {
		insert_posts_one(object: {title: $t, body: "hello", published: true}) { id author_id title published }
	}`, map[string]any{"t": "Grace's new post"})
	id := r.Int(t, "insert_posts_one.id")
	if a := r.Int(t, "insert_posts_one.author_id"); a != 2 {
		t.Errorf("author_id = %d, want preset 2 from :jwt.sub", a)
	}
	if got := env.QueryInt(t, "SELECT author_id FROM posts WHERE id = ?", id); got != 2 {
		t.Errorf("stored author_id = %d, want 2", got)
	}

	// Negative RBAC: the preset column is not part of the input type, so an
	// author cannot impersonate another author.
	before := env.QueryInt(t, "SELECT COUNT(*) FROM posts")
	env.GQL(t, grace, `mutation { insert_posts_one(object: {title: "spoof", author_id: 1}) { id } }`, nil).
		MustFail(t, "author_id")
	// Anonymous has no write permissions at all.
	env.GQL(t, "", `mutation { insert_posts_one(object: {title: "anon"}) { id } }`, nil).MustFail(t, "not configured for mutations")
	if after := env.QueryInt(t, "SELECT COUNT(*) FROM posts"); after != before {
		t.Errorf("rejected inserts changed the row count: %d -> %d", before, after)
	}
}

func TestSmokeAuthorCannotTouchOthersPosts(t *testing.T) {
	t.Parallel()
	env := New(t)
	grace := env.Token(t, "author", 2) // owns post 3 only

	// Post 1 belongs to user 1: the update filter hides it.
	r := env.MustGQL(t, grace, `mutation { update_posts_by_pk(id: 1, _set: {title: "hacked"}) { id } }`, nil)
	if r.Get("update_posts_by_pk") != nil {
		t.Errorf("update of another author's post returned a row: %s", r.Raw)
	}
	r = env.MustGQL(t, grace, `mutation { update_posts(where: {id: {_in: [1, 2]}}, _set: {title: "hacked"}) { affected_rows } }`, nil)
	if n := r.Int(t, "update_posts.affected_rows"); n != 0 {
		t.Errorf("bulk update touched %d foreign rows", n)
	}
	// Post 2 has no comments, so only RBAC (not an FK) can stop this delete.
	r = env.MustGQL(t, grace, `mutation { delete_posts_by_pk(id: 2) { id } }`, nil)
	if r.Get("delete_posts_by_pk") != nil {
		t.Errorf("delete of another author's post returned a row: %s", r.Raw)
	}
	if got := env.QueryString(t, "SELECT title FROM posts WHERE id = 1"); got != "Notes on the Analytical Engine" {
		t.Errorf("post 1 title changed to %q", got)
	}
	if n := env.QueryInt(t, "SELECT COUNT(*) FROM posts WHERE id = 2"); n != 1 {
		t.Error("post 2 was deleted by a non-owner")
	}

	// The owner's own post is writable.
	r = env.MustGQL(t, grace, `mutation { update_posts_by_pk(id: 3, _set: {title: "Compilers, revisited"}) { id title } }`, nil)
	if got := r.String(t, "update_posts_by_pk.title"); got != "Compilers, revisited" {
		t.Errorf("own update returned title %q", got)
	}
	// Admin is unrestricted.
	r = env.MustGQL(t, env.Token(t, "admin", 4), `mutation { update_posts(where: {id: {_eq: 1}}, _set: {views: 421}) { affected_rows } }`, nil)
	if n := r.Int(t, "update_posts.affected_rows"); n != 1 {
		t.Errorf("admin update affected %d rows, want 1", n)
	}
}

func TestSmokeCursorPagination(t *testing.T) {
	t.Parallel()
	env := New(t)
	const q = `query($after: String, $where: posts_bool_exp) {
		posts_connection(first: 2, after: $after, where: $where) {
			nodes { id } page_info { has_next_page end_cursor }
		}
	}`
	walk := func(token string, where map[string]any) []int64 {
		t.Helper()
		var ids []int64
		vars := map[string]any{"after": nil, "where": where}
		for page := 0; page < 10; page++ {
			r := env.MustGQL(t, token, q, vars)
			ids = append(ids, r.IDs(t, "posts_connection.nodes")...)
			if r.Get("posts_connection.page_info.has_next_page") != true {
				return ids
			}
			vars["after"] = r.String(t, "posts_connection.page_info.end_cursor")
		}
		t.Fatal("pagination did not terminate")
		return nil
	}

	admin := env.Token(t, "admin", 4)
	if got := walk(admin, nil); !slices.Equal(got, []int64{1, 2, 3, 4}) {
		t.Errorf("admin pages = %v, want [1 2 3 4]", got)
	}
	// The row filter holds on every page.
	if got := walk("", nil); !slices.Equal(got, []int64{1, 3, 4}) {
		t.Errorf("anonymous pages = %v, want [1 3 4]", got)
	}
	if got := walk(admin, map[string]any{"author_id": map[string]any{"_eq": 1}}); !slices.Equal(got, []int64{1, 2}) {
		t.Errorf("filtered pages = %v, want [1 2]", got)
	}

	// A cursor is bound to its query's filter and cannot be replayed elsewhere.
	r := env.MustGQL(t, admin, q, map[string]any{"where": map[string]any{"id": map[string]any{"_gt": 0}}})
	cursor := r.String(t, "posts_connection.page_info.end_cursor")
	env.GQL(t, admin, q, map[string]any{"after": cursor}).MustFail(t, "cursor does not match")
	env.GQL(t, admin, q, map[string]any{"after": "not-a-cursor"}).MustFail(t, "invalid cursor")
}

func TestSmokeAggregateCount(t *testing.T) {
	t.Parallel()
	env := New(t)

	r := env.MustGQL(t, env.Token(t, "admin", 4), `{ posts_aggregate { count sum { views } max { views } } }`, nil)
	if n := r.Int(t, "posts_aggregate.count"); n != 4 {
		t.Errorf("admin count = %d, want 4", n)
	}
	if n := r.Int(t, "posts_aggregate.sum.views"); n != 420+3+250+999 {
		t.Errorf("admin sum(views) = %d, want 1672", n)
	}

	r = env.MustGQL(t, env.Token(t, "author", 1), `{ posts_aggregate(where: {author_id: {_eq: 1}}) { count } }`, nil)
	if n := r.Int(t, "posts_aggregate.count"); n != 2 {
		t.Errorf("author where-count = %d, want 2", n)
	}

	// The anonymous row filter applies to aggregates, and hidden columns
	// cannot be aggregated.
	r = env.MustGQL(t, "", `{ posts_aggregate { count } }`, nil)
	if n := r.Int(t, "posts_aggregate.count"); n != 3 {
		t.Errorf("anonymous count = %d, want 3 (published only)", n)
	}
	env.GQL(t, "", `{ posts_aggregate { sum { views } } }`, nil).MustFail(t, "views")
}

func TestSmokeAuthRejections(t *testing.T) {
	t.Parallel()
	env := New(t)
	const q = `{ posts_aggregate { count } }`

	if r := env.GQL(t, "not.a.jwt", q, nil); r.Status != http.StatusUnauthorized {
		t.Errorf("garbage token: HTTP %d, want 401", r.Status)
	}
	if r := env.GQL(t, env.Token(t, "superuser", 1), q, nil); r.Status != http.StatusForbidden {
		t.Errorf("unknown role: HTTP %d, want 403", r.Status)
	}
	expired := env.SignClaims(t, map[string]any{"role": "admin", "sub": 4, "exp": 1})
	if r := env.GQL(t, expired, q, nil); r.Status != http.StatusUnauthorized {
		t.Errorf("expired token: HTTP %d, want 401", r.Status)
	}
}
