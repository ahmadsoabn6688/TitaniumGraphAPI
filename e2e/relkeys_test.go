package e2e

import (
	"strconv"
	"testing"
)

// End-to-end tests for how relationship batches match child rows to parent
// keys (character keys follow the column collation) and for nested reads in
// the response of a multi-mutation request.

// collationRoles: admin reads everything; scout sees players without the
// score column and never player 3; anonymous sees only teams.
const collationRoles = `roles:
  admin:
    tables:
      "*":
        select: true
        insert: true
        update: true
        delete: true
  scout:
    tables:
      teams:
        select: true
      players:
        select:
          allow: true
          columns: [id, team_code, nick]
          filter: "id <> 3"
  anonymous:
    tables:
      teams:
        select: true
`

// TestRelationshipCollationKeys: teams.code is utf8mb4_general_ci (case
// insensitive, PAD SPACE), so players.team_code values 'ABC', 'abc' and 'Abc'
// all reference team 'abc', and 'def' references 'def '. The list, the
// aggregate and the object relationship must all agree with SQL equality.
func TestRelationshipCollationKeys(t *testing.T) {
	t.Parallel()
	env := New(t, WithRolesYAML(collationRoles), WithSQL(
		"CREATE TABLE teams (code VARCHAR(10) COLLATE utf8mb4_general_ci PRIMARY KEY, name VARCHAR(20) NOT NULL)",
		"CREATE TABLE players (id BIGINT PRIMARY KEY, team_code VARCHAR(10) COLLATE utf8mb4_general_ci NOT NULL, "+
			"nick VARCHAR(20) COLLATE utf8mb4_bin NOT NULL, score INT NOT NULL, "+
			"CONSTRAINT fk_players_team FOREIGN KEY (team_code) REFERENCES teams (code))",
		"INSERT INTO teams VALUES ('abc', 'Alpha'), ('xyz', 'Xray'), ('def ', 'Delta'), ('nil', 'Empty')",
		"INSERT INTO players VALUES (1, 'ABC', 'ann', 10), (2, 'abc', 'bob', 20), (3, 'Abc', 'cy', 30), (4, 'xyz', 'dee', 5), (5, 'def', 'eve', 7)",
		// utf8mb4_bin is case-sensitive but PAD SPACE: 'ann ' references
		// 'ann', 'ANN' references 'ANN ', and nothing crosses case.
		"CREATE TABLE badges (nick VARCHAR(20) COLLATE utf8mb4_bin PRIMARY KEY)",
		"CREATE TABLE awards (id BIGINT PRIMARY KEY, nick VARCHAR(20) COLLATE utf8mb4_bin NOT NULL, "+
			"CONSTRAINT fk_awards_badge FOREIGN KEY (nick) REFERENCES badges (nick))",
		"INSERT INTO badges VALUES ('ann'), ('ANN ')",
		"INSERT INTO awards VALUES (1, 'ann '), (2, 'ANN'), (3, 'ann')",
	))
	admin := env.Token(t, "admin", 1)
	const q = `{ teams_connection { nodes {
		code
		players { id }
		top: players(limit: 2, order_by: [{id: desc}]) { id }
		players_aggregate { count count_distinct { team_code } }
		many: players_aggregate(where: {id: {_gt: 1}}) { count }
	} } }`

	// Teams in PK order: 'abc', 'def ', 'nil', 'xyz'.
	type want struct {
		code  string
		ids   []int64
		top   []int64
		count int64
		many  int64
	}
	check := func(t *testing.T, r *Result, rows []want) {
		t.Helper()
		if n := len(r.List(t, "teams_connection.nodes")); n != len(rows) {
			t.Fatalf("teams = %d, want %d: %s", n, len(rows), r.Raw)
		}
		for i, w := range rows {
			p := "teams_connection.nodes." + strconv.Itoa(i) + "."
			if got := r.String(t, p+"code"); got != w.code {
				t.Errorf("team %d code = %q, want %q", i, got, w.code)
			}
			if got := r.IDs(t, p+"players"); !equalIDs(got, w.ids) {
				t.Errorf("%s players = %v, want %v", w.code, got, w.ids)
			}
			if got := r.IDs(t, p+"top"); !equalIDs(got, w.top) {
				t.Errorf("%s top players = %v, want %v", w.code, got, w.top)
			}
			wantInt(t, r, p+"players_aggregate.count", w.count)
			wantInt(t, r, p+"many.count", w.many)
			if w.count > 0 {
				wantInt(t, r, p+"players_aggregate.count_distinct.team_code", 1) // one value under the collation
			}
		}
	}
	check(t, env.MustGQL(t, admin, q, nil), []want{
		{"abc", []int64{1, 2, 3}, []int64{3, 2}, 3, 2},
		{"def ", []int64{5}, []int64{5}, 1, 1},
		{"nil", nil, nil, 0, 0},
		{"xyz", []int64{4}, []int64{4}, 1, 1},
	})

	// Object relationship: every player finds its team whatever the case.
	r := env.MustGQL(t, admin, `{ players_connection { nodes { id team_code teams { code name } } } }`, nil)
	for i, name := range []string{"Alpha", "Alpha", "Alpha", "Xray", "Delta"} {
		p := "players_connection.nodes." + strconv.Itoa(i)
		if got := r.String(t, p+".teams.name"); got != name {
			t.Errorf("player %d team = %q, want %q", i+1, got, name)
		}
	}

	// Case-sensitive PAD SPACE keys: badges in PK order 'ANN ', 'ann'.
	r = env.MustGQL(t, admin, `{
		badges_connection { nodes { nick awards { id } awards_aggregate { count } } }
		awards_connection { nodes { id badges { nick } } }
	}`, nil)
	for i, w := range [][]int64{{2}, {1, 3}} {
		p := "badges_connection.nodes." + strconv.Itoa(i)
		if got := r.IDs(t, p+".awards"); !equalIDs(got, w) {
			t.Errorf("%s awards = %v, want %v", p, got, w)
		}
		wantInt(t, r, p+".awards_aggregate.count", int64(len(w)))
	}
	for i, nick := range []string{"ann", "ANN ", "ann"} {
		if got := r.String(t, "awards_connection.nodes."+strconv.Itoa(i)+".badges.nick"); got != nick {
			t.Errorf("award %d badge = %q, want %q", i+1, got, nick)
		}
	}

	// The scout's row filter hides player 3 from the list and the aggregate
	// alike, and the hidden score column can be neither aggregated nor
	// filtered on.
	scout := env.Token(t, "scout", 9)
	check(t, env.MustGQL(t, scout, q, nil), []want{
		{"abc", []int64{1, 2}, []int64{2, 1}, 2, 1},
		{"def ", []int64{5}, []int64{5}, 1, 1},
		{"nil", nil, nil, 0, 0},
		{"xyz", []int64{4}, []int64{4}, 1, 1},
	})
	r = env.MustGQL(t, scout, `{ players_connection { nodes { id teams { code } } } }`, nil)
	if got := r.IDs(t, "players_connection.nodes"); !equalIDs(got, []int64{1, 2, 4, 5}) {
		t.Errorf("scout players = %v", got)
	}
	env.GQL(t, scout, `{ teams_connection { nodes { players_aggregate { sum { score } } } } }`, nil).MustFail(t, "sum")
	env.GQL(t, scout, `{ teams_connection { nodes { players_aggregate(where: {score: {_gt: 0}}) { count } } } }`, nil).MustFail(t, "score")
	env.GQL(t, scout, `{ teams_connection { nodes { players { score } } } }`, nil).MustFail(t, "score")
	// anonymous cannot follow teams to players at all.
	env.GQL(t, "", `{ teams_connection { nodes { players_aggregate { count } } } }`, nil).MustFail(t, "players_aggregate")
}

func equalIDs(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestMutationNestedReadsPerMutation: in `mutation { a: … b: … }` the rows
// nested under a's response (relationships and <rel>_aggregate) show the
// database after a, not after b.
func TestMutationNestedReadsPerMutation(t *testing.T) {
	t.Parallel()
	env := New(t)
	admin := env.Token(t, "admin", 4)

	// Ada's posts: 1 (views 420) and 2 (views 3).
	r := env.MustGQL(t, admin, `mutation {
		a: update_posts_by_pk(id: 1, _set: {views: 1}) { id author { posts_aggregate { sum { views } } posts(order_by: [{id: asc}]) { views } } }
		b: update_posts_by_pk(id: 1, _set: {views: 1000}) { id author { posts_aggregate { sum { views } } posts(order_by: [{id: asc}]) { views } } }
		c: insert_comments_one(object: {id: 9, post_id: 1, user_id: 4, body: "x"}) { post { comments_aggregate { count } } }
	}`, nil)
	wantInt(t, r, "a.author.posts_aggregate.sum.views", 4)
	wantInt(t, r, "a.author.posts.0.views", 1)
	wantInt(t, r, "b.author.posts_aggregate.sum.views", 1003)
	wantInt(t, r, "b.author.posts.0.views", 1000)
	wantInt(t, r, "c.post.comments_aggregate.count", 3)

	// A single mutation still reads its own result.
	r = env.MustGQL(t, admin, `mutation { update_posts_by_pk(id: 2, _set: {views: 6}) { author { posts_aggregate { sum { views } } } } }`, nil)
	wantInt(t, r, "update_posts_by_pk.author.posts_aggregate.sum.views", 1006)

	// The author role: ada (sub 1) retitles her post twice; each response
	// shows its own title. She cannot touch grace's post or set views.
	ada := env.Token(t, "author", 1)
	r = env.MustGQL(t, ada, `mutation {
		a: update_posts_by_pk(id: 1, _set: {title: "A"}) { author { posts(where: {id: {_eq: 1}}) { title } } }
		b: update_posts_by_pk(id: 1, _set: {title: "B"}) { author { posts(where: {id: {_eq: 1}}) { title } } }
		g: update_posts_by_pk(id: 3, _set: {title: "hijack"}) { id }
	}`, nil)
	if got := r.String(t, "a.author.posts.0.title"); got != "A" {
		t.Errorf("a sees title %q, want A", got)
	}
	if got := r.String(t, "b.author.posts.0.title"); got != "B" {
		t.Errorf("b sees title %q, want B", got)
	}
	if v := r.Get("g"); v != nil {
		t.Errorf("author updated someone else's post: %v", v)
	}
	if got := env.QueryString(t, "SELECT title FROM posts WHERE id = 3"); got != "Compilers for humans" {
		t.Errorf("post 3 title = %q", got)
	}
	env.GQL(t, ada, `mutation { a: update_posts_by_pk(id: 1, _set: {views: 5}) { id } b: update_posts_by_pk(id: 1, _set: {title: "C"}) { id } }`, nil).MustFail(t, "views")
}
