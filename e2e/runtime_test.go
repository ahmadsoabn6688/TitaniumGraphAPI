package e2e

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/graphql-go/graphql"

	"gqlgate"
	"gqlgate/config"
)

// End-to-end tests for the request runtime: role selection through the role
// header (allowed roles from a claim, an identity column or a role table),
// concurrent query root fields, hook-provided object fields on table types
// and typed JSON columns.

// jwtTemplate swaps the role_claim line of the default config for other jwt
// settings.
func jwtTemplate(jwtYAML string) string {
	return strings.Replace(DefaultConfigTemplate, "  role_claim: role\n", jwtYAML, 1)
}

func roleHeader(token, role string) map[string]string {
	h := map[string]string{}
	if token != "" {
		h["Authorization"] = "Bearer " + token
	}
	if role != "" {
		h[config.DefaultRoleHeader] = role
	}
	return h
}

// --- #14 allowed roles + role header -----------------------------------------

func TestRoleHeaderFromClaim(t *testing.T) {
	t.Parallel()
	env := New(t, WithConfigTemplate(jwtTemplate("  role_claim: role\n  allowed_roles_claim: app.roles\n")))
	tok := env.Token(t, "author", 1, map[string]any{"app": map[string]any{"roles": []any{"admin"}}})
	q := `{ _role users_connection { nodes { id email } } }`

	// No header: the default role from the role claim, which cannot read email.
	env.GQL(t, tok, q, nil).MustFail(t, "email")
	r := env.MustGQL(t, tok, `{ _role }`, nil)
	if r.String(t, "_role") != "author" {
		t.Fatalf("default role = %s", r.Raw)
	}
	// The header switches to an allowed role for this request only.
	r = env.Do(t, roleHeader(tok, "admin"), q, nil).MustOK(t)
	if r.String(t, "_role") != "admin" || r.String(t, "users_connection.nodes.0.email") != "ada@example.com" {
		t.Fatalf("as admin: %s", r.Raw)
	}
	// Naming the default role is fine.
	r = env.Do(t, roleHeader(tok, "author"), `{ _role }`, nil).MustOK(t)
	if r.String(t, "_role") != "author" {
		t.Fatalf("explicit default: %s", r.Raw)
	}

	// Negative cases: all 403, never served as some other role.
	plain := env.Token(t, "author", 2) // no allowed roles at all
	ghost := env.Token(t, "author", 1, map[string]any{"app": map[string]any{"roles": []any{"superuser"}}})
	for name, h := range map[string]map[string]string{
		"role not in the allowed list":  roleHeader(plain, "admin"),
		"allowed but not configured":    roleHeader(ghost, "superuser"),
		"anonymous cannot pick a role":  roleHeader("", "admin"),
		"anonymous cannot pick author":  roleHeader("", "author"),
		"allowed list does not include": roleHeader(tok, "anonymous"),
	} {
		r := env.Do(t, h, `{ _role }`, nil)
		if r.Status != http.StatusForbidden || r.Data != nil {
			t.Errorf("%s: want 403 without data, got HTTP %d: %s", name, r.Status, r.Raw)
		}
	}
	// Anonymous without a header keeps working as before.
	r = env.Do(t, roleHeader("", ""), `{ _role }`, nil).MustOK(t)
	if r.String(t, "_role") != "anonymous" {
		t.Fatalf("anonymous: %s", r.Raw)
	}
	r = env.Do(t, roleHeader("", "anonymous"), `{ _role }`, nil).MustOK(t)
	if r.String(t, "_role") != "anonymous" {
		t.Fatalf("anonymous naming itself: %s", r.Raw)
	}
}

func TestRoleHeaderWithoutAllowedRoles(t *testing.T) {
	t.Parallel()
	env := New(t) // the default config has no allowed-roles source
	tok := env.Token(t, "author", 1, map[string]any{"roles": []any{"admin"}})
	r := env.Do(t, roleHeader(tok, "admin"), `{ _role }`, nil)
	if r.Status != http.StatusForbidden {
		t.Fatalf("want 403, got HTTP %d: %s", r.Status, r.Raw)
	}
	r = env.Do(t, roleHeader(tok, "author"), `{ _role }`, nil).MustOK(t)
	if r.String(t, "_role") != "author" {
		t.Fatalf("own role: %s", r.Raw)
	}
	// Existing behaviour without the header is unchanged.
	r = env.MustGQL(t, tok, `{ _role }`, nil)
	if r.String(t, "_role") != "author" {
		t.Fatalf("no header: %s", r.Raw)
	}
}

const lookupJWT = `  role_lookup:
    table: users
    id_claim: sub
`

func TestRoleHeaderFromIdentityColumn(t *testing.T) {
	t.Parallel()
	env := New(t,
		WithSQL(`ALTER TABLE users ADD COLUMN allowed_roles VARCHAR(200) NULL`,
			`UPDATE users SET allowed_roles = '["admin"]' WHERE id = 1`,
			`UPDATE users SET allowed_roles = 'admin, author' WHERE id = 2`),
		WithConfigTemplate(jwtTemplate(lookupJWT+"    allowed_roles_column: allowed_roles\n")))
	ada := env.SignClaims(t, map[string]any{"sub": 1})   // author; may be admin (JSON list)
	grace := env.SignClaims(t, map[string]any{"sub": 2}) // author; may be admin (comma list)
	alan := env.SignClaims(t, map[string]any{"sub": 3})  // author; NULL list
	gone := env.SignClaims(t, map[string]any{"sub": 99}) // no identity row

	for _, tok := range []string{ada, grace} {
		r := env.Do(t, roleHeader(tok, "admin"), `{ _role users_connection { nodes { email } } }`, nil).MustOK(t)
		if r.String(t, "_role") != "admin" || len(r.List(t, "users_connection.nodes")) != 4 {
			t.Fatalf("as admin: %s", r.Raw)
		}
	}
	r := env.MustGQL(t, ada, `{ _role }`, nil)
	if r.String(t, "_role") != "author" {
		t.Fatalf("default from the role column: %s", r.Raw)
	}
	for name, h := range map[string]map[string]string{
		"NULL allowed list":  roleHeader(alan, "admin"),
		"deleted identity":   roleHeader(gone, "author"),
		"unconfigured role":  roleHeader(ada, "editor"),
		"anonymous switches": roleHeader("", "admin"),
	} {
		if r := env.Do(t, h, `{ _role }`, nil); r.Status != http.StatusForbidden {
			t.Errorf("%s: want 403, got HTTP %d: %s", name, r.Status, r.Raw)
		}
	}
	// A revoked grant takes effect on the next request (no cache configured).
	env.Exec(t, `UPDATE users SET allowed_roles = NULL WHERE id = 1`)
	if r := env.Do(t, roleHeader(ada, "admin"), `{ _role }`, nil); r.Status != http.StatusForbidden {
		t.Errorf("revoked: want 403, got HTTP %d: %s", r.Status, r.Raw)
	}
}

func TestRoleHeaderFromRoleTable(t *testing.T) {
	t.Parallel()
	env := New(t,
		WithSQL(`CREATE TABLE user_roles (uid BIGINT NOT NULL, role_name VARCHAR(32) NOT NULL, PRIMARY KEY (uid, role_name))`,
			`INSERT INTO user_roles VALUES (2, 'admin'), (2, 'anonymous')`),
		WithConfigTemplate(jwtTemplate(lookupJWT+"    allowed_roles_table: {table: user_roles, id_column: uid, role_column: role_name}\n")))
	ada := env.SignClaims(t, map[string]any{"sub": 1})
	grace := env.SignClaims(t, map[string]any{"sub": "2"}) // string ids bind too

	r := env.Do(t, roleHeader(grace, "admin"), `{ _role }`, nil).MustOK(t)
	if r.String(t, "_role") != "admin" {
		t.Fatalf("grace as admin: %s", r.Raw)
	}
	r = env.Do(t, roleHeader(grace, "anonymous"), `{ _role posts_connection { nodes { id } } }`, nil).MustOK(t)
	if r.String(t, "_role") != "anonymous" || len(r.List(t, "posts_connection.nodes")) != 3 {
		t.Fatalf("grace as anonymous sees only published posts: %s", r.Raw)
	}
	if r := env.Do(t, roleHeader(ada, "admin"), `{ _role }`, nil); r.Status != http.StatusForbidden {
		t.Errorf("ada has no admin row: want 403, got HTTP %d: %s", r.Status, r.Raw)
	}
}

func TestRoleLookupAllowedRolesStartupChecks(t *testing.T) {
	t.Parallel()
	env := New(t)
	for name, jwtYAML := range map[string]string{
		"missing column": lookupJWT + "    allowed_roles_column: nope\n",
		"missing table":  lookupJWT + "    allowed_roles_table: {table: nope}\n",
	} {
		cfg := *env.Config
		cfg.JWT.RoleLookup = config.RoleLookup{Table: "users", Schema: env.DBName, IDClaim: "sub", IDColumn: "id", RoleColumn: "role"}
		if strings.Contains(jwtYAML, "allowed_roles_column") {
			cfg.JWT.RoleLookup.AllowedRolesColumn = "nope"
		} else {
			cfg.JWT.RoleLookup.AllowedRolesTable = &config.AllowedRolesTable{Table: "nope", Schema: env.DBName, IDColumn: "user_id", RoleColumn: "role"}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		g, err := gqlgate.Open(ctx, &cfg)
		cancel()
		if err == nil {
			g.Close()
			t.Errorf("%s: Open must fail", name)
		} else if !strings.Contains(err.Error(), "nope") {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
}

// --- #15 concurrent root fields ------------------------------------------------

// slowSQL adds a view whose every row takes 0.4s to produce (SLEEP runs per
// output row), so overlapping root fields are measurable.
var slowSQL = []string{`CREATE VIEW slow_users AS SELECT id, name, SLEEP(0.4) AS slept FROM users`}

const slowTables = `tables:
  slow_users:
    primary_key: [id]
`

const slowRoles = `roles:
  admin:
    tables:
      "*":
        select: true
      slow_users:
        select: true
  author:
    tables:
      posts:
        select: true
      slow_users:
        select:
          allow: true
          columns: [id, slept]
  anonymous:
    tables:
      posts:
        select:
          allow: true
          columns: [id, title]
          filter: "published = 1"
`

func TestConcurrentRootFields(t *testing.T) {
	t.Parallel()
	timed := func(env *Env, tok string) time.Duration {
		start := time.Now()
		r := env.MustGQL(t, tok, `{ a: slow_users_by_pk(id: 1) { id slept } b: slow_users_by_pk(id: 2) { id }
			c: slow_users_by_pk(id: 3) { id } }`, nil)
		if r.Int(t, "a.id") != 1 || r.Int(t, "b.id") != 2 || r.Int(t, "c.id") != 3 {
			t.Fatalf("results: %s", r.Raw)
		}
		return time.Since(start)
	}

	parallel := New(t, WithSQL(slowSQL...), WithExtraYAML(slowTables), WithRolesYAML(slowRoles))
	serial := New(t, WithSQL(slowSQL...), WithExtraYAML(slowTables), WithRolesYAML(slowRoles),
		WithConfig(func(c *config.Config) { c.Server.MaxParallelRootFields = 1 }))
	if parallel.Config.Server.MaxParallelRootFields != 4 {
		t.Fatalf("default cap = %d, want 4", parallel.Config.Server.MaxParallelRootFields)
	}
	admin := parallel.Token(t, "admin", 4)
	author := parallel.Token(t, "author", 1)

	// Three 0.4s root fields: about 0.4s together, 1.2s one after another.
	if d := timed(parallel, admin); d > 1000*time.Millisecond {
		t.Errorf("parallel request took %v; the root fields did not overlap", d)
	}
	if d := timed(parallel, author); d > 1000*time.Millisecond {
		t.Errorf("parallel request (author) took %v", d)
	}
	if d := timed(serial, serial.Token(t, "admin", 4)); d < 1150*time.Millisecond {
		t.Errorf("serial request took %v; max_parallel_root_fields: 1 must run them one by one", d)
	}

	// Negative RBAC holds per root field: author cannot read slow_users.name,
	// and anonymous has no slow_users at all.
	parallel.GQL(t, author, `{ a: slow_users_by_pk(id: 1) { name } b: posts_aggregate { count } }`, nil).MustFail(t, "name")
	parallel.GQL(t, "", `{ a: slow_users_by_pk(id: 1) { id } b: posts_aggregate { count } }`, nil).MustFail(t, "slow_users_by_pk")
}

func TestConcurrentRootFieldsResults(t *testing.T) {
	t.Parallel()
	query := `query Dash($min: BigInt) {
		a: posts_aggregate { count }
		b: posts_connection(first: 2, where: {id: {_gte: $min}}) { nodes { id title author { name } comments { body user { name } } } page_info { has_next_page } }
		c: users_connection { nodes { id posts_aggregate { count } } }
		d: comments_by_pk(id: 1) { body post { title } }
		...More
		_role
	}
	fragment More on Query { e: posts_by_pk(id: 2) { title } }`
	vars := map[string]any{"min": 1}
	// The same request against a parallel and a serial gateway gives the
	// same response, per role.
	parallel := New(t)
	serial := New(t, WithConfig(func(c *config.Config) { c.Server.MaxParallelRootFields = 1 }))
	for _, role := range []string{"admin", "author"} {
		p := parallel.MustGQL(t, parallel.Token(t, role, 1), query, vars)
		s := serial.MustGQL(t, serial.Token(t, role, 1), query, vars)
		if string(p.Raw) != string(s.Raw) {
			t.Errorf("%s: parallel and serial responses differ:\n%s\n%s", role, p.Raw, s.Raw)
		}
	}
	// Anonymous: published posts only, in every root field.
	r := parallel.MustGQL(t, "", `{ a: posts_aggregate { count } b: posts_connection { nodes { id } } c: posts_by_pk(id: 2) { id } }`, nil)
	if r.Int(t, "a.count") != 3 || len(r.List(t, "b.nodes")) != 3 || r.Get("c") != nil {
		t.Errorf("anonymous: %s", r.Raw)
	}
	parallel.GQL(t, "", `{ a: posts_aggregate { count } b: users_connection { nodes { email } } }`, nil).MustFail(t, "email")
}

func TestConcurrentRootFieldsLimits(t *testing.T) {
	t.Parallel()
	env := New(t, WithConfig(func(c *config.Config) { c.Server.MaxResponseRows = 5 }))
	admin := env.Token(t, "admin", 4)
	r := env.GQL(t, admin, `{ a: posts_connection { nodes { id } } b: users_connection { nodes { id } } c: comments_connection { nodes { id } } }`, nil)
	if r.Data != nil || len(r.Errors) != 1 || r.Errors[0].Extensions["code"] != "response_too_large" {
		t.Fatalf("want one response_too_large error and no data: %s", r.Raw)
	}
	// An error of one concurrent root field keeps its path; a nullable root
	// field that fails leaves the others intact.
	r = env.GQL(t, admin, `{ a: posts_connection(after: "bogus") { nodes { id } } }`, nil)
	if len(r.Errors) != 1 || len(r.Errors[0].Path) == 0 || r.Errors[0].Path[0] != "a" {
		t.Fatalf("want one error at path a: %s", r.Raw)
	}
	r = env.GQL(t, admin, `{ a: users_by_pk(id: 1) { id } b: posts_by_pk(id: 1) { id } }`, nil).MustOK(t)
	if r.Int(t, "a.id") != 1 || r.Int(t, "b.id") != 1 {
		t.Fatalf("by_pk pair: %s", r.Raw)
	}
}

// TestConcurrentRootFieldsPoolGuard: the per-request cap must leave a pooled
// connection free, and a hot reload cannot resize the pool (it is sized once
// at startup), so it cannot raise the cap past the pool actually in use.
func TestConcurrentRootFieldsPoolGuard(t *testing.T) {
	t.Parallel()
	env := New(t)
	raw, err := os.ReadFile(env.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	rewrite := func(pool, parallel string) string {
		y := strings.Replace(string(raw), "  max_open_conns: 10\n", "  max_open_conns: "+pool+"\n", 1)
		return strings.Replace(y, "server:\n", "server:\n  max_parallel_root_fields: "+parallel+"\n", 1)
	}
	// Equal to the pool: one request could hold every connection.
	equal := filepath.Join(t.TempDir(), "equal.yaml")
	if err := os.WriteFile(equal, []byte(rewrite("10", "10")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(equal); err == nil || !strings.Contains(err.Error(), "must be less than database.max_open_conns") {
		t.Errorf("max_parallel_root_fields == max_open_conns must be rejected, got %v", err)
	}

	// A reload that grows the pool to 40 and the cap to 20 is rejected: the
	// live pool stays at 10.
	if err := os.WriteFile(env.ConfigPath, []byte(rewrite("40", "20")), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := env.Gate.Reload(ctx); err == nil || !strings.Contains(err.Error(), "max_open_conns") {
		t.Fatalf("a pool-size change must be rejected on reload, got %v", err)
	}
	// The previous config keeps serving, for every role.
	r := env.MustGQL(t, env.Token(t, "admin", 4), `{ a: posts_aggregate { count } b: users_aggregate { count } }`, nil)
	if r.Int(t, "a.count") != 4 || r.Int(t, "b.count") != 4 {
		t.Errorf("admin after rejected reload: %s", r.Raw)
	}
	r = env.MustGQL(t, "", `{ a: posts_aggregate { count } }`, nil)
	if r.Int(t, "a.count") != 3 {
		t.Errorf("anonymous after rejected reload: %s", r.Raw)
	}
	env.GQL(t, "", `{ users_connection { nodes { email } } }`, nil).MustFail(t, "email")
}

// --- #16 object fields ------------------------------------------------------------

func TestObjectFields(t *testing.T) {
	t.Parallel()
	var batches, batchRows atomic.Int32
	fields := []gqlgate.ObjectField{
		{
			// Visible to every role that can read email (admin only here).
			Table: "users", Name: "avatar_url", Requires: []string{"email"}, Type: graphql.String,
			Args: graphql.FieldConfigArgument{"size": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 80}},
			Resolve: func(_ context.Context, p gqlgate.ObjectFieldParams) (any, error) {
				return fmt.Sprintf("https://avatars.example/%s?s=%d", p.Row["email"], p.Args["size"]), nil
			},
		},
		{
			// Batched: one query per wave of users, whatever the row count.
			Table: "users", Name: "published_posts", Requires: []string{"id"}, Type: graphql.Int,
			ResolveBatch: func(ctx context.Context, ps []gqlgate.ObjectFieldParams) ([]any, error) {
				batches.Add(1)
				batchRows.Add(int32(len(ps)))
				ids := make([]string, len(ps))
				args := make([]any, len(ps))
				for i, p := range ps {
					ids[i], args[i] = "?", p.Row["id"]
				}
				rows, err := ps[0].DB.QueryContext(ctx,
					"SELECT author_id, COUNT(*) FROM posts WHERE published = 1 AND author_id IN ("+strings.Join(ids, ",")+") GROUP BY author_id", args...)
				if err != nil {
					return nil, err
				}
				defer rows.Close()
				counts := map[int64]int{}
				for rows.Next() {
					var id int64
					var n int
					if err := rows.Scan(&id, &n); err != nil {
						return nil, err
					}
					counts[id] = n
				}
				out := make([]any, len(ps))
				for i, p := range ps {
					out[i] = counts[p.Row["id"].(int64)]
				}
				return out, rows.Err()
			},
		},
		{
			// Uses the caller's claims; only for authors.
			Table: "posts", Name: "is_mine", Requires: []string{"author_id"}, Type: graphql.Boolean,
			AllowedRoles: []string{"author"},
			Resolve: func(_ context.Context, p gqlgate.ObjectFieldParams) (any, error) {
				return fmt.Sprint(p.Row["author_id"]) == fmt.Sprint(p.Claims["sub"]), nil
			},
		},
	}
	env := New(t, WithGateOptions(gqlgate.WithObjectFields(fields...)))
	admin := env.Token(t, "admin", 4)
	author := env.Token(t, "author", 1)

	r := env.MustGQL(t, admin, `{ users_connection { nodes { id avatar_url big: avatar_url(size: 200) published_posts } } }`, nil)
	if got := r.String(t, "users_connection.nodes.0.avatar_url"); got != "https://avatars.example/ada@example.com?s=80" {
		t.Errorf("avatar_url = %s", got)
	}
	if got := r.String(t, "users_connection.nodes.1.big"); got != "https://avatars.example/grace@example.com?s=200" {
		t.Errorf("big = %s", got)
	}
	// ada has 1 published post (post 2 is a draft), grace 1, alan 1, root 0.
	for i, want := range []int64{1, 1, 1, 0} {
		if got := r.Int(t, fmt.Sprintf("users_connection.nodes.%d.published_posts", i)); got != want {
			t.Errorf("user %d published_posts = %d, want %d", i+1, got, want)
		}
	}
	if batches.Load() != 1 || batchRows.Load() != 4 {
		t.Errorf("published_posts ran %d batches over %d rows, want 1 over 4", batches.Load(), batchRows.Load())
	}

	// Through a relationship, as another role: author reads users.id (so it
	// gets published_posts) but not email (so no avatar_url).
	r = env.MustGQL(t, author, `{ posts_connection { nodes { id is_mine author { published_posts } } } }`, nil)
	for i, want := range []bool{true, true, false, false} {
		if got := r.Get(fmt.Sprintf("posts_connection.nodes.%d.is_mine", i)); got != want {
			t.Errorf("post %d is_mine = %v, want %v", i+1, got, want)
		}
	}
	if r.Int(t, "posts_connection.nodes.2.author.published_posts") != 1 {
		t.Errorf("published_posts via relationship: %s", r.Raw)
	}

	// Negative RBAC: author cannot read email, so avatar_url does not exist
	// for it; is_mine is for authors only (admin and anonymous both read
	// posts.author_id, yet do not get it).
	env.GQL(t, author, `{ users_connection { nodes { avatar_url } } }`, nil).MustFail(t, `Cannot query field "avatar_url"`)
	env.GQL(t, admin, `{ posts_connection { nodes { is_mine } } }`, nil).MustFail(t, `Cannot query field "is_mine"`)
	env.GQL(t, "", `{ posts_connection { nodes { is_mine } } }`, nil).MustFail(t, `Cannot query field "is_mine"`)

	// In a mutation's returning (rows read inside the write's transaction).
	r = env.MustGQL(t, author, `mutation { update_posts(where: {id: {_eq: 1}}, _set: {title: "Notes"}) {
		returning { id is_mine author { published_posts } } } }`, nil)
	if r.Get("update_posts.returning.0.is_mine") != true || r.Int(t, "update_posts.returning.0.author.published_posts") != 1 {
		t.Errorf("returning: %s", r.Raw)
	}
}

func TestObjectFieldStartupErrors(t *testing.T) {
	t.Parallel()
	env := New(t)
	ok := func(context.Context, gqlgate.ObjectFieldParams) (any, error) { return nil, nil }
	for want, f := range map[string]gqlgate.ObjectField{
		`collides with the field of column "name"`: {Table: "users", Name: "name", Type: graphql.String, Resolve: ok},
		`requires column "nope"`:                   {Table: "users", Name: "x", Requires: []string{"nope"}, Type: graphql.String, Resolve: ok},
		`collides with the relationship field`:     {Table: "posts", Name: "comments", Type: graphql.String, Resolve: ok},
		`role "ghost"`:                             {Table: "users", Name: "x", AllowedRoles: []string{"ghost"}, Type: graphql.String, Resolve: ok},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		g, err := gqlgate.Open(ctx, env.Config, gqlgate.WithObjectFields(f))
		cancel()
		if err == nil {
			g.Close()
			t.Errorf("want startup error %q", want)
		} else if !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
}

// TestObjectFieldRenamedAggregate: a declared relationship called
// posts_aggregate pushes the posts aggregate to posts_aggregate_by_author_id;
// a hook field may not take that name and replace the aggregate.
func TestObjectFieldRenamedAggregate(t *testing.T) {
	t.Parallel()
	env := New(t, WithExtraYAML(`tables:
  users:
    relationships:
      posts_aggregate: {type: array, target: comments, mapping: {id: user_id}}
`))
	ok := func(context.Context, gqlgate.ObjectFieldParams) (any, error) { return "hook", nil }
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	g, err := gqlgate.Open(ctx, env.Config, gqlgate.WithObjectFields(gqlgate.ObjectField{
		Table: "users", Name: "posts_aggregate_by_author_id", Type: graphql.String, Resolve: ok}))
	if err == nil {
		g.Close()
		t.Fatal("a hook field named like the renamed aggregate must be rejected at startup")
	}
	if !strings.Contains(err.Error(), "collides with the nested aggregate field") {
		t.Errorf("startup error = %v", err)
	}

	// The renamed aggregate itself works for admin and author (ada has two
	// posts); anonymous only counts the published one (row filter) and
	// cannot read users.email.
	for _, tok := range []string{env.Token(t, "admin", 4), env.Token(t, "author", 1)} {
		r := env.MustGQL(t, tok, `{ users_by_pk(id: 1) { posts_aggregate_by_author_id { count } posts_aggregate { id } } }`, nil)
		if r.Int(t, "users_by_pk.posts_aggregate_by_author_id.count") != 2 {
			t.Errorf("posts aggregate: %s", r.Raw)
		}
	}
	r := env.MustGQL(t, "", `{ users_by_pk(id: 1) { posts_aggregate_by_author_id { count } } }`, nil)
	if r.Int(t, "users_by_pk.posts_aggregate_by_author_id.count") != 1 {
		t.Errorf("anonymous must not count the draft: %s", r.Raw)
	}
	env.GQL(t, "", `{ users_by_pk(id: 1) { email } }`, nil).MustFail(t, `Cannot query field "email"`)
}

// --- #17 typed JSON columns -------------------------------------------------------

const jsonTypesYAML = `json_types:
  UserMetadata:
    description: "Profile data kept in users.metadata."
    fields:
      tier: String
      tags: "[String]"
      score: {type: Int, description: "Loyalty score"}
  OrderItem:
    fields:
      sku: String
      qty: Int
      attrs: ItemAttrs
  ItemAttrs:
    fields:
      color: String
      gift_wrap: {type: Boolean, key: "gift-wrap"}
tables:
  users:
    columns:
      metadata: {json_type: UserMetadata}
  orders:
    columns:
      items: {name: lines, json_type: "[OrderItem]"}
`

var ordersSQL = []string{
	`CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT NOT NULL, items JSON NULL)`,
	`INSERT INTO orders VALUES
	   (1, 1, '[{"sku": "A-1", "qty": 2, "attrs": {"color": "red", "gift-wrap": true}}, {"sku": "B-2", "qty": 1}]'),
	   (2, 2, '{"sku": "not-a-list"}'),
	   (3, 2, NULL)`,
	`UPDATE users SET metadata = '{"tier": 5, "tags": ["x"], "score": 7}' WHERE id = 3`,
}

const jsonRoles = `roles:
  admin:
    tables:
      "*":
        select: true
        insert: true
        update: true
  author:
    tables:
      users:
        select:
          allow: true
          columns: [id, name]
      orders:
        select:
          allow: true
          filter: "user_id = :jwt.sub"
  anonymous:
    tables:
      posts:
        select: true
`

func TestTypedJSONColumns(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(ordersSQL...), WithExtraYAML(jsonTypesYAML), WithRolesYAML(jsonRoles))
	admin := env.Token(t, "admin", 4)
	author := env.Token(t, "author", 1)

	r := env.GQL(t, admin, `{ users_connection { nodes { id metadata { tier tags score } } } }`, nil)
	if got := r.String(t, "users_connection.nodes.0.metadata.tier"); got != "gold" {
		t.Errorf("tier = %s", got)
	}
	if got := r.List(t, "users_connection.nodes.1.metadata.tags"); len(got) != 1 || got[0] != "navy" {
		t.Errorf("tags = %v", got)
	}
	if r.Get("users_connection.nodes.0.metadata.score") != nil || r.Get("users_connection.nodes.3.metadata") != nil {
		t.Errorf("missing key / SQL NULL must be null: %s", r.Raw)
	}
	// User 3 stored a number as tier: that field is null with a coded error,
	// the rest of the row and the response are intact.
	if r.Get("users_connection.nodes.2.metadata.tier") != nil || r.Int(t, "users_connection.nodes.2.metadata.score") != 7 {
		t.Errorf("user 3 metadata: %s", r.Raw)
	}
	if len(r.Errors) != 1 || r.Errors[0].Extensions["code"] != "json_shape_mismatch" ||
		!strings.Contains(r.Errors[0].Message, "UserMetadata.tier") {
		t.Errorf("want one json_shape_mismatch error on UserMetadata.tier: %s", r.Raw)
	}

	// Arrays of nested objects, a renamed column and a JSON key that is not
	// a GraphQL name.
	r = env.GQL(t, admin, `{ orders_connection { nodes { id lines { sku qty attrs { color gift_wrap } } } } }`, nil)
	if r.String(t, "orders_connection.nodes.0.lines.0.attrs.color") != "red" ||
		r.Get("orders_connection.nodes.0.lines.0.attrs.gift_wrap") != true ||
		r.Int(t, "orders_connection.nodes.0.lines.1.qty") != 1 ||
		r.Get("orders_connection.nodes.0.lines.1.attrs") != nil {
		t.Errorf("order 1: %s", r.Raw)
	}
	if r.Get("orders_connection.nodes.1.lines") != nil || r.Get("orders_connection.nodes.2.lines") != nil ||
		len(r.Errors) != 1 || r.Errors[0].Extensions["code"] != "json_shape_mismatch" {
		t.Errorf("order 2 holds an object where a list is declared: %s", r.Raw)
	}

	// Writes still take a JSON value, and returning reads it typed; where
	// keeps the JSON operators.
	r = env.MustGQL(t, admin, `mutation { update_users_by_pk(id: 3, _set: {metadata: {tier: "bronze", tags: []}}) {
		metadata { tier tags } } }`, nil)
	if r.String(t, "update_users_by_pk.metadata.tier") != "bronze" {
		t.Errorf("returning: %s", r.Raw)
	}
	r = env.MustGQL(t, admin, `{ users_connection(where: {metadata: {_contains: {tier: "gold"}}}) { nodes { id } } }`, nil)
	if ids := r.IDs(t, "users_connection.nodes"); len(ids) != 1 || ids[0] != 1 {
		t.Errorf("_contains: %s", r.Raw)
	}

	// The author sees only its own orders (row filter) with the same typed
	// shape; it cannot read users.metadata, filter on it, or see its type.
	r = env.MustGQL(t, author, `{ orders_connection { nodes { id lines { sku } } } }`, nil)
	if ids := r.IDs(t, "orders_connection.nodes"); len(ids) != 1 || ids[0] != 1 {
		t.Errorf("author orders: %s", r.Raw)
	}
	env.GQL(t, author, `{ users_connection { nodes { metadata { tier } } } }`, nil).MustFail(t, "metadata")
	env.GQL(t, author, `{ users_connection(where: {metadata: {_is_null: false}}) { nodes { id } } }`, nil).MustFail(t, "metadata")
	r = env.MustGQL(t, author, `{ __type(name: "UserMetadata") { name } }`, nil)
	if r.Get("__type") != nil {
		t.Errorf("UserMetadata must not exist in the author schema: %s", r.Raw)
	}
	r = env.MustGQL(t, admin, `{ __type(name: "UserMetadata") { description fields { name } } }`, nil)
	if r.String(t, "__type.description") != "Profile data kept in users.metadata." || len(r.List(t, "__type.fields")) != 3 {
		t.Errorf("admin introspection: %s", r.Raw)
	}
	// Anonymous cannot reach orders at all.
	env.GQL(t, "", `{ orders_connection { nodes { id } } }`, nil).MustFail(t, "orders_connection")
}

// TestTypedJSONListElements: one element of the wrong kind nulls only that
// element (with an error at its path); the other elements still resolve.
func TestTypedJSONListElements(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(
		`CREATE TABLE orders (id BIGINT PRIMARY KEY, user_id BIGINT NOT NULL, items JSON NULL)`,
		`INSERT INTO orders VALUES
		   (1, 1, '[{"sku": "A-1"}, "oops", {"sku": "B-2"}]'),
		   (2, 2, '[{"sku": "C-3"}, 42]')`,
		`UPDATE users SET metadata = '{"tier": "gold", "tags": ["a", 7, "c"]}' WHERE id = 1`,
	), WithExtraYAML(jsonTypesYAML), WithRolesYAML(jsonRoles))
	admin := env.Token(t, "admin", 4)
	author := env.Token(t, "author", 1)

	r := env.GQL(t, admin, `{ orders_connection { nodes { id lines { sku } } } }`, nil)
	if r.String(t, "orders_connection.nodes.0.lines.0.sku") != "A-1" || r.Get("orders_connection.nodes.0.lines.1") != nil ||
		r.String(t, "orders_connection.nodes.0.lines.2.sku") != "B-2" || r.String(t, "orders_connection.nodes.1.lines.0.sku") != "C-3" ||
		r.Get("orders_connection.nodes.1.lines.1") != nil {
		t.Errorf("admin lines: %s", r.Raw)
	}
	paths := map[string]bool{}
	for _, e := range r.Errors {
		if e.Extensions["code"] != "json_shape_mismatch" {
			t.Errorf("error without json_shape_mismatch: %s", r.Raw)
		}
		paths[fmt.Sprint(e.Path)] = true
	}
	if len(r.Errors) != 2 || !paths["[orders_connection nodes 0 lines 1]"] || !paths["[orders_connection nodes 1 lines 1]"] {
		t.Errorf("want errors at both bad elements: %s", r.Raw)
	}

	r = env.GQL(t, admin, `{ users_by_pk(id: 1) { metadata { tier tags } } }`, nil)
	if tags := r.List(t, "users_by_pk.metadata.tags"); len(tags) != 3 || tags[0] != "a" || tags[1] != nil || tags[2] != "c" ||
		r.String(t, "users_by_pk.metadata.tier") != "gold" || len(r.Errors) != 1 ||
		!strings.Contains(r.Errors[0].Message, "UserMetadata.tags[1]") {
		t.Errorf("admin tags: %s", r.Raw)
	}

	// The author sees its own order the same way, never order 2 (row
	// filter), and cannot read users.metadata at all.
	r = env.GQL(t, author, `{ orders_connection { nodes { id lines { sku } } } }`, nil)
	if ids := r.IDs(t, "orders_connection.nodes"); len(ids) != 1 || ids[0] != 1 ||
		r.String(t, "orders_connection.nodes.0.lines.2.sku") != "B-2" || len(r.Errors) != 1 {
		t.Errorf("author lines: %s", r.Raw)
	}
	env.GQL(t, author, `{ users_by_pk(id: 1) { metadata { tags } } }`, nil).MustFail(t, "metadata")
}

func TestTypedJSONStartupAndReload(t *testing.T) {
	t.Parallel()
	env := New(t, WithSQL(ordersSQL...), WithExtraYAML(jsonTypesYAML), WithRolesYAML(jsonRoles))
	// json_type on a non-JSON column is rejected and the previous config
	// keeps serving.
	bad := strings.Replace(jsonTypesYAML, "      metadata: {json_type: UserMetadata}", "      name: {json_type: UserMetadata}", 1)
	if err := env.ReloadExtra(t, bad); err == nil || !strings.Contains(err.Error(), "json_type needs a JSON column") {
		t.Fatalf("reload with json_type on a varchar: %v", err)
	}
	admin := env.Token(t, "admin", 4)
	env.MustGQL(t, admin, `{ users_by_pk(id: 1) { metadata { tier } } }`, nil)
	// Without the declaration the column is the JSON scalar again.
	if err := env.ReloadExtra(t, ""); err != nil {
		t.Fatal(err)
	}
	r := env.MustGQL(t, admin, `{ users_by_pk(id: 1) { metadata } }`, nil)
	if m, ok := r.Get("users_by_pk.metadata").(map[string]any); !ok || m["tier"] != "gold" {
		t.Errorf("untyped metadata: %s", r.Raw)
	}
}

// TestDemoConfigRuntime runs the demo gqlgate.yaml's role selection (allowed
// roles from the identity table), typed users.metadata and root-field
// parallelism over the blog schema the demo seeds.
func TestDemoConfigRuntime(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "gqlgate.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	demo, err := config.Parse([]byte(strings.ReplaceAll(string(raw), "${GQLGATE_JWT_SECRET}", JWTSecret)))
	if err != nil {
		t.Fatalf("demo gqlgate.yaml: %v", err)
	}
	if demo.JWT.RoleLookup.AllowedRolesColumn == "" || demo.JSONTypes["UserMetadata"] == nil {
		t.Fatal("the demo config no longer shows allowed roles / typed JSON")
	}
	env := New(t,
		WithSQL(demoModelingSQL(t),
			`ALTER TABLE users ADD COLUMN allowed_roles VARCHAR(200) NULL`,
			`UPDATE users SET allowed_roles = '["author"]' WHERE id = 4`),
		WithConfig(func(c *config.Config) {
			c.Roles = demo.Roles
			c.SchemaGen = demo.SchemaGen
			c.Tables = demo.Tables
			c.JSONTypes = demo.JSONTypes
			c.NativeQueries = demo.NativeQueries
			c.Server.MaxParallelRootFields = demo.Server.MaxParallelRootFields
			c.JWT = demo.JWT
			// The identity table lives in the private test database, never
			// the demo's appdb.
			c.JWT.RoleLookup.Schema = c.Database.Schema
		}))
	root := env.SignClaims(t, map[string]any{"sub": 4})
	ada := env.SignClaims(t, map[string]any{"sub": 1})

	r := env.MustGQL(t, root, `{ _role users_by_pk(id: 1) { metadata { tier tags } } posts_aggregate { count } }`, nil)
	if r.String(t, "_role") != "admin" || r.String(t, "users_by_pk.metadata.tier") != "gold" || r.Int(t, "posts_aggregate.count") != 4 {
		t.Errorf("root as admin: %s", r.Raw)
	}
	r = env.Do(t, roleHeader(root, "author"), `{ _role posts_aggregate { count } }`, nil).MustOK(t)
	if r.String(t, "_role") != "author" {
		t.Errorf("root as author: %s", r.Raw)
	}
	env.Do(t, roleHeader(root, "author"), `{ users_by_pk(id: 1) { metadata { tier } } }`, nil).MustFail(t, "metadata")
	if r := env.Do(t, roleHeader(ada, "admin"), `{ _role }`, nil); r.Status != http.StatusForbidden {
		t.Errorf("ada may not act as admin: HTTP %d %s", r.Status, r.Raw)
	}
}
