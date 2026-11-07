package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestCompileNativeSQL(t *testing.T) {
	ok := []struct {
		sql    string
		params []string
		render string
	}{
		{"SELECT id FROM posts WHERE author_id = :author", []string{"author"}, "SELECT id FROM posts WHERE author_id = ?"},
		{"  select a from t where a = :x or b = :x;  \n", []string{"x", "x"}, "  select a from t where a = ? or b = ?"},
		{"WITH c AS (SELECT 1 AS n) SELECT n FROM c WHERE n > :min", []string{"min"}, "WITH c AS (SELECT 1 AS n) SELECT n FROM c WHERE n > ?"},
		{"(SELECT 1 AS a)", nil, "(SELECT 1 AS a)"},
		// Quoted text, quoted identifiers and comments are never parameters.
		{"SELECT ':no', \"?\", `a:b` FROM t WHERE x = :yes", []string{"yes"}, "SELECT ':no', \"?\", `a:b` FROM t WHERE x = ?"},
		{"SELECT 'it''s :no' AS s, 'a\\':no' AS e FROM t", nil, "SELECT 'it''s :no' AS s, 'a\\':no' AS e FROM t"},
		{"SELECT a -- comment :no ?\nFROM t # other :no\nWHERE b = :p /* :no ? */", []string{"p"}, "SELECT a  \nFROM t  \nWHERE b = ?  "},
		// A trailing line comment never swallows what follows the statement.
		{"SELECT a FROM t -- trailing", nil, "SELECT a FROM t  "},
		// Qualified names and function forms of denied words are fine.
		{"SELECT t.update, INSERT('abc', 1, 1, 'x'), REPLACE (a, 'b', 'c') FROM t", nil, "SELECT t.update, INSERT('abc', 1, 1, 'x'), REPLACE (a, 'b', 'c') FROM t"},
		{"SELECT a-1--1 AS x FROM t", nil, "SELECT a-1--1 AS x FROM t"},
		// Optimizer hints reach TiDB verbatim; a ':' inside one is not a
		// parameter. TiDB's /*T! … */ executable comments are removed.
		{"SELECT /*+ USE_INDEX(posts, ia) MAX_EXECUTION_TIME(10) */ id FROM posts WHERE a = :p", []string{"p"},
			"SELECT /*+ USE_INDEX(posts, ia) MAX_EXECUTION_TIME(10) */ id FROM posts WHERE a = ?"},
		{"SELECT /*+ READ_FROM_STORAGE(TIFLASH[t]) X(a:b) */ id FROM t", nil, "SELECT /*+ READ_FROM_STORAGE(TIFLASH[t]) X(a:b) */ id FROM t"},
		{"SELECT /*T! , SLEEP(1) */ id FROM t", nil, "SELECT   id FROM t"},
	}
	for _, c := range ok {
		n, err := CompileNativeSQL(c.sql)
		if err != nil {
			t.Errorf("CompileNativeSQL(%q): %v", c.sql, err)
			continue
		}
		if !reflect.DeepEqual(n.Params, c.params) {
			t.Errorf("CompileNativeSQL(%q).Params = %v, want %v", c.sql, n.Params, c.params)
		}
		vals := map[string]any{}
		for _, p := range c.params {
			vals[p] = p + "-value"
		}
		got, args := n.Render(vals)
		if got != c.render {
			t.Errorf("Render(%q) = %q, want %q", c.sql, got, c.render)
		}
		if len(args) != len(c.params) {
			t.Errorf("Render(%q) args = %v", c.sql, args)
		}
	}

	bad := []struct{ sql, want string }{
		{"", "empty"},
		{"DELETE FROM posts", "only SELECT"},
		{"UPDATE posts SET a = 1", "only SELECT"},
		{"SHOW TABLES", "only SELECT"},
		{"'x' SELECT 1", "only SELECT"},
		{"WITH x AS (SELECT 1) DELETE FROM posts", "DELETE is not allowed"},
		{"WITH x AS (SELECT 1) UPDATE posts SET a = 1", "UPDATE is not allowed"},
		{"SELECT 1; DROP TABLE posts", "only one statement"},
		{"SELECT 1;;", "only one statement"},
		{"SELECT * FROM posts FOR UPDATE", "UPDATE is not allowed"},
		{"SELECT * FROM posts FOR SHARE", "SHARE is not allowed"},
		{"SELECT * FROM posts LOCK IN SHARE MODE", "LOCK is not allowed"},
		{"SELECT id INTO @x FROM posts", "INTO is not allowed"},
		{"SELECT id FROM posts INTO OUTFILE '/tmp/x'", "INTO is not allowed"},
		{"SELECT @x := 1", ":= assignments"},
		{"SELECT id FROM posts WHERE id = ?", "literal ?"},
		{"SELECT id FROM posts WHERE a = :jwt.sub", "claims are not referenced"},
		{"SELECT id FROM posts WHERE a = :1", "parameter name"},
		{"SELECT 'unterminated FROM t", "unterminated"},
		{"SELECT 1 /* open", "unterminated /*"},
		{"SELECT 1 /*!50000 , SLEEP(1) */", "executable comments"},
		{"SELECT /*+ X(?) */ 1", "optimizer hints"},
		{"SELECT /*+ X(); */ 1", "optimizer hints"},
		{"SELECT /*+ USE_INDEX(t, a) 1", "unterminated /*"},
	}
	for _, c := range bad {
		_, err := CompileNativeSQL(c.sql)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("CompileNativeSQL(%q) = %v, want an error containing %q", c.sql, err, c.want)
		}
	}
}

func TestParseNativeQueries(t *testing.T) {
	yaml := minimalYAML + `    native_queries:
      stats:
        allow: true
        columns: [post_id, views]
        filter: "author_id = :jwt.sub"
        presets: {author: ":jwt.sub"}
native_queries:
  stats:
    sql: "SELECT id AS post_id, author_id, views FROM posts WHERE author_id = :author AND views > :min"
    arguments:
      author: BigInt!
      min: {type: Int, description: "View floor"}
    columns:
      views: Int!
      post_id: {name: postId, description: "The post"}
    key: [post_id]
    type_name: PostStat
    root_fields:
      list: {name: postStats, description: "Stats"}
      connection: postStatsPage
    relationships:
      author: {type: object, target: users, mapping: {author_id: id}}
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	nq := cfg.NativeQueries["stats"]
	if nq.Arguments["author"].Type != "BigInt!" || nq.Arguments["min"].Description != "View floor" {
		t.Errorf("arguments = %+v", nq.Arguments)
	}
	if nq.Columns["views"].Type != "Int!" || nq.Columns["post_id"].Name != "postId" {
		t.Errorf("columns = %+v", nq.Columns)
	}
	if nq.RootFields.List.Name != "postStats" || nq.RootFields.Connection.Name != "postStatsPage" {
		t.Errorf("root fields = %+v", nq.RootFields)
	}
	perm := cfg.Roles["admin"].NativeQueries["stats"]
	if perm == nil || !perm.Allow || perm.Presets["author"] != ":jwt.sub" {
		t.Errorf("grant = %+v", perm)
	}
	found := false
	for _, n := range cfg.NamedTables() {
		found = found || n == "users"
	}
	if !found {
		t.Errorf("NamedTables() = %v, missing the relationship target users", cfg.NamedTables())
	}
	if s, nn := ParseScalarType(" BigInt! "); s != "BigInt" || !nn {
		t.Errorf("ParseScalarType = %q %v", s, nn)
	}
}

func TestNativeQueryValidation(t *testing.T) {
	base := minimalYAML + `native_queries:
  q:
    sql: "SELECT id FROM posts WHERE author_id = :a"
    arguments: {a: BigInt!}
`
	cases := []struct{ extra, want string }{
		{"    columns: {id: Nope}\n", "not a known scalar"},
		{"    columns: {id: {name: _and}}\n", "logical operator"},
		{"    columns: {id: {name: \"bad name\"}}\n", "not a valid GraphQL name"},
		{"    key: [id, id]\n", "listed twice"},
		{"    type_name: \"1x\"\n", "type_name"},
		{"    root_fields: {connection: page}\n", "a connection needs key"},
		{"    root_fields: {list: {name: \"a-b\"}}\n", "not a valid GraphQL name"},
		{"    relationships: {r: {foreign_key: fk_x}}\n", "foreign_key does not apply"},
		{"    relationships: {r: {type: object, target: users}}\n", "needs target and mapping"},
		{"    relationships: {_or: {type: object, target: users, mapping: {id: id}}}\n", "not a usable relationship field name"},
	}
	for _, c := range cases {
		_, err := Parse([]byte(base + c.extra))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: err = %v, want %q", c.extra, err, c.want)
		}
	}

	other := []struct{ yaml, want string }{
		{minimalYAML + "native_queries:\n  q:\n    sql: \"DELETE FROM posts\"\n", "native_queries.q.sql: only SELECT"},
		{minimalYAML + "native_queries:\n  q:\n    sql: \"SELECT :a AS x\"\n", "parameter :a is not declared"},
		{minimalYAML + "native_queries:\n  q:\n    sql: \"SELECT 1 AS x\"\n    arguments: {a: Int}\n", "not used in the sql"},
		{minimalYAML + "native_queries:\n  q:\n    sql: \"SELECT :a AS x\"\n    arguments: {a: JSON}\n", "is not supported"},
		{minimalYAML + "native_queries:\n  q:\n    sql: \"SELECT :a AS x\"\n    arguments: {a: \"[Int]\"}\n", "is not supported"},
		{minimalYAML + "native_queries:\n  q:\n    sql: \"SELECT :jwt AS x\"\n    arguments: {jwt: Int}\n", "reserved"},
		{minimalYAML + "native_queries:\n  q:\n    sql: \"SELECT 1 AS x\"\n    arguments: {a: {description: x}}\n", "type is required"},
		{minimalYAML + "native_queries:\n  \"bad-name\":\n    sql: \"SELECT 1 AS x\"\n", "not a valid GraphQL name"},
		{minimalYAML + "native_queries:\n  q:\n    sql: \"SELECT 1 AS x\"\n    bogus: 1\n", "bogus"},
		{minimalYAML + "    native_queries: {missing: true}\n", "no such entry under native_queries"},
		{minimalYAML + "    native_queries: {q: {allow: true, check: \"x = 1\"}}\nnative_queries:\n  q: {sql: \"SELECT 1 AS x\"}\n", "check applies to table writes only"},
		{minimalYAML + "    native_queries: {q: {allow: true, presets: {x: \"1\"}}}\nnative_queries:\n  q: {sql: \"SELECT 1 AS x\"}\n", "not a declared argument"},
		{minimalYAML + "    native_queries: {q: {allow: true, presets: {a: \":jwt.bad path\"}}}\nnative_queries:\n  q: {sql: \"SELECT :a AS x\", arguments: {a: Int}}\n", "invalid claim path"},
		{minimalYAML + "    native_queries: {q: {allow: true, filter_operators: [eq]}}\nnative_queries:\n  q: {sql: \"SELECT 1 AS x\"}\n", "not an operator name"},
	}
	for _, c := range other {
		_, err := Parse([]byte(c.yaml))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("err = %v, want %q\n%s", err, c.want, c.yaml)
		}
	}
}
