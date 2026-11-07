package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseTablesSection(t *testing.T) {
	yaml := minimalYAML + `
tables:
  post_stats:
    primary_key: [post_id]
    type_name: PostStats
    root_fields:
      connection: postStatsPage
      by_pk: {name: postStats, description: "One", deprecated: "old"}
    columns:
      comment_count: commentCount
      author_id: {description: "Author", deprecated: "use post"}
    relationships:
      post: {type: object, target: posts, mapping: {post_id: id}}
  posts:
    relationships:
      writer: {foreign_key: fk_posts_author}
schema_gen:
  descriptions_from_comments: true
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	ps := cfg.Tables["post_stats"]
	if ps.TypeName != "PostStats" || !reflect.DeepEqual(ps.PrimaryKey, []string{"post_id"}) {
		t.Errorf("post_stats = %+v", ps)
	}
	if ps.RootFields.Connection.Name != "postStatsPage" || ps.RootFields.ByPK.Deprecated != "old" || ps.RootFields.ByKind(RootByPK).Description != "One" {
		t.Errorf("root fields = %+v", ps.RootFields)
	}
	if ps.Columns["comment_count"].Name != "commentCount" || ps.Columns["author_id"].Deprecated != "use post" {
		t.Errorf("columns = %+v", ps.Columns)
	}
	l, r := ps.Relationships["post"].MappingColumns()
	if !reflect.DeepEqual(l, []string{"post_id"}) || !reflect.DeepEqual(r, []string{"id"}) {
		t.Errorf("mapping = %v -> %v", l, r)
	}
	if !cfg.SchemaGen.DescriptionsFromComments {
		t.Error("descriptions_from_comments not parsed")
	}
	named := cfg.NamedTables()
	for _, want := range []string{"post_stats", "posts"} {
		found := false
		for _, n := range named {
			found = found || n == want
		}
		if !found {
			t.Errorf("NamedTables() = %v, missing %s", named, want)
		}
	}
}

func TestTablesSectionValidation(t *testing.T) {
	for _, tc := range []struct{ name, block, want string }{
		{"bad type name", "  t:\n    type_name: \"1x\"\n", "type_name"},
		{"reserved type name", "  t:\n    type_name: __X\n", "type_name"},
		{"bad root name", "  t:\n    root_fields:\n      by_pk: \"a-b\"\n", "root_fields.by_pk"},
		{"bad column name", "  t:\n    columns:\n      c: \"x y\"\n", "columns.c"},
		{"dup pk column", "  t:\n    primary_key: [a, a]\n", "primary_key"},
		{"bad rel name", "  t:\n    relationships:\n      _and: {foreign_key: f}\n", "relationship field name"},
		{"bad rel type", "  t:\n    relationships:\n      r: {type: many, target: u, mapping: {a: b}}\n", "object or array"},
		{"missing type", "  t:\n    relationships:\n      r: {target: u, mapping: {a: b}}\n", "type is required"},
		{"missing mapping", "  t:\n    relationships:\n      r: {type: array, target: u}\n", "target and mapping"},
		{"fk plus target", "  t:\n    relationships:\n      r: {foreign_key: f, target: u}\n", "cannot also have"},
		{"target mapped twice", "  t:\n    relationships:\n      r: {type: array, target: u, mapping: {a: x, b: x}}\n", "mapped twice"},
		{"unknown key", "  t:\n    nope: 1\n", "nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(minimalYAML + "tables:\n" + tc.block))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
