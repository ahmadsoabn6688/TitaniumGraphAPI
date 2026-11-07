package config

import (
	"strings"
	"testing"
)

func TestMutationResponseSetting(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaGen.MutationResponse != MutationResponsePerTable {
		t.Errorf("mutation_response default = %q, want per_table", cfg.SchemaGen.MutationResponse)
	}
	cfg, err = Parse([]byte(minimalYAML + "schema_gen:\n  mutation_response: shared\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaGen.MutationResponse != MutationResponseShared {
		t.Errorf("mutation_response = %q, want shared", cfg.SchemaGen.MutationResponse)
	}
	if _, err := Parse([]byte(minimalYAML + "schema_gen:\n  mutation_response: object\n")); err == nil || !strings.Contains(err.Error(), "mutation_response") {
		t.Errorf("an unknown mutation_response must fail, got %v", err)
	}
}
