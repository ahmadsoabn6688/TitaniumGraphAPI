package config

import (
	"strings"
	"testing"
)

func TestWriteCheckParsed(t *testing.T) {
	yaml := strings.Replace(minimalYAML, "select: true", `select: true
        insert:
          allow: true
          check: "org_id IN (:jwt.orgs)"
        update:
          allow: true
          filter: "owner = :jwt.sub"
          check: "status <> 'archived'"`, 1)
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	tp := cfg.Roles["admin"].Tables["*"]
	if tp.Insert.Check != "org_id IN (:jwt.orgs)" || tp.Update.Check != "status <> 'archived'" {
		t.Errorf("checks not decoded: insert %+v update %+v", tp.Insert, tp.Update)
	}
}

func TestWriteCheckRejectedWhereMeaningless(t *testing.T) {
	for name, block := range map[string]string{
		"select": `select:
          allow: true
          check: "1 = 1"`,
		"delete": `select: true
        delete:
          allow: true
          check: "1 = 1"`,
		"insert filter and check": `select: true
        insert:
          allow: true
          filter: "a = 1"
          check: "b = 1"`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(strings.Replace(minimalYAML, "select: true", block, 1)))
			if err == nil || !strings.Contains(err.Error(), "check") {
				t.Errorf("got %v, want a check error", err)
			}
		})
	}
}

func TestResponseLimits(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.MaxResponseRows != 0 || cfg.Server.MaxResponseBytes != 0 {
		t.Errorf("response limits must default to unlimited, got %d rows / %d bytes", cfg.Server.MaxResponseRows, cfg.Server.MaxResponseBytes)
	}
	cfg, err = Parse([]byte(minimalYAML + "server:\n  max_response_rows: 5000\n  max_response_bytes: 1048576\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.MaxResponseRows != 5000 || cfg.Server.MaxResponseBytes != 1048576 {
		t.Errorf("limits not decoded: %+v", cfg.Server)
	}
	for _, bad := range []string{"max_response_rows: -1", "max_response_bytes: -1"} {
		if _, err := Parse([]byte(minimalYAML + "server:\n  " + bad + "\n")); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
}
