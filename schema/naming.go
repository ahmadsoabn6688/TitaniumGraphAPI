package schema

import (
	"regexp"
	"strings"
)

var invalidNameChars = regexp.MustCompile(`[^_a-zA-Z0-9]`)

// graphqlName sanitizes a SQL identifier into a valid GraphQL name
// (/[_A-Za-z][_0-9A-Za-z]*/, not starting with the reserved "__").
func graphqlName(raw string) string {
	n := invalidNameChars.ReplaceAllString(raw, "_")
	if n == "" {
		n = "_"
	}
	if n[0] >= '0' && n[0] <= '9' {
		n = "_" + n
	}
	for strings.HasPrefix(n, "__") {
		n = n[1:]
	}
	return n
}
