package schema

import "testing"

func TestGraphQLName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"users", "users"},
		{"user-events", "user_events"},
		{"2fa_codes", "_2fa_codes"},
		{"weird name!", "weird_name_"},
		{"__meta", "_meta"},
		{"", "_"},
	}
	for _, tc := range tests {
		if got := graphqlName(tc.in); got != tc.want {
			t.Errorf("graphqlName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
