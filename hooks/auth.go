// Custom auth for the sample blog schema: two mutations, signup and signin,
// exposed to the anonymous role. Both hash/verify passwords with bcrypt (a
// third-party library — fine here because hooks/ files are compiled into the
// binary) and return a signed JWT that the gateway then verifies. The token's
// `sub` claim is the user id; the role is read from the users table by
// jwt.role_lookup (see gqlgate.yaml), so no role is baked into the token.
//
// Activate: this file is already in hooks/, so `docker compose up --build`
// compiles it in. Then, unauthenticated, call:
//
//	mutation { signup(username:"alice", password:"password123") }   # -> JWT
//	mutation { signin(username:"alice", password:"password123") }   # -> JWT
//
// Put the returned token in the Authorization header (Bearer <token>) for
// subsequent requests.
package hooks

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/graphql-go/graphql"
	"golang.org/x/crypto/bcrypt"

	"gqlgate"
	"gqlgate/register"
)

func init() {
	// signup — create an account, return a token for the new user.
	register.CustomField(register.CustomFieldDef{
		Name:         "signup",
		Operation:    "mutation",
		AllowedRoles: []string{"anonymous"}, // only unauthenticated callers see it
		Field: &graphql.Field{
			Type:        graphql.NewNonNull(graphql.String),
			Description: "Create an account and return a signed JWT.",
			Args: graphql.FieldConfigArgument{
				"username": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"password": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"name":     &graphql.ArgumentConfig{Type: graphql.String},
				"email":    &graphql.ArgumentConfig{Type: graphql.String},
			},
			Resolve: signupResolver,
		},
	})

	// signin — verify credentials, return a token.
	register.CustomField(register.CustomFieldDef{
		Name:         "signin",
		Operation:    "mutation",
		AllowedRoles: []string{"anonymous"},
		Field: &graphql.Field{
			Type:        graphql.NewNonNull(graphql.String),
			Description: "Verify username/password and return a signed JWT.",
			Args: graphql.FieldConfigArgument{
				"username": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				"password": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
			},
			Resolve: signinResolver,
		},
	})
}

func signupResolver(p graphql.ResolveParams) (any, error) {
	username, _ := p.Args["username"].(string)
	password, _ := p.Args["password"].(string)
	name, _ := p.Args["name"].(string)
	email, _ := p.Args["email"].(string)

	if len(username) < 3 || len(password) < 8 {
		return nil, errors.New("username must be at least 3 characters and password at least 8")
	}
	if name == "" {
		name = username
	}
	if email == "" {
		email = username + "@example.com"
	}

	gate := gqlgate.FromContext(p.Context)
	if gate == nil {
		return nil, errors.New("gateway unavailable")
	}

	// Hash the password with bcrypt — never store it in plain text.
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// New users get the 'author' role; provision admins out of band.
	res, err := gate.DB().ExecContext(p.Context,
		"INSERT INTO users (username, password, role, name, email) VALUES (?, ?, 'author', ?, ?)",
		username, string(hash), name, email)
	if err != nil {
		// A UNIQUE-constraint violation lands here; don't echo the raw error.
		return nil, fmt.Errorf("could not create account (username or email may already be taken)")
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	// Issue the same kind of token the gateway verifies (iat/exp filled in).
	return gate.SignToken(map[string]any{"sub": id})
}

func signinResolver(p graphql.ResolveParams) (any, error) {
	username, _ := p.Args["username"].(string)
	password, _ := p.Args["password"].(string)

	gate := gqlgate.FromContext(p.Context)
	if gate == nil {
		return nil, errors.New("gateway unavailable")
	}

	var (
		id     int64
		hash   string
		active int
	)
	err := gate.DB().QueryRowContext(p.Context,
		"SELECT id, password, is_active FROM users WHERE username = ?", username).
		Scan(&id, &hash, &active)
	if errors.Is(err, sql.ErrNoRows) {
		// Same message whether the user is missing or the password is wrong,
		// so we don't reveal which usernames exist.
		return nil, errors.New("invalid username or password")
	}
	if err != nil {
		return nil, err
	}
	if active == 0 {
		return nil, errors.New("account is disabled")
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return nil, errors.New("invalid username or password")
	}

	return gate.SignToken(map[string]any{"sub": id})
}
