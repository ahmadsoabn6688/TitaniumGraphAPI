package server

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/gqlerrors"

	gqlschema "gqlgate/schema"
)

// An error returned from a deferred (batched) resolver reaches the response
// without its extensions; restoreExtensions recovers the code from the
// original error.
func TestRestoreExtensionsFromThunkErrors(t *testing.T) {
	coded := &gqlschema.CodedError{Message: "too many", Code: gqlschema.CodeResponseTooLarge}
	thunkErr := gqlerrors.FormatError(coded) // what graphql-go does with a thunk's error
	located := gqlerrors.FormatError(gqlerrors.NewLocatedError(thunkErr, nil))
	if located.Extensions != nil {
		t.Fatalf("precondition: graphql-go dropped the extensions, got %v", located.Extensions)
	}
	plain := gqlerrors.FormatError(gqlerrors.NewLocatedError(errors.New("plain"), nil))
	errs := []gqlerrors.FormattedError{located, plain}
	restoreExtensions(errs)
	if errs[0].Extensions["code"] != gqlschema.CodeResponseTooLarge {
		t.Errorf("extensions not restored: %v", errs[0].Extensions)
	}
	if errs[1].Extensions != nil {
		t.Errorf("a plain error must stay without extensions, got %v", errs[1].Extensions)
	}
}

func TestLimitResult(t *testing.T) {
	limitErr := gqlerrors.FormattedError{Message: "limit", Extensions: map[string]any{"code": gqlschema.CodeResponseTooLarge}}
	mk := func() *graphql.Result {
		return &graphql.Result{
			Data:   map[string]any{"posts": []any{1, 2, 3}},
			Errors: []gqlerrors.FormattedError{limitErr, limitErr, {Message: "other"}},
		}
	}
	r := mk()
	limitResult(r, false)
	if r.Data != nil || len(r.Errors) != 2 {
		t.Errorf("a query over the limit returns no data and one limit error, got %v %v", r.Data, r.Errors)
	}
	r = mk()
	limitResult(r, true)
	if r.Data == nil {
		t.Error("a committed mutation's partial result must be kept")
	}
}

func TestTooLargeBody(t *testing.T) {
	var resp struct {
		Data   any `json:"data"`
		Errors []struct {
			Message    string         `json:"message"`
			Extensions map[string]any `json:"extensions"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(tooLargeBody(5000, 100, true), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data != nil || len(resp.Errors) != 1 || resp.Errors[0].Extensions["code"] != gqlschema.CodeResponseTooLarge {
		t.Fatalf("unexpected body %+v", resp)
	}
	if msg := resp.Errors[0].Message; !strings.Contains(msg, "max_response_bytes") || !strings.Contains(msg, "applied") {
		t.Errorf("message %q must name the limit and say the mutation was applied", msg)
	}
}
