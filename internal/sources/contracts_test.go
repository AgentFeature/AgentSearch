package sources

import (
	"context"
	"errors"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/models"
)

type contractFailure struct{ cause error }

func (*contractFailure) Error() string   { return "lookup failed" }
func (e *contractFailure) Unwrap() error { return e.cause }

type failingContractSource struct{ err error }

func (failingContractSource) Name() string            { return "first" }
func (failingContractSource) Type() models.SourceType { return models.SourceAPI }
func (s failingContractSource) SearchUsername(_ context.Context, _ string, emit Emit) error {
	if e := emit(models.Result{Status: models.StatusFound, Confidence: 100}); e != nil {
		return e
	}
	return s.err
}
func TestProviderContextIdentityAndPartialResults(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		registry := NewRegistry()
		original := &contractFailure{cause: cause}
		if err := registry.Register(failingContractSource{err: original}); err != nil {
			t.Fatal(err)
		}
		if err := registry.Register(&usernameSource{name: "second"}); err != nil {
			t.Fatal(err)
		}
		target, _ := models.NewTarget(models.TargetUsername, "example")
		var rows []models.Result
		err := NewManager(registry).Search(context.Background(), target, func(r models.Result) error { rows = append(rows, r); return nil })
		if !errors.Is(err, cause) {
			t.Fatal("standard context identity discarded")
		}
		var retained *contractFailure
		if errors.As(err, &retained) {
			t.Fatal("original provider error retained")
		}
		if err.Error() != "source first: lookup failed" {
			t.Fatal("safe error message changed")
		}
		if len(rows) != 2 || rows[0].Source != "first" || rows[1].Source != "second" || !rows[0].Found || rows[0].Confidence != 100 || rows[0].Target != "example" {
			t.Fatal("partial normalized results/order changed")
		}
	}
}
