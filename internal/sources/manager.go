package sources

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/AgentFeature/agentsearch/internal/diagnostics"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

var ErrUnsupportedTarget = errors.New("no source supports target type")

type Manager struct{ registry *Registry }

func NewManager(registry *Registry) *Manager { return &Manager{registry: registry} }

// Search dispatches only supported operations from an ordered registry snapshot.
// Sensitive and single-source searches remain synchronous. Independent sources
// may overlap without invoking the result consumer concurrently.
// Provider errors do not discard partial results or prevent subsequent providers.
func (m *Manager) Search(ctx context.Context, target models.Target, emit Emit) error {
	if !target.Valid() {
		return fmt.Errorf("invalid target")
	}
	if target.Type().Sensitive() {
		defer target.Secret().Destroy()
	}
	if emit == nil {
		return fmt.Errorf("nil result consumer")
	}
	if m.registry == nil {
		return ErrUnsupportedTarget
	}
	snapshot := m.registry.All()
	if !target.Type().Sensitive() {
		var selected []Source
		for _, source := range snapshot {
			if err := ctx.Err(); err != nil {
				return err
			}
			if Supports(source, target.Type()) {
				selected = append(selected, source)
			}
		}
		if len(selected) > 1 {
			return searchParallel(ctx, target, selected, emit)
		}
	}
	return searchSequential(ctx, target, snapshot, emit)
}

func searchSequential(ctx context.Context, target models.Target, snapshot []Source, emit Emit) error {
	var failures []error
	supported := false
	for _, s := range snapshot {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if !Supports(s, target.Type()) {
			continue
		}
		supported = true
		failure, consumerErr := invoke(ctx, target, s, emit)
		if consumerErr != nil {
			return consumerErr
		}
		if failure != nil {
			failures = append(failures, failure)
		}
	}
	if !supported {
		return ErrUnsupportedTarget
	}
	if err := ctx.Err(); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

// invoke preserves normalization, source diagnostics and sanitized error identity
// for both execution paths. Consumer errors remain distinct from provider errors.
func invoke(ctx context.Context, target models.Target, s Source, emit Emit) (error, error) {
	sourceStart := time.Now()
	var summary diagnostics.Summary
	diagnostics.Started(ctx, "source_search", target.Type(), s.Name())
	var consumerErr error
	deliver := func(r models.Result) error {
		if consumerErr != nil {
			return consumerErr
		}
		if r.Source == "" {
			r.Source = s.Name()
		}
		r.SourceType = s.Type()
		r.Target = target.String()
		r.TargetType = target.Type()
		if target.Type().Sensitive() {
			r = r.Redacted(target.Value())
		}
		summary.Observe(r)
		consumerErr = emit(r.Normalized())
		return consumerErr
	}
	var err error
	func() {
		completed := false
		defer func() {
			outcome := summary.Finish(ctx, err)
			if consumerErr != nil {
				outcome = diagnostics.Failure(diagnostics.ErrorCategory(consumerErr, "internal_error"))
			}
			if !completed {
				outcome = diagnostics.Failure("internal_error")
			}
			diagnostics.Completed(ctx, "source_search", target.Type(), s.Name(), sourceStart, outcome)
		}()
		switch target.Type() {
		case models.TargetBitcoinTransaction:
			err = s.(BitcoinTransactionSearcher).SearchBitcoinTransaction(ctx, target.Value(), deliver)
		case models.TargetBitcoin:
			err = s.(BitcoinSearcher).SearchBitcoin(ctx, target.Value(), deliver)
		case models.TargetIP:
			err = s.(IPSearcher).SearchIP(ctx, target.Value(), deliver)
		case models.TargetDomain:
			err = s.(DomainSearcher).SearchDomain(ctx, target.Value(), deliver)
		case models.TargetUsername:
			err = s.(UsernameSearcher).SearchUsername(ctx, target.Value(), deliver)
		case models.TargetEmail:
			err = s.(EmailSearcher).SearchEmail(ctx, target.Value(), deliver)
		case models.TargetPassword:
			err = s.(PasswordSearcher).SearchPassword(ctx, target.Secret(), deliver)
		case models.TargetPasswordHash:
			err = s.(PasswordHashSearcher).SearchPasswordHash(ctx, target.Secret(), deliver)
		}
		completed = true
	}()

	if consumerErr != nil {
		return nil, consumerErr
	}
	if err != nil {
		// Do not retain a provider error containing sensitive input downstream.
		message := security.Redact(err.Error())
		if target.Type().Sensitive() {
			message = security.Redact(message, target.Value())
		}
		failure := &sourceFailure{message: fmt.Sprintf("source %s: %s", s.Name(), message)}
		// Preserve standard cancellation semantics without retaining the original
		// provider error chain, which may contain request data or credentials.
		if errors.Is(err, context.Canceled) {
			failure.contextErr = context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			failure.contextErr = errors.Join(failure.contextErr, context.DeadlineExceeded)
		}
		return failure, nil
	}
	return nil, nil
}

// sourceFailure retains the existing safe message and only context sentinels.
// Provider-specific details continue to travel in normalized error metadata.
type sourceFailure struct {
	message    string
	contextErr error
}

func (e *sourceFailure) Error() string { return e.message }
func (e *sourceFailure) Unwrap() error { return e.contextErr }
