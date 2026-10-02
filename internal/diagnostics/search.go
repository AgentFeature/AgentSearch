// Package diagnostics projects search state into bounded slog fields, not results.
package diagnostics

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
)

type loggerKey struct{}

func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}
func Logger(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}
func Target(kind models.TargetType) string {
	switch kind {
	case models.TargetBitcoinTransaction, models.TargetBitcoin, models.TargetIP, models.TargetUsername, models.TargetEmail, models.TargetDomain, models.TargetPassword, models.TargetPasswordHash:
		return string(kind)
	}
	return "unknown"
}

// Never truncate arbitrary identifiers: a short identifier can itself be a key.
func Source(name string) string {
	switch name {
	case "bitcoin-tx", "bitcoin-labels", "bitcoin", "ipinfo", "websites", "hibp", "pwned-passwords", "pwned-passwords-local", "securitytrails":
		return name
	}
	return "other"
}
func ErrorCategory(err error, fallback string) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return fallback
}
func Category(kind string) string {
	switch kind {
	case "timeout", "request_timeout", "deadline_exceeded":
		return "deadline_exceeded"
	case "cancelled", "canceled":
		return "canceled"
	case "missing_api_key", "unauthorized", "forbidden":
		return "authentication"
	case "rate_limited":
		return "rate_limited"
	case "bad_request", "invalid_request":
		return "invalid_request"
	default:
		return "provider_error"
	}
}

type Outcome struct{ Outcome, Category string }

// Summary retains only booleans/categories, never a result, target or error text.
// It observes serial Emit calls without changing output or error propagation.
type Summary struct {
	found, absent, blocked, unclassified bool
	category                             string
}

func (s *Summary) Observe(r models.Result) {
	status := r.Status
	if status == "" {
		if r.Error != "" {
			status = models.StatusError
		} else if r.Found {
			status = models.StatusFound
		} else {
			status = models.StatusNotFound
		}
	}
	switch status {
	case models.StatusFound:
		s.found = true
	case models.StatusNotFound:
		s.absent = true
	case models.StatusBlocked:
		s.blocked = true
	case models.StatusError:
		category := Category(r.Metadata["error_kind"])
		if priority(category) > priority(s.category) {
			s.category = category
		}
	default:
		s.unclassified = true
	}
}
func priority(category string) int {
	switch category {
	case "deadline_exceeded":
		return 6
	case "canceled":
		return 5
	case "authentication":
		return 4
	case "rate_limited":
		return 3
	case "invalid_request":
		return 2
	case "provider_error":
		return 1
	}
	return 0
}
func Failure(category string) Outcome {
	outcome := "error"
	if category == "canceled" || category == "deadline_exceeded" {
		outcome = category
	}
	return Outcome{outcome, category}
}
func (s Summary) Finish(ctx context.Context, err error) Outcome {
	category := ErrorCategory(ctx.Err(), ErrorCategory(err, s.category))
	if category != "" {
		return Failure(category)
	}
	if err != nil {
		return Failure("provider_error")
	}
	if s.found {
		return Outcome{"success", "none"}
	}
	if s.blocked {
		return Outcome{"blocked", "none"}
	}
	if s.absent && !s.unclassified {
		return Outcome{"not_found", "none"}
	}
	return Outcome{"success", "none"} // No observations is not verified absence.
}
func Started(ctx context.Context, operation string, kind models.TargetType, source string) {
	Logger(ctx).DebugContext(ctx, "search started", "operation", operation, "target_type", Target(kind), "source", Source(source), "outcome", "started")
}
func Completed(ctx context.Context, operation string, kind models.TargetType, source string, start time.Time, outcome Outcome) {
	Logger(ctx).InfoContext(ctx, "search completed", "operation", operation, "target_type", Target(kind), "source", Source(source), "duration_ms", time.Since(start).Milliseconds(), "outcome", outcome.Outcome, "error_category", outcome.Category)
}
