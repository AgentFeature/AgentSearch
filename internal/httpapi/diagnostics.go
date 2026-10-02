package httpapi

import (
	"context"
	"net/http"

	"github.com/AgentFeature/agentsearch/internal/diagnostics"
)

func diagnosticMethod(method string) string {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
		return method
	}
	return "OTHER"
}
func (w *writer) diagnosticOutcome(ctx context.Context) diagnostics.Outcome {
	if w.status < 400 {
		return w.summary.Finish(ctx, nil)
	}
	switch w.errorCode {
	case "internal_error":
		return diagnostics.Failure("internal_error")
	case "too_many_requests", "request_too_large", "result_limit":
		return diagnostics.Outcome{Outcome: "rejected", Category: "resource_limit"}
	case "unauthorized":
		return diagnostics.Outcome{Outcome: "rejected", Category: "authentication"}
	case "invalid_request", "method_not_allowed", "not_found", "unsupported_media_type":
		return diagnostics.Outcome{Outcome: "rejected", Category: "invalid_request"}
	case "cancelled":
		return diagnostics.Failure(diagnostics.ErrorCategory(ctx.Err(), "canceled"))
	case "timeout", "request_timeout":
		return diagnostics.Failure("deadline_exceeded")
	case "rate_limited":
		return diagnostics.Failure("rate_limited")
	}
	// Provider rows may distinguish authentication from generic public 503s.
	if outcome := w.summary.Finish(ctx, nil); outcome.Category != "none" {
		return outcome
	}
	if w.status >= http.StatusInternalServerError {
		return diagnostics.Failure("provider_error")
	}
	return diagnostics.Outcome{Outcome: "rejected", Category: "invalid_request"}
}
