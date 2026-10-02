package hibp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"
)

// ErrorKind is provider-specific detail, not a new global result status.
type ErrorKind string

const (
	MissingKey       ErrorKind = "missing_api_key"
	Unauthorized     ErrorKind = "unauthorized"
	Forbidden        ErrorKind = "forbidden"
	RateLimited      ErrorKind = "rate_limited"
	BadRequest       ErrorKind = "bad_request"
	Unavailable      ErrorKind = "service_unavailable"
	Timeout          ErrorKind = "timeout"
	NetworkFailure   ErrorKind = "network_failure"
	Cancelled        ErrorKind = "cancelled"
	InvalidResponse  ErrorKind = "invalid_response"
	UnexpectedStatus ErrorKind = "unexpected_status"
)

// Error contains only safe classifications. Raw transport errors, request URLs,
// response bodies and credentials are deliberately not retained.
type Error struct {
	Kind       ErrorKind
	StatusCode int
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	switch e.Kind {
	case MissingKey:
		return "HIBP email lookup requires an API key from the configured environment variable"
	case Unauthorized:
		return "HIBP denied authorization for this request"
	case Forbidden:
		return "HIBP denied access to this request"
	case RateLimited:
		return "HIBP request was rate limited"
	case BadRequest:
		return "HIBP rejected the request; check the input"
	case Unavailable:
		return "HIBP service is unavailable"
	case Timeout:
		return "HIBP request timed out"
	case NetworkFailure:
		return "HIBP request failed due to a network or response-read error"
	case Cancelled:
		return "HIBP request was cancelled"
	case InvalidResponse:
		return "HIBP returned an invalid or oversized response"
	default:
		return "HIBP returned an unexpected HTTP status"
	}
}

// Only standard context errors are exposed through the error chain.
func (e *Error) Unwrap() error {
	switch e.Kind {
	case Cancelled:
		return context.Canceled
	case Timeout:
		return context.DeadlineExceeded
	}
	return nil
}
func requestError(ctx context.Context, err error) *Error {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return &Error{Kind: Cancelled}
	}
	var networkError net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
		return &Error{Kind: Timeout}
	}
	return &Error{Kind: NetworkFailure}
}
func statusError(code int, retryAfter string) *Error {
	e := &Error{Kind: UnexpectedStatus, StatusCode: code}
	switch {
	case code == http.StatusBadRequest:
		e.Kind = BadRequest
	case code == http.StatusUnauthorized:
		e.Kind = Unauthorized
	case code == http.StatusForbidden:
		e.Kind = Forbidden
	case code == http.StatusTooManyRequests:
		e.Kind = RateLimited
	case code >= 500:
		e.Kind = Unavailable
	}
	if code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable {
		e.RetryAfter = parseRetryAfter(retryAfter, time.Now())
	}
	return e
}
func parseRetryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds >= 0 && seconds <= int64((1<<63-1)/time.Second) {
			return time.Duration(seconds) * time.Second
		}
		return 0
	}
	if when, err := http.ParseTime(value); err == nil && when.After(now) {
		return when.Sub(now)
	}
	return 0
}

// errorMetadata exports only allowlisted classifications, not remote headers.
func errorMetadata(err error) map[string]string {
	metadata := make(map[string]string)
	var apiErr *Error
	if errors.As(err, &apiErr) {
		metadata["error_kind"] = string(apiErr.Kind)
		if apiErr.StatusCode != 0 {
			metadata["http_status"] = strconv.Itoa(apiErr.StatusCode)
		}
		if apiErr.RetryAfter > 0 {
			metadata["retry_after_seconds"] = strconv.FormatInt(int64((apiErr.RetryAfter-1)/time.Second)+1, 10)
		}
	}
	return metadata
}
