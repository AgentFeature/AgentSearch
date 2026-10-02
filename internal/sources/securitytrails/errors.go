package securitytrails

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Error contains classifications only, never credentials, URLs or remote text.
// Kind names follow the existing normalized error_metadata convention.
type Error struct {
	Kind       string
	StatusCode int
	RetryAfter time.Duration
}

func (e *Error) Error() string { return "SecurityTrails lookup failed (" + safeKind(e.Kind) + ")" }
func safeKind(kind string) string {
	switch kind {
	case "missing_api_key", "unauthorized", "forbidden", "rate_limited", "bad_request", "service_unavailable", "timeout", "cancelled", "network_failure", "invalid_response", "unexpected_status":
		return kind
	}
	return "unexpected_status"
}
func (e *Error) Unwrap() error {
	switch e.Kind {
	case "cancelled":
		return context.Canceled
	case "timeout":
		return context.DeadlineExceeded
	}
	return nil
}
func requestError(ctx context.Context, err error) *Error {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return &Error{Kind: "cancelled"}
	}
	var timed net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timed) && timed.Timeout()) {
		return &Error{Kind: "timeout"}
	}
	return &Error{Kind: "network_failure"}
}
func statusError(code int, header string) *Error {
	e := &Error{Kind: "unexpected_status", StatusCode: code}
	switch {
	case code == 400:
		e.Kind = "bad_request"
	case code == 401:
		e.Kind = "unauthorized"
	case code == 403:
		e.Kind = "forbidden"
	case code == 429:
		e.Kind = "rate_limited"
	case code >= 500:
		e.Kind = "service_unavailable"
	}
	if code == 429 || code == 503 {
		if seconds, err := strconv.ParseInt(header, 10, 64); err == nil && seconds >= 0 && seconds <= int64((1<<63-1)/time.Second) {
			e.RetryAfter = time.Duration(seconds) * time.Second
		} else if when, err := http.ParseTime(header); err == nil && when.After(time.Now()) {
			e.RetryAfter = time.Until(when)
		}
	}
	if code == 429 && e.RetryAfter < time.Second {
		e.RetryAfter = time.Second
	}
	return e
}
func errorMetadata(err error) map[string]string {
	fields := map[string]string{"error_kind": "network_failure"}
	var e *Error
	if errors.As(err, &e) {
		fields["error_kind"] = safeKind(e.Kind)
		if e.StatusCode != 0 {
			fields["http_status"] = strconv.Itoa(e.StatusCode)
		}
		if e.RetryAfter > 0 {
			fields["retry_after_seconds"] = strconv.FormatInt(int64((e.RetryAfter-1)/time.Second)+1, 10)
		}
	}
	return fields
}
