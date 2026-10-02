package network

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

// NewRetryableClient wraps an HTTP client with retryablehttp.
// It retries eligible failures:
//   - 429 Too Many Requests
//   - 5xx Server Errors
//   - network timeouts
//   - connection errors
//
// Uses the library's default backoff policy.
func NewRetryableClient(base *http.Client, maxRetries int) *http.Client {
	if maxRetries < 0 {
		maxRetries = 0
	}

	retryClient := retryablehttp.NewClient()
	// Redirects belong to the outer client, not the retry transport.
	// Otherwise a caller's CheckRedirect policy is silently bypassed.
	inner := *base
	inner.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	retryClient.HTTPClient = &inner
	retryClient.RetryMax = maxRetries
	retryClient.RetryWaitMin = 500 * time.Millisecond
	retryClient.RetryWaitMax = 5 * time.Second
	retryClient.Logger = nil // Disable the library logger; diagnostics use slog.

	// Log only status: even a redacted URL can contain private paths/query values.
	retryClient.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		shouldRetry, checkErr := retryablehttp.DefaultRetryPolicy(ctx, resp, err)
		if shouldRetry && resp != nil {
			slog.Warn("retrying request", "source", "websites", "status", resp.StatusCode)
		}
		return shouldRetry, checkErr
	}

	// Expose the wrapper as a standard HTTP client.
	client := retryClient.StandardClient()
	client.Timeout = base.Timeout // Includes retry backoff and response reads.
	client.CheckRedirect = base.CheckRedirect
	return client
}
