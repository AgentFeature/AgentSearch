// Package bitcoin provides bounded, read-only Esplora mainnet observations.
package bitcoin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/AgentFeature/agentsearch/internal/ratelimit"
)

const (
	DefaultURL           = "https://blockstream.info/api"
	MaxPages             = 5
	PageSize             = 25 // Esplora's confirmed-history endpoint has a fixed page size.
	MaxTransactions      = 100
	MaxCounterparties    = 256
	MaxRequests          = 6 // One address request plus at most five history pages.
	MaxRetries           = 0 // Match the existing service-client policy; never retry failures.
	MaxResponseBytes     = 1 << 20
	MaxTransactionIO     = 1000
	RequestTimeout       = 15 * time.Second
	InvestigationTimeout = 90 * time.Second
)

type Source struct {
	http    *http.Client
	baseURL string
	limiter *ratelimit.HostLimiter
}

// New accepts operator configuration only. Targets cannot change the endpoint.
// The application injects network.NewServiceClient (no retry transport).
func New(endpoint string, client *http.Client, interval time.Duration) (*Source, error) {
	if endpoint == "" {
		endpoint = DefaultURL
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Path != "/api" {
		return nil, errors.New("invalid Bitcoin endpoint; expected an API base ending in /api")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && e == nil && ip.IsLoopback() && ip.Zone() == "") {
		return nil, errors.New("Bitcoin requires HTTPS except literal loopback fixtures")
	}
	if client == nil || client.Timeout <= 0 || interval <= 0 || interval > 30*time.Second {
		return nil, errors.New("Bitcoin requires a positive client timeout and bounded pacing interval")
	}
	safe := *client
	safe.Timeout = min(client.Timeout, RequestTimeout)
	safe.Jar = nil
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Source{http: &safe, baseURL: u.String(), limiter: ratelimit.NewHostLimiter(interval)}, nil
}
func (s *Source) Close() { s.http.CloseIdleConnections() }

// failure never retains arbitrary errors, request URLs, headers or body text.
type failure struct {
	kind   string
	status int
	retry  uint64
}

func (e *failure) Error() string { return "Bitcoin lookup failed (" + e.kind + ")" }
func (e *failure) Unwrap() error {
	if e.kind == "timeout" {
		return context.DeadlineExceeded
	}
	if e.kind == "cancelled" {
		return context.Canceled
	}
	return nil
}
func invalid() error { return &failure{kind: "invalid_response"} }
func requestFailure(ctx context.Context, err error) error {
	var timed net.Error
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
		return &failure{kind: "timeout"}
	case errors.Is(ctx.Err(), context.Canceled), errors.Is(err, context.Canceled):
		return &failure{kind: "cancelled"}
	case errors.As(err, &timed) && timed.Timeout():
		return &failure{kind: "timeout"}
	default:
		return &failure{kind: "network_failure"}
	}
}

func (s *Source) get(ctx context.Context, path string, requests *int, dst any) error {
	return s.getBounded(ctx, path, requests, MaxRequests, "", dst)
}

func (s *Source) getBounded(ctx context.Context, path string, requests *int, maxRequests int, notFoundBody string, dst any) error {
	if *requests >= maxRequests {
		return &failure{kind: "request_limit"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.http.Timeout)
	defer cancel()
	endpoint := s.baseURL + path
	if err := s.limiter.WaitContext(ctx, endpoint); err != nil {
		return requestFailure(ctx, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return &failure{kind: "bad_request"}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AgentSearch Bitcoin intelligence")
	*requests++
	resp, err := s.http.Do(req)
	if err != nil {
		return requestFailure(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e := &failure{kind: "http_error", status: resp.StatusCode}
		if resp.StatusCode == http.StatusNotFound && notFoundBody != "" {
			raw, err := io.ReadAll(io.LimitReader(resp.Body, 65))
			defer clear(raw)
			if err != nil {
				return requestFailure(ctx, err)
			}
			if len(raw) <= 64 && strings.TrimSpace(string(raw)) == notFoundBody {
				e.kind = "not_found"
			}
		}
		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			if resp.StatusCode == 429 {
				e.kind = "rate_limited"
			}
			delay := time.Minute
			h := resp.Header.Get("Retry-After")
			if n, err := strconv.ParseUint(h, 10, 32); err == nil {
				delay = time.Duration(min(n, 86400)) * time.Second
			} else if when, err := http.ParseTime(h); err == nil {
				delay = min(max(time.Until(when), 0), 24*time.Hour)
			}
			e.retry = uint64((delay + time.Second - 1) / time.Second)
			s.limiter.Defer(endpoint, delay)
		}
		return e
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	defer clear(raw)
	if err != nil {
		return requestFailure(ctx, err)
	}
	if len(raw) > MaxResponseBytes {
		return &failure{kind: "response_too_large"}
	}
	if ctx.Err() != nil {
		return requestFailure(ctx, ctx.Err())
	}
	if !utf8.Valid(raw) || len(strings.TrimSpace(string(raw))) == 0 || json.Unmarshal(raw, dst) != nil {
		return invalid()
	}
	return nil
}
