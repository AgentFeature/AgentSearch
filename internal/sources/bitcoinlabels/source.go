package bitcoinlabels

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
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/ratelimit"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

const (
	DefaultURL     = "https://www.walletexplorer.com/api/1/address-lookup"
	MaxRequests    = 1
	MaxRetries     = 0
	RequestTimeout = 15 * time.Second
)

type Source struct {
	http     *http.Client
	endpoint string
	limiter  *ratelimit.HostLimiter
}

// New uses the existing no-retry service client supplied by the composition root.
// Only trusted operator configuration can select an endpoint; no provider links
// or target-supplied URLs are ever followed.
func New(endpoint string, client *http.Client, interval time.Duration) (*Source, error) {
	if endpoint == "" {
		endpoint = DefaultURL
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Path != "/api/1/address-lookup" {
		return nil, errors.New("invalid WalletExplorer address-lookup endpoint")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && e == nil && ip.IsLoopback() && ip.Zone() == "") {
		return nil, errors.New("WalletExplorer requires HTTPS except literal loopback fixtures")
	}
	if client == nil || client.Timeout <= 0 || interval <= 0 || interval > 30*time.Second {
		return nil, errors.New("WalletExplorer requires a positive bounded timeout and pacing interval")
	}
	safe := *client
	safe.Timeout = min(client.Timeout, RequestTimeout)
	safe.Jar = nil
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Source{http: &safe, endpoint: u.String(), limiter: ratelimit.NewHostLimiter(interval)}, nil
}
func (s *Source) Close()                { s.http.CloseIdleConnections() }
func (*Source) Name() string            { return "bitcoin-labels" }
func (*Source) Type() models.SourceType { return models.SourceAPI }

var _ sources.BitcoinSearcher = (*Source)(nil)

type failure struct {
	kind   string
	status int
	retry  uint64
}

func (e *failure) Error() string { return "WalletExplorer label lookup failed (" + e.kind + ")" }
func (e *failure) Unwrap() error {
	if e.kind == "timeout" {
		return context.DeadlineExceeded
	}
	if e.kind == "cancelled" {
		return context.Canceled
	}
	return nil
}
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

func (s *Source) lookup(ctx context.Context, address string) (association, error) {
	if err := s.limiter.WaitContext(ctx, s.endpoint); err != nil {
		return association{}, requestFailure(ctx, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+"?"+url.Values{"address": {address}}.Encode(), nil)
	if err != nil {
		return association{}, &failure{kind: "bad_request"}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AgentSearch Bitcoin label intelligence")
	resp, err := s.http.Do(req) // Exactly one attempt; no pagination, wallet lookup or retry.
	if err != nil {
		return association{}, requestFailure(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		e := &failure{kind: "http_error", status: resp.StatusCode}
		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			if resp.StatusCode == 429 {
				e.kind = "rate_limited"
			}
			delay := time.Minute
			if n, err := strconv.ParseUint(resp.Header.Get("Retry-After"), 10, 32); err == nil {
				delay = time.Duration(min(n, 86400)) * time.Second
			} else if when, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil {
				delay = min(max(time.Until(when), 0), 24*time.Hour)
			}
			s.limiter.Defer(s.endpoint, delay)
			e.retry = uint64((delay + time.Second - 1) / time.Second)
		}
		return association{}, e // Never retain error bodies or arbitrary header values.
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	defer clear(raw)
	if err != nil {
		return association{}, requestFailure(ctx, err)
	}
	if len(raw) > MaxResponseBytes {
		return association{}, &failure{kind: "response_too_large"}
	}
	if ctx.Err() != nil {
		return association{}, requestFailure(ctx, ctx.Err())
	}
	return parse(raw)
}

func (s *Source) SearchBitcoin(parent context.Context, value string, emit sources.Emit) error {
	if emit == nil {
		return errors.New("WalletExplorer requires a result consumer")
	}
	target, err := models.NewBitcoinTarget(value)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, s.http.Timeout)
	defer cancel()
	row := models.NewResult(s.Name(), s.Type(), target)
	row.SiteName = "WalletExplorer provider associations (not verified ownership)"
	row.URL = s.endpoint + "?" + url.Values{"address": {target.Value()}}.Encode()
	row.Metadata = map[string]string{"provider": "WalletExplorer", "scope": "external_provider_association", "confidence_basis": "provider-reported; not scored", "ownership": "not independently verified", "label_age": "unknown"}
	a, err := s.lookup(ctx, target.Value())
	if err != nil {
		row.Status = models.StatusError
		row.Error = err.Error()
		row.Metadata["label_status"] = "unavailable"
		var e *failure
		if errors.As(err, &e) {
			row.Metadata["error_kind"] = e.kind
			if e.status != 0 {
				row.Metadata["http_status"] = strconv.Itoa(e.status)
			}
			if e.retry > 0 {
				row.Metadata["retry_after_seconds"] = strconv.FormatUint(e.retry, 10)
			}
		}
	} else {
		row.Status = models.StatusNotFound
		row.Metadata["label_status"] = "no_label"
		if a.Label != "" {
			row.Status = models.StatusFound
			row.Metadata["label_status"] = "provider_label"
		}
		// A bounded array of independent evidence records does not assert one entity
		// per address. The selected provider currently returns at most one association.
		if a.WalletID != "" {
			raw, _ := json.Marshal(a)
			row.Evidence = []models.Evidence{{Kind: "crypto_provider_association", Value: string(raw)}}
		}
	}
	if e := emit(row.Normalized()); e != nil {
		return e
	}
	return err
}
