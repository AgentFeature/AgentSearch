// Package securitytrails integrates only the official read-only Get Domain API.
package securitytrails

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

const DefaultBaseURL = "https://api.securitytrails.com/v1"
const MaxResponseBytes = 2 << 20

// Client uses an injected standard service transport, never website retries.
// One shared client per configured source paces request starts, not all searches.
type Client struct {
	http     *http.Client
	baseURL  string
	key      security.Secret
	interval time.Duration
	mu       sync.Mutex
	next     time.Time
}

// NewClient takes ownership of key, also on configuration failure. Close only
// after in-flight searches drain. Other provider credentials are never supplied.
func NewClient(baseURL string, key security.Secret, httpClient *http.Client, interval time.Duration) (client *Client, err error) {
	defer func() {
		if err != nil {
			key.Destroy()
		}
	}()
	value := key.Reveal()
	if len(value) == 0 {
		return nil, &Error{Kind: "missing_api_key"}
	}
	if len(value) > 4096 {
		return nil, &Error{Kind: "unauthorized"}
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return nil, &Error{Kind: "unauthorized"}
		}
	}
	if httpClient == nil || httpClient.Timeout <= 0 || interval <= 0 {
		return nil, errors.New("SecurityTrails requires positive HTTP timeout and request interval")
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	u, e := url.Parse(baseURL)
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.TrimRight(u.Path, "/") != "/v1" {
		return nil, errors.New("invalid SecurityTrails endpoint; use an API base ending in /v1")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, errors.New("SecurityTrails requires HTTPS except literal loopback tests")
	}
	safe := *httpClient
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	safe.Jar = nil
	return &Client{http: &safe, baseURL: strings.TrimRight(u.String(), "/"), key: key, interval: interval}, nil
}
func (c *Client) Close()         { c.http.CloseIdleConnections(); c.key.Destroy() }
func (*Client) String() string   { return "securitytrails.Client" }
func (*Client) GoString() string { return "securitytrails.Client" }

// wait never reserves a future slot on cancellation. No lock is held while
// waiting or doing network I/O. This is per-instance pacing, not a quota ledger.
func (c *Client) wait(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return requestError(ctx, err)
		}
		c.mu.Lock()
		delay := time.Until(c.next)
		if delay <= 0 {
			c.next = time.Now().Add(c.interval)
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return requestError(ctx, ctx.Err())
		case <-timer.C:
		}
	}
}
func (c *Client) deferRequests(delay time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if next := time.Now().Add(delay); next.After(c.next) {
		c.next = next
	}
}
func (c *Client) lookup(ctx context.Context, domain string) (*domainData, error) {
	target, err := models.NewDomainTarget(domain)
	if err != nil {
		return nil, &Error{Kind: "bad_request"}
	}
	if err = c.wait(ctx); err != nil {
		return nil, err
	}
	if c.key.Empty() {
		return nil, &Error{Kind: "missing_api_key"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/domain/"+url.PathEscape(target.Value()), nil)
	if err != nil {
		return nil, &Error{Kind: "bad_request"}
	}
	req.Header.Set("APIKEY", c.key.Reveal())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AgentSearch (https://github.com/AgentFeature/AgentSearch)")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, requestError(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		e := statusError(resp.StatusCode, resp.Header.Get("Retry-After"))
		if resp.StatusCode == 429 {
			c.deferRequests(e.RetryAfter)
		}
		return nil, e // Do not consume or retain arbitrary error bodies, including 404.
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	defer clear(raw)
	if err != nil {
		return nil, requestError(ctx, err)
	}
	if len(raw) > MaxResponseBytes {
		return nil, &Error{Kind: "invalid_response", StatusCode: 200}
	}
	data, err := parseDomain(raw, target.Value())
	if ctx.Err() != nil {
		return nil, requestError(ctx, ctx.Err())
	}
	return data, err
}

// Wire structs are private and allow harmless unknown fields. Only the selected
// DNS families are parsed; WHOIS, TXT tokens, SOA email and raw JSON are excluded.
type domainWire struct {
	Hostname string                     `json:"hostname"`
	DNS      map[string]json.RawMessage `json:"current_dns"`
}
type recordSet struct {
	Values []json.RawMessage `json:"values"`
}
type addressWire struct {
	IP string `json:"ip"`
}
type mxWire struct {
	Host     string `json:"host"`
	Priority *int   `json:"priority"`
}
type nsWire struct {
	Nameserver string `json:"nameserver"`
}
type dnsRecord struct{ kind, value string }
type domainData struct{ records []dnsRecord }
