// Package ipinfo implements single-address passive IPinfo Lite lookups.
package ipinfo

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
	"unicode"
	"unicode/utf8"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

const DefaultURL = "https://api.ipinfo.io/lite"
const maxResponseBytes = 64 << 10

type Client struct {
	http    *http.Client
	baseURL string
	key     security.Secret
}

// NewClient owns key, destroying it on failure or Close. Only trusted operator
// configuration may set endpoint; a target cannot control the destination.
func NewClient(endpoint string, key security.Secret, client *http.Client) (c *Client, err error) {
	defer func() {
		if err != nil {
			key.Destroy()
		}
	}()
	token := key.Reveal()
	if len(token) == 0 || len(token) > 4096 {
		return nil, &Error{Kind: "missing_api_key"}
	}
	for _, b := range []byte(token) {
		if b < 33 || b > 126 {
			return nil, &Error{Kind: "unauthorized"}
		}
	}
	if endpoint == "" {
		endpoint = DefaultURL
	}
	u, e := url.Parse(endpoint)
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || u.Path != "/lite" {
		return nil, errors.New("invalid IPinfo Lite endpoint")
	}
	addr, e := netip.ParseAddr(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && e == nil && addr.IsLoopback() && addr.Zone() == "") {
		return nil, errors.New("IPinfo requires HTTPS; HTTP is only allowed for literal loopback fixtures")
	}
	if client == nil || client.Timeout <= 0 {
		return nil, errors.New("IPinfo requires a client with a positive timeout")
	}
	safe := *client
	safe.Jar = nil
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{http: &safe, baseURL: u.String(), key: key}, nil
}
func (c *Client) Close()         { c.http.CloseIdleConnections(); c.key.Destroy() }
func (*Client) String() string   { return "ipinfo.Client" }
func (*Client) GoString() string { return "ipinfo.Client" }

// profile is a private, selected wire projection, not an alternate result model.
// Unknown upstream fields are ignored and never become metadata.
type profile struct {
	IP            string `json:"ip"`
	ASN           string `json:"asn"`
	ASName        string `json:"as_name"`
	ASDomain      string `json:"as_domain"`
	CountryCode   string `json:"country_code"`
	Country       string `json:"country"`
	ContinentCode string `json:"continent_code"`
	Continent     string `json:"continent"`
	Bogon         *bool  `json:"bogon"`
}

func validText(s string) bool {
	if len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func parse(raw []byte, target string) (*profile, error) {
	invalid := func() (*profile, error) { return nil, &Error{Kind: "invalid_response"} }
	if !utf8.Valid(raw) {
		return invalid()
	}
	var p profile
	if json.Unmarshal(raw, &p) != nil {
		return invalid()
	}
	ip, e := models.NewIPTarget(p.IP)
	if e != nil || ip.Value() != target {
		return invalid()
	}
	for _, s := range []string{p.ASN, p.ASName, p.ASDomain, p.CountryCode, p.Country, p.ContinentCode, p.Continent} {
		if !validText(s) {
			return invalid()
		}
	}
	if p.ASN != "" {
		n, e := strconv.ParseUint(strings.TrimPrefix(p.ASN, "AS"), 10, 32)
		if !strings.HasPrefix(p.ASN, "AS") || e != nil || n == 0 {
			return invalid()
		}
	}
	if p.ASDomain != "" {
		if _, e := models.NewDomainTarget(p.ASDomain); e != nil {
			return invalid()
		}
	}
	if p.CountryCode != "" && (len(p.CountryCode) != 2 || p.CountryCode[0] < 'A' || p.CountryCode[0] > 'Z' || p.CountryCode[1] < 'A' || p.CountryCode[1] > 'Z') {
		return invalid()
	}
	if p.ContinentCode != "" {
		switch p.ContinentCode {
		case "AF", "AN", "AS", "EU", "NA", "OC", "SA":
		default:
			return invalid()
		}
	}
	p.IP = ip.Value()
	return &p, nil
}
func (c *Client) lookup(ctx context.Context, ip string) (*profile, error) {
	target, e := models.NewIPTarget(ip)
	if e != nil {
		return nil, &Error{Kind: "bad_request"}
	}
	if ctx.Err() != nil {
		return nil, requestError(ctx, ctx.Err())
	}
	// Only canonical literal path data is appended, never a hostname/URL expression.
	req, e := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/"+target.Value(), nil)
	if e != nil {
		return nil, &Error{Kind: "bad_request"}
	}
	req.Header.Set("Authorization", "Bearer "+c.key.Reveal())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AgentSearch (https://github.com/AgentFeature/AgentSearch)")
	resp, e := c.http.Do(req)
	if e != nil {
		return nil, requestError(ctx, e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, statusError(resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	defer clear(raw)
	if e != nil {
		return nil, requestError(ctx, e)
	}
	if len(raw) > maxResponseBytes {
		return nil, &Error{Kind: "invalid_response"}
	}
	if ctx.Err() != nil {
		return nil, requestError(ctx, ctx.Err())
	}
	return parse(raw, target.Value())
}

// Error retains safe classifications only, never upstream text or error chains.
type Error struct {
	Kind              string
	StatusCode        int
	RetryAfterSeconds uint64
}

func (e *Error) Error() string { return "IPinfo lookup failed (" + safeKind(e.Kind) + ")" }
func safeKind(kind string) string {
	switch kind {
	case "missing_api_key", "unauthorized", "forbidden", "bad_request", "rate_limited", "service_unavailable", "timeout", "cancelled", "network_failure", "invalid_response":
		return kind
	}
	return "unexpected_status"
}
func (e *Error) Unwrap() error {
	switch e.Kind {
	case "timeout":
		return context.DeadlineExceeded
	case "cancelled":
		return context.Canceled
	}
	return nil
}
func requestError(ctx context.Context, err error) *Error {
	var timed net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return &Error{Kind: "timeout"}
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return &Error{Kind: "cancelled"}
	}
	if errors.As(err, &timed) && timed.Timeout() {
		return &Error{Kind: "timeout"}
	}
	return &Error{Kind: "network_failure"}
}
func statusError(code int, retry string) *Error {
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
		if n, err := strconv.ParseUint(retry, 10, 64); err == nil && n <= 86400 {
			e.RetryAfterSeconds = n
		}
	}
	return e
}
