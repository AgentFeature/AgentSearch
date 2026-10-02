// Package hibp integrates the official authenticated email breach API.
// Email breaches and password ranges use separate clients and capabilities.
package hibp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/AgentFeature/agentsearch/internal/security"
)

const DefaultBaseURL = "https://haveibeenpwned.com/api/v3"
const userAgent = "AgentSearch (https://github.com/AgentFeature/AgentSearch)"

// httpEndpoint holds shared, authentication-neutral transport settings.
type httpEndpoint struct {
	http    *http.Client
	baseURL string
}

// Client performs authenticated email lookups. It does not log or retry.
// Inject a standard, non-retrying client from network.NewServiceClient.
type Client struct {
	*httpEndpoint
	key security.Secret
}

// NewClient owns key, releasing it on failure or Close after searches drain.
func NewClient(baseURL string, key security.Secret, httpClient *http.Client) (client *Client, err error) {
	defer func() {
		if err != nil {
			key.Destroy()
		}
	}()
	if strings.TrimSpace(key.Reveal()) == "" {
		return nil, &Error{Kind: MissingKey}
	}
	if strings.ContainsAny(key.Reveal(), "\r\n") {
		return nil, &Error{Kind: Unauthorized}
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	endpoint, err := newHTTPEndpoint(baseURL, httpClient)
	if err != nil {
		return nil, err
	}
	return &Client{httpEndpoint: endpoint, key: key}, nil
}

// newHTTPEndpoint shares transport safeguards without sharing authentication.
func newHTTPEndpoint(baseURL string, httpClient *http.Client) (*httpEndpoint, error) {
	if httpClient == nil || httpClient.Timeout <= 0 {
		return nil, fmt.Errorf("HIBP requires an HTTP client with a positive timeout")
	}

	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("invalid HIBP base URL; credentials, queries and fragments are not allowed")
	}
	loopback := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback != nil && loopback.IsLoopback()) {
		return nil, fmt.Errorf("HIBP requires HTTPS; HTTP is allowed only for literal loopback test endpoints")
	}
	safeClient := *httpClient
	// net/http does not recognize hibp-api-key as a sensitive redirect header.
	// Reject every redirect, including same-origin redirects, before another request.
	safeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	safeClient.Jar = nil
	return &httpEndpoint{http: &safeClient, baseURL: strings.TrimRight(u.String(), "/")}, nil
}
func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	return c.httpEndpoint.get(ctx, path, http.Header{"Hibp-Api-Key": []string{c.key.Reveal()}, "Accept": []string{"application/json"}})
}
func (e *httpEndpoint) get(ctx context.Context, path string, headers http.Header) (*http.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, requestError(ctx, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.baseURL+path, nil)
	if err != nil {
		return nil, &Error{Kind: BadRequest}
	}
	req.Header = headers.Clone()
	req.Header.Set("User-Agent", userAgent)
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, requestError(ctx, err)
	}
	return resp, nil
}

func readResponse(ctx context.Context, resp *http.Response, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, requestError(ctx, err)
	}
	if int64(len(data)) > limit {
		return nil, &Error{Kind: InvalidResponse, StatusCode: resp.StatusCode}
	}
	return data, nil
}

const DefaultPasswordsURL = "https://api.pwnedpasswords.com/range"

// PasswordClient cannot carry an email API key. Its only request operation
// accepts an already-derived five-character prefix, never a password or hash.
type PasswordClient struct{ *httpEndpoint }

func NewPasswordClient(rangeURL string, httpClient *http.Client) (*PasswordClient, error) {
	if rangeURL == "" {
		rangeURL = DefaultPasswordsURL
	}
	endpoint, err := newHTTPEndpoint(rangeURL, httpClient)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(endpoint.baseURL)
	if err != nil || u.Path != "/range" || u.RawPath != "" {
		return nil, fmt.Errorf("Pwned Passwords endpoint must end with /range")
	}
	return &PasswordClient{httpEndpoint: endpoint}, nil
}
func (c *PasswordClient) getRange(ctx context.Context, prefix string) (*http.Response, error) {
	if !validHex(prefix, 5) {
		return nil, &Error{Kind: BadRequest}
	}
	return c.httpEndpoint.get(ctx, "/"+strings.ToUpper(prefix), http.Header{"Accept": []string{"text/plain"}, "Add-Padding": []string{"true"}})
}
func (*PasswordClient) String() string   { return "hibp.PasswordClient" }
func (*PasswordClient) GoString() string { return "hibp.PasswordClient" }

func (*Client) String() string   { return "hibp.Client" }
func (*Client) GoString() string { return "hibp.Client" }

// Close releases reusable credentials and idle transport resources.
func (c *Client) Close() { c.http.CloseIdleConnections(); c.key.Destroy() }
