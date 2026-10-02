package network

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

// ClientConfig holds HTTP connection and timeout settings.
type ClientConfig struct {
	RequestTimeout      time.Duration
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	UseUTLS             bool // Enable experimental uTLS fingerprints.
	MaxRetries          int  // Retry count for eligible failures.
}

// NewOptimizedClient constructs the legacy website HTTP client.
// Without proxies, it shares a connection-pooled transport.
// With proxies, it uses a rotating transport.
func NewOptimizedClient(cfg ClientConfig, ua *UARotator, pr *ProxyRotator) *http.Client {
	baseTransport := newTransport(cfg)

	baseClient := &http.Client{
		Timeout:   cfg.RequestTimeout,
		Transport: baseTransport,
	}

	// Wrap direct requests with retryablehttp.
	client := NewRetryableClient(baseClient, cfg.MaxRetries)

	// Use the shared client when no proxies are configured.
	if !pr.HasProxies() {
		return client
	}

	// Clone the transport for each proxied request.
	return &http.Client{
		Timeout: cfg.RequestTimeout,
		Transport: &proxyRotatorTransport{
			base:    baseTransport,
			rotator: pr,
			ua:      ua,
			client:  client, // Retained retry client; the proxy transport currently bypasses it.
		},
	}
}

// proxyRotatorTransport selects a proxy for each request.
type proxyRotatorTransport struct {
	base    *http.Transport
	rotator *ProxyRotator
	ua      *UARotator
	client  *http.Client // Retained for compatibility; currently unused by RoundTrip.
}

func (t *proxyRotatorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rotate User-Agent headers for proxied requests.
	if t.ua != nil {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", t.ua.GetRandom())
	}

	proxyAddr := t.rotator.GetNext()
	if proxyAddr == "" {
		return t.base.RoundTrip(req)
	}

	proxyURL, err := validatedProxyURL(proxyAddr)
	if err != nil {
		return nil, err
	}

	// Isolate each request's proxy settings in a cloned transport.
	tr := t.base.Clone()
	// This transport serves one request; do not retain a per-request idle pool.
	tr.DisableKeepAlives = true

	switch proxyURL.Scheme {
	case "http", "https":
		tr.Proxy = http.ProxyURL(proxyURL)
	case "socks5", "socks5h":
		dialer, err := proxy.FromURL(proxyURL, &net.Dialer{Timeout: 5 * time.Second})
		if err != nil {
			return nil, errors.New("invalid SOCKS proxy configuration")
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return cd.DialContext(ctx, network, addr)
			}
		} else {
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
		tr.Proxy = nil
		tr.DialTLSContext = nil // Standard TLS uses the SOCKS DialContext; never bypass the proxy.
	}

	return tr.RoundTrip(req)
}

// newTransport shares connection tuning without imposing website retry policy.
func newTransport(cfg ClientConfig) *http.Transport {
	baseTransport := &http.Transport{
		MaxIdleConns:           cfg.MaxIdleConns,
		MaxIdleConnsPerHost:    cfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:        cfg.MaxIdleConnsPerHost,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  cfg.RequestTimeout / 2,
		ExpectContinueTimeout:  1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}

	// Enable uTLS when requested.
	if cfg.UseUTLS {
		EnableUTLS(baseTransport, true)
	}

	return baseTransport
}

// NewServiceClient uses the shared standard transport without website proxies,
// browser fingerprints, random User-Agents or automatic retries. Services own
// their authentication, redirect and rate-limit policies.
func NewServiceClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{Timeout: timeout, Transport: newTransport(ClientConfig{RequestTimeout: timeout, MaxIdleConns: 20, MaxIdleConnsPerHost: 2})}
}
