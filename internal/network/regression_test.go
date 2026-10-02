package network

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegressionRetryHonorsOuterRedirectPolicy(t *testing.T) {
	var destinations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/destination", http.StatusFound)
			return
		}
		destinations.Add(1)
	}))
	defer server.Close()
	base := server.Client()
	base.Timeout = time.Second
	client := NewRetryableClient(base, 1)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound || destinations.Load() != 0 {
		t.Fatalf("redirect escaped caller policy: status=%d destinations=%d", response.StatusCode, destinations.Load())
	}
}

func TestRegressionZeroRetriesAndWholeRequestTimeout(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) }))
	defer server.Close()
	base := server.Client()
	base.Timeout = 80 * time.Millisecond
	client := NewRetryableClient(base, 0)
	response, _ := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	if calls.Load() != 1 {
		t.Errorf("zero retries made %d requests", calls.Load())
	}
	if client.Timeout != base.Timeout {
		t.Errorf("outer timeout = %v; want %v", client.Timeout, base.Timeout)
	}
}

func TestRegressionInvalidProxyFailsClosed(t *testing.T) {
	for _, value := range []string{"ftp://127.0.0.1:80", "http://", "http://host:bad", "socks5://host:1080/path", "http://host:80?query=1"} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "proxies.txt")
			if err := os.WriteFile(path, []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewProxyRotator(path); err == nil {
				t.Fatal("invalid proxy accepted; transport could route directly")
			}
		})
	}
}

func TestRegressionUTLSVerifiedLocalTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "verified") }))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	EnableUTLS(transport, true)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "verified" {
		t.Fatal("TLS response unavailable", err)
	}
}

func TestRegressionSOCKSWithUTLSNeverDialsDestinationDirectly(t *testing.T) {
	var direct atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			direct.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	unavailable, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := unavailable.Addr().String()
	unavailable.Close()
	ua, _ := NewUARotator("")
	client := NewOptimizedClient(ClientConfig{RequestTimeout: time.Second, UseUTLS: true}, ua, &ProxyRotator{proxies: []string{"socks5://" + address}})
	response, err := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || direct.Load() != 0 {
		t.Fatalf("unavailable proxy bypassed: direct connections=%d err=%v", direct.Load(), err)
	}
}

func TestRegressionUserAgentListIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ua.txt")
	var builder strings.Builder
	for i := 0; i < 10001; i++ {
		builder.WriteString("Agent/1.0\n")
	}
	if err := os.WriteFile(path, []byte(builder.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewUARotator(path); err == nil {
		t.Fatal("unbounded User-Agent list accepted")
	}
	small := filepath.Join(t.TempDir(), "small.txt")
	if err := os.WriteFile(small, []byte("# comment\nCustom/1.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ua, err := NewUARotator(small)
	if err != nil {
		t.Fatal(err)
	}
	if len(ua.agents) <= len(defaultUserAgents) {
		t.Fatal("custom User-Agent values were not loaded")
	}
}
