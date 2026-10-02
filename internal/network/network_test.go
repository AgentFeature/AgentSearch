package network

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryAndTimeout(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(429)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()
	ua, _ := NewUARotator("")
	pr, _ := NewProxyRotator("")
	client := NewOptimizedClient(ClientConfig{RequestTimeout: time.Second, MaxRetries: 1}, ua, pr)
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 || attempts.Load() != 2 {
		t.Fatal("retry lost", attempts.Load())
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", slow.URL, nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("timeout ignored")
	}
}
func TestHTTPProxyRouting(t *testing.T) {
	var calls atomic.Int32
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Host != "destination.invalid" {
			t.Errorf("not a proxy request: %s", r.URL)
		}
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")) {
			t.Error("proxy auth lost")
		}
		_, _ = io.WriteString(w, "proxied")
	}))
	defer proxyServer.Close()
	path := filepath.Join(t.TempDir(), "proxies.txt")
	_ = os.WriteFile(path, []byte(strings.Replace(proxyServer.URL, "http://", "http://user:pass@", 1)), 0600)
	ua, _ := NewUARotator("")
	pr, err := NewProxyRotator(path)
	if err != nil {
		t.Fatal(err)
	}
	client := NewOptimizedClient(ClientConfig{RequestTimeout: time.Second}, ua, pr)
	response, err := client.Get("http://destination.invalid/alice")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	b, _ := io.ReadAll(response.Body)
	if string(b) != "proxied" || calls.Load() != 1 {
		t.Fatal("proxy bypassed")
	}
}
func TestProxyRotationAndUTLSWiring(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.txt")
	data := "# comment\n127.0.0.1:80\nhttps://host:443\nsocks5://host:1080\nsocks5h://host:1081\n"
	_ = os.WriteFile(path, []byte(data), 0600)
	pr, err := NewProxyRotator(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"http://127.0.0.1:80", "https://host:443", "socks5://host:1080", "socks5h://host:1081", "http://127.0.0.1:80"}
	for _, value := range want {
		if got := pr.GetNext(); got != value {
			t.Fatal(got, value)
		}
	}
	tr := &http.Transport{}
	EnableUTLS(tr, false)
	if tr.DialTLSContext != nil {
		t.Fatal("uTLS enabled unexpectedly")
	}
	EnableUTLS(tr, true)
	if tr.DialTLSContext == nil {
		t.Fatal("uTLS not wired")
	}
}
func TestConcurrentUserAgent(t *testing.T) {
	ua, err := NewUARotator("")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if ua.GetRandom() == "" {
					t.Error("empty UA")
				}
			}
		}()
	}
	wg.Wait()
}
