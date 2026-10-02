package httpapi

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/passworddb"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

func putFile(t *testing.T, path, body string) {
	t.Helper()
	if e := os.WriteFile(path, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestHTTPExistingProviderDispatch(t *testing.T) {
	digest := sha1.Sum([]byte("example-password"))
	encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
	var web, email, password atomic.Int32
	var upstreamStatus atomic.Int32
	key := "synthetic-email-key"
	t.Setenv("AGENTSEARCH_HTTP_TEST_KEY", key)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "example-password") || strings.Contains(r.RequestURI, encoded) {
			t.Error("password or full hash in upstream URL")
		}
		switch {
		case r.URL.Path == "/users/example":
			web.Add(1)
			w.WriteHeader(200)
		case r.URL.Path == "/api/v3/breachedaccount/user@example.test":
			email.Add(1)
			if r.Header.Get("hibp-api-key") != key {
				t.Error("email auth lost")
			}
			fmt.Fprint(w, "[]")
		case r.URL.Path == "/range/"+encoded[:5]:
			password.Add(1)
			if r.Header.Get("hibp-api-key") != "" || r.Header.Get("Add-Padding") != "true" {
				t.Error("password headers incorrect")
			}
			if code := upstreamStatus.Load(); code != 0 {
				w.Header().Set("Retry-After", "11")
				w.WriteHeader(int(code))
				fmt.Fprint(w, "example-password /private/database")
				return
			}
			fmt.Fprintf(w, "%s:42\r\n", encoded[5:])
		default:
			t.Error("unexpected outbound endpoint")
		}
	}))
	defer upstream.Close()
	dir := t.TempDir()
	cfg := config.DefaultServerConfig()
	cfg.Engine.SitesFile = filepath.Join(dir, "sites.yaml")
	cfg.Engine.ServicesFile = filepath.Join(dir, "services.yaml")
	cfg.Engine.RateLimitPerHost = 0
	putFile(t, cfg.Engine.SitesFile, fmt.Sprintf("- name: Fixture\n  url: %s/users/{username}\n  check_type: status\n", upstream.URL))
	putFile(t, cfg.Engine.ServicesFile, fmt.Sprintf("services:\n  hibp:\n    enabled: true\n    api_key_env: AGENTSEARCH_HTTP_TEST_KEY\n    api_url: %s/api/v3\n    passwords_api_url: %s/range\n", upstream.URL, upstream.URL))
	service, e := app.NewSearchService(context.Background(), cfg.Engine)
	if e != nil {
		t.Fatal(e)
	}
	defer service.Close()
	var logs bytes.Buffer
	handler, e := New(service, security.NewSecret(testToken), cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if e != nil {
		t.Fatal(e)
	}
	for _, body := range []string{`{"type":"username","target":"example"}`, `{"type":"email","target":"user@example.test"}`, `{"type":"password","password":"example-password"}`} {
		w := request(handler, "POST", "/api/v1/search", body, "Bearer "+testToken)
		if w.Code != 200 {
			t.Fatalf("provider lookup status %d", w.Code)
		}
		var payload struct{ Results []models.Result }
		if json.Unmarshal(w.Body.Bytes(), &payload) != nil || len(payload.Results) != 1 {
			t.Fatal("provider result missing")
		}
		if strings.Contains(w.Body.String(), "example-password") {
			t.Fatal("password response leak")
		}
	}
	if web.Load() != 1 || email.Load() != 1 || password.Load() != 1 {
		t.Fatal("provider isolation failed")
	}
	upstreamStatus.Store(429)
	w := request(handler, "POST", "/api/v1/search", `{"type":"password","password":"example-password"}`, "Bearer "+testToken)
	if w.Code != 429 || w.Header().Get("Retry-After") != "11" {
		t.Fatal("dispatcher error mapping/Retry-After lost")
	}
	if strings.Contains(w.Body.String()+logs.String(), "example-password") {
		t.Fatal("password leak")
	}
}
func TestHTTPLocalBackendNoFallback(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	root := filepath.Join(dir, "db")
	input := filepath.Join(dir, "fixture.txt")
	key := sha1.Sum([]byte("example-password"))
	text := fmt.Sprintf("%X:42\r\n", key)
	sum := sha256.Sum256([]byte(text))
	putFile(t, input, text)
	id, e := passworddb.Import(ctx, root, input, passworddb.ImportOptions{ExpectedSHA256: hex.EncodeToString(sum[:]), Complete: true, AcquiredAt: time.Now()})
	if e != nil {
		t.Fatal(e)
	}
	if e = passworddb.Activate(ctx, root, id); e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	cfg := config.DefaultServerConfig()
	cfg.Engine.SitesFile = ""
	cfg.Engine.PasswordBackend = config.PasswordBackendLocal
	cfg.Engine.PasswordDatabasePath = root
	cfg.Engine.ServicesFile = filepath.Join(dir, "services.yaml")
	putFile(t, cfg.Engine.ServicesFile, fmt.Sprintf("services:\n  hibp:\n    enabled: false\n    passwords_api_url: %s/range\n", upstream.URL))
	service, e := app.NewSearchService(ctx, cfg.Engine)
	if e != nil {
		t.Fatal(e)
	}
	defer service.Close()
	handler, e := New(service, security.NewSecret(testToken), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if e != nil {
		t.Fatal(e)
	}
	w := request(handler, "POST", "/api/v1/search", `{"type":"password","password":"example-password"}`, "Bearer "+testToken)
	var payload struct{ Results []models.Result }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &payload) != nil || len(payload.Results) != 1 || payload.Results[0].Source != "pwned-passwords-local" || payload.Results[0].Confidence != 100 || !payload.Results[0].Found {
		t.Fatal("local normalized lookup failed")
	}
	// Damage the selected record after startup: health must stay cheap; search
	// must report unavailability, never absence and never call the configured API.
	records := filepath.Join(root, "versions", id, "hashes.bin")
	if e := os.Chmod(records, 0600); e != nil {
		t.Fatal(e)
	}
	file, e := os.OpenFile(records, os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	one := []byte{key[0] ^ 1}
	if _, e = file.WriteAt(one, 128); e != nil {
		file.Close()
		t.Fatal(e)
	}
	file.Close()
	if w = request(handler, "GET", "/health", "", ""); w.Code != 200 {
		t.Fatal("health performed corpus lookup")
	}
	w = request(handler, "POST", "/api/v1/search", `{"type":"password","password":"example-password"}`, "Bearer "+testToken)
	if w.Code != 503 || strings.Contains(w.Body.String(), "not_found") || strings.Contains(w.Body.String(), root) || strings.Contains(w.Body.String(), "example-password") {
		t.Fatal("local integrity failure not safely mapped")
	}
	if calls.Load() != 0 {
		t.Fatal("local backend performed network fallback")
	}
	w = request(handler, "POST", "/api/v1/search", `{"type":"email","target":"user@example.test"}`, "Bearer "+testToken)
	if w.Code != 503 {
		t.Fatal("disabled email not unavailable")
	}
}
func TestServerClientCancellationAndShutdown(t *testing.T) {
	entered := make(chan struct{})
	cancelled := make(chan struct{})
	cfg := config.DefaultServerConfig()
	handler := handlerFor(t, func(ctx context.Context, _ models.Target, _ sources.Emit) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	}, io.Discard, nil)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	stopped := make(chan error, 1)
	go func() { stopped <- Serve(ctx, listener, handler, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()
	clientCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, e := http.NewRequestWithContext(clientCtx, "POST", "http://"+listener.Addr().String()+"/api/v1/search", strings.NewReader(`{"type":"password","password":"example-password"}`))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 3 * time.Second}
	defer client.CloseIdleConnections()
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, _ := client.Do(r)
		if resp != nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("server never entered engine")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("client cancellation lost")
	}
	<-done
	stop()
	select {
	case e := <-stopped:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}
