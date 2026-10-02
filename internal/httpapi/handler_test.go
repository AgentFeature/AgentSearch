package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
	"github.com/AgentFeature/agentsearch/internal/sources/hibp"
)

const testToken = "synthetic-test-token-not-for-deployment"

type searchFunc func(context.Context, models.Target, sources.Emit) error

func (f searchFunc) Search(c context.Context, t models.Target, e sources.Emit) error {
	return f(c, t, e)
}
func handlerFor(t *testing.T, f searchFunc, logs io.Writer, change func(*config.ServerConfig)) *Handler {
	t.Helper()
	cfg := config.DefaultServerConfig()
	if change != nil {
		change(&cfg)
	}
	token := security.NewSecret(testToken)
	h, e := New(f, token, cfg, slog.New(slog.NewTextHandler(logs, nil)))
	if e != nil {
		t.Fatal(e)
	}
	if !token.Empty() {
		t.Fatal("bootstrap token retained")
	}
	return h
}
func request(h http.Handler, method, path, body, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	r.Header.Set("X-Request-ID", "example-password")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestRoutingValidationAuthentication(t *testing.T) {
	var calls atomic.Int32
	var logs bytes.Buffer
	h := handlerFor(t, func(context.Context, models.Target, sources.Emit) error { calls.Add(1); return nil }, &logs, nil)
	cases := []struct {
		name, method, path, body, auth string
		status                         int
	}{
		{"health", "GET", "/health", "", "", 200},
		{"missing token", "POST", "/api/v1/search", `{"type":"username","target":"example"}`, "", 401},
		{"invalid token", "POST", "/api/v1/search", `{"type":"username","target":"example"}`, "Bearer invalid", 401},
		{"valid token", "POST", "/api/v1/search", `{"type":"username","target":"example"}`, "Bearer " + testToken, 200},
		{"search method", "GET", "/api/v1/search?password=example-password", "", "", 405},
		{"health method", "POST", "/health", "", "", 405},
		{"unknown", "GET", "/example-password", "", "", 404},
		{"no redirect", "GET", "//api/v1/search", "", "", 404},
		{"query forbidden", "POST", "/api/v1/search?password=example-password", `{}`, "Bearer " + testToken, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := request(h, tc.method, tc.path, tc.body, tc.auth)
			if w.Code != tc.status {
				t.Fatalf("status %d want %d", w.Code, tc.status)
			}
			if w.Header().Get("X-Request-ID") == "" || w.Header().Get("X-Request-ID") == "example-password" {
				t.Fatal("unsafe request ID")
			}
			if w.Header().Get("Location") != "" || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("unexpected redirect/CORS")
			}
			if tc.name == "health" && strings.TrimSpace(w.Body.String()) != `{"status":"ok"}` {
				t.Fatal("health body")
			}
			if strings.Contains(w.Body.String(), "example-password") {
				t.Fatal("input in response")
			}
		})
	}
	if calls.Load() != 1 {
		t.Fatal("invalid request reached engine")
	}
	invalid := []string{
		``, `[]`, `null`, `{}`, `{"type":"password"}`, `{"type":"password","password":null}`,
		`{"type":"password","password":""}`, `{"type":"password","password":17}`,
		`{"type":"password","password":"example-password","target":""}`,
		`{"type":"username","target":"example","password":""}`,
		`{"type":"username","target":"example","backend":"local"}`,
		`{"type":"username","target":"example","target":"other"}`,
		`{"type":"username","target":"example"} {"password":"example-password"}`,
		`{"type":"username","target":"https://example.test"}`,
		`{"type":"email","target":"not-an-address"}`,
		`{"type":"password_hash","password":"example-password"}`,
		`{"Type":"username","target":"example"}`,
		`{"type":"password","password":"\uD800"}`,
		`{"type":"password","password":"\uDC00"}`,
		`{"type":"username","target":"` + strings.Repeat("x", 257) + `"}`,
		`{"type":"email","target":"` + strings.Repeat("x", 255) + `@example.test"}`,
		`{"type":"password","password":"` + strings.Repeat("x", app.MaxPasswordBytes+1) + `"}`,
		"{\"type\":\"password\",\"password\":\"\xff\"}",
	}
	for i, body := range invalid {
		w := request(h, "POST", "/api/v1/search", body, "Bearer "+testToken)
		if w.Code != 400 {
			t.Fatalf("invalid case %d status %d", i, w.Code)
		}
		if strings.Contains(w.Body.String(), "example-password") {
			t.Fatal("invalid input echoed")
		}
	}
	w := request(h, "POST", "/api/v1/search", strings.Repeat(" ", MaxBodyBytes+1), "Bearer "+testToken)
	if w.Code != 413 {
		t.Fatal("body not bounded")
	}
	r := httptest.NewRequest("POST", "/api/v1/search", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+testToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatal("content type not checked")
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Add("Authorization", "Bearer "+testToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("duplicate auth accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("validation reached engine")
	}
	if strings.Contains(logs.String(), "example-password") || strings.Contains(logs.String(), testToken) {
		t.Fatal("request/credential logged")
	}
}
func TestValidTypesAndSecretCleanup(t *testing.T) {
	for _, kind := range []string{"username", "email", "password"} {
		t.Run(kind, func(t *testing.T) {
			var held security.Secret
			h := handlerFor(t, func(ctx context.Context, target models.Target, emit sources.Emit) error {
				if string(target.Type()) != kind {
					t.Fatal("wrong target type")
				}
				if kind == "password" {
					held = target.Secret()
					if e := held.Consume(func(b []byte) error {
						if string(b) != " example-password\n" {
							t.Fatal("password normalized")
						}
						return nil
					}); e != nil {
						t.Fatal(e)
					}
				}
				result := models.NewResult("fixture", models.SourceLocal, target)
				result.Status = models.StatusNotFound
				result.Confidence = 100
				return emit(result)
			}, io.Discard, nil)
			body := `{"type":"username","target":"example"}`
			if kind == "email" {
				body = `{"type":"email","target":"user@example.test"}`
			}
			if kind == "password" {
				body = `{"type":"password","password":" example-password\n"}`
			}
			w := request(h, "POST", "/api/v1/search", body, "Bearer "+testToken)
			if w.Code != 200 {
				t.Fatal("valid lookup failed")
			}
			var result struct{ Results []models.Result }
			if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil || len(result.Results) != 1 || result.Results[0].Status != models.StatusNotFound {
				t.Fatal("normalized response missing")
			}
			if kind == "password" && (!held.Empty() || strings.Contains(w.Body.String(), "example-password")) {
				t.Fatal("password retained/exposed")
			}
		})
	}
	for _, mode := range []string{"error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			var held security.Secret
			var logs bytes.Buffer
			h := handlerFor(t, func(_ context.Context, target models.Target, _ sources.Emit) error {
				held = target.Secret()
				if mode == "panic" {
					panic("example-password /private/database")
				}
				return errors.New("example-password /private/database")
			}, &logs, nil)
			w := request(h, "POST", "/api/v1/search", `{"type":"password","password":"example-password"}`, "Bearer "+testToken)
			expected := 502
			if mode == "panic" {
				expected = 500
			}
			if w.Code != expected || !held.Empty() {
				t.Fatal("failed request retained secret or wrong status")
			}
			for _, s := range []string{"example-password", "/private/database", testToken} {
				if strings.Contains(w.Body.String()+logs.String(), s) {
					t.Fatal("sensitive failure exposed")
				}
			}
		})
	}
}
func TestErrorsAndRetryAfter(t *testing.T) {
	cases := []struct {
		kind   string
		source models.SourceType
		status int
		err    error
		retry  string
	}{
		{"rate_limited", models.SourceAPI, 429, nil, "7"},
		{"service_unavailable", models.SourceAPI, 503, nil, "9"},
		{"unauthorized", models.SourceAPI, 503, nil, ""},
		{"forbidden", models.SourceAPI, 503, nil, ""},
		{"invalid_response", models.SourceAPI, 502, nil, ""},
		{"timeout", models.SourceAPI, 504, nil, ""},
		{"integrity_failure", models.SourceLocal, 503, nil, ""},
		{"", models.SourceAPI, 503, app.ErrSearchUnavailable, ""},
		{"", models.SourceAPI, 429, &hibp.Error{Kind: hibp.RateLimited, RetryAfter: 7 * time.Second}, "7"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			h := handlerFor(t, func(_ context.Context, target models.Target, emit sources.Emit) error {
				if tc.kind == "" {
					return tc.err
				}
				r := models.NewResult("fixture", tc.source, target)
				r.Status = models.StatusError
				r.Error = "example-password /private/database https://internal.invalid"
				r.URL = "https://internal.invalid"
				r.Metadata = map[string]string{"error_kind": tc.kind, "retry_after_seconds": tc.retry, "raw": "example-password"}
				return emit(r)
			}, io.Discard, nil)
			w := request(h, "POST", "/api/v1/search", `{"type":"password","password":"example-password"}`, "Bearer "+testToken)
			if w.Code != tc.status || w.Header().Get("Retry-After") != tc.retry {
				t.Fatalf("status/retry %d %q", w.Code, w.Header().Get("Retry-After"))
			}
			for _, s := range []string{"example-password", "/private/database", "internal.invalid"} {
				if strings.Contains(w.Body.String(), s) {
					t.Fatal("raw backend error exposed")
				}
			}
		})
	}
}
func TestCancellationTimeoutAndAdmission(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		entered := make(chan struct{})
		var held security.Secret
		h := handlerFor(t, func(ctx context.Context, target models.Target, _ sources.Emit) error {
			held = target.Secret()
			close(entered)
			<-ctx.Done()
			return ctx.Err()
		}, io.Discard, func(c *config.ServerConfig) { c.RequestTimeout = 100 * time.Millisecond; c.MaxConcurrent = 1 })
		ctx, cancel := context.WithCancel(context.Background())
		r := httptest.NewRequest("POST", "/api/v1/search", strings.NewReader(`{"type":"password","password":"example-password"}`)).WithContext(ctx)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+testToken)
		w := httptest.NewRecorder()
		done := make(chan struct{})
		go func() { defer close(done); h.ServeHTTP(w, r) }()
		<-entered
		if !timeout {
			busy := request(h, "POST", "/api/v1/search", `{"type":"password","password":"example-password"}`, "Bearer "+testToken)
			if busy.Code != 429 || busy.Header().Get("Retry-After") != "1" {
				t.Fatal("admission not bounded")
			}
			cancel()
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("cancellation not propagated")
		}
		cancel()
		status := 408
		if timeout {
			status = 504
		}
		if w.Code != status || !held.Empty() {
			t.Fatal("context status or secret cleanup")
		}
	}
}
func TestConcurrentRequests(t *testing.T) {
	h := handlerFor(t, func(_ context.Context, target models.Target, emit sources.Emit) error {
		return emit(models.NewResult("fixture", models.SourceLocal, target))
	}, io.Discard, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := request(h, "POST", "/api/v1/search", `{"type":"password","password":"example-password"}`, "Bearer "+testToken)
			if w.Code != 200 {
				t.Error("concurrent lookup failed")
			}
		}()
	}
	wg.Wait()
}

func TestTokenRequirementsAndJSONEscapes(t *testing.T) {
	for _, value := range []string{"", "short", strings.Repeat("x", 4097), strings.Repeat("x", 32) + " "} {
		token := security.NewSecret(value)
		if _, e := New(searchFunc(func(context.Context, models.Target, sources.Emit) error { return nil }), token, config.DefaultServerConfig(), nil); e == nil || !token.Empty() {
			t.Fatal("invalid auth configuration accepted or retained")
		}
	}
	for _, body := range []string{`{"type":"password","password":"example-password\uD83D\uDE00"}`, `{"type":"password","password":"example-password\\uD800"}`, `{"type":"password","password":"example-password\uFFFD"}`} {
		raw := []byte(body)
		target, e := decodeRequest(raw)
		if e != nil {
			t.Fatal("valid escaped password rejected")
		}
		target.Secret().Destroy()
		for _, b := range raw {
			if b != 0 {
				t.Fatal("encoded input not cleared")
			}
		}
	}
}
