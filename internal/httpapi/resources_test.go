package httpapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

type countedBody struct {
	io.Reader
	read   int
	closed bool
}

func (b *countedBody) Read(p []byte) (int, error) { n, e := b.Reader.Read(p); b.read += n; return n, e }
func (b *countedBody) Close() error               { b.closed = true; return nil }
func TestBodyBoundAndAdmissionReleaseOnFailures(t *testing.T) {
	var logs bytes.Buffer
	for _, mode := range []string{"oversized", "malformed", "error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			h := handlerFor(t, func(_ context.Context, _ models.Target, _ sources.Emit) error {
				calls++
				if mode == "panic" {
					panic("example-password")
				}
				return errors.New("example-password")
			}, &logs, func(c *config.ServerConfig) { c.MaxConcurrent = 1 })
			body := `{"type":"password","password":"example-password"}`
			want := 502
			if mode == "oversized" {
				body += strings.Repeat(" ", 4*MaxBodyBytes)
				want = 413
			} else if mode == "malformed" {
				body = `{"type":`
				want = 400
			} else if mode == "panic" {
				want = 500
			}
			reader := &countedBody{Reader: strings.NewReader(body)}
			req := httptest.NewRequest("POST", "/api/v1/search", reader)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+testToken)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != want || !reader.closed || len(h.admission) != 0 {
				t.Fatal("failure did not close body/release admission")
			}
			if mode == "malformed" && calls != 0 {
				t.Fatal("malformed request reached engine")
			}
			if mode == "oversized" && (calls != 0 || reader.read > MaxBodyBytes+1) {
				t.Fatal("oversized input reached engine or exceeded read bound")
			}
			if strings.Contains(w.Body.String(), "example-password") {
				t.Fatal("failure echoed password")
			}
			// A following request must not be rejected by a leaked slot.
			next := request(h, "POST", "/api/v1/search", `{"type":"username","target":"example"}`, "Bearer "+testToken)
			expected := 502
			if mode == "panic" {
				expected = 500
			}
			if next.Code != expected || len(h.admission) != 0 {
				t.Fatal("admission slot unavailable after failure")
			}
		})
	}
	if strings.Contains(logs.String(), "example-password") || strings.Contains(logs.String(), testToken) {
		t.Fatal("secret in operational log")
	}
}
func TestBusyAdmissionRejectsWithoutReadingOrQueueing(t *testing.T) {
	entered := make(chan struct{})
	done := make(chan struct{})
	h := handlerFor(t, func(ctx context.Context, _ models.Target, _ sources.Emit) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}, io.Discard, func(c *config.ServerConfig) { c.MaxConcurrent = 1 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := httptest.NewRequest("POST", "/api/v1/search", strings.NewReader(`{"type":"password","password":"example-password"}`)).WithContext(ctx)
	first.Header.Set("Content-Type", "application/json")
	first.Header.Set("Authorization", "Bearer "+testToken)
	result := httptest.NewRecorder()
	go func() { defer close(done); h.ServeHTTP(result, first) }()
	t.Cleanup(func() { cancel(); awaitLifecycle(t, done) })
	awaitLifecycle(t, entered)
	for _, cancelled := range []bool{false, true} {
		reader := &countedBody{Reader: strings.NewReader(`{"type":"password","password":"example-password"}`)}
		req := httptest.NewRequest("POST", "/api/v1/search", reader)
		if cancelled {
			ctx, stop := context.WithCancel(req.Context())
			stop()
			req = req.WithContext(ctx)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+testToken)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		want := 429
		if cancelled {
			want = 408
		}
		if w.Code != want || reader.read != 0 || !reader.closed || len(h.admission) != 1 {
			t.Fatal("busy/cancelled caller read input or changed admission")
		}
		if !cancelled && w.Header().Get("Retry-After") != "1" {
			t.Fatal("busy retry guidance lost")
		}
	}
	cancel()
	awaitLifecycle(t, done)
	if result.Code != 408 || len(h.admission) != 0 || strings.Contains(result.Body.String(), "example-password") {
		t.Fatal("provider cancellation leaked slot/input")
	}
}
