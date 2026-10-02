package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
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
	"github.com/AgentFeature/agentsearch/internal/network"
	"github.com/AgentFeature/agentsearch/internal/ratelimit"
	"github.com/AgentFeature/agentsearch/internal/sources"
	"github.com/AgentFeature/agentsearch/internal/sources/websites"
)

type reliabilityTransport func(*http.Request) (*http.Response, error)

func (f reliabilityTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWebsiteConsumerPanicJoinsBeforeHTTPRecovery(t *testing.T) {
	entered, cleanup, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var exited, joinedAtUnwind, samePanic atomic.Bool
	client := &http.Client{Transport: reliabilityTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "slow.test" {
			close(entered)
			<-r.Context().Done()
			close(cleanup)
			<-release
			exited.Store(true)
			return nil, r.Context().Err()
		}
		<-entered
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	ua, err := network.NewUARotator("")
	if err != nil {
		t.Fatal(err)
	}
	source, err := websites.New([]models.SiteConfig{{Name: "fast", URL: "https://fast.test/{username}"}, {Name: "slow", URL: "https://slow.test/{username}"}}, 2, client, ua, ratelimit.NewHostLimiter(0))
	if err != nil {
		t.Fatal(err)
	}
	registry := sources.NewRegistry()
	if err = registry.Register(source); err != nil {
		t.Fatal(err)
	}
	runner := app.NewRunner(registry)
	const marker = "private-consumer-panic"
	var calls atomic.Int32
	var logs bytes.Buffer
	h := handlerFor(t, func(ctx context.Context, target models.Target, _ sources.Emit) error {
		if calls.Add(1) > 1 {
			return nil
		}
		defer func() {
			if value := recover(); value != nil {
				samePanic.Store(value == marker)
				joinedAtUnwind.Store(exited.Load())
				panic(value)
			}
		}()
		return runner.Search(ctx, target, func(models.Result) error { panic(marker) })
	}, &logs, func(c *config.ServerConfig) { c.MaxConcurrent = 1 })
	h.log = slog.New(slog.NewJSONHandler(&logs, nil))
	done := make(chan struct{})
	var reply *httptest.ResponseRecorder
	go func() {
		defer close(done)
		reply = request(h, "POST", "/api/v1/search", `{"type":"username","target":"private-user"}`, "Bearer "+testToken)
	}()
	t.Cleanup(func() { unblock(); awaitLifecycle(t, done) })
	awaitLifecycle(t, cleanup)
	if len(h.admission) != 1 {
		t.Error("admission released while website cleanup is active")
	}
	// A worker acknowledges cancellation but intentionally holds its cleanup.
	// Capture the invariant at unwind, not through scheduler-dependent sleeps.
	unblock()
	awaitLifecycle(t, done)
	if !samePanic.Load() || !joinedAtUnwind.Load() {
		t.Fatal("consumer panic escaped before website work joined")
	}
	if reply.Code != 500 || len(h.admission) != 0 {
		t.Fatal("panic recovery/slot cleanup changed")
	}
	id := reply.Header().Get("X-Request-ID")
	for _, record := range httpDiagnosticRecords(t, &logs) {
		if record["request_id"] != id {
			t.Fatal("request correlation lost")
		}
		if record["msg"] == "search completed" && record["error_category"] != "internal_error" {
			t.Fatal("panic misclassified")
		}
	}
	if strings.Contains(logs.String(), "private-") || strings.Contains(logs.String(), testToken) || strings.Contains(reply.Body.String(), marker) {
		t.Fatal("panic diagnostic leak")
	}
	if next := request(h, "POST", "/api/v1/search", `{"type":"username","target":"fixture"}`, "Bearer "+testToken); next.Code != 200 || len(h.admission) != 0 {
		t.Fatal("slot unavailable after panic")
	}
}

func TestExpiredRequestDistinguishesDeadlineBeforeAdmission(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "deadline"}[deadline], func(t *testing.T) {
			var calls int
			var logs bytes.Buffer
			h := handlerFor(t, func(context.Context, models.Target, sources.Emit) error { calls++; return nil }, &logs, nil)
			var ctx context.Context
			var cancel context.CancelFunc
			if deadline {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			cancel()
			body := &countedBody{Reader: strings.NewReader(`{"type":"username","target":"private-user"}`)}
			r := httptest.NewRequest("POST", "/api/v1/search", body).WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+testToken)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want, code := 408, "cancelled"
			if deadline {
				want, code = 504, "timeout"
			}
			if w.Code != want || !strings.Contains(w.Body.String(), `"code":"`+code+`"`) || calls != 0 || body.read != 0 || !body.closed || len(h.admission) != 0 {
				t.Fatal("expired request lost identity or performed work", w.Code)
			}
			if strings.Contains(logs.String(), "private-") || strings.Contains(logs.String(), testToken) {
				t.Fatal("expired request leak")
			}
			if next := request(h, "POST", "/api/v1/search", `{"type":"username","target":"fixture"}`, "Bearer "+testToken); next.Code != 200 || len(h.admission) != 0 || calls != 1 {
				t.Fatal("expired request retained capacity")
			}
		})
	}
}

func TestShutdownDuringOrderedSourceDelivery(t *testing.T) {
	for _, forced := range []bool{false, true} {
		t.Run(map[bool]string{false: "grace", true: "forced"}[forced], func(t *testing.T) {
			cfg := config.DefaultServerConfig()
			if forced {
				cfg.ShutdownTimeout = 100 * time.Millisecond
			}
			firstEntered, secondSending := make(chan struct{}), make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			sourceContext := make(chan context.Context, 1)
			var exited atomic.Int32
			registry := sources.NewRegistry()
			first := orchestrationHTTPSource{"first", func(ctx context.Context, e sources.Emit) error {
				defer exited.Add(1)
				sourceContext <- ctx
				close(firstEntered)
				select {
				case <-release:
				case <-ctx.Done():
					<-release
					return ctx.Err()
				}
				return e(models.Result{Status: models.StatusFound})
			}}
			second := orchestrationHTTPSource{"second", func(ctx context.Context, e sources.Emit) error {
				defer exited.Add(1)
				<-firstEntered
				close(secondSending)
				return e(models.Result{Status: models.StatusFound}) // Ordered behind the blocked first source.
			}}
			if err := registry.Register(first); err != nil {
				t.Fatal(err)
			}
			if err := registry.Register(second); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			h := handlerFor(t, app.NewRunner(registry).Search, &logs, func(c *config.ServerConfig) { c.MaxConcurrent = 1 })
			h.log = slog.New(slog.NewJSONHandler(&logs, nil))
			handlerDone := make(chan struct{})
			observed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(handlerDone); h.ServeHTTP(w, r) })
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			tracked := &closingListener{Listener: listener, closed: make(chan struct{})}
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			serverDone := make(chan struct{})
			var serverErr error
			go func() { defer close(serverDone); serverErr = Serve(ctx, tracked, observed, cfg, h.log) }()
			t.Cleanup(func() { unblock(); stop(); awaitLifecycle(t, serverDone) })
			reply := make(chan lifecycleReply, 1)
			go func() {
				client := &http.Client{Timeout: 5 * time.Second}
				defer client.CloseIdleConnections()
				req, _ := http.NewRequest("POST", "http://"+listener.Addr().String()+"/api/v1/search", strings.NewReader(`{"type":"username","target":"private-user"}`))
				req.Header.Set("Authorization", "Bearer "+testToken)
				req.Header.Set("Content-Type", "application/json")
				res, err := client.Do(req)
				if err != nil {
					reply <- lifecycleReply{err: err}
					return
				}
				defer res.Body.Close()
				body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
				reply <- lifecycleReply{status: res.StatusCode, body: string(body), err: err}
			}()
			awaitLifecycle(t, secondSending)
			t.Cleanup(func() { unblock(); awaitLifecycle(t, handlerDone) })
			requestCtx := <-sourceContext
			stop()
			awaitLifecycle(t, tracked.closed)
			if forced {
				awaitLifecycle(t, requestCtx.Done())
				awaitLifecycle(t, serverDone)
				if serverErr == nil || len(h.admission) != 1 {
					t.Error("forced shutdown waited for blocked cleanup or released slot early")
				}
			} else if requestCtx.Err() != nil {
				t.Error("grace canceled active orchestration")
			}
			unblock()
			awaitLifecycle(t, handlerDone)
			awaitLifecycle(t, serverDone)
			if exited.Load() != 2 || len(h.admission) != 0 {
				t.Fatal("source/slot cleanup incomplete")
			}
			select {
			case res := <-reply:
				if !forced {
					var payload response
					if serverErr != nil || res.err != nil || res.status != 200 || json.Unmarshal([]byte(res.body), &payload) != nil || len(payload.Results) != 2 || payload.Results[0].Source != "first" || payload.Results[1].Source != "second" {
						t.Fatal("grace lost ordered partial work")
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("HTTP client did not finish")
			}
			want := "none"
			if forced {
				want = "canceled"
			}
			id := ""
			completed := 0
			for _, record := range httpDiagnosticRecords(t, &logs) {
				if record["msg"] == "search completed" || record["msg"] == "http request" {
					completed++
					rid, _ := record["request_id"].(string)
					if id == "" {
						id = rid
					}
					if len(rid) != 32 || rid != id || record["error_category"] != want {
						t.Fatal("shutdown diagnostic identity/classification lost")
					}
				}
			}
			if completed != 4 || strings.Contains(logs.String(), "private-user") || strings.Contains(logs.String(), testToken) {
				t.Fatal("shutdown diagnostic leak/missing completion")
			}
		})
	}
}
