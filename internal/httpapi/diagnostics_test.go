package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
	"github.com/AgentFeature/agentsearch/internal/sources/hibp"
)

func httpDiagnosticRecords(t *testing.T, b *bytes.Buffer) []map[string]any {
	t.Helper()
	var rows []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(b.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if len(line) > 1024 {
			t.Fatal("unbounded HTTP diagnostic")
		}
		var row map[string]any
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	return rows
}
func TestHTTPDiagnosticOutcomesAndRedaction(t *testing.T) {
	private := "private-email@example.test private-token-marker private-body-marker https://user:credential@private.test/secret"
	for _, tc := range []struct {
		name              string
		status            models.ResultStatus
		kind              string
		err               error
		http              int
		outcome, category string
	}{
		{"success", models.StatusFound, "", nil, 200, "success", "none"},
		{"absence", models.StatusNotFound, "", nil, 200, "not_found", "none"},
		{"raw error", "", "", errors.New(private), 502, "error", "provider_error"},
		{"authentication", models.StatusError, "unauthorized", nil, 503, "error", "authentication"},
		{"typed authentication", "", "", &hibp.Error{Kind: hibp.Forbidden}, 503, "error", "authentication"},
		{"rate", models.StatusError, "rate_limited", nil, 429, "error", "rate_limited"},
		{"bad request", models.StatusError, "bad_request", nil, 502, "error", "invalid_request"},
		{"unknown metadata", models.StatusError, private, nil, 502, "error", "provider_error"},
		{"cancel", "", "", context.Canceled, 408, "canceled", "canceled"},
		{"deadline", "", "", context.DeadlineExceeded, 504, "deadline_exceeded", "deadline_exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			h := handlerFor(t, func(_ context.Context, target models.Target, e sources.Emit) error {
				if tc.status != "" {
					if err := e(models.Result{Status: tc.status, TargetType: target.Type(), Target: target.String(), Error: private, Metadata: map[string]string{"error_kind": tc.kind, "body": strings.Repeat(private, 1000)}}); err != nil {
						return err
					}
				}
				return tc.err
			}, &b, nil)
			h.log = slog.New(slog.NewJSONHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug}))
			w := request(h, "POST", "/api/v1/search", `{"type":"password","password":"private-password-marker"}`, "Bearer "+testToken)
			if w.Code != tc.http {
				t.Fatalf("status=%d want=%d", w.Code, tc.http)
			}
			rows := httpDiagnosticRecords(t, &b)
			last := rows[len(rows)-1]
			if last["outcome"] != tc.outcome || last["error_category"] != tc.category || last["target_type"] != "password" || last["active_searches"] != float64(0) || last["method"] != "POST" {
				t.Fatal(last)
			}
			if last["request_id"] != w.Header().Get("X-Request-ID") || len(last["request_id"].(string)) != 32 {
				t.Fatal("request ID mismatch")
			}
			for _, marker := range append(strings.Split(private, " "), "private-password-marker", testToken, "example-password") {
				if strings.Contains(b.String(), marker) {
					t.Fatal("secret in HTTP logs")
				}
			}
		})
	}
}
func TestHTTPDiagnosticRejectionsAndHealth(t *testing.T) {
	marker := "PRIVATE-INJECTION-MARKER"
	for _, tc := range []struct {
		method, path, body, auth string
		status                   int
		category                 string
	}{
		{marker, "/" + marker, "", "", 404, "invalid_request"},
		{marker, "/api/v1/search", "", "", 405, "invalid_request"},
		{"POST", "/api/v1/search?secret=" + marker, "{}", "Bearer " + testToken, 400, "invalid_request"},
		{"POST", "/api/v1/search", "{}", "Bearer " + marker, 401, "authentication"},
		{"POST", "/api/v1/search", `{"type":"` + marker + `"}`, "Bearer " + testToken, 400, "invalid_request"},
		{"POST", "/api/v1/search", strings.Repeat(marker, MaxBodyBytes), "Bearer " + testToken, 413, "resource_limit"},
	} {
		var b bytes.Buffer
		h := handlerFor(t, func(context.Context, models.Target, sources.Emit) error {
			t.Fatal("invalid request invoked provider")
			return nil
		}, &b, nil)
		h.log = slog.New(slog.NewJSONHandler(&b, nil))
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Authorization", tc.auth)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Cookie", marker)
		r.Header.Set("X-Request-ID", marker)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("status=%d want=%d", w.Code, tc.status)
		}
		rows := httpDiagnosticRecords(t, &b)
		last := rows[len(rows)-1]
		if strings.Contains(b.String(), marker) || last["outcome"] != "rejected" || last["error_category"] != tc.category {
			t.Fatal("unsafe/wrong rejection diagnostic")
		}
		if tc.method == marker && last["method"] != "OTHER" {
			t.Fatal("arbitrary method logged")
		}
	}
	var b bytes.Buffer
	h := handlerFor(t, func(context.Context, models.Target, sources.Emit) error { return nil }, &b, nil)
	h.log = slog.New(slog.NewJSONHandler(&b, nil))
	_ = request(h, "GET", "/health", "", "")
	if b.Len() != 0 {
		t.Fatal("healthy health check logged at info")
	}
	_ = request(h, "POST", "/health", "", "")
	if rows := httpDiagnosticRecords(t, &b); len(rows) != 1 || rows[0]["level"] != "INFO" {
		t.Fatal("failed health check invisible")
	}
	b.Reset()
	h.log = slog.New(slog.NewJSONHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug}))
	_ = request(h, "GET", "/health", "", "")
	if rows := httpDiagnosticRecords(t, &b); len(rows) != 1 || rows[0]["level"] != "DEBUG" {
		t.Fatal("debug health check unavailable")
	}
}
func TestHTTPDiagnosticAdmissionAndCancellation(t *testing.T) {
	var b bytes.Buffer
	entered, done := make(chan struct{}), make(chan *httptest.ResponseRecorder, 1)
	h := handlerFor(t, func(ctx context.Context, _ models.Target, _ sources.Emit) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}, &b, func(c *config.ServerConfig) { c.MaxConcurrent = 1 })
	h.log = slog.New(slog.NewJSONHandler(&b, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("POST", "/api/v1/search", strings.NewReader(`{"type":"username","target":"private-user"}`)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Content-Type", "application/json")
	go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, r); done <- w }()
	<-entered
	rejected := request(h, "POST", "/api/v1/search", `{}`, "Bearer "+testToken)
	cancel()
	finished := <-done
	if rejected.Code != 429 || rejected.Header().Get("Retry-After") != "1" || finished.Code != 408 {
		t.Fatal("admission/cancellation changed")
	}
	rows := httpDiagnosticRecords(t, &b)
	if len(rows) != 3 {
		t.Fatal("wrong number of events")
	}
	if rows[0]["outcome"] != "started" || rows[0]["active_searches"] != float64(1) || rows[0]["max_concurrent"] != float64(1) {
		t.Fatal(rows[0])
	}
	if rows[1]["outcome"] != "rejected" || rows[1]["error_category"] != "resource_limit" || rows[1]["active_searches"] != float64(1) {
		t.Fatal(rows[1])
	}
	if rows[2]["outcome"] != "canceled" || rows[2]["active_searches"] != float64(0) || len(h.admission) != 0 {
		t.Fatal(rows[2])
	}
}

type httpDiagnosticSource struct{}

func (httpDiagnosticSource) Name() string            { return "hibp" }
func (httpDiagnosticSource) Type() models.SourceType { return models.SourceAPI }
func (httpDiagnosticSource) SearchEmail(_ context.Context, _ string, e sources.Emit) error {
	return e(models.Result{Status: models.StatusNotFound})
}
func TestHTTPDiagnosticRunnerCorrelation(t *testing.T) {
	var b bytes.Buffer
	h := handlerFor(t, func(context.Context, models.Target, sources.Emit) error { return nil }, &b, nil)
	registry := sources.NewRegistry()
	_ = registry.Register(httpDiagnosticSource{})
	h.searcher = app.NewRunner(registry)
	h.log = slog.New(slog.NewJSONHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug}))
	start := time.Now()
	w := request(h, http.MethodPost, "/api/v1/search", `{"type":"email","target":"private-email@example.test"}`, "Bearer "+testToken)
	elapsed := time.Since(start).Milliseconds()
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	rows := httpDiagnosticRecords(t, &b)
	if len(rows) != 6 {
		t.Fatalf("missing correlated events: %d", len(rows))
	}
	for _, row := range rows {
		if row["request_id"] != w.Header().Get("X-Request-ID") {
			t.Fatal("source/Runner/request logs not correlated")
		}
		if ms, ok := row["duration_ms"].(float64); ok && (ms < 0 || ms > float64(elapsed)) {
			t.Fatal("wrong elapsed time")
		}
	}
	if strings.Contains(b.String(), "private-email@example.test") {
		t.Fatal("full email in logs")
	}
}
func TestHTTPDiagnosticPanicAndResultLimit(t *testing.T) {
	for _, limited := range []bool{false, true} {
		var b bytes.Buffer
		h := handlerFor(t, func(_ context.Context, _ models.Target, e sources.Emit) error {
			if !limited {
				panic("private-panic-marker")
			}
			for i := 0; i <= 10000; i++ {
				if err := e(models.Result{Status: models.StatusFound}); err != nil {
					return err
				}
			}
			return nil
		}, &b, nil)
		h.log = slog.New(slog.NewJSONHandler(&b, nil))
		w := request(h, "POST", "/api/v1/search", `{"type":"username","target":"private-user"}`, "Bearer "+testToken)
		rows := httpDiagnosticRecords(t, &b)
		last := rows[len(rows)-1]
		status, want := 500, "internal_error"
		if limited {
			status, want = 503, "resource_limit"
		}
		if w.Code != status || last["error_category"] != want || last["active_searches"] != float64(0) || strings.Contains(b.String(), "private-") {
			t.Fatal("unsafe/incomplete failure diagnostic")
		}
	}
}
