package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

type orchestrationHTTPSource struct {
	name   string
	search func(context.Context, sources.Emit) error
}

func (s orchestrationHTTPSource) Name() string          { return s.name }
func (orchestrationHTTPSource) Type() models.SourceType { return models.SourceAPI }
func (s orchestrationHTTPSource) SearchUsername(ctx context.Context, _ string, e sources.Emit) error {
	return s.search(ctx, e)
}

func TestHTTPOrchestrationPartialResultsAndDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, kind string
		err        error
		status     int
		category   string
	}{
		{"success", "", nil, 200, "none"},
		{"provider error", "", errors.New("private-provider-error"), 502, "provider_error"},
		{"authentication", "unauthorized", errors.New("private-provider-error"), 503, "authentication"},
		{"canceled", "", context.Canceled, 408, "canceled"},
		{"deadline", "", context.DeadlineExceeded, 504, "deadline_exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := sources.NewRegistry()
			first, second := make(chan struct{}), make(chan struct{})
			a := orchestrationHTTPSource{"first", func(ctx context.Context, e sources.Emit) error {
				close(first)
				<-second
				return e(models.Result{Status: models.StatusFound, Confidence: 88, Evidence: []models.Evidence{{Kind: "observation", Value: "kept"}}, Metadata: map[string]string{"detail": "kept"}})
			}}
			b := orchestrationHTTPSource{"second", func(ctx context.Context, e sources.Emit) error {
				close(second)
				<-first
				if tc.kind != "" {
					if err := e(models.Result{Status: models.StatusError, Error: "private-provider-error", Metadata: map[string]string{"error_kind": tc.kind}}); err != nil {
						return err
					}
				}
				return tc.err
			}}
			if err := registry.Register(a); err != nil {
				t.Fatal(err)
			}
			if err := registry.Register(b); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			h := handlerFor(t, app.NewRunner(registry).Search, &logs, nil)
			h.log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			w := request(h, "POST", "/api/v1/search", `{"type":"username","target":"private-user"}`, "Bearer "+testToken)
			var payload response
			if w.Code != tc.status || json.Unmarshal(w.Body.Bytes(), &payload) != nil || len(payload.Results) < 1 {
				t.Fatal("partial response/status changed", w.Code)
			}
			row := payload.Results[0]
			if row.Source != "first" || !row.Found || row.Confidence != 88 || row.Metadata["detail"] != "kept" || len(row.Evidence) != 1 || row.Evidence[0].Value != "kept" {
				t.Fatal("successful evidence lost")
			}
			if tc.kind != "" && (len(payload.Results) != 2 || payload.Results[1].Source != "second" || payload.Results[1].Status != models.StatusError) {
				t.Fatal("failing observation lost")
			}
			records := httpDiagnosticRecords(t, &logs)
			aggregate := 0
			for _, record := range records {
				if record["request_id"] != w.Header().Get("X-Request-ID") {
					t.Fatal("request context lost in source goroutine")
				}
				if record["operation"] == "search" && record["msg"] == "search completed" {
					aggregate++
					if record["error_category"] != tc.category {
						t.Fatal("aggregate diagnostic depends on source finish order")
					}
				}
			}
			if aggregate != 1 || strings.Contains(logs.String(), "private-") || strings.Contains(logs.String(), testToken) {
				t.Fatal("unsafe/duplicate diagnostics")
			}
		})
	}
}

func TestHTTPOrchestrationPanicAndResultLimit(t *testing.T) {
	for _, panics := range []bool{false, true} {
		t.Run(map[bool]string{false: "result limit", true: "panic"}[panics], func(t *testing.T) {
			registry := sources.NewRegistry()
			entered := make(chan struct{})
			var joined atomic.Bool
			a := orchestrationHTTPSource{"first", func(ctx context.Context, e sources.Emit) error {
				<-entered
				if panics {
					panic("private-provider-panic")
				}
				for i := 0; i <= 10000; i++ {
					if err := e(models.Result{Status: models.StatusFound}); err != nil {
						return err
					}
				}
				return nil
			}}
			b := orchestrationHTTPSource{"second", func(ctx context.Context, e sources.Emit) error {
				defer joined.Store(true)
				close(entered)
				<-ctx.Done()
				return ctx.Err()
			}}
			if err := registry.Register(a); err != nil {
				t.Fatal(err)
			}
			if err := registry.Register(b); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			h := handlerFor(t, app.NewRunner(registry).Search, &logs, nil)
			w := request(h, "POST", "/api/v1/search", `{"type":"username","target":"fixture"}`, "Bearer "+testToken)
			var payload response
			want, code := 503, "result_limit"
			if panics {
				want, code = 500, "internal_error"
			}
			if w.Code != want || json.Unmarshal(w.Body.Bytes(), &payload) != nil || payload.Error == nil || payload.Error.Code != code || !joined.Load() || len(h.admission) != 0 {
				t.Fatal("failure mapping/slot release/join changed")
			}
			if strings.Contains(logs.String(), "private-provider-panic") || strings.Contains(w.Body.String(), "private-provider-panic") {
				t.Fatal("panic value exposed")
			}
		})
	}
}
