package diagnostics

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
)

func TestSummaryOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows []models.Result
		err  error
		want Outcome
	}{
		{"empty", nil, nil, Outcome{"success", "none"}},
		{"unclassified is not absence", []models.Result{{Status: models.StatusNotFound}, {Status: "unknown-private-status"}}, nil, Outcome{"success", "none"}},
		{"found", []models.Result{{Status: models.StatusFound}}, nil, Outcome{"success", "none"}},
		{"absent", []models.Result{{Status: models.StatusNotFound}}, nil, Outcome{"not_found", "none"}},
		{"blocked", []models.Result{{Status: models.StatusNotFound}, {Status: models.StatusBlocked}}, nil, Outcome{"blocked", "none"}},
		{"mixed", []models.Result{{Status: models.StatusFound}, {Status: models.StatusError, Metadata: map[string]string{"error_kind": "forbidden"}}}, nil, Outcome{"error", "authentication"}},
		{"rate", []models.Result{{Status: models.StatusError, Metadata: map[string]string{"error_kind": "rate_limited"}}}, nil, Outcome{"error", "rate_limited"}},
		{"bad request", []models.Result{{Status: models.StatusError, Metadata: map[string]string{"error_kind": "bad_request"}}}, nil, Outcome{"error", "invalid_request"}},
		{"error text is not classification", nil, errors.New("unauthorized 429 timeout"), Outcome{"error", "provider_error"}},
		{"canceled", nil, errors.Join(errors.New("private"), context.Canceled), Outcome{"canceled", "canceled"}},
		{"deadline", nil, context.DeadlineExceeded, Outcome{"deadline_exceeded", "deadline_exceeded"}},
		{"legacy error", []models.Result{{Error: "private"}}, nil, Outcome{"error", "provider_error"}},
		{"legacy found", []models.Result{{Found: true}}, nil, Outcome{"success", "none"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s Summary
			for _, r := range tc.rows {
				s.Observe(r)
			}
			if got := s.Finish(context.Background(), tc.err); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := (Summary{}).Finish(ctx, nil); got.Outcome != "canceled" {
		t.Fatal(got)
	}
	ctx, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if got := (Summary{}).Finish(ctx, nil); got.Outcome != "deadline_exceeded" {
		t.Fatal(got)
	}
}
func TestBoundedDiagnosticLabels(t *testing.T) {
	for _, name := range []string{"websites", "hibp", "pwned-passwords", "pwned-passwords-local", "securitytrails"} {
		if Source(name) != name {
			t.Fatal(name)
		}
	}
	marker := strings.Repeat("private\nvalue", 10000)
	var b bytes.Buffer
	ctx := WithLogger(context.Background(), slog.New(slog.NewJSONHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug})))
	var s Summary
	s.Observe(models.Result{Status: models.StatusError, Metadata: map[string]string{"error_kind": marker}, Error: marker, Source: marker})
	Started(ctx, "source_search", models.TargetType(marker), marker)
	Completed(ctx, "source_search", models.TargetType(marker), marker, time.Now(), s.Finish(ctx, errors.New(marker)))
	if b.Len() > 1024 || strings.Contains(b.String(), "private") || !strings.Contains(b.String(), `"source":"other"`) || !strings.Contains(b.String(), `"target_type":"unknown"`) {
		t.Fatal("unsafe/unbounded diagnostics")
	}
}
