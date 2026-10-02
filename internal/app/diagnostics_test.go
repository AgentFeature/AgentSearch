package app

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/diagnostics"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

type diagnosticSource struct {
	name string
	call func(context.Context, sources.Emit) error
}

func (s diagnosticSource) Name() string          { return s.name }
func (diagnosticSource) Type() models.SourceType { return models.SourceAPI }
func (s diagnosticSource) SearchEmail(ctx context.Context, _ string, e sources.Emit) error {
	return s.call(ctx, e)
}
func (s diagnosticSource) SearchPassword(ctx context.Context, _ security.Secret, e sources.Emit) error {
	return s.call(ctx, e)
}

func diagnosticRecords(t *testing.T, b *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(b.Bytes()), []byte("\n")) {
		if len(line) > 1024 {
			t.Fatal("unbounded record")
		}
		var row map[string]any
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		records = append(records, row)
	}
	return records
}
func TestRunnerSafeDiagnostics(t *testing.T) {
	password := "synthetic-private-password-9!"
	sum := sha1.Sum([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(sum[:]))
	markers := []string{password, hash, hash[:5], hash[5:], "private-key-marker", "synthetic-full-email@example.test", "https://user:credential@private.test/path", "Bearer private-token-marker", "private-body-marker"}
	private := strings.Join(markers, " | ") + strings.Repeat(" payload\n", 200)
	for _, tc := range []struct {
		name, source       string
		kind               models.TargetType
		status             models.ResultStatus
		category           string
		err, consumer      error
		want, categoryWant string
	}{
		{name: "found", source: "hibp", kind: models.TargetEmail, status: models.StatusFound, want: "success", categoryWant: "none"},
		{name: "absent", source: "hibp", kind: models.TargetEmail, status: models.StatusNotFound, want: "not_found", categoryWant: "none"},
		{name: "auth", source: "hibp", kind: models.TargetEmail, status: models.StatusError, category: "unauthorized", want: "error", categoryWant: "authentication"},
		{name: "raw error", source: private + "end", kind: models.TargetEmail, status: models.StatusFound, err: errors.New(private), want: "error", categoryWant: "provider_error"},
		{name: "cancel", source: "hibp", kind: models.TargetEmail, status: models.StatusFound, err: context.Canceled, want: "canceled", categoryWant: "canceled"},
		{name: "deadline", source: "hibp", kind: models.TargetEmail, status: models.StatusFound, err: context.DeadlineExceeded, want: "deadline_exceeded", categoryWant: "deadline_exceeded"},
		{name: "consumer", source: "hibp", kind: models.TargetEmail, status: models.StatusFound, consumer: errors.New(private), want: "error", categoryWant: "internal_error"},
		{name: "password found", source: "pwned-passwords", kind: models.TargetPassword, status: models.StatusFound, want: "success", categoryWant: "none"},
		{name: "password absent", source: "pwned-passwords-local", kind: models.TargetPassword, status: models.StatusNotFound, want: "not_found", categoryWant: "none"},
		{name: "password error", source: "pwned-passwords", kind: models.TargetPassword, status: models.StatusError, category: private, err: errors.New(private), want: "error", categoryWant: "provider_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			ctx := diagnostics.WithLogger(context.Background(), slog.New(slog.NewJSONHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug})))
			registry := sources.NewRegistry()
			if err := registry.Register(diagnosticSource{tc.source, func(_ context.Context, e sources.Emit) error {
				_ = e(models.Result{Status: tc.status, Source: private, SiteName: private, URL: private, Error: private, Duration: 24 * time.Hour, Metadata: map[string]string{"error_kind": tc.category, "method": private, "occurrences": private}})
				return tc.err
			}}); err != nil {
				t.Fatal(err)
			}
			value := markers[5]
			if tc.kind.Sensitive() {
				value = password
			}
			target, err := models.NewTarget(tc.kind, value)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			err = NewRunner(registry).Search(ctx, target, func(models.Result) error { return tc.consumer })
			elapsed := time.Since(start).Milliseconds()
			if (err != nil) != (tc.err != nil || tc.consumer != nil) {
				t.Fatal("error propagation changed")
			}
			if tc.consumer != nil && !errors.Is(err, tc.consumer) {
				t.Fatal("consumer identity lost")
			}
			if tc.kind.Sensitive() && !target.Secret().Empty() {
				t.Fatal("secret ownership changed")
			}
			for _, marker := range markers {
				if strings.Contains(b.String(), marker) {
					t.Fatal("sensitive material logged")
				}
			}
			records := diagnosticRecords(t, &b)
			if len(records) != 4 {
				t.Fatalf("got %d events", len(records))
			}
			for i, row := range records {
				if i < 2 {
					if row["outcome"] != "started" || row["level"] != "DEBUG" {
						t.Fatal(row)
					}
					continue
				}
				if row["outcome"] != tc.want || row["error_category"] != tc.categoryWant || row["target_type"] != string(tc.kind) {
					t.Fatal(row)
				}
				ms, ok := row["duration_ms"].(float64)
				if !ok || ms < 0 || ms > float64(elapsed) {
					t.Fatal("duration not actual invocation time")
				}
				if i == 2 && row["source"] != diagnostics.Source(tc.source) {
					t.Fatal("wrong provider identity")
				}
				for _, key := range []string{"method", "occurrences", "error", "target", "url"} {
					if _, ok := row[key]; ok {
						t.Fatal("private detail field")
					}
				}
			}
		})
	}
}
func TestRunnerDiagnosticsWaitForProvider(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var b bytes.Buffer
	ctx := diagnostics.WithLogger(context.Background(), slog.New(slog.NewJSONHandler(&b, nil)))
	registry := sources.NewRegistry()
	_ = registry.Register(diagnosticSource{"hibp", func(ctx context.Context, e sources.Emit) error {
		close(entered)
		<-release
		return e(models.Result{Status: models.StatusNotFound})
	}})
	target, _ := models.NewTarget(models.TargetEmail, "private@example.test")
	go func() { done <- NewRunner(registry).Search(ctx, target, func(models.Result) error { return nil }) }()
	<-entered
	// Provider is held at a barrier, so there are no concurrent writes to b.
	premature := b.Len() != 0
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if premature {
		t.Fatal("completion logged before provider returned")
	}
	if rows := diagnosticRecords(t, &b); len(rows) != 2 {
		t.Fatal("missing source/operation completion")
	}
}
func TestRunnerDiagnosticPanicAndInvalidInput(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		var b bytes.Buffer
		ctx := diagnostics.WithLogger(context.Background(), slog.New(slog.NewJSONHandler(&b, nil)))
		registry := sources.NewRegistry()
		_ = registry.Register(diagnosticSource{"hibp", func(context.Context, sources.Emit) error { panic("private-panic-marker") }})
		target, _ := models.NewTarget(models.TargetEmail, "private@example.test")
		if invalid {
			target = models.Target{}
		}
		panicked := false
		func() {
			defer func() {
				if recover() != nil {
					panicked = true
				}
			}()
			_ = NewRunner(registry).Search(ctx, target, func(models.Result) error { return nil })
		}()
		if panicked == invalid {
			t.Fatal("panic behavior changed")
		}
		rows := diagnosticRecords(t, &b)
		want := "internal_error"
		if invalid {
			want = "invalid_request"
		}
		if rows[len(rows)-1]["error_category"] != want || strings.Contains(b.String(), "private-panic-marker") {
			t.Fatal("wrong failure diagnostic")
		}
	}
}

func TestOutputSetupDiagnosticRedaction(t *testing.T) {
	var b bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&b, nil)))
	defer slog.SetDefault(original)
	path := filepath.Join(t.TempDir(), "private-email@example.test")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	application := &App{cfg: &config.AppConfig{OutputDir: path, OutputFormats: []string{"json"}}}
	target, _ := models.NewTarget(models.TargetEmail, "private-email@example.test")
	if err := application.searchTarget(context.Background(), target); err == nil {
		t.Fatal("invalid output destination accepted")
	}
	rows := diagnosticRecords(t, &b)
	if len(rows) != 1 || rows[0]["error_category"] != "internal_error" || strings.Contains(b.String(), "private-email@example.test") {
		t.Fatal("output failure not safely diagnosed")
	}
}
