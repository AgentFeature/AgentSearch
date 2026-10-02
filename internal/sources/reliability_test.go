package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/diagnostics"
	"github.com/AgentFeature/agentsearch/internal/models"
)

// A controlled parent deadline event: both sources enter before expiry is
// signaled. No race against a short wall-clock deadline is needed to test identity.
type signaledDeadline struct {
	context.Context
	done chan struct{}
	at   time.Time
}

func (c signaledDeadline) Done() <-chan struct{}       { return c.done }
func (c signaledDeadline) Deadline() (time.Time, bool) { return c.at, true }
func (c signaledDeadline) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}
func awaitReliability(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("cooperative work did not complete")
	}
}

func TestActiveOrchestrationDeadlineJoins(t *testing.T) {
	parent := signaledDeadline{context.Background(), make(chan struct{}), time.Now().Add(time.Hour)}
	var once sync.Once
	expire := func() { once.Do(func() { close(parent.done) }) }
	defer expire()
	registry := NewRegistry()
	entered := make(chan struct{}, 2)
	cleanup := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var exited atomic.Int32
	for _, name := range []string{"first", "second"} {
		addOrchestrationSource(t, registry, name, func(ctx context.Context, e Emit) error {
			defer exited.Add(1)
			entered <- struct{}{}
			<-ctx.Done()
			cleanup <- struct{}{}
			<-release
			return ctx.Err()
		})
	}
	addOrchestrationSource(t, registry, "unlaunched", func(context.Context, Emit) error { t.Error("launch after deadline"); return nil })
	done := make(chan struct{})
	var result error
	go func() {
		defer close(done)
		result = NewManager(registry).Search(parent, orchestrationTarget(), func(models.Result) error { t.Error("unexpected row"); return nil })
	}()
	t.Cleanup(func() { expire(); unblock(); awaitReliability(t, done) })
	awaitReliability(t, entered)
	awaitReliability(t, entered)
	expire()
	awaitReliability(t, cleanup)
	awaitReliability(t, cleanup)
	select {
	case <-done:
		t.Error("returned before cleanup joined")
	default:
	}
	unblock()
	awaitReliability(t, done)
	if !errors.Is(result, context.DeadlineExceeded) || errors.Is(result, context.Canceled) || exited.Load() != 2 {
		t.Fatal("active deadline identity/cleanup lost")
	}
}

func TestProviderLocalCancellationDoesNotCancelSibling(t *testing.T) {
	registry := NewRegistry()
	entered := make(chan struct{})
	failed := make(chan struct{})
	addOrchestrationSource(t, registry, "first", func(context.Context, Emit) error {
		<-entered
		close(failed)
		return &contractFailure{cause: context.Canceled}
	})
	addOrchestrationSource(t, registry, "second", func(ctx context.Context, e Emit) error {
		close(entered)
		<-failed
		if ctx.Err() != nil {
			t.Error("provider-local cancellation canceled sibling")
		}
		return e(models.Result{Status: models.StatusFound})
	})
	var rows []models.Result
	err := NewManager(registry).Search(context.Background(), orchestrationTarget(), func(r models.Result) error { rows = append(rows, r); return nil })
	if !errors.Is(err, context.Canceled) || len(rows) != 1 || rows[0].Source != "second" || !rows[0].Found {
		t.Fatal("local cancellation/partial evidence lost")
	}
}

func TestConsumerStopDiagnosticsAndCleanup(t *testing.T) {
	for _, stop := range []error{context.Canceled, errors.New("private-consumer-stop")} {
		t.Run(diagnostics.ErrorCategory(stop, "internal_error"), func(t *testing.T) {
			registry := NewRegistry()
			entered := make(chan struct{})
			var exited atomic.Int32
			addOrchestrationSource(t, registry, "hibp", func(ctx context.Context, e Emit) error {
				defer exited.Add(1)
				<-entered
				return e(models.Result{Status: models.StatusFound})
			})
			addOrchestrationSource(t, registry, "securitytrails", func(ctx context.Context, e Emit) error {
				defer exited.Add(1)
				close(entered)
				<-ctx.Done()
				return ctx.Err()
			})
			addOrchestrationSource(t, registry, "unlaunched", func(context.Context, Emit) error { t.Error("launch after consumer stop"); return nil })
			var logs bytes.Buffer
			parent := diagnostics.WithLogger(context.Background(), slog.New(slog.NewJSONHandler(&logs, nil)))
			calls := 0
			err := NewManager(registry).Search(parent, orchestrationTarget(), func(models.Result) error { calls++; return stop })
			if err != stop || parent.Err() != nil || calls != 1 || exited.Load() != 2 {
				t.Fatal("consumer ownership/identity/cleanup lost")
			}
			records := 0
			for _, line := range bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n")) {
				var row map[string]any
				if json.Unmarshal(line, &row) != nil {
					t.Fatal("invalid diagnostic")
				}
				records++
				want := "canceled"
				if row["source"] == "hibp" {
					want = diagnostics.ErrorCategory(stop, "internal_error")
				}
				if row["error_category"] != want {
					t.Fatal("consumer/internal cancellation reported as provider failure")
				}
			}
			if records != 2 || strings.Contains(logs.String(), "private-") || strings.Contains(logs.String(), "fixture-user") {
				t.Fatal("unsafe/missing diagnostics")
			}
		})
	}
}

func TestConcurrentSourcePanicsPreserveRegistryPrecedence(t *testing.T) {
	registry := NewRegistry()
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var exited atomic.Int32
	markers := []error{errors.New("first private panic"), errors.New("second private panic")}
	for i, name := range []string{"first", "second"} {
		addOrchestrationSource(t, registry, name, func(context.Context, Emit) error {
			defer exited.Add(1)
			entered <- struct{}{}
			<-release
			panic(markers[i])
		})
	}
	done := make(chan struct{})
	var value any
	go func() {
		defer close(done)
		defer func() { value = recover() }()
		_ = NewManager(registry).Search(context.Background(), orchestrationTarget(), func(models.Result) error { return nil })
	}()
	t.Cleanup(func() { unblock(); awaitReliability(t, done) })
	awaitReliability(t, entered)
	awaitReliability(t, entered)
	unblock()
	awaitReliability(t, done)
	if value != markers[0] || exited.Load() != 2 {
		t.Fatal("panic precedence/join lost")
	}
}
