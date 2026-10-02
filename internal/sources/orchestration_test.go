package sources

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

type orchestrationSource struct {
	name   string
	search func(context.Context, Emit) error
}

func (s orchestrationSource) Name() string          { return s.name }
func (orchestrationSource) Type() models.SourceType { return models.SourceAPI }
func (s orchestrationSource) SearchUsername(ctx context.Context, _ string, e Emit) error {
	return s.search(ctx, e)
}
func addOrchestrationSource(t *testing.T, r *Registry, name string, f func(context.Context, Emit) error) {
	t.Helper()
	if err := r.Register(orchestrationSource{name, f}); err != nil {
		t.Fatal(err)
	}
}
func orchestrationTarget() models.Target {
	target, _ := models.NewTarget(models.TargetUsername, "fixture-user")
	return target
}

func TestOrchestrationBoundedSelectionAndOrder(t *testing.T) {
	const count = 5
	registry := NewRegistry()
	// This source has no username capability and must never be invoked.
	if err := registry.Register(emailHashSource{}); err != nil {
		t.Fatal(err)
	}
	entered := make(chan int, count)
	release := make([]chan struct{}, count)
	var active, peak, exited atomic.Int32
	for i := 0; i < count; i++ {
		release[i] = make(chan struct{})
		addOrchestrationSource(t, registry, fmt.Sprintf("source-%d", i), func(ctx context.Context, e Emit) error {
			n := active.Add(1)
			defer active.Add(-1)
			defer exited.Add(1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			entered <- i
			select {
			case <-release[i]:
			case <-ctx.Done():
				return ctx.Err()
			}
			row := models.Result{Status: models.StatusFound, Confidence: 71, URL: "https://shared.test/observation", FinalURL: "https://shared.test/final", Duration: 7 * time.Millisecond, Evidence: []models.Evidence{{Kind: "observation", Value: fmt.Sprint(i)}}, Metadata: map[string]string{"detail": "first"}}
			if i == 2 {
				row.Status = models.StatusNotFound
			}
			if i == 1 {
				row.Status = models.StatusError
				row.Error = "safe source failure"
				row.Metadata["error_kind"] = "unauthorized"
			}
			if err := e(row); err != nil {
				return err
			}
			if i == 0 {
				// Identical observations are retained, and source-owned maps/slices can be
				// reused after Emit without mutating already-delivered observations.
				if err := e(row); err != nil {
					return err
				}
				row.Metadata["detail"] = "changed"
				row.Evidence[0].Value = "changed"
			}
			if i == 1 || i == 3 {
				return errors.New("fixture failure")
			}
			return nil
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		rows []models.Result
		err  error
	}
	done := make(chan result, 1)
	go func() {
		var rows []models.Result
		err := NewManager(registry).Search(ctx, orchestrationTarget(), func(r models.Result) error { rows = append(rows, r); return nil })
		done <- result{rows, err}
	}()
	// Both members of each pair must begin before either can be released. The
	// next pair cannot begin until the previous pair's invocation cleanup ends.
	for first := 0; first < count; first += 2 {
		wave := min(2, count-first)
		seen := map[int]bool{}
		for j := 0; j < wave; j++ {
			i := <-entered
			if i < first || i >= first+wave || seen[i] {
				t.Fatal("unexpected selection/batch")
			}
			seen[i] = true
		}
		if first == 0 {
			addOrchestrationSource(t, registry, "late-registration", func(context.Context, Emit) error { t.Error("snapshot changed mid-search"); return nil })
		}
		if exited.Load() != int32(first) {
			t.Fatal("previous batch still running")
		}
		for i := first; i < first+wave; i++ {
			close(release[i])
		}
	}
	got := <-done
	if peak.Load() != 2 || active.Load() != 0 || exited.Load() != count {
		t.Fatal("source bound or joining violated")
	}
	if got.err == nil || got.err.Error() != "source source-1: fixture failure\nsource source-3: fixture failure" {
		t.Fatal("failure order changed", got.err)
	}
	want := []string{"source-0", "source-0", "source-1", "source-2", "source-3", "source-4"}
	if len(got.rows) != len(want) {
		t.Fatal("observation lost or false deduplication")
	}
	for i, row := range got.rows {
		if row.Source != want[i] || row.Target != "fixture-user" || row.SourceType != models.SourceAPI || row.TargetType != models.TargetUsername || row.Confidence != 71 || row.Duration != 7*time.Millisecond || row.Metadata["detail"] != "first" || row.URL != "https://shared.test/observation" || row.FinalURL != "https://shared.test/final" {
			t.Fatal("order/evidence changed", i)
		}
	}
	if !reflect.DeepEqual(got.rows[0], got.rows[1]) || got.rows[0].Evidence[0].Value != "0" || got.rows[2].Status != models.StatusError || got.rows[2].Metadata["error_kind"] != "unauthorized" || got.rows[3].Status != models.StatusNotFound || got.rows[3].Found {
		t.Fatal("source semantics changed")
	}
}

func TestOrchestrationIndependentFailureAndDeadline(t *testing.T) {
	// A provider-local deadline is not the parent deadline and must not cancel a
	// sibling, even when that sibling has not yet produced its successful row.
	registry := NewRegistry()
	both := make(chan struct{})
	failed := make(chan struct{})
	deadline := time.Now().Add(time.Hour)
	type key struct{}
	ctx, cancel := context.WithDeadline(context.WithValue(context.Background(), key{}, "request-value"), deadline)
	defer cancel()
	addOrchestrationSource(t, registry, "first", func(c context.Context, e Emit) error {
		<-both
		close(failed)
		return &contractFailure{cause: context.DeadlineExceeded}
	})
	addOrchestrationSource(t, registry, "second", func(c context.Context, e Emit) error {
		close(both)
		<-failed
		d, ok := c.Deadline()
		if !ok || d != deadline || c.Value(key{}) != "request-value" || c.Err() != nil {
			t.Error("parent context lost or sibling canceled")
		}
		return e(models.Result{Status: models.StatusFound})
	})
	var rows []models.Result
	err := NewManager(registry).Search(ctx, orchestrationTarget(), func(r models.Result) error { rows = append(rows, r); return nil })
	if !errors.Is(err, context.DeadlineExceeded) || len(rows) != 1 || !rows[0].Found || rows[0].Source != "second" || ctx.Err() != nil {
		t.Fatal("partial result/deadline identity lost")
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	var calls atomic.Int32
	r := NewRegistry()
	for _, name := range []string{"one", "two"} {
		addOrchestrationSource(t, r, name, func(context.Context, Emit) error { calls.Add(1); return nil })
	}
	if err := NewManager(r).Search(expired, orchestrationTarget(), func(models.Result) error { return nil }); !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 0 {
		t.Fatal("expired parent dispatched sources")
	}
}

func TestOrchestrationCancellationJoinsLaunchedWork(t *testing.T) {
	registry := NewRegistry()
	entered := make(chan struct{}, 2)
	cleanup := make(chan struct{}, 2)
	release := make(chan struct{})
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
	addOrchestrationSource(t, registry, "unlaunched", func(context.Context, Emit) error { t.Error("dispatch after cancellation"); return nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- NewManager(registry).Search(ctx, orchestrationTarget(), func(models.Result) error { t.Error("unexpected observation"); return nil })
	}()
	<-entered
	<-entered
	cancel()
	<-cleanup
	<-cleanup
	early := false
	select {
	case <-done:
		early = true
	default:
	}
	close(release)
	if early {
		t.Fatal("returned before launched work was joined")
	}
	if err := <-done; !errors.Is(err, context.Canceled) || exited.Load() != 2 {
		t.Fatal("cancellation or cleanup lost")
	}
}

func TestOrchestrationConsumerStopAndPanic(t *testing.T) {
	for _, panics := range []bool{false, true} {
		t.Run(fmt.Sprint(panics), func(t *testing.T) {
			registry := NewRegistry()
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			var exited atomic.Int32
			for _, name := range []string{"first", "second"} {
				addOrchestrationSource(t, registry, name, func(ctx context.Context, e Emit) error {
					defer exited.Add(1)
					entered <- struct{}{}
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
					for i := 0; i < 3; i++ {
						if err := e(models.Result{Status: models.StatusFound}); err != nil {
							return err
						}
					}
					return nil
				})
			}
			stop := errors.New("consumer stopped")
			calls := 0
			type outcome struct {
				err        error
				panicValue any
			}
			done := make(chan outcome, 1)
			go func() {
				var o outcome
				defer func() { o.panicValue = recover(); done <- o }()
				o.err = NewManager(registry).Search(context.Background(), orchestrationTarget(), func(models.Result) error {
					calls++
					if panics {
						panic(stop)
					}
					return stop
				})
			}()
			<-entered
			<-entered
			close(release)
			got := <-done
			if calls != 1 || exited.Load() != 2 {
				t.Fatal("consumer concurrency/backpressure or joining violated")
			}
			if panics {
				if got.panicValue != stop {
					t.Fatal("consumer panic changed")
				}
			} else if !errors.Is(got.err, stop) {
				t.Fatal("consumer error identity changed")
			}
		})
	}
}

func TestOrchestrationSourcePanicRejoinsCaller(t *testing.T) {
	registry := NewRegistry()
	entered := make(chan struct{})
	cleanup := make(chan struct{})
	release := make(chan struct{})
	var exited atomic.Bool
	marker := errors.New("private panic value")
	addOrchestrationSource(t, registry, "first", func(ctx context.Context, e Emit) error {
		defer exited.Store(true)
		close(entered)
		<-ctx.Done()
		close(cleanup)
		<-release
		return ctx.Err()
	})
	addOrchestrationSource(t, registry, "second", func(context.Context, Emit) error { <-entered; panic(marker) })
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		_ = NewManager(registry).Search(context.Background(), orchestrationTarget(), func(models.Result) error { return nil })
	}()
	<-cleanup
	early := false
	select {
	case <-done:
		early = true
	default:
	}
	close(release)
	if early {
		t.Fatal("panic propagated before sibling cleanup")
	}
	if got := <-done; got != marker || !exited.Load() {
		t.Fatal("panic swallowed/changed or sibling leaked")
	}
}

type orchestrationPasswordSource struct {
	name   string
	search func(context.Context, security.Secret, Emit) error
}

func (s orchestrationPasswordSource) Name() string          { return s.name }
func (orchestrationPasswordSource) Type() models.SourceType { return models.SourceLocal }
func (s orchestrationPasswordSource) SearchPassword(ctx context.Context, secret security.Secret, e Emit) error {
	return s.search(ctx, secret, e)
}
func TestOrchestrationPasswordStaysSynchronous(t *testing.T) {
	registry := NewRegistry()
	ctx := context.WithValue(context.Background(), struct{}{}, "fixture")
	password := " exact synthetic password bytes "
	first := orchestrationPasswordSource{"first", func(c context.Context, secret security.Secret, e Emit) error {
		if c != ctx {
			t.Fatal("password entered concurrent child-context path")
		}
		if err := secret.Consume(func(b []byte) error {
			if string(b) != password {
				t.Error("password bytes changed")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return e(models.Result{Status: models.StatusNotFound})
	}}
	second := orchestrationPasswordSource{"second", func(context.Context, security.Secret, Emit) error {
		t.Fatal("password consumer stop ignored")
		return nil
	}}
	if err := registry.Register(first); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(second); err != nil {
		t.Fatal(err)
	}
	target, _ := models.NewTarget(models.TargetPassword, password)
	stop := errors.New("stop")
	err := NewManager(registry).Search(ctx, target, func(r models.Result) error {
		if r.Target != security.Redacted || strings.Contains(r.Error, password) {
			t.Fatal("secret exposed")
		}
		return stop
	})
	if err != stop || !target.Secret().Empty() {
		t.Fatal("password ownership/consumer identity changed")
	}
}
