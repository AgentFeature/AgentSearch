package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

func parseTarget(kind, value string) (models.Target, error) {
	return app.NewSearchTarget(kind, value, nil)
}
func target(t testing.TB, value string) models.Target {
	t.Helper()
	v, e := models.NewDomainTarget(value)
	if e != nil {
		t.Fatal(e)
	}
	return v
}

type searchFunc func(context.Context, models.Target, sources.Emit) error

func (f searchFunc) Search(c context.Context, t models.Target, e sources.Emit) error {
	return f(c, t, e)
}
func row(source, kind, value string) models.Result {
	return models.Result{Source: source, SourceType: models.SourceAPI, Status: models.StatusFound, URL: "https://provider.example/api", Metadata: map[string]string{"provider": "fixture"}, Evidence: []models.Evidence{{Kind: kind, Value: value}}}
}
func openTestStore(t testing.TB, dir string) *Store {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("monitor durable storage requires Linux")
	}
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := OpenStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func newTestEngine(t *testing.T, dir string, targets []models.Target, f searchFunc) (*Engine, *bytes.Buffer) {
	t.Helper()
	s := openTestStore(t, dir)
	var alerts bytes.Buffer
	e, err := New(f, s, targets, DefaultOptions(), &alerts)
	if err != nil {
		t.Fatal(err)
	}
	return e, &alerts
}
func lines(t testing.TB, dir, name string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	return bytes.Split(raw, []byte{'\n'})
}
func readChanges(t testing.TB, dir string) []Change {
	t.Helper()
	out := []Change{}
	for _, line := range lines(t, dir, "changes") {
		var e Change
		if json.Unmarshal(line, &e) != nil {
			t.Fatal("bad event")
		}
		out = append(out, e)
	}
	return out
}
func cycle(t *testing.T, e *Engine) {
	t.Helper()
	if err := e.cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWatchlistValidationAndIdentity(t *testing.T) {
	raw := []byte("targets:\n  - type: domain\n    value: ' EXAMPLE.COM. '\n  - type: username\n    value: Alice\n  - type: domain\n    value: example.com\n  - type: bitcoin_tx\n    value: " + strings.Repeat("A", 64) + "\n")
	targets, err := ParseWatchlist(raw, parseTarget)
	if err != nil || len(targets) != 3 {
		t.Fatal(targets, err)
	}
	if targets[0].Type() != models.TargetBitcoinTransaction || targets[0].Value() != strings.Repeat("a", 64) || targets[1].Value() != "example.com" || targets[2].Value() != "Alice" {
		t.Fatal("normalization/order")
	}
	a := target(t, "EXAMPLE.COM.")
	b := target(t, "example.com")
	if Identity(a) != Identity(b) || !validStorageKey(Identity(a)) {
		t.Fatal("unstable identity")
	}
	u, _ := models.NewTarget(models.TargetUsername, "example.com")
	if Identity(u) == Identity(b) {
		t.Fatal("type collision")
	}
	for _, bad := range []string{"", "targets: []", "targets: null", "unknown: true", "targets:\n- type: password\n  value: secret", "targets:\n- type: password_hash\n  value: abcd", "targets:\n- type: unknown\n  value: x", "targets:\n- type: domain\n  value: ../bad", "targets:\n- type: username\n  value: ../../bad", "targets:\n- type: username\n  value: x\n  command: whoami", "targets:\n- type: username\n  value: 123", "targets:\n- type: username\n  value: x\n  value: y", "targets: &x [*x]", "targets:\n- type: username\n  value: x\n---\ntargets: []"} {
		if _, err := ParseWatchlist([]byte(bad), parseTarget); err == nil {
			t.Fatal("invalid accepted", bad)
		}
	}
	if _, err = ParseWatchlist(make([]byte, MaxWatchBytes+1), parseTarget); err == nil {
		t.Fatal("size bound")
	}
	for _, n := range []int{MaxTargets, MaxTargets + 1} {
		var b strings.Builder
		b.WriteString("targets:\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "- type: username\n  value: user%d\n", i)
		}
		v, e := ParseWatchlist([]byte(b.String()), parseTarget)
		if n == MaxTargets && (e != nil || len(v) != n) {
			t.Fatal(e)
		}
		if n > MaxTargets && e == nil {
			t.Fatal("target limit")
		}
	}
}
func TestCanonicalDiff(t *testing.T) {
	first := row("provider", "balance", "100")
	first.Evidence = append(first.Evidence, models.Evidence{Kind: "http_service", Value: "A"}, models.Evidence{Kind: "technology", Value: "old"}, models.Evidence{Kind: "observation_time", Value: "old"}, models.Evidence{Kind: "detail", Value: `{"value":2100000000000000,"observation_time":"old","nested":{"request_id":"a"}}`})
	p, err := project([]models.Result{first}, nil)
	if err != nil {
		t.Fatal(err)
	}
	next := first
	next.Duration = time.Hour
	next.Metadata = map[string]string{"provider": "fixture", "random_id": "abc"}
	next.Evidence = append([]models.Evidence(nil), first.Evidence...)
	next.Evidence[3].Value = "new"
	next.Evidence[4].Value = `{"nested":{"request_id":"b"},"observation_time":"new","value":2100000000000000}`
	next.Evidence = append(next.Evidence, next.Evidence[0])
	for i, j := 0, len(next.Evidence)-1; i < j; i, j = i+1, j-1 {
		next.Evidence[i], next.Evidence[j] = next.Evidence[j], next.Evidence[i]
	}
	q, err := project([]models.Result{next}, nil)
	if err != nil || !reflect.DeepEqual(p.Good, q.Good) {
		t.Fatal("noise/order changed snapshot", err)
	}
	next.Evidence = []models.Evidence{{Kind: "balance", Value: "150"}, {Kind: "http_service", Value: "A"}, {Kind: "hostname", Value: "new"}}
	q, err = project([]models.Result{next}, nil)
	if err != nil {
		t.Fatal(err)
	}
	changes := diff(p.Good[0], q.Good[0])
	kinds := map[string]string{}
	for _, e := range changes {
		kinds[e.EvidenceType] = e.Kind
		if len(e.Provenance) == 0 || len(e.OldProvenance) == 0 {
			t.Fatal("missing provenance")
		}
	}
	if kinds["balance"] != "MODIFIED" || kinds["technology"] != "REMOVED" || kinds["hostname"] != "ADDED" || kinds["http_service"] != "" {
		t.Fatal(kinds)
	}
	if !reflect.DeepEqual(changes, diff(p.Good[0], q.Good[0])) {
		t.Fatal("nondeterministic diff")
	}
}
func TestProviderFailureRegression(t *testing.T) {
	for _, failure := range []string{"timeout", "network_failure", "rate_limited", "partial", "truncated", "silent"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			phase := 0
			subject := target(t, "example.com")
			e, _ := newTestEngine(t, dir, []models.Target{subject}, func(ctx context.Context, tt models.Target, emit sources.Emit) error {
				good := row("http", "http_service", "A")
				if phase == 1 {
					if failure == "silent" {
						return errors.New("private failure")
					}
					if failure == "partial" {
						good.Metadata["history_status"] = "partial"
						good.Evidence = nil
						return emit(good)
					}
					if failure == "truncated" {
						good.Metadata["counterparties_truncated"] = "true"
						good.Evidence = nil
						return emit(good)
					}
					failed := row("http", "", "")
					failed.Status = models.StatusError
					failed.Evidence = nil
					failed.Metadata["error_kind"] = failure
					_ = emit(failed)
					return errors.New("provider failure")
				}
				return emit(good)
			})
			cycle(t, e)
			before, _, err := e.store.Load(subject)
			if err != nil {
				t.Fatal(err)
			}
			phase = 1
			cycle(t, e)
			after, _, err := e.store.Load(subject)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("failure erased baseline")
			}
			phase = 2
			cycle(t, e)
			if len(readChanges(t, dir)) != 0 {
				t.Fatal("false removal/addition")
			}
			records := lines(t, dir, "observations")
			if len(records) != 3 {
				t.Fatal("missing observations")
			}
			var o Observation
			_ = json.Unmarshal(records[1], &o)
			want := "failed"
			if failure == "partial" || failure == "truncated" {
				want = "partial"
			}
			if o.Status != want || o.Outcome != "skipped" {
				t.Fatal(o)
			}
		})
	}
}
func TestBalanceDedupReversalAndRestart(t *testing.T) {
	dir := t.TempDir()
	subject := target(t, "example.com")
	value := "100"
	f := searchFunc(func(_ context.Context, _ models.Target, emit sources.Emit) error {
		return emit(row("bitcoin", "crypto_confirmed_balance_sats", value))
	})
	e, alerts := newTestEngine(t, dir, []models.Target{subject}, f)
	cycle(t, e)
	cycle(t, e)
	if len(readChanges(t, dir)) != 0 {
		t.Fatal("first run flood")
	}
	value = "150"
	cycle(t, e)
	cycle(t, e)
	events := readChanges(t, dir)
	if len(events) != 1 || events[0].Kind != "MODIFIED" || events[0].Old.Value != "100" || events[0].New.Value != "150" {
		t.Fatal(events)
	}
	if strings.Count(alerts.String(), "[CHANGE]") != 1 {
		t.Fatal("duplicate alert")
	}
	if err := e.store.Close(); err != nil {
		t.Fatal(err)
	}
	e, _ = newTestEngine(t, dir, []models.Target{subject}, f)
	cycle(t, e)
	if len(readChanges(t, dir)) != 1 {
		t.Fatal("restart duplicated change")
	}
	value = "100"
	cycle(t, e)
	events = readChanges(t, dir)
	if len(events) != 2 || events[0].ID == events[1].ID {
		t.Fatal("reversal lost")
	}
}
func TestPartialSourcesAndMissingSource(t *testing.T) {
	dir := t.TempDir()
	phase := 0
	e, _ := newTestEngine(t, dir, []models.Target{target(t, "example.com")}, func(_ context.Context, _ models.Target, emit sources.Emit) error {
		if phase == 0 {
			_ = emit(row("a", "service", "A"))
			return emit(row("b", "balance", "100"))
		}
		if phase == 1 {
			_ = emit(row("a", "service", "new-partial"))
			failed := row("a", "", "")
			failed.Status = models.StatusError
			_ = emit(failed)
			_ = emit(row("b", "balance", "150"))
			return errors.New("partial failure")
		}
		return emit(row("b", "balance", "150"))
	})
	cycle(t, e)
	phase = 1
	cycle(t, e)
	phase = 2
	cycle(t, e)
	events := readChanges(t, dir)
	if len(events) != 1 || events[0].Source != "b" {
		t.Fatal("failed or missing source replaced", events)
	}
	var o Observation
	_ = json.Unmarshal(lines(t, dir, "observations")[1], &o)
	if o.Status != "partial" || len(o.SourcesSucceeded) != 1 || len(o.SourcesPartial) != 1 {
		t.Fatal(o)
	}
}
func TestSchedulingBoundCancellationNoOverlap(t *testing.T) {
	dir := t.TempDir()
	subjects := []models.Target{}
	for i := 0; i < 9; i++ {
		subjects = append(subjects, target(t, fmt.Sprintf("x%d.example", i)))
	}
	var active, maximum, calls atomic.Int32
	e, _ := newTestEngine(t, dir, subjects, func(ctx context.Context, t models.Target, emit sources.Emit) error {
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if n <= old || maximum.CompareAndSwap(old, n) {
				break
			}
		}
		calls.Add(1)
		select {
		case <-time.After(time.Millisecond):
			return emit(row("fixture", "value", t.Value()))
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	waits := 0
	e.wait = func(ctx context.Context, d time.Duration) error {
		if active.Load() != 0 || d != DefaultInterval {
			t.Error("overlap/interval")
		}
		waits++
		if waits == 2 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	if err := e.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 18 || maximum.Load() > 4 || maximum.Load() < 2 || active.Load() != 0 {
		t.Fatal("concurrency bound", calls.Load(), maximum.Load())
	}
	records := lines(t, dir, "observations")
	for i, line := range records {
		var o Observation
		_ = json.Unmarshal(line, &o)
		if o.Target != subjects[i%9].Value() {
			t.Fatal("nondeterministic target order")
		}
	}
	// Cancellation while an investigation is in flight joins it and preserves state.
	waiting := make(chan struct{}, 1)
	e.investigator = searchFunc(func(ctx context.Context, _ models.Target, _ sources.Emit) error {
		select {
		case waiting <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	})
	ctx, cancel = context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	<-waiting
	if err := e.Run(context.Background()); err == nil {
		t.Fatal("overlapping Run accepted")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop")
	}
	if len(readChanges(t, dir)) != 0 {
		t.Fatal("cancellation erased evidence")
	}
}
func TestOptionsAndTimeout(t *testing.T) {
	for _, d := range []time.Duration{MinInterval, MaxInterval, DefaultInterval} {
		o := DefaultOptions()
		o.Interval = d
		if o.Validate() != nil {
			t.Fatal(d)
		}
	}
	for _, d := range []time.Duration{0, -1, MinInterval - 1, MaxInterval + 1, time.Hour} {
		o := DefaultOptions()
		o.Interval = d
		if o.Validate() == nil {
			t.Fatal("interval accepted", d)
		}
	}
	for _, n := range []int{0, 5, 1000} {
		o := DefaultOptions()
		o.Concurrency = n
		if o.Validate() == nil {
			t.Fatal("concurrency accepted")
		}
	}
	e, _ := newTestEngine(t, t.TempDir(), []models.Target{target(t, "example.com")}, func(ctx context.Context, _ models.Target, _ sources.Emit) error { <-ctx.Done(); return ctx.Err() })
	e.options.CycleTimeout = 20 * time.Millisecond
	start := time.Now()
	cycle(t, e)
	if time.Since(start) > time.Second {
		t.Fatal("unbounded timeout")
	}
}
func TestRedactionAndInvalidCompleteStatus(t *testing.T) {
	r := row("source", "token", "private-token")
	r.Evidence = append(r.Evidence, models.Evidence{Kind: "detail", Value: "password=private-password"})
	p, err := project([]models.Result{r}, nil)
	if err != nil || strings.Contains(string(marshal(p.Good)), "private-") {
		t.Fatal("redaction")
	}
	r.Status = ""
	r.Evidence = nil
	p, err = project([]models.Result{r}, nil)
	if err != nil || len(p.Good) != 0 {
		t.Fatal("implicit absence")
	}
	if _, err = canonicalValue(strings.Repeat("a", MaxValueBytes+1)); err == nil {
		t.Fatal("value limit")
	}
}
func FuzzWatchlist(f *testing.F) {
	f.Add([]byte("targets:\n- type: domain\n  value: example.com\n"))
	f.Add([]byte("targets: []"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxWatchBytes+1 {
			return
		}
		targets, err := ParseWatchlist(raw, parseTarget)
		if err == nil {
			if len(targets) == 0 || len(targets) > MaxTargets {
				t.Fatal("target bound")
			}
			again, e := ParseWatchlist(raw, parseTarget)
			if e != nil || !reflect.DeepEqual(targets, again) {
				t.Fatal("nondeterministic")
			}
		}
	})
}
func FuzzStateAndEvents(f *testing.F) {
	subject := target(f, "example.com")
	f.Add(marshal(newSnapshot(subject)))
	f.Add([]byte(`{"run_id":"bad"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxStateBytes+1 {
			return
		}
		state, err := parseState(raw, subject)
		if err == nil {
			if !bytes.Equal(raw, marshal(state)) {
				t.Fatal("state canonicalization")
			}
		}
		_, _ = eventID(raw)
	})
}

func TestTargetFailureDoesNotPreventOthers(t *testing.T) {
	dir := t.TempDir()
	subjects := []models.Target{target(t, "a.example"), target(t, "b.example"), target(t, "c.example")}
	e, _ := newTestEngine(t, dir, subjects, func(_ context.Context, t models.Target, emit sources.Emit) error {
		if t.Value() == "a.example" {
			failed := row("fixture", "", "")
			failed.Status = models.StatusError
			_ = emit(failed)
			return errors.New("timeout")
		}
		return emit(row("fixture", "service", "A"))
	})
	cycle(t, e)
	if len(lines(t, dir, "observations")) != 3 {
		t.Fatal("target failure prevented another investigation")
	}
	for _, subject := range subjects[1:] {
		state, _, err := e.store.Load(subject)
		if err != nil || len(state.Sources) != 1 {
			t.Fatal("healthy target baseline lost")
		}
	}
}
func TestCollectorLimitsAndInvalidUTF8(t *testing.T) {
	dir := t.TempDir()
	e, _ := newTestEngine(t, dir, []models.Target{target(t, "example.com")}, func(_ context.Context, _ models.Target, emit sources.Emit) error {
		for i := 0; i <= MaxRows; i++ {
			if err := emit(row("fixture", "value", fmt.Sprint(i))); err != nil {
				return err
			}
		}
		return nil
	})
	cycle(t, e)
	var observation Observation
	_ = json.Unmarshal(lines(t, dir, "observations")[0], &observation)
	if observation.Status != "failed" || len(readChanges(t, dir)) != 0 {
		t.Fatal("truncated collection became complete")
	}
	if _, err := canonicalValue(string([]byte{255})); err == nil {
		t.Fatal("invalid UTF8 accepted")
	}
}
