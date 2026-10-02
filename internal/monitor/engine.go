package monitor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

type Investigator interface {
	Search(context.Context, models.Target, sources.Emit) error
}
type Options struct {
	Interval     time.Duration
	Concurrency  int
	CycleTimeout time.Duration
}

func DefaultOptions() Options { return Options{DefaultInterval, MaxConcurrency, CycleTimeout} }
func (o Options) Validate() error {
	if o.Interval < MinInterval || o.Interval > MaxInterval || o.Concurrency < 1 || o.Concurrency > MaxConcurrency || o.CycleTimeout <= 0 || o.CycleTimeout > CycleTimeout {
		return errors.New("invalid bounded watch options")
	}
	return nil
}

type Observation struct {
	RunID               string            `json:"run_id"`
	Timestamp           string            `json:"timestamp"`
	Target              string            `json:"target"`
	TargetType          models.TargetType `json:"target_type"`
	Status              string            `json:"status"`
	Outcome             string            `json:"outcome"`
	SourcesAttempted    []string          `json:"sources_attempted"`
	SourcesSucceeded    []string          `json:"sources_succeeded"`
	SourcesPartial      []string          `json:"sources_partial"`
	SourcesFailed       []string          `json:"sources_failed"`
	UnattributedFailure bool              `json:"unattributed_failure,omitempty"`
	DurationMS          int64             `json:"duration_ms"`
	ChangeCount         int               `json:"change_count"`
	BaselinesCreated    int               `json:"baselines_created"`
}
type Engine struct {
	investigator Investigator
	store        *Store
	targets      []models.Target
	options      Options
	alerts       io.Writer
	running      sync.Mutex
	wait         func(context.Context, time.Duration) error // Internal deterministic test seam.
}

func New(investigator Investigator, store *Store, targets []models.Target, options Options, alerts io.Writer) (*Engine, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if investigator == nil || store == nil || alerts == nil || len(targets) == 0 || len(targets) > MaxTargets {
		return nil, errors.New("invalid monitor dependencies")
	}
	previous := ""
	for _, t := range targets {
		key := string(t.Type()) + "\x00" + t.Value()
		if !t.Valid() || t.Type().Sensitive() || key <= previous {
			return nil, errors.New("watch targets must be valid, sorted and unique")
		}
		previous = key
	}
	if err := store.ValidateTargets(targets); err != nil {
		return nil, err
	}
	// Validate all baselines before the first investigation, never eagerly create one.
	for _, t := range targets {
		if _, _, err := store.Load(t); err != nil {
			return nil, err
		}
	}
	return &Engine{investigator: investigator, store: store, targets: append([]models.Target(nil), targets...), options: options, alerts: alerts, wait: waitInterval}, nil
}
func waitInterval(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (e *Engine) warnings() error {
	for _, warning := range e.store.Warnings() {
		if _, err := fmt.Fprintf(e.alerts, "[WATCH] %s\n", warning); err != nil {
			return err
		}
	}
	return nil
}
func (e *Engine) Run(ctx context.Context) error {
	if !e.running.TryLock() {
		return errors.New("monitor already running")
	}
	defer e.running.Unlock()
	if err := e.warnings(); err != nil {
		return err
	}
	for ctx.Err() == nil {
		if err := e.cycle(ctx); err != nil {
			return err
		}
		if err := e.wait(ctx, e.options.Interval); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
	return nil
}

type inspection struct {
	rows     []models.Result
	err      error
	started  time.Time
	duration time.Duration
	called   bool
}

func (e *Engine) inspect(ctx context.Context, t models.Target) inspection {
	r := inspection{}
	if ctx.Err() != nil {
		return r
	}
	r.started = time.Now()
	r.called = true
	size, count := 0, 0
	limit := false
	r.err = e.investigator.Search(ctx, t, func(row models.Result) error {
		if limit {
			return errors.New("monitor result limit")
		}
		count += len(row.Evidence)
		raw := marshal(row)
		size += len(raw)
		if len(r.rows) >= MaxRows || size > MaxResultBytes || count > MaxEvidence {
			limit = true
			return errors.New("monitor result limit")
		}
		status := row.Status
		row = row.Normalized()
		row.Status = status
		r.rows = append(r.rows, row)
		return nil
	})
	r.duration = time.Since(r.started)
	if limit || ctx.Err() != nil {
		r.rows = nil
		r.err = errors.New("investigation incomplete")
	}
	return r
}
func (e *Engine) cycle(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, e.options.CycleTimeout)
	defer cancel()
	// Reserve a share for every batch, rather than letting early slow targets
	// consume the whole cycle. Providers retain their own stricter deadlines.
	batches := (len(e.targets) + e.options.Concurrency - 1) / e.options.Concurrency
	targetBudget := min(90*time.Second, e.options.CycleTimeout/time.Duration(batches+1))
	for first := 0; first < len(e.targets) && ctx.Err() == nil; first += e.options.Concurrency {
		batch := e.targets[first:min(first+e.options.Concurrency, len(e.targets))]
		results := make([]inspection, len(batch))
		var wg sync.WaitGroup
		for i, t := range batch {
			wg.Add(1)
			go func(i int, t models.Target) {
				defer wg.Done()
				local, stop := context.WithTimeout(ctx, targetBudget)
				defer stop()
				results[i] = e.inspect(local, t)
			}(i, t)
		}
		wg.Wait()
		// Only the owner persists/alerts, in target order, with at most four bounded
		// result collections resident at once. Storage failure stops future work.
		for i, t := range batch {
			if results[i].called {
				if err := e.record(t, results[i]); err != nil {
					return safeError(err)
				}
			}
		}
	}
	if ctx.Err() != nil && parent.Err() == nil {
		_, err := fmt.Fprintln(e.alerts, "[WATCH] cycle deadline reached; unstarted targets were not observed")
		return err
	}
	return nil
}
func (e *Engine) record(t models.Target, r inspection) error {
	p, err := project(r.rows, r.err)
	if err != nil {
		p = projection{}
		r.err = err
	} // A malformed/oversized observation never replaces a baseline.
	old, _, err := e.store.Load(t)
	if err != nil {
		return err
	}
	next, events, created := merge(old, p.Good)
	observation := Observation{Timestamp: r.started.UTC().Format(time.RFC3339Nano), Target: t.Value(), TargetType: t.Type(), Status: "complete", Outcome: "unchanged", SourcesAttempted: p.Attempted, SourcesFailed: p.Failed, SourcesPartial: p.Partial, DurationMS: r.duration.Milliseconds(), ChangeCount: len(events), BaselinesCreated: created}
	for _, s := range p.Good {
		observation.SourcesSucceeded = append(observation.SourcesSucceeded, s.Source)
	}
	if len(p.Good) == 0 {
		observation.Status = "failed"
		observation.Outcome = "skipped"
	} else if len(p.Failed) > 0 || len(p.Partial) > 0 || r.err != nil {
		observation.Status = "partial"
	}
	if len(p.Partial) > 0 {
		observation.Status = "partial"
	}
	if r.err != nil && len(p.Failed) == 0 && len(p.Partial) == 0 {
		observation.UnattributedFailure = true
	}
	if created > 0 {
		observation.Outcome = "baseline_created"
	}
	if len(events) > 0 {
		observation.Outcome = "changed"
	}
	var random [32]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	observation.RunID = hex.EncodeToString(random[:])
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	for i := range events {
		event := &events[i]
		event.Target = t.Value()
		event.TargetType = t.Type()
		seed := append([]byte(fmt.Sprintf("%s:%d:", Identity(t), old.Revision)), marshal(event)...)
		id := sha256.Sum256(seed)
		event.ID = hex.EncodeToString(id[:])
		event.Timestamp = timestamp
	}
	// Validate all state before committing logs; errors leave the old baseline intact.
	raw := marshal(next)
	if _, err = parseState(raw, t); err != nil {
		return err
	}
	// Durable log first, then atomic baseline. Stable change IDs suppress replay
	// after a crash between these operations, while retained logs contain the ID.
	if err = e.store.Observations(observation); err != nil {
		return err
	}
	if err = e.store.Changes(events); err != nil {
		return err
	}
	if len(p.Good) > 0 && !bytes.Equal(marshal(old), raw) {
		if err = e.store.Save(t, next); err != nil {
			return err
		}
	}
	if err = e.warnings(); err != nil {
		return err
	}
	for _, event := range events {
		oldValue, newValue := "", ""
		if event.Old != nil {
			oldValue = event.Old.Value
		}
		if event.New != nil {
			newValue = event.New.Value
		}
		if _, err = fmt.Fprintf(e.alerts, "[CHANGE] %s %q source=%q %s %q old=%q new=%q\n", t.Type(), t.Value(), event.Source, event.Kind, event.EvidenceType, preview(oldValue), preview(newValue)); err != nil {
			return err
		}
	}
	return nil
}
func preview(s string) string {
	if len(s) > 512 {
		return s[:512] + "... (full value in changes.jsonl)"
	}
	return s
}
