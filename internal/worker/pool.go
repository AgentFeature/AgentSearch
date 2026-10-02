package worker

import (
	"context"
	"log/slog"
	"sync"

	"github.com/AgentFeature/agentsearch/internal/models"
)

// Job is a website work item.
type Job struct {
	Site   models.SiteConfig
	Target string
}

// Processor handles one work item.
type Processor interface {
	Process(ctx context.Context, job Job) models.Result
}

// Pool runs a fixed number of workers.
// Unbuffered channels provide backpressure.
// Callers must drain the results channel.
type Pool struct {
	workers   int
	jobs      chan Job
	results   chan models.Result
	processor Processor
}

// NewPool creates a pool with the requested worker count.
func NewPool(workers int, processor Processor) *Pool {
	return &Pool{
		workers:   workers,
		jobs:      make(chan Job),
		results:   make(chan models.Result),
		processor: processor,
	}
}

// Start launches workers asynchronously and closes results when they finish.
func (p *Pool) Start(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			slog.Debug("worker started", "id", id)
			for {
				select {
				case job, ok := <-p.jobs:
					if !ok {
						slog.Debug("worker stopped", "id", id, "reason", "jobs_closed")
						return
					}
					res := p.processor.Process(ctx, job)
					select {
					case p.results <- res:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					slog.Debug("worker stopped", "id", id, "reason", "context_cancelled")
					return
				}
			}
		}(i)
	}

	// Close results after all workers finish.
	go func() {
		wg.Wait()
		close(p.results)
	}()
}

// Submit blocks until a worker accepts the job.
// Use SubmitContext when the search may be cancelled.
func (p *Pool) Submit(job Job) {
	p.jobs <- job
}

// Close closes the jobs channel; only the submitting owner should call it.
func (p *Pool) Close() {
	close(p.jobs)
}

// Results returns the result stream.
func (p *Pool) Results() <-chan models.Result {
	return p.results
}

// SubmitContext preserves backpressure but cannot deadlock after workers exit
// on cancellation. The submitting owner must still Close and drain Results.
func (p *Pool) SubmitContext(ctx context.Context, job Job) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case p.jobs <- job:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
