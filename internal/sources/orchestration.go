package sources

import (
	"context"
	"errors"
	"sync"

	"github.com/AgentFeature/agentsearch/internal/models"
)

// A registry can be arbitrarily large for embedding callers. Pairs bound source
// fan-out independently of HTTP admission and providers' own website workers.
// Batches deliberately avoid a scheduler, a task queue and unbounded result storage.
const maxParallelSources = 2

func searchParallel(ctx context.Context, target models.Target, selected []Source, emit Emit) error {
	var failures []error
	for first := 0; first < len(selected); first += maxParallelSources {
		if ctx.Err() != nil {
			break
		}
		batch := selected[first:min(first+maxParallelSources, len(selected))]
		sourceErrors, consumerErr := searchBatch(ctx, target, batch, emit)
		failures = append(failures, sourceErrors...)
		if consumerErr != nil {
			return consumerErr
		}
	}
	if err := ctx.Err(); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

type sourceStream struct {
	rows       chan models.Result
	ack        chan error
	err        error // Read only after joining the producer.
	panicked   bool
	panicValue any // Never logged or converted to a provider error.
}

func searchBatch(parent context.Context, target models.Target, batch []Source, emit Emit) (failures []error, consumerErr error) {
	ctx, cancel := context.WithCancel(parent)
	streams := make([]sourceStream, len(batch))
	var running sync.WaitGroup
	defer func() {
		// Also runs when the caller's consumer panics. Waiting is intentional: Go
		// cannot safely preempt a provider that ignores cancellation.
		cancel()
		running.Wait()
		for i := range streams {
			if streams[i].panicked {
				panic(streams[i].panicValue)
			}
			if streams[i].err != nil {
				failures = append(failures, streams[i].err)
			}
		}
	}()
	for i, source := range batch {
		stream := &streams[i]
		stream.rows = make(chan models.Result)
		stream.ack = make(chan error)
		running.Add(1)
		go func() {
			defer running.Done()
			defer close(stream.rows)
			completed := false
			defer func() {
				if !completed {
					stream.panicValue = recover()
					stream.panicked = true
					cancel() // A programming failure must not strand a sibling in Emit.
				}
			}()
			if ctx.Err() != nil {
				stream.err = ctx.Err()
				completed = true
				return
			}
			failure, deliveryErr := invoke(ctx, target, source, func(row models.Result) error {
				select {
				case stream.rows <- row:
				case <-ctx.Done():
					return ctx.Err()
				}
				// A source's Emit succeeds only after the real consumer accepts its row.
				// This preserves backpressure, consumer-error diagnostics and ownership.
				select {
				case err := <-stream.ack:
					return err
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			stream.err = failure
			if deliveryErr != nil {
				stream.err = deliveryErr
			}
			completed = true
		}()
	}
	// Only this goroutine calls emit; output never depends on source completion
	// order. Each source's own emission order and all normalized evidence survive.
	for i := range streams {
		stream := &streams[i]
	drain:
		for {
			select {
			case row, ok := <-stream.rows:
				if !ok {
					break drain
				}
				if ctx.Err() != nil {
					return
				}
				consumerErr = emit(row)
				select {
				case stream.ack <- consumerErr:
				case <-ctx.Done():
				}
				if consumerErr != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}
	return
}
