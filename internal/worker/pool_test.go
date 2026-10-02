package worker

import (
	"context"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
)

type processor struct{}

func (processor) Process(context.Context, Job) models.Result {
	return models.Result{Status: models.StatusFound}
}
func TestSubmitCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := NewPool(1, processor{})
	p.Start(ctx)
	cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.SubmitContext(ctx, Job{})
		p.Close()
		for range p.Results() {
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled submit deadlocked")
	}
}
