// Package websites adapts the existing site database engine into one provider.
package websites

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"

	"github.com/AgentFeature/agentsearch/internal/detector"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/network"
	"github.com/AgentFeature/agentsearch/internal/ratelimit"
	"github.com/AgentFeature/agentsearch/internal/sources"
	"github.com/AgentFeature/agentsearch/internal/worker"
)

type Source struct {
	plans     []sitePlan
	planIndex map[string]int
	workers   int
	client    *http.Client
	ua        *network.UARotator
	detector  *detector.Engine
	limiter   *ratelimit.HostLimiter
}

// New reuses the existing HTTP client, detector, limiter and worker pool.
// The provider plan is compiled and validated once here: duplicate
// provider names are removed, ordering is deterministic, rule regexes are
// verified and body requirements are resolved. Plans are immutable.
func New(sites []models.SiteConfig, workers int, client *http.Client, ua *network.UARotator, limiter *ratelimit.HostLimiter) (*Source, error) {
	if workers < 1 {
		return nil, fmt.Errorf("website workers must be positive")
	}
	if client == nil || ua == nil || limiter == nil {
		return nil, fmt.Errorf("missing website dependency")
	}
	plans, index := buildPlans(sites)
	return &Source{plans: plans, planIndex: index, workers: workers, client: client, ua: ua, detector: detector.New(), limiter: limiter}, nil
}

func (*Source) Name() string            { return "websites" }
func (*Source) Type() models.SourceType { return models.SourceWebsite }

func (s *Source) planFor(name string) *sitePlan {
	if i, ok := s.planIndex[name]; ok {
		return &s.plans[i]
	}
	return nil
}

func (s *Source) SearchUsername(ctx context.Context, username string, emit sources.Emit) error {
	return s.search(ctx, models.TargetUsername, username, emit)
}

// SearchEmail retains the legacy behavior: substitute the email in the site
// templates, without claiming that every configured website supports emails.
func (s *Source) SearchEmail(ctx context.Context, email string, emit sources.Emit) error {
	return s.search(ctx, models.TargetEmail, email, emit)
}

func (s *Source) search(ctx context.Context, kind models.TargetType, value string, emit sources.Emit) error {
	if emit == nil {
		return fmt.Errorf("nil result consumer")
	}
	target, err := models.NewTarget(kind, value)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	pool := worker.NewPool(s.workers, &siteProcessor{source: s, target: target.Value(), kind: kind, cache: newFetchCache()})
	pool.Start(ctx)
	submitted := make(chan struct{})
	go func() {
		defer close(submitted)
		defer pool.Close()
		count := 0
		for i := range s.plans {
			if err := pool.SubmitContext(ctx, worker.Job{Site: s.plans[i].site, Target: value}); err != nil {
				break
			}
			count++
		}
		slog.Debug("jobs submitted", "source", "websites", "target_type", string(kind), "count", count)
	}()
	// Consumer panics must unwind only after owned work is joined, just like
	// returned errors. Cancel before draining so workers/submission can unblock.
	defer func() {
		cancel()
		for range pool.Results() {
		}
		<-submitted
	}()

	// Execution is concurrent; emission is deterministic. Results are
	// buffered by plan index and released strictly in configured-plan
	// (name-sorted) order, so downstream streamed outputs are reproducible.
	pending := make(map[int]models.Result, len(s.plans))
	next := 0
	var consumerErr error
	emitReady := func() {
		for consumerErr == nil {
			res, ok := pending[next]
			if !ok {
				return
			}
			delete(pending, next)
			next++
			if consumerErr = emit(res); consumerErr != nil {
				cancel()
			}
		}
	}
	for res := range pool.Results() {
		idx, ok := s.planIndex[res.SiteName]
		if !ok {
			idx = len(s.plans) + len(pending)
		}
		pending[idx] = res
		emitReady()
	}
	// A cancelled run may have index gaps; flush the remainder in stable order.
	if consumerErr == nil && len(pending) > 0 {
		rest := make([]int, 0, len(pending))
		for idx := range pending {
			rest = append(rest, idx)
		}
		sort.Ints(rest)
		for _, idx := range rest {
			if consumerErr != nil {
				break
			}
			if consumerErr = emit(pending[idx]); consumerErr != nil {
				cancel()
			}
		}
	}
	<-submitted
	if consumerErr != nil {
		return consumerErr
	}
	return ctx.Err()
}

var _ sources.Source = (*Source)(nil)
var _ sources.UsernameSearcher = (*Source)(nil)
var _ sources.EmailSearcher = (*Source)(nil)
