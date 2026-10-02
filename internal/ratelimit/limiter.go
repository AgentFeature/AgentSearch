package ratelimit

import (
	"context"
	"net/url"
	"sync"
	"time"
)

// HostLimiter spaces requests to each host.
// Callers can cancel a pending delay using WaitContext.
type HostLimiter struct {
	delay       time.Duration
	mu          sync.Mutex
	lastRequest map[string]time.Time
}

// NewHostLimiter creates a limiter; zero delay disables waiting.
func NewHostLimiter(delay time.Duration) *HostLimiter {
	return &HostLimiter{
		delay:       delay,
		lastRequest: make(map[string]time.Time),
	}
}

// Wait blocks until the minimum interval for this host has elapsed.
func (rl *HostLimiter) Wait(rawURL string) { _ = rl.WaitContext(context.Background(), rawURL) }

// WaitContext is the cancellation-aware adapter used by website searches.
func (rl *HostLimiter) WaitContext(ctx context.Context, rawURL string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if rl.delay <= 0 {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	host := u.Host
	if host == "" {
		return nil
	}

	// Recheck after each wait: a provider may extend the host cooldown while
	// another request is waiting. Do not hold the mutex across a cancellable wait.
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rl.mu.Lock()
		delay := time.Until(rl.lastRequest[host].Add(rl.delay))
		if delay <= 0 {
			rl.lastRequest[host] = time.Now()
			rl.mu.Unlock()
			return nil
		}
		rl.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}

}

// Defer postpones this host's next request after a provider Retry-After response.
// It only extends an existing delay; callers bound and validate the duration.
func (rl *HostLimiter) Defer(rawURL string, delay time.Duration) {
	if delay <= 0 {
		return
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	next := time.Now().Add(delay - rl.delay)
	if next.After(rl.lastRequest[u.Host]) {
		rl.lastRequest[u.Host] = next
	}
}
