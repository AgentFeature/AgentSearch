package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitContext(t *testing.T) {
	limiter := NewHostLimiter(20 * time.Millisecond)
	limiter.Wait("https://example.test/first")
	start := time.Now()
	limiter.Wait("https://example.test/second")
	if time.Since(start) < 15*time.Millisecond {
		t.Fatal("rate limit lost")
	}
	limiter = NewHostLimiter(time.Hour)
	limiter.Wait("http://example.test")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(limiter.WaitContext(ctx, "http://example.test"), context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if !errors.Is(limiter.WaitContext(ctx, "http://example.test"), context.DeadlineExceeded) {
		t.Fatal("timer not cancellable")
	}
}

func TestDeferHost(t *testing.T) {
	limiter := NewHostLimiter(time.Millisecond)
	limiter.Defer("https://example.test/api", time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := limiter.WaitContext(ctx, "https://example.test/another"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("host cooldown ignored")
	}
	// A shorter deferral must not shorten the provider's requested cooldown.
	limiter.mu.Lock()
	before := limiter.lastRequest["example.test"]
	limiter.mu.Unlock()
	limiter.Defer("https://example.test/api", time.Millisecond)
	limiter.mu.Lock()
	after := limiter.lastRequest["example.test"]
	limiter.mu.Unlock()
	if !before.Equal(after) {
		t.Fatal("cooldown shortened")
	}
	if err := limiter.WaitContext(context.Background(), "https://other.test/api"); err != nil {
		t.Fatal(err)
	}
}

func TestDeferDuringWait(t *testing.T) {
	limiter := NewHostLimiter(40 * time.Millisecond)
	limiter.Wait("https://example.test")
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- limiter.WaitContext(ctx, "https://example.test") }()
	time.Sleep(5 * time.Millisecond)
	limiter.Defer("https://example.test", time.Second)
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("pending wait bypassed extended cooldown")
	}
}
