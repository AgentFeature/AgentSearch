package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

// The close barrier observes Shutdown stopping accepts without polling or sleeps.
type closingListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
}

func (l *closingListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}
func awaitLifecycle(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle operation did not complete")
	}
}

type lifecycleInput struct {
	ctx    context.Context
	secret security.Secret
}
type lifecycleReply struct {
	status int
	body   string
	err    error
}

func callLifecycleServer(address string) <-chan lifecycleReply {
	done := make(chan lifecycleReply, 1)
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		defer client.CloseIdleConnections()
		req, _ := http.NewRequest("POST", "http://"+address+"/api/v1/search", strings.NewReader(`{"type":"password","password":"example-password"}`))
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			done <- lifecycleReply{err: err}
			return
		}
		defer res.Body.Close()
		body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
		done <- lifecycleReply{status: res.StatusCode, body: string(body), err: err}
	}()
	return done
}
func TestShutdownAllowsInFlightCompletion(t *testing.T) {
	cfg := config.DefaultServerConfig()
	entered := make(chan lifecycleInput, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	handler := handlerFor(t, func(ctx context.Context, target models.Target, emit sources.Emit) error {
		entered <- lifecycleInput{ctx, target.Secret()}
		<-release
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return emit(models.NewResult("fixture", models.SourceLocal, target))
	}, io.Discard, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tracked := &closingListener{Listener: listener, closed: make(chan struct{})}
	ctx, stop := context.WithCancel(context.Background())
	serverDone := make(chan struct{})
	var serverErr error
	go func() {
		defer close(serverDone)
		serverErr = Serve(ctx, tracked, handler, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	t.Cleanup(func() { unblock(); stop(); awaitLifecycle(t, serverDone) })
	reply := callLifecycleServer(listener.Addr().String())
	var input lifecycleInput
	select {
	case input = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("search never entered")
	}
	stop()
	awaitLifecycle(t, tracked.closed)
	if input.ctx.Err() != nil {
		t.Fatal("shutdown cancelled an in-flight search before its grace period")
	}
	if connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second); err == nil {
		connection.Close()
		t.Fatal("shutdown still accepting connections")
	}
	unblock()
	select {
	case res := <-reply:
		if res.err != nil || res.status != 200 || strings.Contains(res.body, "example-password") {
			t.Fatal("graceful response lost or secret exposed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("response did not complete")
	}
	awaitLifecycle(t, serverDone)
	if serverErr != nil || !input.secret.Empty() {
		t.Fatal("graceful shutdown failed or secret retained")
	}
}

func TestShutdownDeadlineCancelsAndReturnsWithoutWaitingForever(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.ShutdownTimeout = 100 * time.Millisecond
	entered := make(chan lifecycleInput, 1)
	finished := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	handler := handlerFor(t, func(ctx context.Context, target models.Target, _ sources.Emit) error {
		entered <- lifecycleInput{ctx, target.Secret()}
		<-ctx.Done()
		// Model an operation that notices cancellation but cannot return until released.
		<-release
		return ctx.Err()
	}, io.Discard, nil)
	observed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { defer close(finished); handler.ServeHTTP(w, r) })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tracked := &closingListener{Listener: listener, closed: make(chan struct{})}
	ctx, stop := context.WithCancel(context.Background())
	serverDone := make(chan struct{})
	var serverErr error
	go func() {
		defer close(serverDone)
		serverErr = Serve(ctx, tracked, observed, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	t.Cleanup(func() { unblock(); stop(); awaitLifecycle(t, serverDone); awaitLifecycle(t, finished) })
	reply := callLifecycleServer(listener.Addr().String())
	var input lifecycleInput
	select {
	case input = <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("search never entered")
	}
	stop()
	awaitLifecycle(t, tracked.closed)
	awaitLifecycle(t, input.ctx.Done())
	awaitLifecycle(t, serverDone) // Must finish before the uncooperative operation is released.
	if serverErr == nil || serverErr.Error() != "HTTP shutdown exceeded grace period" {
		t.Fatal("forced shutdown error missing or unsafe")
	}
	unblock()
	awaitLifecycle(t, finished)
	if !input.secret.Empty() || len(handler.admission) != 0 {
		t.Fatal("completed cancelled request retained input or admission slot")
	}
	select {
	case res := <-reply:
		if strings.Contains(res.body, "example-password") {
			t.Fatal("password exposed on forced stop")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("connection not closed on forced stop")
	}
}
