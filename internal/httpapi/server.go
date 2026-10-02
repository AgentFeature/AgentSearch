package httpapi

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/AgentFeature/agentsearch/internal/config"
)

// transportLog deliberately discards net/http diagnostic text, which may include
// untrusted headers, URLs or panic values. Handler logs contain safe fields only.
type transportLog struct{ log *slog.Logger }

func (w transportLog) Write(b []byte) (int, error) {
	w.log.Warn("HTTP transport error")
	return len(b), nil
}

// Serve owns the listener. ctx is the stop trigger, not the request lifetime:
// signals stop accepts first, allowing in-flight requests their grace period.
// A forced stop cancels requests and closes connections without waiting forever
// for a handler that does not cooperate. Owners must not then block on app cleanup.
func Serve(ctx context.Context, listener net.Listener, handler http.Handler, cfg config.ServerConfig, logger *slog.Logger) error {
	if e := cfg.Validate(); e != nil {
		listener.Close()
		return e
	}
	if ctx.Err() != nil {
		listener.Close()
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	// Preserve lifecycle values while separating signal cancellation from the
	// drain phase. Incoming HTTP contexts still propagate client disconnects and
	// request deadlines; only the stop signal is delayed until grace expires.
	requests, cancelRequests := context.WithCancel(context.WithoutCancel(ctx))
	server := &http.Server{Handler: handler, ReadHeaderTimeout: min(5*time.Second, cfg.ReadTimeout), ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout, IdleTimeout: cfg.IdleTimeout, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(transportLog{logger}, "", 0), BaseContext: func(net.Listener) context.Context { return requests }}
	defer func() { cancelRequests(); _ = server.Close() }()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("HTTP server stopped unexpectedly")
	case <-ctx.Done():
		// Cleanup has its own finite deadline, unaffected by the stop trigger.
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.ShutdownTimeout)
		defer cancel()
		err := server.Shutdown(shutdown)
		if err != nil {
			cancelRequests()
			_ = server.Close()
		}
		<-done
		if err != nil {
			return errors.New("HTTP shutdown exceeded grace period")
		}
		return nil
	}
}
