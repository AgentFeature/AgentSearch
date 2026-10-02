// Command agentsearch-server exposes the existing engine to a controlled operator API.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/AgentFeature/agentsearch/internal/analysis"
	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/httpapi"
	"github.com/AgentFeature/agentsearch/internal/security"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], logger)
	stop()
	os.Exit(code)
}
func run(ctx context.Context, args []string, logger *slog.Logger) int {
	cfg, err := config.ParseServerArgs(args)
	if err == flag.ErrHelp {
		fmt.Fprintln(os.Stdout, "Usage: agentsearch-server [-listen 127.0.0.1:8080] [-token-env AGENTSEARCH_API_TOKEN]\nHTTP: -read-timeout 15s -write-timeout 75s -idle-timeout 60s -request-timeout 60s -max-concurrent 8 -shutdown-timeout 10s\nSources: -s configs/sites.yaml -services FILE -password-backend api|local -password-db ROOT\nWebsite/provider options: -w 10 -p FILE -ua FILE -rl 500ms -rt 15s -retries 2 -utls\nAnalysis: -ai-config FILE (also requires request analysis:true). Search requires an environment-supplied bearer token. Use TLS termination for non-loopback deployment.")
		return 0
	}
	if err != nil {
		logger.Error("server configuration error; use -h for options", "error_category", "invalid_request")
		return 1
	}
	token := security.NewSecret(os.Getenv(cfg.TokenEnv))
	defer token.Destroy()
	if token.Empty() {
		logger.Error("server requires bearer token from configured environment variable")
		return 1
	}
	service, err := app.NewSearchService(ctx, cfg.Engine)
	if err != nil {
		logger.Error("search service initialization failed")
		return 1
	}
	safeToClose := true
	defer func() {
		if safeToClose {
			_ = service.Close()
		}
	}()
	var analyzer *analysis.Service
	if cfg.AIConfig != "" {
		var closeAI func()
		analyzer, closeAI = analysis.FromFile(cfg.AIConfig)
		defer closeAI()
	}
	handler, err := httpapi.New(service, token, cfg, logger, analyzer)
	if err != nil {
		logger.Error("server authentication configuration failed")
		return 1
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		logger.Error("HTTP listener could not be opened")
		return 1
	}
	logger.Info("HTTP server listening", "max_concurrent", cfg.MaxConcurrent)
	if err = httpapi.Serve(ctx, listener, handler, cfg, logger); err != nil {
		// A forced/failed stop may leave an uncooperative request in app.Search.
		// Do not wait on its lifecycle lock or close its snapshot underneath it.
		// main exits this process; the OS releases remaining descriptors/leases.
		safeToClose = false
		logger.Error("HTTP server stopped", "error", err)
		return 1
	}
	return 0
}
