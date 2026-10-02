package main

import (
	"context"
	"io"
	"log/slog"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/monitor"
)

func runWatch(ctx context.Context, cfg *config.AppConfig, alerts io.Writer) (code int) {
	targets, err := monitor.ReadWatchlist(cfg.WatchFile, func(kind, value string) (models.Target, error) { return app.NewSearchTarget(kind, value, nil) })
	if err != nil {
		slog.Error("invalid watchlist; expected public type/value targets")
		return 1
	}
	service, err := app.NewSearchService(ctx, *cfg)
	if err != nil {
		if ctx.Err() != nil {
			return 0
		}
		slog.Error("watch providers could not be initialized; check sites and enabled services")
		return 1
	}
	defer func() {
		if service.Close() != nil {
			code = 1
		}
	}()
	for _, t := range targets {
		if !service.Supports(t.Type()) {
			slog.Error("watch target type is not enabled", "target_type", t.Type())
			return 1
		}
	}
	store, err := monitor.OpenStore(cfg.WatchStateDir)
	if err != nil {
		slog.Error("watch storage unavailable; check private directory permissions, capacity and exclusive access")
		return 1
	}
	defer func() {
		if store.Close() != nil {
			code = 1
		}
	}()
	engine, err := monitor.New(service, store, targets, monitor.Options{Interval: cfg.WatchInterval, Concurrency: cfg.WatchConcurrency, CycleTimeout: cfg.TotalTimeout}, alerts)
	if err != nil {
		slog.Error("watch state or configuration is invalid")
		return 1
	}
	slog.Info("watch started", "targets", len(targets), "interval", cfg.WatchInterval, "concurrency", cfg.WatchConcurrency)
	if err = engine.Run(ctx); err != nil {
		slog.Error("watch stopped: unrecoverable storage or output failure")
		return 1
	}
	slog.Info("watch stopped cleanly")
	return 0
}
