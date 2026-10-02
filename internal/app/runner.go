package app

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AgentFeature/agentsearch/internal/analysis"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/diagnostics"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/report"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

// Runner executes typed searches without CLI, signals or output policy.
type Runner struct{ manager *sources.Manager }

func NewRunner(registry *sources.Registry) *Runner {
	return &Runner{manager: sources.NewManager(registry)}
}
func (r *Runner) Search(ctx context.Context, target models.Target, emit sources.Emit) (err error) {
	start := time.Now()
	var summary diagnostics.Summary
	completed := false
	invalidTarget := !target.Valid()
	var consumerErr error
	diagnostics.Started(ctx, "search", target.Type(), "")
	defer func() {
		outcome := summary.Finish(ctx, err)
		if invalidTarget {
			outcome = diagnostics.Failure("invalid_request")
		}
		if errors.Is(err, sources.ErrUnsupportedTarget) {
			outcome = diagnostics.Failure("invalid_request")
		}
		if emit == nil {
			outcome = diagnostics.Failure("internal_error")
		}
		if consumerErr != nil {
			outcome = diagnostics.Failure(diagnostics.ErrorCategory(consumerErr, "internal_error"))
		}
		if !completed {
			outcome = diagnostics.Failure("internal_error")
		}
		diagnostics.Completed(ctx, "search", target.Type(), "", start, outcome)
	}()
	if emit == nil {
		err = r.manager.Search(ctx, target, nil)
	} else {
		err = r.manager.Search(ctx, target, func(result models.Result) error {
			summary.Observe(result)
			consumerErr = emit(result)
			return consumerErr
		})
	}
	completed = true
	return err
}

// Run searches all CLI targets and handles graceful shutdown.
func (a *App) Run(ctx context.Context) error {
	// Cancel pending work on SIGINT or SIGTERM.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if a.cfg.AI && a.analyzer == nil {
		var closeAI func()
		a.analyzer, closeAI = analysis.FromFile(a.cfg.AIConfig)
		defer func() { closeAI(); a.analyzer = nil }()
	}
	if a.cfg.Mode == config.ModePassword {
		defer a.cfg.Password.Destroy()
		target, err := models.NewSensitiveTarget(models.TargetPassword, a.cfg.Password)
		if err != nil {
			return err
		}
		return a.searchTarget(ctx, target)
	}

	for _, value := range a.cfg.Targets {
		target, err := models.LegacyTarget(value)
		if a.cfg.Mode == config.ModeEmail {
			target, err = models.NewEmailTarget(value)
		}
		if a.cfg.Mode == config.ModeBitcoinTransaction {
			target, err = models.NewBitcoinTransactionTarget(value)
		}
		if a.cfg.Mode == config.ModeBitcoin {
			target, err = models.NewBitcoinTarget(value)
		}
		if a.cfg.Mode == config.ModeIP {
			target, err = models.NewIPTarget(value)
		}
		if a.cfg.Mode == config.ModeDomain {
			target, err = models.NewDomainTarget(value)
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			slog.Warn("shutdown signal received, exiting")
			return ctx.Err()
		default:
		}
		if err := a.searchTarget(ctx, target); err != nil {
			var outputErr *report.OutputError
			if errors.As(err, &outputErr) {
				return err
			}
			// Preserve the legacy website exit policy; service modes report failures.
			if a.cfg.Mode == config.ModeEmail || a.cfg.Mode == config.ModeDomain || a.cfg.Mode == config.ModeIP || a.cfg.Mode == config.ModeBitcoin || a.cfg.Mode == config.ModeBitcoinTransaction {
				return err
			}
		}
	}
	return nil
}

func (a *App) searchTarget(ctx context.Context, target models.Target) error {
	start := time.Now()
	if len(a.cfg.OutputFormats) > 0 || len(a.cfg.ReportFormats) > 0 {
		if err := report.PrepareDirectory(a.cfg.OutputDir); err != nil {
			slog.Error("output initialization failed", "operation", "output_setup", "target_type", diagnostics.Target(target.Type()), "outcome", "error", "error_category", "internal_error")
			return &report.OutputError{Err: err}
		}
	}
	var results []models.Result
	size, count := 0, 0
	truncated := false
	searchErr := a.runner.Search(ctx, target, func(res models.Result) error {
		n, err := report.ResultSize(res)
		if err != nil || len(results) >= report.MaxResults || size+n > report.MaxInputBytes || count+len(res.Evidence) > report.MaxEvidence {
			truncated = true
			return report.ErrLimit
		}
		size += n
		count += len(res.Evidence)
		results = append(results, res)
		return nil
	})
	opts := report.Options{CreatedAt: start, Duration: time.Since(start), Partial: searchErr != nil, Truncated: truncated}
	if searchErr != nil {
		opts.Errors = []string{"Investigation did not complete; inspect source statuses and error kinds."}
	}
	if len(a.cfg.OutputFormats) > 0 || len(a.cfg.ReportFormats) > 0 {
		document, err := report.New(target.Type(), target.String(), results, opts)
		if err != nil {
			return &report.OutputError{Err: err}
		}
		if a.cfg.AI {
			result := a.analyzer.Analyze(ctx, document)
			enriched, attachErr := document.WithAnalysis(result)
			if attachErr != nil {
				enriched, attachErr = document.WithAnalysis(analysis.Failed("internal_error"))
			}
			if attachErr == nil {
				document = enriched
			}
		}
		if err = report.WriteOutputs(a.cfg.OutputDir, a.cfg.OutputFormats, a.cfg.ReportFormats, document); err != nil {
			return err
		}
	}
	return searchErr
}
