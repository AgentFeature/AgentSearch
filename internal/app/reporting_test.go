package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/report"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

// A local capability fixture, not a new production provider.
type reportingSource struct{}

func (reportingSource) Name() string            { return "report-fixture" }
func (reportingSource) Type() models.SourceType { return models.SourceLocal }
func reportEmit(emit sources.Emit) error {
	return emit(models.Result{Status: models.StatusFound, Evidence: []models.Evidence{{Kind: "observation", Value: "canonical-evidence"}}})
}
func (reportingSource) SearchUsername(_ context.Context, _ string, e sources.Emit) error {
	return reportEmit(e)
}
func (reportingSource) SearchEmail(_ context.Context, _ string, e sources.Emit) error {
	return reportEmit(e)
}
func (reportingSource) SearchDomain(_ context.Context, _ string, e sources.Emit) error {
	return reportEmit(e)
}
func (reportingSource) SearchIP(_ context.Context, _ string, e sources.Emit) error {
	return reportEmit(e)
}
func (reportingSource) SearchBitcoin(_ context.Context, _ string, e sources.Emit) error {
	return reportEmit(e)
}
func (reportingSource) SearchBitcoinTransaction(_ context.Context, _ string, e sources.Emit) error {
	return reportEmit(e)
}
func (reportingSource) SearchPassword(_ context.Context, _ security.Secret, e sources.Emit) error {
	return reportEmit(e)
}
func (reportingSource) SearchPasswordHash(_ context.Context, _ security.Secret, e sources.Emit) error {
	return reportEmit(e)
}
func TestApplicationReportingAllTargetTypes(t *testing.T) {
	for _, tc := range []struct {
		k models.TargetType
		v string
	}{{models.TargetUsername, "alice"}, {models.TargetEmail, "alice@example.test"}, {models.TargetDomain, "example.test"}, {models.TargetIP, "192.0.2.1"}, {models.TargetBitcoin, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}, {models.TargetBitcoinTransaction, strings.Repeat("a", 64)}, {models.TargetPassword, "private-fixture-password"}, {models.TargetPasswordHash, strings.Repeat("A", 40)}} {
		t.Run(string(tc.k), func(t *testing.T) {
			target, err := models.NewTarget(tc.k, tc.v)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Secret().Destroy()
			registry := sources.NewRegistry()
			if err = registry.Register(reportingSource{}); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			a := NewWithSources(&config.AppConfig{OutputDir: dir, OutputFormats: report.Formats}, registry)
			if err = a.searchTarget(context.Background(), target); err != nil {
				t.Fatal(err)
			}
			base := report.SafeBase(target.String())
			for _, format := range report.Formats {
				b, err := os.ReadFile(filepath.Join(dir, base+"."+format))
				if err != nil || len(b) == 0 {
					t.Fatal(format, err)
				}
			}
			b, err := os.ReadFile(filepath.Join(dir, base+"_report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				TargetType models.TargetType `json:"target_type"`
				Results    []struct {
					Result models.Result `json:"result"`
				}
			}
			if err = json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			if doc.TargetType != tc.k || len(doc.Results) != 1 || doc.Results[0].Result.Evidence[0].Value != "canonical-evidence" {
				t.Fatal("canonical app data lost")
			}
		})
	}
}
