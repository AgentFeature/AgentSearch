package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/analysis"
	"github.com/AgentFeature/agentsearch/internal/analysis/analysistest"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/report"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

func TestAIApplicationOptInAllTargets(t *testing.T) {
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		t.Fatal(err)
	}
	secret := hex.EncodeToString(secretBytes)
	for _, tc := range []struct {
		kind   models.TargetType
		target string
	}{{models.TargetUsername, "fixture"}, {models.TargetEmail, "fixture@example.test"}, {models.TargetDomain, "example.test"}, {models.TargetIP, "192.0.2.1"}, {models.TargetBitcoin, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}, {models.TargetBitcoinTransaction, strings.Repeat("a", 64)}, {models.TargetPassword, secret}, {models.TargetPasswordHash, secret[:40]}} {
		t.Run(string(tc.kind), func(t *testing.T) {
			for _, enabled := range []bool{false, true} {
				target, err := models.NewTarget(tc.kind, tc.target)
				if err != nil {
					t.Fatal(err)
				}
				defer target.Secret().Destroy()
				registry := sources.NewRegistry()
				if err = registry.Register(reportingSource{}); err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				cfg := &config.AppConfig{AI: enabled, OutputDir: dir, OutputFormats: report.Formats}
				a := NewWithSources(cfg, registry)
				fake := &analysistest.Fake{}
				a.analyzer = analysis.New(fake, "test-fake")
				if err = a.searchTarget(context.Background(), target); err != nil {
					t.Fatal(err)
				}
				b, err := os.ReadFile(filepath.Join(dir, report.SafeBase(target.String())+"_report.json"))
				if err != nil {
					t.Fatal(err)
				}
				var doc struct {
					Results  []json.RawMessage
					Analysis *models.Analysis
				}
				if err = json.Unmarshal(b, &doc); err != nil || len(doc.Results) != 1 {
					t.Fatal("evidence lost", err)
				}
				if enabled {
					if doc.Analysis == nil || doc.Analysis.Status != "completed" || len(fake.Inputs()) != 1 {
						t.Fatal("missing analysis")
					}
					if tc.kind.Sensitive() && bytes.Contains(fake.Inputs()[0], []byte(tc.target)) {
						t.Fatal("password material entered request")
					}
				} else if doc.Analysis != nil || len(fake.Inputs()) != 0 {
					t.Fatal("disabled analysis ran")
				}
			}
		})
	}
}
func TestAIParsedCLIAndFailureIsolation(t *testing.T) {
	for _, mode := range []string{"", "malformed", "error"} {
		dir := t.TempDir()
		cfg, err := config.ParseArgs([]string{"-u", "fixture", "-ai", "-of", "json,csv,txt,html,pdf,docx", "-rf", "", "-o", dir})
		if err != nil || !cfg.AI {
			t.Fatal("CLI opt-in not accepted", err)
		}
		registry := sources.NewRegistry()
		registry.Register(reportingSource{})
		a := NewWithSources(cfg, registry)
		fake := &analysistest.Fake{Mode: mode}
		a.analyzer = analysis.New(fake, "test-fake")
		if err = a.Run(context.Background()); err != nil {
			t.Fatal("AI failure changed recon exit", err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "fixture_report.json"))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Status   string
			Results  []json.RawMessage
			Analysis models.Analysis
		}
		if err = json.Unmarshal(raw, &doc); err != nil || doc.Status != "complete" || len(doc.Results) != 1 {
			t.Fatal("recon state changed", err)
		}
		if mode != "" && doc.Analysis.Status != "failed" {
			t.Fatal("failure hidden")
		}
	}
	cfg, err := config.ParseArgs([]string{"-u", "fixture", "-ai", "-ai-config", filepath.Join(t.TempDir(), "missing"), "-of", "json", "-rf", "", "-o", t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	registry := sources.NewRegistry()
	registry.Register(reportingSource{})
	if err = NewWithSources(cfg, registry).Run(context.Background()); err != nil {
		t.Fatal("missing AI config broke reconnaissance", err)
	}
	if _, err = config.ParseArgs([]string{"-watch-file", "watch.yaml", "-ai"}); err == nil {
		t.Fatal("AI entered watch critical path")
	}
}
