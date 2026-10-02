package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

type localTestSource struct{}

func (localTestSource) Name() string            { return "local-test" }
func (localTestSource) Type() models.SourceType { return models.SourceLocal }
func (localTestSource) SearchEmail(ctx context.Context, email string, emit sources.Emit) error {
	return emit(models.Result{Status: models.StatusFound, Metadata: map[string]string{"observation": "fixture"}})
}
func TestApplicationWithoutWebsiteInfrastructure(t *testing.T) {
	registry := sources.NewRegistry()
	if err := registry.Register(localTestSource{}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := &config.AppConfig{Targets: []string{"alice@example.test"}, OutputDir: dir, OutputFormats: []string{"json", "csv", "txt"}}
	// No site database, network client, proxy, limiter or workers are required.
	a := NewWithSources(cfg, registry)
	if err := a.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "alice@example.test.json"))
	if err != nil {
		t.Fatal(err)
	}
	var results []models.Result
	if err := json.Unmarshal(b, &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Source != "local-test" || results[0].TargetType != models.TargetEmail || results[0].Metadata["observation"] != "fixture" {
		t.Fatal("generic path failed", results)
	}
}

func TestHIBPConfiguration(t *testing.T) {
	dir := t.TempDir()
	services := filepath.Join(dir, "services.yaml")
	t.Setenv(config.DefaultHIBPKeyEnv, "")
	cfg := &config.AppConfig{Mode: config.ModeEmail, ServicesFile: services, Targets: []string{"alice@example.test"}}
	if _, err := New(cfg); err == nil {
		t.Fatal("missing services file accepted")
	}
	if err := os.WriteFile(services, []byte("services:\n  hibp:\n    enabled: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil {
		t.Fatal("disabled service accepted")
	}
	if err := os.WriteFile(services, []byte("services:\n  hibp:\n    enabled: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil {
		t.Fatal("missing API key accepted")
	}
}

func TestWebsiteModeDoesNotActivateHIBP(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/website/alice@example.test" || r.Header.Get("hibp-api-key") != "" {
			t.Error("website mode activated an authenticated service")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	dir := t.TempDir()
	sitePath := filepath.Join(dir, "sites.yaml")
	servicePath := filepath.Join(dir, "services.yaml")
	if err := os.WriteFile(sitePath, []byte(fmt.Sprintf("- name: WebsiteFixture\n  url: %s/website/{username}\n", server.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(servicePath, []byte("services:\n  hibp:\n    enabled: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Enabling the service in configuration does not opt legacy callers into it.
	// No API key is needed for this website-only lookup.
	t.Setenv(config.DefaultHIBPKeyEnv, "")
	cfg := &config.AppConfig{Mode: config.ModeWebsites, ServicesFile: servicePath, SitesFile: sitePath, Targets: []string{"alice@example.test"}, Workers: 1, RequestTimeout: time.Second, OutputDir: dir, OutputFormats: []string{"json"}}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "alice@example.test.json"))
	if err != nil {
		t.Fatal(err)
	}
	var results []models.Result
	if err := json.Unmarshal(b, &results); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || len(results) != 1 || results[0].SourceType != models.SourceWebsite {
		t.Fatal("website mode changed its providers")
	}
}

func TestPasswordCompositionNeedsNoKeyOrServiceFile(t *testing.T) {
	t.Setenv(config.DefaultHIBPKeyEnv, "")
	cfg := &config.AppConfig{Mode: config.ModePassword, Password: security.NewSecret("test-password"), RequestTimeout: time.Second}
	defer cfg.Password.Destroy()
	// Construction only: no external lookup is performed.
	if _, err := New(cfg); err != nil {
		t.Fatal("default password source required email configuration")
	}
	cfg.ServicesFile = filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := New(cfg); err == nil || !cfg.Password.Empty() {
		t.Fatal("initialization failure retained input")
	}
}
