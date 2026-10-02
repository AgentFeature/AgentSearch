package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
)

func TestDomainCredentialSelection(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "services.yaml")
	t.Setenv("AGENTSEARCH_DOMAIN_MISSING_KEY", "")
	cfg := config.DefaultServerConfig().Engine
	cfg.SitesFile = ""
	cfg.ServicesFile = settings
	write := func(enabled string) {
		t.Helper()
		if e := os.WriteFile(settings, []byte("services:\n  securitytrails:\n    enabled: "+enabled+"\n    api_key_env: AGENTSEARCH_DOMAIN_MISSING_KEY\n    min_interval: 1ms\n"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("false")
	service, e := NewSearchService(context.Background(), cfg)
	if e != nil {
		t.Fatal("disabled provider required credentials")
	}
	target, _ := NewSearchTarget("domain", "example.com", nil)
	if e = service.Search(context.Background(), target, func(models.Result) error { return nil }); !errors.Is(e, ErrSearchUnavailable) {
		t.Fatal("disabled domain did not report unavailability")
	}
	service.Close()
	write("true")
	// Password-only application ignores an enabled but unrelated provider's key.
	cfg.Mode = config.ModePassword
	a, e := New(&cfg)
	if e != nil {
		t.Fatal("unrelated provider broke password setup")
	}
	a.Close()
	cfg.Mode = config.ModeDomain
	if a, e := New(&cfg); e == nil {
		a.Close()
		t.Fatal("selected provider without credentials accepted")
	}
	if service, e := NewSearchService(context.Background(), cfg); e == nil {
		service.Close()
		t.Fatal("enabled server provider without key accepted")
	}
}
