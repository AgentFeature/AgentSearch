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

func TestBitcoinTransactionOptInAndConfiguration(t *testing.T) {
	file := filepath.Join(t.TempDir(), "services.yaml")
	cfg := config.DefaultServerConfig().Engine
	cfg.SitesFile = ""
	cfg.ServicesFile = file
	if err := os.WriteFile(file, []byte("services:\n  bitcoin_tx:\n    enabled: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewSearchService(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	target, err := NewSearchTarget("bitcoin_tx", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Search(context.Background(), target, func(models.Result) error { return nil }); !errors.Is(err, ErrSearchUnavailable) {
		t.Fatal("disabled source available")
	}
	cfg.Mode = config.ModeBitcoinTransaction
	for _, extra := range []string{"    min_interval: 0s\n", "    min_interval: 31s\n", "    api_key_env: UNUSED_KEY\n", "    api_url: http://example.com/api\n"} {
		if err = os.WriteFile(file, []byte("services:\n  bitcoin_tx:\n    enabled: true\n"+extra), 0600); err != nil {
			t.Fatal(err)
		}
		if a, err := New(&cfg); err == nil {
			a.Close()
			t.Fatal("unsafe configuration accepted")
		}
	}
	if err = os.WriteFile(file, []byte("services:\n  bitcoin_tx:\n    enabled: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
}
