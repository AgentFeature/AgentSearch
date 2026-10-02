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

func TestBitcoinOptInAndConfiguration(t *testing.T) {
	file := filepath.Join(t.TempDir(), "services.yaml")
	cfg := config.DefaultServerConfig().Engine
	cfg.SitesFile = ""
	cfg.ServicesFile = file
	if err := os.WriteFile(file, []byte("services:\n  bitcoin:\n    enabled: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewSearchService(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	target, err := NewSearchTarget("bitcoin", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Search(context.Background(), target, func(models.Result) error { return nil }); !errors.Is(err, ErrSearchUnavailable) {
		t.Fatal("disabled source available")
	}
	cfg.Mode = config.ModeBitcoin
	for _, extra := range []string{"    min_interval: 0s\n", "    min_interval: 31s\n", "    api_key_env: UNUSED_KEY\n", "    api_url: http://example.com/api\n"} {
		if err = os.WriteFile(file, []byte("services:\n  bitcoin:\n    enabled: true\n"+extra), 0600); err != nil {
			t.Fatal(err)
		}
		if a, err := New(&cfg); err == nil {
			a.Close()
			t.Fatal("unsafe configuration accepted")
		}
	}
	if err = os.WriteFile(file, []byte("services:\n  bitcoin:\n    enabled: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
}

func TestBitcoinLabelsConfiguration(t *testing.T) {
	file := filepath.Join(t.TempDir(), "services.yaml")
	cfg := config.DefaultServerConfig().Engine
	cfg.Mode = config.ModeBitcoin
	cfg.ServicesFile = file
	for _, extra := range []string{"    min_interval: 0s\n", "    min_interval: 31s\n", "    api_key_env: UNUSED_LABELS_KEY\n", "    api_url: http://example.com/api/1/address-lookup\n"} {
		if err := os.WriteFile(file, []byte("services:\n  bitcoin_labels:\n    enabled: true\n"+extra), 0600); err != nil {
			t.Fatal(err)
		}
		if a, err := New(&cfg); err == nil {
			a.Close()
			t.Fatal("unsafe label configuration accepted")
		}
	}
	if err := os.WriteFile(file, []byte("services:\n  bitcoin_labels:\n    enabled: true\n  bitcoin:\n    enabled: false\n    api_key_env: UNUSED_CHAIN_KEY\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
}
