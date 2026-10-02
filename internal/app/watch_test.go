package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/config"
)

func TestWatchWebsiteAdmission(t *testing.T) {
	cfg := config.DefaultServerConfig().Engine
	cfg.WatchFile = "watch.yaml"
	cfg.Mode = config.ModeWebsites
	cfg.SitesFile = filepath.Join(t.TempDir(), "sites.yaml")
	for _, data := range []string{"- name: fixture\n  url: https://example.test/{username}\n  request_method: POST\n", "- name: fixture\n  url: https://example.test/{username}\n  request_payload: data\n"} {
		if err := os.WriteFile(cfg.SitesFile, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if a, err := New(&cfg); err == nil {
			a.Close()
			t.Fatal("write-capable website allowed in watch")
		}
	}
}
