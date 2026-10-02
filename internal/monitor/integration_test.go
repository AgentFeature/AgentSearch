package monitor

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
)

func TestLocalDispatcherEndToEnd(t *testing.T) {
	var phase, calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/v1/domain/example.com" {
			t.Error("unexpected provider request")
		}
		address := "192.0.2.1"
		if phase.Load() > 0 {
			address = "192.0.2.2"
		}
		fmt.Fprintf(w, `{"hostname":"example.com","current_dns":{"a":{"values":[{"ip":%q}]}}}`, address)
	}))
	defer server.Close()
	dir := t.TempDir()
	services := filepath.Join(dir, "services.yaml")
	t.Setenv("WATCH_FIXTURE_KEY", "local-fixture-key")
	if err := os.WriteFile(services, []byte(fmt.Sprintf("services:\n  securitytrails:\n    enabled: true\n    api_url: %s/v1\n    api_key_env: WATCH_FIXTURE_KEY\n", server.URL)), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultServerConfig().Engine
	cfg.SitesFile = ""
	cfg.ServicesFile = services
	service, err := app.NewSearchService(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	targets, err := ParseWatchlist([]byte("targets:\n- type: domain\n  value: ' EXAMPLE.COM. '\n"), parseTarget)
	if err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	store := openTestStore(t, stateDir)
	var alerts bytes.Buffer
	engine, err := New(service, store, targets, DefaultOptions(), &alerts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	waits := 0
	engine.wait = func(ctx context.Context, _ time.Duration) error {
		waits++
		phase.Store(1)
		if waits == 3 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	if err = engine.Run(ctx); err != nil {
		t.Fatal(err)
	}
	changes := readChanges(t, stateDir)
	if calls.Load() != 3 || len(changes) != 1 || changes[0].Kind != "MODIFIED" || changes[0].Source != "securitytrails" || changes[0].Old.Value == changes[0].New.Value {
		t.Fatal("end-to-end change detection", calls.Load(), changes)
	}
	if len(lines(t, stateDir, "observations")) != 3 || strings.Count(alerts.String(), "[CHANGE]") != 1 || strings.Contains(alerts.String(), "local-fixture-key") {
		t.Fatal("logs/alerts")
	}
	state, _, err := store.Load(targets[0])
	if err != nil || state.TargetType != models.TargetDomain {
		t.Fatal("persistent state", err)
	}
}
