package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

func TestUnifiedDomainHTTP(t *testing.T) {
	var entropy [16]byte
	if _, e := rand.Read(entropy[:]); e != nil {
		t.Fatal(e)
	}
	key := hex.EncodeToString(entropy[:])
	t.Setenv("AGENTSEARCH_DOMAIN_HTTP_KEY", key)
	var calls atomic.Int32
	var status atomic.Int32
	status.Store(200)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("APIKEY") != key || r.Header.Get("Authorization") != "" || r.URL.Path != "/v1/domain/example.com" {
			t.Error("provider/header routing mismatch")
		}
		code := status.Load()
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(int(code))
		if code == 200 {
			fmt.Fprint(w, `{"hostname":"example.com","current_dns":{"a":{"values":[{"ip":"192.0.2.1"}]}}}`)
		} else {
			fmt.Fprint(w, key)
		}
	}))
	defer upstream.Close()
	cfg := config.DefaultServerConfig()
	cfg.Engine.SitesFile = ""
	cfg.Engine.ServicesFile = filepath.Join(t.TempDir(), "services.yaml")
	putFile(t, cfg.Engine.ServicesFile, fmt.Sprintf("services:\n  securitytrails:\n    enabled: true\n    api_url: %s/v1\n    api_key_env: AGENTSEARCH_DOMAIN_HTTP_KEY\n    min_interval: 1ms\n", upstream.URL))
	service, e := app.NewSearchService(context.Background(), cfg.Engine)
	if e != nil {
		t.Fatal(e)
	}
	defer service.Close()
	var logs bytes.Buffer
	h, e := New(service, security.NewSecret(testToken), cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ upstream, want int }{{200, 200}, {401, 503}, {404, 502}, {429, 429}} {
		status.Store(int32(tc.upstream))
		w := request(h, "POST", "/api/v1/search", `{"type":"domain","target":"Example.COM."}`, "Bearer "+testToken)
		if w.Code != tc.want {
			t.Fatalf("HTTP status %d want %d", w.Code, tc.want)
		}
		var payload struct{ Results []models.Result }
		if json.Unmarshal(w.Body.Bytes(), &payload) != nil || len(payload.Results) != 1 || payload.Results[0].Source != "securitytrails" || payload.Results[0].TargetType != models.TargetDomain {
			t.Fatal("normalized domain payload missing")
		}
		if tc.upstream != 200 && payload.Results[0].Status != models.StatusError {
			t.Fatal("provider failure became absence")
		}
		if tc.upstream == 429 && w.Header().Get("Retry-After") != "2" {
			t.Fatal("Retry-After lost")
		}
		if strings.Contains(w.Body.String()+logs.String(), key) {
			t.Fatal("provider key leaked")
		}
	}
	for _, body := range []string{`{"type":"domain","target":"https://example.com"}`, `{"type":"domain","target":"example.com","password":"example-password"}`, `{"type":"domain","target":"example.com","provider":"securitytrails"}`} {
		if w := request(h, "POST", "/api/v1/search", body, "Bearer "+testToken); w.Code != 400 {
			t.Fatal("invalid domain contract accepted")
		}
	}
	if calls.Load() != 4 || strings.Contains(logs.String(), "example.com") {
		t.Fatal("unexpected dispatch or domain access-log leak")
	}
}
