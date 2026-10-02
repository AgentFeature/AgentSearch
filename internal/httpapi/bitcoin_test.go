package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

func TestUnifiedBitcoinHTTP(t *testing.T) {
	const address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	for _, status := range []int{200, 500, 429} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.Header.Get("Authorization") != "" {
					t.Error("credentials forwarded")
				}
				if strings.HasSuffix(r.URL.Path, "/txs/chain") {
					if status != 200 {
						w.Header().Set("Retry-After", "2")
						w.WriteHeader(status)
						fmt.Fprint(w, "private-provider-marker")
						return
					}
					fmt.Fprint(w, "[]")
					return
				}
				fmt.Fprintf(w, `{"address":%q,"chain_stats":{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0}}`, address)
			}))
			defer upstream.Close()
			cfg := config.DefaultServerConfig()
			cfg.Engine.SitesFile = ""
			cfg.Engine.ServicesFile = filepath.Join(t.TempDir(), "services.yaml")
			putFile(t, cfg.Engine.ServicesFile, fmt.Sprintf("services:\n  bitcoin:\n    enabled: true\n    api_url: %s/api\n", upstream.URL))
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
			w := request(h, "POST", "/api/v1/search", fmt.Sprintf(`{"type":"bitcoin","target":%q}`, address), "Bearer "+testToken)
			want := status
			if status == 500 {
				want = 502
			}
			if w.Code != want {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
			var payload struct{ Results []models.Result }
			if e = json.Unmarshal(w.Body.Bytes(), &payload); e != nil {
				t.Fatal(e)
			}
			n := 1
			if status != 200 {
				n = 2
			}
			if len(payload.Results) != n {
				t.Fatal("missing observations/error")
			}
			observed := payload.Results[0]
			if observed.Source != "bitcoin" || observed.TargetType != models.TargetBitcoin || observed.Status != models.StatusFound {
				t.Fatal("routing/provenance")
			}
			found := false
			for _, ev := range observed.Evidence {
				if ev.Kind == "crypto_confirmed_balance_sats" && ev.Value == "0" {
					found = true
				}
			}
			if !found {
				t.Fatal("API discarded partial statistics")
			}
			if status != 200 && (observed.Metadata["history_status"] != "unavailable" || payload.Results[1].Status != models.StatusError) {
				t.Fatal("failure represented as absence")
			}
			if status == 429 && w.Header().Get("Retry-After") != "2" {
				t.Fatal("Retry-After lost")
			}
			if strings.Contains(w.Body.String()+logs.String(), "private-provider-marker") || strings.Contains(logs.String(), address) {
				t.Fatal("unsafe diagnostics")
			}
			for _, body := range []string{`{"type":"bitcoin","target":"bad"}`, fmt.Sprintf(`{"type":"bitcoin","target":%q,"private_key":"not-accepted"}`, address), fmt.Sprintf(`{"type":"bitcoin","target":%q,"password":"not-accepted"}`, address), fmt.Sprintf(`{"type":"bitcoin","target":%q,"seed":"not-accepted"}`, address)} {
				if r := request(h, "POST", "/api/v1/search", body, "Bearer "+testToken); r.Code != 400 {
					t.Fatal("invalid request accepted")
				}
			}
		})
	}
}
