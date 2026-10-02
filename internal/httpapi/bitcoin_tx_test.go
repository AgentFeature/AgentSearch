package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

func TestBitcoinTransactionHTTP(t *testing.T) {
	const id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fixture, err := os.ReadFile("../sources/bitcoin/testdata/transaction.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		enabled, other bool
		status, want   int
		body           string
	}{
		{"independent", true, false, 200, 200, string(fixture)},
		{"all-enabled-no-enrichment", true, true, 200, 200, string(fixture)},
		{"unconfirmed", true, false, 200, 200, strings.Replace(string(fixture), `"confirmed": true,`+"\n"+`    "block_height": 800000,`+"\n"+`    "block_hash": "`+strings.Repeat("c", 64)+`",`+"\n"+`    "block_time": 1700000000`, `"confirmed": false`, 1)},
		{"absent", true, false, 404, 200, "Transaction not found"},
		{"unknown-404", true, false, 404, 502, "private-marker"},
		{"server-error", true, false, 500, 503, "private-marker"},
		{"limited", true, false, 429, 429, "private-marker"},
		{"malformed", true, false, 200, 502, "{"},
		{"disabled", false, true, 200, 503, string(fixture)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.URL.Path != "/api/tx/"+id || r.Header.Get("Authorization") != "" {
					t.Error("unexpected request/enrichment/credentials")
				}
				w.Header().Set("Retry-After", "2")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer upstream.Close()
			cfg := config.DefaultServerConfig()
			cfg.Engine.SitesFile = ""
			cfg.Engine.ServicesFile = filepath.Join(t.TempDir(), "services.yaml")
			putFile(t, cfg.Engine.ServicesFile, fmt.Sprintf("services:\n  bitcoin_tx:\n    enabled: %t\n    api_url: %s/api\n  bitcoin:\n    enabled: %t\n    api_url: %s/api\n  bitcoin_labels:\n    enabled: %t\n    api_url: %s/api/1/address-lookup\n", tc.enabled, upstream.URL, tc.other, upstream.URL, tc.other, upstream.URL))
			service, err := app.NewSearchService(context.Background(), cfg.Engine)
			if err != nil {
				t.Fatal(err)
			}
			defer service.Close()
			var logs bytes.Buffer
			h, err := New(service, security.NewSecret(testToken), cfg, slog.New(slog.NewTextHandler(&logs, nil)))
			if err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf(`{"type":"bitcoin_tx","target":%q}`, " "+strings.ToUpper(id)+" ")
			if r := request(h, "POST", "/api/v1/search", body, ""); r.Code != 401 {
				t.Fatal("auth bypass")
			}
			for _, bad := range []string{`{"type":"bitcoin_tx","target":"bad"}`, fmt.Sprintf(`{"type":"bitcoin_tx","target":%q,"password":"secret"}`, id), fmt.Sprintf(`{"type":"bitcoin_tx","target":%q,"seed":"secret"}`, id), fmt.Sprintf(`{"type":"bitcoin_tx","target":%q,"private_key":"secret"}`, id)} {
				if r := request(h, "POST", "/api/v1/search", bad, "Bearer "+testToken); r.Code != 400 {
					t.Fatal("invalid request accepted", r.Code)
				}
			}
			if calls.Load() != 0 {
				t.Fatal("invalid request reached provider")
			}
			response := request(h, "POST", "/api/v1/search", body, "Bearer "+testToken)
			if response.Code != tc.want {
				t.Fatalf("HTTP %d: %s", response.Code, response.Body.String())
			}
			if !tc.enabled {
				if calls.Load() != 0 {
					t.Fatal("disabled queried")
				}
				return
			}
			var payload struct{ Results []models.Result }
			if json.Unmarshal(response.Body.Bytes(), &payload) != nil || len(payload.Results) != 1 || calls.Load() != 1 {
				t.Fatal("routing/serialization")
			}
			row := payload.Results[0]
			if row.Source != "bitcoin-tx" || row.TargetType != models.TargetBitcoinTransaction || row.Target != id {
				t.Fatal("provenance")
			}
			if tc.want == 200 {
				want := models.StatusFound
				if tc.status == 404 {
					want = models.StatusNotFound
				}
				if row.Status != want || row.Metadata["provider"] != "esplora" || row.URL != upstream.URL+"/api/tx/"+id {
					t.Fatal("provider observation lost")
				}
				if want == models.StatusFound {
					if len(row.Evidence) < 6 || row.Evidence[0].Kind != "crypto_transaction_summary" {
						t.Fatal("evidence lost")
					}
					for _, e := range row.Evidence {
						if !json.Valid([]byte(e.Value)) {
							t.Fatal("corrupted evidence")
						}
					}
					if tc.name == "unconfirmed" && (row.Evidence[1].Value != `{"confirmed":false}` || strings.Contains(fmt.Sprint(row.Evidence), "crypto_transaction_block")) {
						t.Fatal("unconfirmed misrepresented")
					}
				}
			} else if row.Status != models.StatusError || len(row.Evidence) != 0 {
				t.Fatal("error became absence/partial success")
			}
			if tc.status == 429 && response.Header().Get("Retry-After") != "2" {
				t.Fatal("lost Retry-After")
			}
			if strings.Contains(response.Body.String()+logs.String(), "private-marker") || strings.Contains(logs.String(), id) || strings.Contains(response.Body.String(), `"confidence"`) {
				t.Fatal("unsafe diagnostics/score")
			}
		})
	}
}
