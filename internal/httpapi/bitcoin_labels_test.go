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
	"sync/atomic"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

func TestBitcoinLabelsIndependentHTTP(t *testing.T) {
	const address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	for _, tc := range []struct {
		name                           string
		chain, labels                  bool
		chainStatus, labelStatus, want int
		negative                       bool
	}{
		{"labels only", false, true, 200, 200, 200, false},
		{"blockchain only", true, false, 200, 200, 200, false},
		{"both", true, true, 200, 200, 200, false},
		{"labels failure", true, true, 200, 500, 502, false},
		{"blockchain failure", true, true, 500, 200, 502, false},
		{"no provider label", true, true, 200, 200, 200, true},
		{"rate limit", false, true, 200, 429, 429, false},
		{"both disabled", false, false, 200, 200, 503, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var chainCalls, labelCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					t.Error("API bearer token forwarded")
				}
				if r.URL.Path == "/api/1/address-lookup" {
					labelCalls.Add(1)
					w.Header().Set("Retry-After", "2")
					w.WriteHeader(tc.labelStatus)
					if tc.labelStatus != 200 {
						fmt.Fprint(w, "private-upstream-marker")
						return
					}
					if tc.negative {
						fmt.Fprint(w, `{"found":false}`)
						return
					}
					fmt.Fprint(w, `{"found":true,"label":"Example Service","wallet_id":"abcd","category":"service"}`)
					return
				}
				chainCalls.Add(1)
				w.WriteHeader(tc.chainStatus)
				if tc.chainStatus != 200 {
					return
				}
				if strings.HasSuffix(r.URL.Path, "/txs/chain") {
					fmt.Fprint(w, "[]")
					return
				}
				fmt.Fprintf(w, `{"address":%q,"chain_stats":{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0}}`, address)
			}))
			defer server.Close()
			cfg := config.DefaultServerConfig()
			cfg.Engine.SitesFile = ""
			cfg.Engine.ServicesFile = filepath.Join(t.TempDir(), "services.yaml")
			putFile(t, cfg.Engine.ServicesFile, fmt.Sprintf("services:\n  bitcoin:\n    enabled: %t\n    api_url: %s/api\n  bitcoin_labels:\n    enabled: %t\n    api_url: %s/api/1/address-lookup\n", tc.chain, server.URL, tc.labels, server.URL))
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
			response := request(h, "POST", "/api/v1/search", fmt.Sprintf(`{"type":"bitcoin","target":%q}`, address), "Bearer "+testToken)
			if response.Code != tc.want {
				t.Fatalf("HTTP %d: %s", response.Code, response.Body.String())
			}
			var payload struct{ Results []models.Result }
			if json.Unmarshal(response.Body.Bytes(), &payload) != nil {
				t.Fatal("bad response")
			}
			var labelRow *models.Result
			balance := false
			for i := range payload.Results {
				r := &payload.Results[i]
				if r.Source == "bitcoin-labels" {
					labelRow = r
				}
				for _, e := range r.Evidence {
					if e.Kind == "crypto_confirmed_balance_sats" {
						balance = true
					}
				}
			}
			if balance != (tc.chain && tc.chainStatus == 200) {
				t.Fatal("blockchain result lost or manufactured")
			}
			if tc.labels {
				if labelRow == nil || labelCalls.Load() != 1 {
					t.Fatal("label routing")
				}
				if tc.labelStatus != 200 {
					if labelRow.Status != models.StatusError {
						t.Fatal("label failure hidden")
					}
				} else {
					want := models.StatusFound
					if tc.negative {
						want = models.StatusNotFound
					}
					if labelRow.Status != want || labelRow.Metadata["provider"] != "WalletExplorer" {
						t.Fatal("label association lost")
					}
					if !tc.negative && (len(labelRow.Evidence) != 1 || labelRow.Evidence[0].Kind != "crypto_provider_association") {
						t.Fatal("label evidence lost")
					}
				}
			} else if labelCalls.Load() != 0 || labelRow != nil {
				t.Fatal("disabled labels queried")
			}
			expectedChain := int32(0)
			if tc.chain {
				expectedChain = 1
				if tc.chainStatus == 200 {
					expectedChain = 2
				}
			}
			if chainCalls.Load() != expectedChain {
				t.Fatal("unexpected blockchain requests")
			}
			if tc.labelStatus == 429 && response.Header().Get("Retry-After") != "2" {
				t.Fatal("rate limit lost")
			}
			if strings.Contains(response.Body.String()+logs.String(), "private-upstream-marker") || strings.Contains(logs.String(), address) {
				t.Fatal("unsafe output/logs")
			}
		})
	}
}
