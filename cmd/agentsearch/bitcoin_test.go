package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/models"
)

func TestBitcoinCLIOutputs(t *testing.T) {
	const address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/txs/chain") {
					if fail {
						w.WriteHeader(500)
						return
					}
					fmt.Fprint(w, "[]")
					return
				}
				fmt.Fprintf(w, `{"address":%q,"chain_stats":{"tx_count":0,"funded_txo_sum":0,"spent_txo_sum":0}}`, address)
			}))
			defer server.Close()
			dir := t.TempDir()
			t.Chdir(dir)
			settings := filepath.Join(dir, "services.yaml")
			output := filepath.Join(dir, "results")
			// Enabled unrelated providers must not initialize or read keys in Bitcoin mode.
			text := fmt.Sprintf("services:\n  bitcoin:\n    enabled: true\n    api_url: %s/api\n  ipinfo:\n    enabled: true\n    api_key_env: BITCOIN_UNUSED_IP_KEY\n", server.URL)
			t.Setenv("BITCOIN_UNUSED_IP_KEY", "")
			if err := os.WriteFile(settings, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			code := run(context.Background(), []string{"-bitcoin", address, "-services", settings, "-o", output, "-of", "json,csv,txt", "-rf", "html"}, nil)
			want := 0
			if fail {
				want = 1
			}
			if code != want {
				t.Fatalf("exit %d", code)
			}
			raw, err := os.ReadFile(filepath.Join(output, address+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var rows []models.Result
			if json.Unmarshal(raw, &rows) != nil || len(rows) == 0 || rows[0].Source != "bitcoin" || rows[0].TargetType != models.TargetBitcoin {
				t.Fatal("output missing")
			}
			for _, ext := range []string{"json", "csv", "txt"} {
				b, err := os.ReadFile(filepath.Join(output, address+"."+ext))
				needle := "crypto_confirmed_balance_sats"
				if ext == "csv" {
					needle = "Bitcoin (Esplora)"
				} // Preserve the legacy summary-only CSV schema.
				if err != nil || !strings.Contains(string(b), needle) {
					t.Fatalf("%s output evidence missing: %v", ext, err)
				}
			}
			// Existing HTML generator owns its output directory; locate its result without
			// imposing a new Bitcoin renderer or filename convention.
			files, _ := filepath.Glob(filepath.Join(dir, "output", "*.html"))
			if len(files) == 0 {
				t.Fatal("HTML report missing")
			}
			b, err := os.ReadFile(files[0])
			if err != nil || !strings.Contains(string(b), "crypto_confirmed_balance_sats") {
				t.Fatal("HTML evidence missing")
			}
		})
	}
}
