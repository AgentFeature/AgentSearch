package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestBitcoinTransactionCLIReports(t *testing.T) {
	const txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fixture, err := os.ReadFile("../../internal/sources/bitcoin/testdata/transaction.json")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/tx/"+txid {
			t.Error("unexpected endpoint")
		}
		_, _ = w.Write(fixture)
	}))
	defer server.Close()
	dir := t.TempDir()
	t.Chdir(dir)
	settings := filepath.Join(dir, "services.yaml")
	out := filepath.Join(dir, "results")
	text := fmt.Sprintf("services:\n  bitcoin:\n    enabled: false\n    api_key_env: UNUSED_KEY\n  bitcoin_tx:\n    enabled: true\n    api_url: %s/api\n", server.URL)
	if err := os.WriteFile(settings, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if code := run(context.Background(), []string{"-bitcoin-tx", strings.ToUpper(txid), "-services", settings, "-o", out, "-of", "json,csv,txt", "-rf", "cli,html"}, nil); code != 0 || calls.Load() != 1 {
		t.Fatalf("exit=%d requests=%d", code, calls.Load())
	}
	raw, err := os.ReadFile(filepath.Join(out, txid+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 || rows[0]["source"] != "bitcoin-tx" {
		t.Fatal("JSON transaction routing")
	}
	if _, exists := rows[0]["confidence"]; exists {
		t.Fatal("fabricated score")
	}
	raw, err = os.ReadFile(filepath.Join(out, txid+".txt"))
	if err != nil || !strings.Contains(string(raw), "not scored") || strings.Contains(string(raw), "Confidence: 0%") {
		t.Fatal("TXT scored provider transaction")
	}
	raw, err = os.ReadFile(filepath.Join(out, txid+".csv"))
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil || records[1][4] != "" {
		t.Fatal("CSV scored provider transaction")
	}
	raw, err = os.ReadFile(filepath.Join(dir, "output", txid+"_report.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	if !strings.Contains(html, "not scored") || strings.Contains(html, "Confidence 0 percent") || strings.Contains(html, "<script>alert(1)</script>") || !strings.Contains(html, "crypto_transaction_input") {
		t.Fatal("HTML unsafe/missing provenance")
	}
	raw, err = os.ReadFile(filepath.Join(dir, "output", txid+"_report.txt"))
	if err != nil || !strings.Contains(string(raw), "not scored") {
		t.Fatal("CLI report missing transaction semantics")
	}
}
