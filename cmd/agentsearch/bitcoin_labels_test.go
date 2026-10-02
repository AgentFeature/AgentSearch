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

func TestBitcoinLabelsCLIReports(t *testing.T) {
	const address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/1/address-lookup" {
			t.Error("unexpected endpoint")
		}
		fmt.Fprint(w, `{"found":true,"label":"Example <script>alert(1)</script>","wallet_id":"abcd"}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	t.Chdir(dir)
	settings := filepath.Join(dir, "services.yaml")
	out := filepath.Join(dir, "results")
	text := fmt.Sprintf("services:\n  bitcoin:\n    enabled: false\n    api_key_env: UNUSED_KEY\n  bitcoin_labels:\n    enabled: true\n    api_url: %s/api/1/address-lookup\n", server.URL)
	if err := os.WriteFile(settings, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if code := run(context.Background(), []string{"-bitcoin", address, "-services", settings, "-o", out, "-of", "json,csv,txt", "-rf", "cli,html"}, nil); code != 0 || calls.Load() != 1 {
		t.Fatalf("exit=%d requests=%d", code, calls.Load())
	}
	raw, err := os.ReadFile(filepath.Join(out, address+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 || rows[0]["source"] != "bitcoin-labels" {
		t.Fatal("JSON label routing")
	}
	if _, exists := rows[0]["confidence"]; exists {
		t.Fatal("fabricated score")
	}
	raw, err = os.ReadFile(filepath.Join(out, address+".txt"))
	if err != nil || !strings.Contains(string(raw), "not scored") || strings.Contains(string(raw), "Confidence: 0%") {
		t.Fatal("TXT scored provider label")
	}
	raw, err = os.ReadFile(filepath.Join(out, address+".csv"))
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil || records[1][4] != "" {
		t.Fatal("CSV scored provider label")
	}
	raw, err = os.ReadFile(filepath.Join(dir, "output", address+"_report.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	if !strings.Contains(html, "not scored") || strings.Contains(html, "Confidence 0 percent") || strings.Contains(html, "<script>alert(1)</script>") || !strings.Contains(html, "not verified ownership") {
		t.Fatal("HTML unsafe/missing provenance")
	}
	raw, err = os.ReadFile(filepath.Join(dir, "output", address+"_report.txt"))
	if err != nil || !strings.Contains(string(raw), "not scored") {
		t.Fatal("CLI report missing label semantics")
	}
}
