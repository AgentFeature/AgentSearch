package main

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
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/models"
)

func TestDomainCLI(t *testing.T) {
	var entropy [16]byte
	if _, e := rand.Read(entropy[:]); e != nil {
		t.Fatal(e)
	}
	key := hex.EncodeToString(entropy[:])
	t.Setenv("AGENTSEARCH_DOMAIN_CLI_KEY", key)
	// An enabled unrelated provider must not require credentials in domain mode.
	t.Setenv("AGENTSEARCH_UNUSED_DOMAIN_HIBP_KEY", "")
	for _, status := range []int{200, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/v1/domain/example.com" || r.Header.Get("APIKEY") != key || r.Header.Get("Hibp-Api-Key") != "" {
					t.Error("domain credentials/route mixed")
				}
				w.WriteHeader(status)
				if status == 200 {
					fmt.Fprint(w, `{"hostname":"example.com","current_dns":{"a":{"values":[{"ip":"192.0.2.1"}]}}}`)
				} else {
					fmt.Fprint(w, key)
				}
			}))
			defer upstream.Close()
			dir := t.TempDir()
			settings := filepath.Join(dir, "services.yaml")
			output := filepath.Join(dir, "results")
			text := fmt.Sprintf("services:\n  securitytrails:\n    enabled: true\n    api_url: %s/v1\n    api_key_env: AGENTSEARCH_DOMAIN_CLI_KEY\n  hibp:\n    enabled: true\n    api_key_env: AGENTSEARCH_UNUSED_DOMAIN_HIBP_KEY\n", upstream.URL)
			if e := os.WriteFile(settings, []byte(text), 0600); e != nil {
				t.Fatal(e)
			}
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(previous)
			code := run(context.Background(), []string{"-domain", " EXAMPLE.COM. ", "-services", settings, "-o", output, "-of", "json,csv,txt", "-rf", "", "-rt", "1s"}, nil)
			expected := 0
			want := models.StatusFound
			if status != 200 {
				expected = 1
				want = models.StatusError
			}
			if code != expected || calls.Load() != 1 {
				t.Fatal("CLI exit/provider dispatch mismatch")
			}
			raw, e := os.ReadFile(filepath.Join(output, "example.com.json"))
			if e != nil {
				t.Fatal(e)
			}
			var rows []models.Result
			if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 || rows[0].Status != want || rows[0].TargetType != models.TargetDomain || rows[0].Source != "securitytrails" {
				t.Fatal("domain output lost")
			}
			for _, format := range []string{"json", "csv", "txt"} {
				b, e := os.ReadFile(filepath.Join(output, "example.com."+format))
				if e != nil || strings.Contains(string(b), key) {
					t.Fatal("missing output or credential leak")
				}
			}
			if strings.Contains(logs.String(), key) || strings.Contains(logs.String(), "example.com") {
				t.Fatal("credential or full domain logged")
			}
		})
	}
}
