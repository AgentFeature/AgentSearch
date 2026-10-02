package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEmailCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "agentsearch")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("generate mock credential")
	}
	key := hex.EncodeToString(random[:])
	for _, tt := range []struct {
		name       string
		status     int
		body       string
		wantStatus string
		failure    bool
	}{
		{"found", 200, `[{"Name":"ExampleBreach","Title":"Example","Domain":"example.test","DataClasses":["Email addresses"],"IsVerified":true}]`, "found", false},
		{"none", 404, "", "not_found", false},
		{"denied", 401, "remote error", "error", true},
		{"limited", 429, "remote error", "error", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/api/v3/breachedaccount/Alice+tag@example.test" || r.Header.Get("hibp-api-key") != key || !strings.HasPrefix(r.UserAgent(), "AgentSearch") {
					t.Error("wrong HIBP request")
				}
				w.Header().Set("Retry-After", "30")
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()
			dir := t.TempDir()
			services := filepath.Join(dir, "services.yaml")
			data := fmt.Sprintf("services:\n  hibp:\n    enabled: true\n    api_url: %q\n    api_key_env: AGENTSEARCH_TEST_API_KEY\n", server.URL+"/api/v3")
			if err := os.WriteFile(services, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-email", " Alice+tag@example.test ", "-services", services, "-o", "results", "-rf", "cli,html", "-rt", "1s")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "AGENTSEARCH_TEST_API_KEY="+key)
			output, err := cmd.CombinedOutput()
			if (err != nil) != tt.failure {
				t.Fatalf("wrong exit status for %s: %v", tt.name, err)
			}
			if strings.Contains(string(output), key) {
				t.Fatal("API key leaked in CLI output")
			}
			if calls.Load() != 1 {
				t.Fatal("lookup retried or website search was started")
			}
			b, err := os.ReadFile(filepath.Join(dir, "results", "Alice+tag@example.test.json"))
			if err != nil {
				t.Fatal(err)
			}
			var rows []map[string]any
			if err := json.Unmarshal(b, &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0]["source"] != "hibp" || rows[0]["source_type"] != "api" || rows[0]["target_type"] != "email" || rows[0]["target"] != "Alice+tag@example.test" || rows[0]["status"] != tt.wantStatus {
				t.Fatal("incorrect HIBP output")
			}
			if tt.status == 429 && rows[0]["metadata"].(map[string]any)["retry_after_seconds"] != "30" {
				t.Fatal("rate-limit information lost")
			}
			for _, path := range []string{"results/Alice+tag@example.test.csv", "results/Alice+tag@example.test.txt", "results/Alice+tag@example.test_summary.json", "output/Alice+tag@example.test_report.txt", "output/Alice+tag@example.test_report.html"} {
				b, err := os.ReadFile(filepath.Join(dir, path))
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(b), key) {
					t.Fatal("API key leaked in persisted output")
				}
			}
		})
	}
	t.Run("missing-key", func(t *testing.T) {
		dir := t.TempDir()
		services := filepath.Join(dir, "services.yaml")
		_ = os.WriteFile(services, []byte("services:\n  hibp:\n    enabled: true\n    api_key_env: AGENTSEARCH_TEST_MISSING_KEY\n"), 0600)
		cmd := exec.Command(binary, "-email", "alice@example.test", "-services", services)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "AGENTSEARCH_TEST_MISSING_KEY=")
		output, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "check service settings and environment credentials") {
			t.Fatal("missing-key error was not actionable")
		}
	})
}
