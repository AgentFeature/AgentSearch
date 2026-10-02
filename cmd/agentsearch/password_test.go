package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

// Public XKCD phrase; hardcoded SHA-1 expectation computed independently.
const publicPassword = "correct horse battery staple"
const publicPrefix = "ABF7A"
const publicSuffix = "AD6438836DBE526AA231ABDE2D0EEF74D42"

func assertPasswordSafe(t *testing.T, text string) {
	t.Helper()
	for _, forbidden := range []string{publicPassword, publicPrefix, publicSuffix, strings.ToLower(publicPrefix + publicSuffix)} {
		if strings.Contains(text, forbidden) {
			t.Fatal("password or lookup material leaked")
		}
	}
}
func passwordServices(t *testing.T, dir, url string) string {
	t.Helper()
	path := filepath.Join(dir, "services.yaml")
	data := fmt.Sprintf("services:\n  hibp:\n    enabled: false\n    api_url: %q\n    api_key_env: AGENTSEARCH_UNUSED_KEY\n    passwords_api_url: %q\n", url+"/email-must-not-be-used", url+"/range")
	if os.WriteFile(path, []byte(data), 0600) != nil {
		t.Fatal("write service fixture failed")
	}
	return path
}
func verifyPasswordOutputs(t *testing.T, dir, wantStatus string) {
	t.Helper()
	for _, path := range []string{"results/[REDACTED].json", "results/[REDACTED].csv", "results/[REDACTED].txt", "results/[REDACTED]_summary.json", "output/[REDACTED]_report.txt", "output/[REDACTED]_report.html"} {
		b, err := os.ReadFile(filepath.Join(dir, path))
		if err != nil {
			t.Fatal("expected normalized output is missing")
		}
		assertPasswordSafe(t, string(b))
		if strings.HasSuffix(path, ".txt") || strings.HasSuffix(path, ".html") {
			label := "ERROR"
			if wantStatus == "found" {
				label = "PWNED"
			} else if wantStatus == "not_found" {
				label = "NOT PWNED"
			}
			if !strings.Contains(string(b), label) || !strings.Contains(string(b), "sha1-k-anonymity") {
				t.Fatal("human output omitted password outcome or method")
			}
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "results/[REDACTED].json"))
	var rows []models.Result
	if json.Unmarshal(b, &rows) != nil || len(rows) != 1 || rows[0].Status != models.ResultStatus(wantStatus) || rows[0].Source != "pwned-passwords" || rows[0].TargetType != models.TargetPassword || rows[0].Target != security.Redacted {
		t.Fatal("incorrect password JSON output")
	}
	if rows[0].Metadata["method"] != "sha1-k-anonymity" {
		t.Fatal("lookup method missing")
	}
	if wantStatus == "error" {
		if rows[0].Metadata["pwned"] != "" {
			t.Fatal("error represented as safe")
		}
	} else {
		wantCount, wantPwned := "0", "false"
		if wantStatus == "found" {
			wantCount, wantPwned = "42", "true"
		}
		if rows[0].Metadata["occurrences"] != wantCount || rows[0].Metadata["pwned"] != wantPwned {
			t.Fatal("incorrect occurrence metadata")
		}
	}
	csvData, _ := os.ReadFile(filepath.Join(dir, "results/[REDACTED].csv"))
	records, err := csv.NewReader(bytes.NewReader(csvData)).ReadAll()
	if err != nil || len(records) != 2 || strings.Join(records[0], ",") != "site_name,target,url,found,confidence,status,duration_ms,error,final_url" {
		t.Fatal("legacy CSV compatibility changed")
	}
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		assertPasswordSafe(t, path)
		if !d.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			assertPasswordSafe(t, string(b))
		}
		return nil
	}); err != nil {
		t.Fatal("output inventory failed")
	}
}
func TestPasswordCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "agentsearch")
	if _, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatal("build failed")
	}
	for _, tc := range []struct {
		name                string
		code                int
		body, status, label string
		failure             bool
	}{
		{"found", 200, publicSuffix + ":42\n", "found", "PWNED", false},
		{"found-email-key-present", 200, publicSuffix + ":42\n", "found", "PWNED", false},
		{"not-pwned", 200, strings.Repeat("0", 35) + ":1\n", "not_found", "NOT PWNED", false},
		{"padding", 200, publicSuffix + ":0\n", "not_found", "NOT PWNED", false},
		{"bad-request", 400, publicPassword, "error", "ERROR", true},
		{"throttled", 429, publicPrefix + publicSuffix, "error", "ERROR", true},
		{"server-error", 500, publicPassword, "error", "ERROR", true},
		{"malformed", 200, publicPassword, "error", "ERROR", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.RequestURI != "/range/"+publicPrefix || r.Method != http.MethodGet || r.Header.Get("Hibp-Api-Key") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.URL.RawQuery != "" {
					t.Error("password CLI sent an unsafe request")
				}
				body, _ := io.ReadAll(r.Body)
				if len(body) != 0 || strings.Contains(fmt.Sprint(r.Header), publicPassword) || strings.Contains(fmt.Sprint(r.Header), publicSuffix) {
					t.Error("password input crossed request boundary")
				}
				w.Header().Set("Retry-After", "3")
				w.Header().Set("Set-Cookie", "sensitive="+publicPassword)
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			dir := t.TempDir()
			services := passwordServices(t, dir, server.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-password", publicPassword, "-services", services, "-o", "results", "-rf", "cli,html", "-rt", "1s")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "HIBP_API_KEY=", "AGENTSEARCH_UNUSED_KEY=")
			if tc.name == "found-email-key-present" {
				cmd.Env = append(cmd.Env, "HIBP_API_KEY=public-test-key-not-a-credential", "AGENTSEARCH_UNUSED_KEY=public-test-key-not-a-credential")
			}
			output, err := cmd.CombinedOutput()
			if strings.Contains(string(output), "public-test-key-not-a-credential") {
				t.Fatal("email credential entered password diagnostics")
			}
			assertPasswordSafe(t, string(output))
			if (err != nil) != tc.failure || calls.Load() != 1 {
				t.Fatal("wrong password CLI exit or request count")
			}
			if !strings.Contains(string(output), tc.label) || !strings.Contains(string(output), "shell history") || !strings.Contains(string(output), "-password-prompt") {
				t.Fatal("password result or argument warning missing")
			}
			if strings.Contains(string(output), "workers=") {
				t.Fatal("password lookup advertised website workers")
			}
			verifyPasswordOutputs(t, dir, tc.status)
		})
	}
	t.Run("non-tty-prompt", func(t *testing.T) {
		cmd := exec.Command(binary, "-password-prompt")
		cmd.Dir = t.TempDir()
		cmd.Stdin = strings.NewReader(publicPassword + "\n")
		output, err := cmd.CombinedOutput()
		assertPasswordSafe(t, string(output))
		if err == nil || !strings.Contains(string(output), "interactive terminal") {
			t.Fatal("redirected password input accepted")
		}
	})
	t.Run("parser-diagnostics", func(t *testing.T) {
		for _, args := range [][]string{{"-password", publicPassword, "-rt", publicPassword}, {"-unknown=" + publicPassword, "-password", publicPassword}, {"-password", publicPassword, "-password", publicPassword}, {"-password", publicPassword, "-h"}} {
			cmd := exec.Command(binary, args...)
			cmd.Dir = t.TempDir()
			output, err := cmd.CombinedOutput()
			assertPasswordSafe(t, string(output))
			help := args[len(args)-1] == "-h"
			if (err == nil) != help {
				t.Fatal("wrong parse/help exit")
			}
		}
	})
}
func TestInjectedPasswordPromptCLI(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	input := security.NewSecret(publicPassword)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !input.Empty() || r.RequestURI != "/range/"+publicPrefix {
			t.Error("prompt input not consumed before range request")
		}
		fmt.Fprint(w, publicSuffix+":42\n")
	}))
	defer server.Close()
	dir := t.TempDir()
	services := passwordServices(t, dir, server.URL)
	prompted := 0
	code := run(context.Background(), []string{"-password-prompt", "-services", services, "-o", dir, "-rf", ""}, func(context.Context) (security.Secret, error) { prompted++; return input, nil })
	if code != 0 || prompted != 1 || calls.Load() != 1 || !input.Empty() {
		t.Fatal("injected prompt did not use normal runner path")
	}
	assertPasswordSafe(t, output.String())
	if strings.Contains(output.String(), "shell history") {
		t.Fatal("prompt mode emitted argument warning")
	}
	for _, tc := range []string{"read-error", "empty", "cancelled", "initialization-error"} {
		t.Run(tc, func(t *testing.T) {
			input := security.NewSecret(publicPassword)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			args := []string{"-password-prompt", "-services", services, "-o", dir, "-rf", ""}
			if tc == "initialization-error" {
				args[2] = filepath.Join(dir, "missing.yaml")
			}
			prompt := func(context.Context) (security.Secret, error) {
				if tc == "read-error" {
					return input, errors.New(publicPassword)
				}
				if tc == "empty" {
					input.Destroy()
					return security.Secret{}, nil
				}
				if tc == "cancelled" {
					cancel()
					return input, context.Canceled
				}
				return input, nil
			}
			if run(ctx, args, prompt) == 0 || !input.Empty() || calls.Load() != 1 {
				t.Fatal("failed prompt/configuration retained input or sent a request")
			}
			assertPasswordSafe(t, output.String())
		})
	}
}
