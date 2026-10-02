package main

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/passworddb"
	"github.com/AgentFeature/agentsearch/internal/security"
)

func TestLocalPasswordCLISelectionAndOutputs(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "database")
	text := publicPrefix + publicSuffix + ":42\n"
	sum := sha256.Sum256([]byte(text))
	input := filepath.Join(t.TempDir(), "artifact.txt")
	if e := os.WriteFile(input, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	id, e := passworddb.Import(ctx, root, input, passworddb.ImportOptions{ExpectedSHA256: hex.EncodeToString(sum[:]), Complete: true, AcquiredAt: time.Now()})
	if e != nil {
		t.Fatal(e)
	}
	if e = passworddb.Activate(ctx, root, id); e != nil {
		t.Fatal(e)
	}
	var networkCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { networkCalls.Add(1) }))
	defer server.Close()
	servicePath := filepath.Join(t.TempDir(), "services.yaml")
	if e = os.WriteFile(servicePath, []byte(fmt.Sprintf("services:\n  hibp:\n    enabled: false\n    passwords_api_url: %q\n    passwords_database_path: %q\n", server.URL+"/range", root)), 0600); e != nil {
		t.Fatal(e)
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	for _, tc := range []string{"found", "absent", "missing"} {
		t.Run(tc, func(t *testing.T) {
			output := t.TempDir()
			args := []string{"-password-prompt", "-password-backend", "local", "-services", servicePath, "-o", output, "-rf", ""}
			if tc == "missing" {
				args = append(args, "-password-db", filepath.Join(t.TempDir(), "missing"))
			}
			called := false
			password := publicPassword
			if tc == "absent" {
				password += "!"
			}
			secret := security.NewSecret(password)
			defer secret.Destroy()
			code := run(ctx, args, func(context.Context) (security.Secret, error) { called = true; return secret, nil })
			if tc == "missing" {
				if code == 0 || called {
					t.Fatal("missing local database did not fail before prompting")
				}
				return
			}
			if code != 0 || !called || !secret.Empty() {
				t.Fatal("local CLI lifecycle failed")
			}
			raw, e := os.ReadFile(filepath.Join(output, "[REDACTED].json"))
			if e != nil {
				t.Fatal(e)
			}
			var rows []models.Result
			if e = json.Unmarshal(raw, &rows); e != nil || len(rows) != 1 {
				t.Fatal("invalid local result")
			}
			r := rows[0]
			if r.Source != "pwned-passwords-local" || r.SourceType != models.SourceLocal || r.Confidence != 100 || r.Metadata["method"] != "sha1-offline" || (r.Status == models.StatusFound) != (tc == "found") {
				t.Fatal("incorrect local outcome")
			}
			if e = filepath.WalkDir(output, func(path string, d os.DirEntry, e error) error {
				if e != nil {
					return e
				}
				assertPasswordSafe(t, path)
				if !d.IsDir() {
					b, e := os.ReadFile(path)
					if e != nil {
						return e
					}
					assertPasswordSafe(t, string(b))
					if strings.Contains(string(b), password) {
						t.Fatal("output contains password")
					}
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
	assertPasswordSafe(t, logs.String())
	if networkCalls.Load() != 0 {
		t.Fatal("local mode contacted API or fell back")
	}
}
