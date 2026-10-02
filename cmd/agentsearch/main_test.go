package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Exercise the actual CLI parser and production app wiring, not a substitute.
func TestCLICompatibility(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "agentsearch")
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	help, err := exec.Command(binary, "-h").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	available := make(map[string]bool)
	for _, line := range strings.Split(string(help), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			available[fields[0]] = true
		}
	}
	for _, flag := range []string{"u", "f", "s", "p", "w", "rl", "rt", "tt", "o", "of", "rf", "ua", "mc", "mch", "utls", "retries", "d"} {
		if !available["-"+flag] {
			t.Errorf("flag removed: %s", flag)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/found/alice", "/found/bob":
			w.WriteHeader(200)
		case "/missing/alice", "/missing/bob":
			w.WriteHeader(404)
		default:
			t.Errorf("unexpanded or unexpected URL: %s", r.URL.Path)
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	for _, format := range []string{"yaml", "sherlock", "maigret"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			sitePath := filepath.Join(dir, "sites")
			var data string
			switch format {
			case "yaml":
				data = fmt.Sprintf("- name: Found\n  url: %s/found/{username}\n  check_type: status_code\n  error_code: 404\n- name: Missing\n  url: %s/missing/{username}\n  check_type: status_code\n  error_code: 404\n", server.URL, server.URL)
			case "sherlock":
				data = fmt.Sprintf(`{"$schema":"fixture","Found":{"url":"%s/found/{}","errorType":"status_code"},"Missing":{"url":"%s/missing/{}","errorType":"status_code"}}`, server.URL, server.URL)
			case "maigret":
				data = fmt.Sprintf(`{"sites":{"Found":{"url":"%s/found/{username}","checkType":"status_code","error_code":404},"Missing":{"url":"%s/missing/{username}","checkType":"status_code","error_code":404}}}`, server.URL, server.URL)
			}
			if err := os.WriteFile(sitePath, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			targets := filepath.Join(dir, "targets.txt")
			_ = os.WriteFile(targets, []byte("# comment\n\nbob\n"), 0600)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-u", "alice", "-f", targets, "-s", sitePath, "-w", "2", "-rl", "0s", "-rt", "1s", "-tt", "5s", "-o", "results", "-of", "json,csv,txt,html,pdf,docx", "-rf", "cli,html,docx", "-retries", "1")
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("CLI: %v\n%s", err, out)
			}
			for _, target := range []string{"alice", "bob"} {
				b, err := os.ReadFile(filepath.Join(dir, "results", target+".json"))
				if err != nil {
					t.Fatal(err)
				}
				var rows []map[string]any
				if err := json.Unmarshal(b, &rows); err != nil {
					t.Fatal(err)
				}
				if len(rows) != 2 {
					t.Fatalf("results: %s", b)
				}
				statuses := map[string]string{}
				for _, row := range rows {
					statuses[row["site_name"].(string)] = row["status"].(string)
					if row["target"] != target || row["target_type"] != "username" || row["source_type"] != "website" {
						t.Fatalf("normalization: %v", row)
					}
				}
				if statuses["Found"] != "found" || statuses["Missing"] != "not_found" {
					t.Fatal("detection changed", statuses)
				}
				b, err = os.ReadFile(filepath.Join(dir, "results", target+".csv"))
				if err != nil {
					t.Fatal(err)
				}
				records, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
				if err != nil || len(records) != 3 || len(records[0]) != 9 {
					t.Fatal("CSV compatibility", err)
				}
				// The legacy -rf bridge retains output/; every -of format respects -o.
				for _, path := range []string{filepath.Join("results", target+".html"), filepath.Join("results", target+".pdf"), filepath.Join("results", target+".docx"), filepath.Join("results", target+"_report.json"), filepath.Join("results", target+"_report.csv"), filepath.Join("output", target+"_report.docx"), filepath.Join("results", target+".txt"), filepath.Join("results", target+"_summary.json"), filepath.Join("output", target+"_report.txt"), filepath.Join("output", target+"_report.html")} {
					if _, err := os.Stat(filepath.Join(dir, path)); err != nil {
						t.Fatal(path, err)
					}
				}
			}
		})
	}
	t.Run("graceful-shutdown", func(t *testing.T) {
		slowStarted := make(chan struct{}, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/slow/alice" {
				select {
				case slowStarted <- struct{}{}:
				default:
				}
				<-r.Context().Done()
				return
			}
			w.WriteHeader(200)
		}))
		defer server.Close()
		dir := t.TempDir()
		data := fmt.Sprintf("- name: Fast\n  url: %s/fast/{username}\n- name: Slow\n  url: %s/slow/{username}\n", server.URL, server.URL)
		sites := filepath.Join(dir, "sites.yaml")
		_ = os.WriteFile(sites, []byte(data), 0600)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "-u", "alice", "-s", sites, "-w", "1", "-rl", "0s", "-rf", "cli,html")
		cmd.Dir = dir
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-slowStarted:
		case <-ctx.Done():
			_ = cmd.Wait()
			t.Fatalf("request not started: %s", output.String())
		}
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("shutdown: %v\n%s", err, output.String())
		}
		b, err := os.ReadFile(filepath.Join(dir, "output", "alice.json"))
		if err != nil {
			t.Fatal(err)
		}
		var rows []map[string]any
		if err := json.Unmarshal(b, &rows); err != nil {
			t.Fatalf("unclosed JSON: %s", b)
		}
		found := false
		for _, row := range rows {
			if row["site_name"] == "Fast" && row["status"] == "found" {
				found = true
			}
		}
		if !found {
			t.Fatalf("completed result lost: %s", b)
		}
	})
}
