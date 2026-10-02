package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestWatchSignalHelper(t *testing.T) {
	if os.Getenv("AGENTSEARCH_WATCH_HELPER") != "1" {
		return
	}
	var args []string
	if json.Unmarshal([]byte(os.Getenv("AGENTSEARCH_WATCH_ARGS")), &args) != nil {
		os.Exit(2)
	}
	os.Exit(run(context.Background(), args, nil))
}
func TestWatchCLIStartupSignals(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("durable monitor storage requires Linux")
	}
	fixture, err := os.ReadFile("../../internal/sources/bitcoin/testdata/transaction.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "GET" || r.URL.Path != "/api/tx/"+strings.Repeat("a", 64) {
					t.Error("unexpected route")
				}
				w.Write(fixture)
			}))
			defer server.Close()
			dir := t.TempDir()
			watch := filepath.Join(dir, "watch.yaml")
			settings := filepath.Join(dir, "services.yaml")
			state := filepath.Join(dir, "state")
			if err := os.WriteFile(watch, []byte("targets:\n- type: bitcoin_tx\n  value: "+strings.Repeat("a", 64)+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(settings, []byte(fmt.Sprintf("services:\n  bitcoin_tx:\n    enabled: true\n    api_url: %s/api\n", server.URL)), 0600); err != nil {
				t.Fatal(err)
			}
			args, _ := json.Marshal([]string{"-watch-file", watch, "-watch-state-dir", state, "-watch-interval", "30s", "-s", "", "-services", settings, "-rt", "1s", "-tt", "2s"})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWatchSignalHelper$")
			cmd.Env = append(os.Environ(), "AGENTSEARCH_WATCH_HELPER=1", "AGENTSEARCH_WATCH_ARGS="+string(args))
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			// Wait for a completed durable baseline, not just the HTTP request.
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			ready := false
			for !ready {
				select {
				case <-ctx.Done():
					cmd.Wait()
					t.Fatal("CLI did not create baseline", output.String())
				case <-ticker.C:
					files, _ := filepath.Glob(filepath.Join(state, "state", "*.json"))
					ready = len(files) == 1
				}
			}
			// Watch must outlive -tt: that timeout bounds a cycle, not the process.
			time.Sleep(2100 * time.Millisecond)
			if err := cmd.Process.Signal(signal); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal("unclean signal shutdown", err, output.String())
			}
			raw, err := os.ReadFile(filepath.Join(state, "observations.jsonl"))
			if err != nil || bytes.Count(raw, []byte{'\n'}) != 1 || calls.Load() != 1 {
				t.Fatal("extra/missing cycle", calls.Load(), err)
			}
			raw, err = os.ReadFile(filepath.Join(state, "changes.jsonl"))
			if err != nil || len(raw) != 0 {
				t.Fatal("first observation flooded changes")
			}
			if strings.Contains(output.String(), "[CHANGE]") {
				t.Fatal("first baseline alerted")
			}
		})
	}
}
func TestWatchCLIRejectsBeforeRequests(t *testing.T) {
	dir := t.TempDir()
	watch := filepath.Join(dir, "watch.yaml")
	os.WriteFile(watch, []byte("targets:\n- type: password\n  value: do-not-persist\n"), 0600)
	if code := run(context.Background(), []string{"-watch-file", watch, "-watch-state-dir", filepath.Join(dir, "state")}, nil); code != 1 {
		t.Fatal("sensitive watch accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "state")); !os.IsNotExist(err) {
		t.Fatal("invalid watch created storage")
	}
}
