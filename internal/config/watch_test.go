package config

import (
	"testing"
	"time"
)

func TestWatchCLIOptions(t *testing.T) {
	cfg, err := ParseArgs([]string{"-watch-file", "watch.yaml"})
	if err != nil || cfg.Mode != ModeWatch || cfg.WatchInterval != 60*time.Second || cfg.WatchConcurrency != 4 || cfg.Workers != 4 || cfg.MaxRetries != 0 || cfg.WatchStateDir != "agentsearch-watch" {
		t.Fatal(cfg, err)
	}
	for _, d := range []string{"30s", "299s", "1m"} {
		if _, err := ParseArgs([]string{"-watch-file", "watch.yaml", "-watch-interval", d}); err != nil {
			t.Fatal(err)
		}
	}
	for _, extra := range [][]string{{"-watch-interval", "0s"}, {"-watch-interval", "29s"}, {"-watch-interval", "300s"}, {"-watch-interval", "-1s"}, {"-watch-concurrency", "0"}, {"-watch-concurrency", "5"}, {"-watch-state-dir", ""}, {"-u", "alice"}, {"-f", "targets"}, {"-bitcoin-tx", "bad"}, {"-password", "secret"}, {"-of", "json"}, {"-rf", "html"}, {"-retries", "2"}, {"-w", "999"}, {"-rt", "16s"}, {"-tt", "11m"}, {"-tt", "0s"}} {
		if _, err := ParseArgs(append([]string{"-watch-file", "watch.yaml"}, extra...)); err == nil {
			t.Fatal("invalid combination", extra)
		}
	}
	if _, err := ParseArgs([]string{"-u", "alice", "-watch-interval", "60s"}); err == nil {
		t.Fatal("watch options leaked to legacy mode")
	}
	if _, err := ParseArgs([]string{"-watch-file", ""}); err == nil {
		t.Fatal("empty watch file")
	}
}
