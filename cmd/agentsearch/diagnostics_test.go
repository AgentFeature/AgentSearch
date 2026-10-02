package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIStartupDiagnosticRedaction(t *testing.T) {
	marker := "private-input@example.test"
	for _, args := range [][]string{{"-w", marker}, {"-u", marker, "-s", filepath.Join(t.TempDir(), marker)}, {"-email", marker, "-services", filepath.Join(t.TempDir(), marker)}} {
		var logs bytes.Buffer
		original := slog.Default()
		slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		stderr := os.Stderr
		os.Stderr = w
		code := run(context.Background(), args, nil)
		os.Stderr = stderr
		_ = w.Close()
		raw, err := io.ReadAll(r)
		_ = r.Close()
		slog.SetDefault(original)
		if err != nil {
			t.Fatal(err)
		}
		if code == 0 {
			t.Fatal("invalid configuration accepted")
		}
		if strings.Contains(logs.String(), marker) || strings.Contains(string(raw), marker) || logs.Len() > 1024 {
			t.Fatal("private argument/path echoed")
		}
	}
}
