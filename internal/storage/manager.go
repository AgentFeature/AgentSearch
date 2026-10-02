package storage

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/AgentFeature/agentsearch/internal/models"
)

// Writer abstracts a result output format.
type Writer interface {
	Write(res models.Result) error
	Close() error
}

// Manager writes results to the configured output formats.
type Manager struct {
	writers []Writer
}

// NewManager creates one writer for each requested format.
func NewManager(dir string, formats []string, target string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	var writers []Writer
	ready := false
	defer func() {
		if !ready {
			// Roll back acquired resources without replacing the setup error.
			(&Manager{writers: writers}).Close()
		}
	}()
	for _, f := range formats {
		path := filepath.Join(dir, fmt.Sprintf("%s.%s", sanitizeFilename(target), f))
		switch f {
		case "json":
			w, err := NewJSONWriter(path)
			if err != nil {
				return nil, err
			}
			writers = append(writers, w)
		case "csv":
			w, err := NewCSVWriter(path)
			if err != nil {
				return nil, err
			}
			writers = append(writers, w)
		case "txt":
			w, err := NewTXTWriter(path)
			if err != nil {
				return nil, err
			}
			writers = append(writers, w)
		default:
			slog.Warn("unknown output format, skipping", "error_category", "invalid_request")
		}
	}
	ready = true
	return &Manager{writers: writers}, nil
}

// Write sends a result to every active writer.
func (m *Manager) Write(res models.Result) {
	for _, w := range m.writers {
		if err := w.Write(res); err != nil {
			slog.Error("write result failed", "error_category", "internal_error")
		}
	}
}

// Close flushes and closes all writers.
func (m *Manager) Close() {
	for _, w := range m.writers {
		if err := w.Close(); err != nil {
			slog.Error("close writer failed", "error_category", "internal_error")
		}
	}
}

// sanitizeFilename replaces characters that are unsafe in filenames.
func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)
	return replacer.Replace(name)
}
