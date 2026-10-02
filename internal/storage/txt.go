package storage

import (
	"fmt"
	"os"
	"sync"

	"github.com/AgentFeature/agentsearch/internal/models"
)

// TXTWriter writes a compact human-readable result log.
type TXTWriter struct {
	file *os.File
	mu   sync.Mutex
}

// NewTXTWriter creates a text output file.
func NewTXTWriter(path string) (*TXTWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &TXTWriter{file: f}, nil
}

// Write formats a normalized result as text.
func (w *TXTWriter) Write(res models.Result) error {
	res = res.Normalized()
	w.mu.Lock()
	defer w.mu.Unlock()

	line := fmt.Sprintf("[%s] %s | Found: %v | Confidence: %s | Status: %s | URL: %s\n",
		res.SiteName, res.Target, res.Found, res.ConfidenceLabel(), res.Status, res.URL)
	if len(res.Metadata) > 0 || len(res.Evidence) > 0 {
		line += fmt.Sprintf("  Outcome: %s\n", res.OutcomeLabel())
		for _, detail := range res.Details() {
			line += fmt.Sprintf("  %s: %s\n", detail.Kind, detail.Value)
		}
	}
	if res.FinalURL != "" && res.FinalURL != res.URL {
		line += fmt.Sprintf("  -> Final URL: %s\n", res.FinalURL)
	}
	_, err := w.file.WriteString(line)
	return err
}

// Close closes the output file.
func (w *TXTWriter) Close() error {
	return w.file.Close()
}
