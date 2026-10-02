package storage

import (
	"encoding/csv"
	"errors"
	"os"
	"sync"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/report"
)

// CSVWriter writes results with the legacy CSV header.
type CSVWriter struct {
	file *os.File
	w    *csv.Writer
	mu   sync.Mutex
}

// NewCSVWriter creates a CSV file and writes its header.
func NewCSVWriter(path string) (*CSVWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	writer := csv.NewWriter(f)
	header := report.LegacyCSVHeader
	if err := writer.Write(header); err != nil {
		_ = f.Close()
		return nil, err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &CSVWriter{file: f, w: writer}, nil
}

// Write projects a normalized result into a CSV record.
func (w *CSVWriter) Write(res models.Result) error {
	res = res.Normalized()
	w.mu.Lock()
	defer w.mu.Unlock()

	record := report.LegacyCSVRecord(res)
	if err := w.w.Write(record); err != nil {
		return err
	}
	w.w.Flush()
	return w.w.Error()
}

// Close flushes and closes the file.
func (w *CSVWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.w.Flush()
	return errors.Join(w.w.Error(), w.file.Close())
}
