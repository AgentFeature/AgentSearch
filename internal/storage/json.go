package storage

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/AgentFeature/agentsearch/internal/models"
)

// JSONWriter streams a JSON array of normalized results.
// Results are written incrementally rather than buffered as one array.
type JSONWriter struct {
	file  *os.File
	mu    sync.Mutex
	first bool
}

// NewJSONWriter creates a file and starts the JSON array.
func NewJSONWriter(path string) (*JSONWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString("[\n"); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &JSONWriter{file: f, first: true}, nil
}

// Write appends a serialized result with the appropriate separator.
// Records are indented so the streamed array is human-readable; the JSON
// structure and field set are unchanged.
func (w *JSONWriter) Write(res models.Result) error {
	res = res.Normalized()
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := json.MarshalIndent(res, "  ", "  ")
	if err != nil {
		return err
	}
	if !w.first {
		if _, err := w.file.WriteString(",\n"); err != nil {
			return err
		}
	}
	if _, err := w.file.WriteString("  "); err != nil {
		return err
	}
	if _, err := w.file.Write(data); err != nil {
		return err
	}
	w.first = false
	return nil
}

// Close terminates the array and closes the file.
func (w *JSONWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, writeErr := w.file.WriteString("\n]\n")
	closeErr := w.file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
