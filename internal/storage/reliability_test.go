package storage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOutputSetupFailureClosesAcquiredWriters(t *testing.T) {
	dir := t.TempDir()
	// JSON opens successfully; the next output cannot be created over a directory.
	if err := os.Mkdir(filepath.Join(dir, "fixture.csv"), 0700); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(dir, []string{"json", "csv"}, "fixture")
	var pathErr *os.PathError
	if manager != nil || !errors.As(err, &pathErr) {
		t.Fatal("setup failure identity lost")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []any
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 0 {
		t.Fatal("earlier writer not finalized on setup failure")
	}
}

func TestJSONFinalizationFailureStillClosesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "readonly.json")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writer := &JSONWriter{file: file}
	var pathErr *os.PathError
	if err = writer.Close(); !errors.As(err, &pathErr) || pathErr.Op != "write" {
		t.Fatal("original finalization error lost")
	}
	if _, err = file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("descriptor retained after finalization failure")
	}
}
