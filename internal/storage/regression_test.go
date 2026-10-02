package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRegressionCSVCloseSerializesWithWriter(t *testing.T) {
	writer, err := NewCSVWriter(filepath.Join(t.TempDir(), "result.csv"))
	if err != nil {
		t.Fatal(err)
	}
	writer.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- writer.Close() }()
	select {
	case <-done:
		writer.mu.Unlock()
		t.Fatal("Close bypassed the active writer's synchronization")
	case <-time.After(50 * time.Millisecond):
	}
	writer.mu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not resume")
	}
}
