package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/models"
)

// The streamed legacy JSON array must be pretty-printed, remain valid JSON
// under concurrent-style sequential writes, and decode to the same data.
func TestStreamingJSONPrettyAndEquivalent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	w, err := NewJSONWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	rows := []models.Result{
		{Source: "site-a", SourceType: models.SourceWebsite, Target: "alice", TargetType: models.TargetUsername, Status: models.StatusFound, URL: "https://a.example.test/alice", Metadata: map[string]string{"k": "v"}, Evidence: []models.Evidence{{Kind: "item", Value: "line1\nline2"}}},
		{Source: "site-b", SourceType: models.SourceWebsite, Target: "alice", TargetType: models.TargetUsername, Status: models.StatusNotFound},
		{Source: "site-c", SourceType: models.SourceWebsite, Target: "alice", TargetType: models.TargetUsername, Status: models.StatusError, Error: "timeout"},
	}
	for _, r := range rows {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b) {
		t.Fatalf("invalid streamed JSON: %s", b)
	}
	if lines := strings.Count(string(b), "\n"); lines < 3*3 {
		t.Fatalf("expected pretty multiline array, got %d newlines", lines)
	}
	var decoded []models.Result
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	want := make([]models.Result, len(rows))
	for i, r := range rows {
		want[i] = r.Normalized()
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatal("pretty streaming changed data")
	}
}

// An empty streamed array remains a valid empty JSON list.
func TestStreamingJSONEmptyStillValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	w, err := NewJSONWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows []models.Result
	if err := json.Unmarshal(b, &rows); err != nil || len(rows) != 0 {
		t.Fatalf("empty array broken: %s (%v)", b, err)
	}
}
