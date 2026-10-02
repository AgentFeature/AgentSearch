package app

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

func TestCLIOrchestrationPreservesPartialWriters(t *testing.T) {
	registry := sources.NewRegistry()
	first, second := make(chan struct{}), make(chan struct{})
	if err := registry.Register(diagnosticSource{"first", func(ctx context.Context, e sources.Emit) error {
		close(first)
		<-second
		return e(models.Result{Status: models.StatusFound, Metadata: map[string]string{"observation": "preserved"}})
	}}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(diagnosticSource{"second", func(ctx context.Context, e sources.Emit) error {
		close(second)
		<-first
		if err := e(models.Result{Status: models.StatusError, Metadata: map[string]string{"error_kind": "rate_limited"}}); err != nil {
			return err
		}
		return errors.New("fixture failure")
	}}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	application := NewWithSources(&config.AppConfig{Mode: config.ModeEmail, Targets: []string{"fixture@example.test"}, OutputDir: dir, OutputFormats: []string{"json", "csv", "txt"}}, registry)
	if err := application.Run(context.Background()); err == nil {
		t.Fatal("email-mode failure exit policy changed")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "fixture@example.test.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []models.Result
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 2 || rows[0].Source != "first" || rows[1].Source != "second" || !rows[0].Found || rows[0].Metadata["observation"] != "preserved" || rows[1].Status != models.StatusError {
		t.Fatal("ordered partial results not persisted")
	}
	f, err := os.Open(filepath.Join(dir, "fixture@example.test.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil || len(records) != 3 || len(records[0]) != 9 || records[1][0] != "first" || records[2][0] != "second" {
		t.Fatal("CSV schema/order changed")
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "fixture@example.test.txt")); err != nil || len(raw) == 0 {
		t.Fatal("TXT writer lost")
	}
}
