package httpapi

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/report"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
	"github.com/AgentFeature/agentsearch/internal/storage"
)

type provenanceSource struct {
	name string
	kind models.SourceType
	run  func(context.Context, sources.Emit) error
}

func (s provenanceSource) Name() string            { return s.name }
func (s provenanceSource) Type() models.SourceType { return s.kind }
func (s provenanceSource) SearchEmail(ctx context.Context, _ string, e sources.Emit) error {
	return s.run(ctx, e)
}

func TestProvenanceThroughConcurrentHTTPAndWriters(t *testing.T) {
	const credential = "synthetic-private-credential"
	const rawBody = "unretained-provider-body"
	const email = "fixture@example.test"
	first, second := make(chan struct{}), make(chan struct{})
	registry := sources.NewRegistry()
	fixtures := []provenanceSource{
		{"websites", models.SourceWebsite, func(ctx context.Context, e sources.Emit) error {
			close(first)
			<-second
			row := models.Result{Source: "ConfiguredSite", SiteName: "ConfiguredSite", Status: models.StatusFound, Confidence: 40, Duration: time.Millisecond, URL: "https://user:" + credential + "@example.test/profile", Evidence: []models.Evidence{{Kind: "signal", Value: "rule-match"}}, Metadata: map[string]string{"api_key": credential}}
			row = row.Redacted(credential)
			if err := e(row); err != nil {
				return err
			}
			return e(row) // Equal observations are not automatically duplicates.
		}},
		{"failing-fixture", models.SourceAPI, func(ctx context.Context, e sources.Emit) error {
			close(second)
			<-first
			if err := e(models.Result{Status: models.StatusError, Error: rawBody, Metadata: map[string]string{"error_kind": "network_failure"}, Evidence: []models.Evidence{{Kind: "detail", Value: rawBody}}}); err != nil {
				return err
			}
			return errors.New(rawBody)
		}},
		{"hibp", models.SourceAPI, func(ctx context.Context, e sources.Emit) error {
			return e(models.Result{Status: models.StatusNotFound, Metadata: map[string]string{"breach_count": "0"}})
		}},
	}
	for _, source := range fixtures {
		if err := registry.Register(source); err != nil {
			t.Fatal(err)
		}
	}
	runner := app.NewRunner(registry)
	var captured []models.Result
	var logs bytes.Buffer
	h := handlerFor(t, func(ctx context.Context, target models.Target, e sources.Emit) error {
		return runner.Search(ctx, target, func(row models.Result) error { captured = append(captured, row); return e(row) })
	}, &logs, nil)
	w := request(h, "POST", "/api/v1/search", `{"type":"email","target":"`+email+`"}`, "Bearer "+testToken)
	var payload response
	if w.Code != 502 || json.Unmarshal(w.Body.Bytes(), &payload) != nil || len(payload.Results) != 4 || len(captured) != 4 {
		t.Fatal("partial response changed")
	}
	wantSources := []string{"ConfiguredSite", "ConfiguredSite", "failing-fixture", "hibp"}
	meanings := []models.EvidenceMeaning{models.MeaningObservation, models.MeaningObservation, models.MeaningError, models.MeaningAbsence}
	kinds := []models.ObservationKind{models.ObservationWebsite, models.ObservationWebsite, models.ObservationUnknown, models.ObservationBreach}
	for i, row := range payload.Results {
		view := models.EvidenceSemantics{Kind: kinds[i], Meaning: meanings[i]}
		if row.Source != wantSources[i] || row.EvidenceSemantics() != view || captured[i].EvidenceSemantics() != view {
			t.Fatal("source-specific interpretation/order lost")
		}
	}
	if !reflect.DeepEqual(captured[0], captured[1]) || captured[0].Evidence[0].Value != "rule-match" || captured[2].Metadata["error_kind"] != "network_failure" {
		t.Fatal("orchestration discarded source evidence")
	}
	if len(payload.Results[2].Evidence) != 0 || len(payload.Results[2].Metadata) != 0 || payload.Results[2].Error != "source lookup failed" {
		t.Fatal("HTTP error sanitization changed")
	}
	if strings.Contains(w.Body.String(), credential) || strings.Contains(w.Body.String(), rawBody) || strings.Contains(logs.String(), email) || strings.Contains(logs.String(), credential) || strings.Contains(logs.String(), rawBody) {
		t.Fatal("sensitive metadata/log leak")
	}
	if payload.Results[0].Metadata["api_key"] != security.Redacted {
		t.Fatal("credential field not redacted")
	}

	// The internal view adds no writer fields or scores. Existing HTTP-safe rows
	// remain suitable for the unchanged JSON/CSV/TXT/report projections.
	before, _ := json.Marshal(payload.Results)
	for _, row := range payload.Results {
		_ = row.EvidenceSemantics()
	}
	after, _ := json.Marshal(payload.Results)
	if !bytes.Equal(before, after) || strings.Contains(string(after), "observation_kind") || strings.Contains(string(after), "observed_at") {
		t.Fatal("public schema changed")
	}
	dir := t.TempDir()
	store, err := storage.NewManager(dir, []string{"csv", "json", "txt"}, email)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range payload.Results {
		store.Write(row)
	}
	store.Close()
	raw, err := os.ReadFile(filepath.Join(dir, email+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored []models.Result
	if json.Unmarshal(raw, &stored) != nil || !reflect.DeepEqual(stored, payload.Results) {
		t.Fatal("JSON evidence changed")
	}
	raw, err = os.ReadFile(filepath.Join(dir, email+".csv"))
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	header := []string{"site_name", "target", "url", "found", "confidence", "status", "duration_ms", "error", "final_url"}
	if err != nil || len(records) != 5 || !reflect.DeepEqual(records[0], header) || records[1][4] != "40" {
		t.Fatal("CSV contract changed")
	}
	raw, err = os.ReadFile(filepath.Join(dir, email+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "signal: rule-match") || !strings.Contains(string(raw), "breach_count: 0") || strings.Contains(string(raw), credential) || strings.Contains(string(raw), rawBody) {
		t.Fatal("TXT evidence missing/unsafe")
	}
	summary := report.BuildSummary(email, payload.Results, time.Second)
	if summary.Total != 4 || summary.Found != 2 || summary.NotFound != 1 || summary.Errors != 1 {
		t.Fatal("partial observations collapsed into one verdict")
	}
}
