package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBitcoinLabelSemanticsAndScore(t *testing.T) {
	for _, status := range []ResultStatus{StatusFound, StatusNotFound, StatusError} {
		row := Result{Source: "bitcoin-labels", SourceType: SourceAPI, TargetType: TargetBitcoin, Status: status}
		view := row.EvidenceSemantics()
		meaning := MeaningObservation
		if status == StatusError {
			meaning = MeaningError
		}
		if view.Kind != ObservationBitcoinLabels || view.Meaning != meaning || row.ConfidenceLabel() != "not scored" {
			t.Fatal("label semantic contract")
		}
		raw, e := json.Marshal(row)
		if e != nil || strings.Contains(string(raw), `"confidence":`) {
			t.Fatal("numerical label confidence exposed")
		}
	}
	// Existing source wire schemas and confidence presentation stay unchanged.
	for _, row := range []Result{{Source: "bitcoin", SourceType: SourceAPI, TargetType: TargetBitcoin, Confidence: 0}, {Source: "example", SourceType: SourceWebsite, TargetType: TargetUsername, Confidence: 80}} {
		raw, e := json.Marshal(row)
		if e != nil || !strings.Contains(string(raw), `"confidence":`) {
			t.Fatal("legacy confidence field changed")
		}
		if !strings.HasSuffix(row.ConfidenceLabel(), "%") {
			t.Fatal("legacy presentation changed")
		}
	}
	wrong := Result{Source: "bitcoin-labels", SourceType: SourceLocal, TargetType: TargetBitcoin, Confidence: 42}
	if wrong.ProviderLabelObservation() || wrong.ConfidenceLabel() != "42%" {
		t.Fatal("source name alone trusted")
	}
}
