package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBitcoinTransactionTargetAndSemantics(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, input := range []string{id, strings.ToUpper(id), " \n" + strings.ToUpper(id) + "\t"} {
		target, err := NewTarget(TargetBitcoinTransaction, input)
		if err != nil || target.Value() != id || !target.Valid() || target.Type() != TargetBitcoinTransaction {
			t.Fatal(target, err)
		}
	}
	for _, input := range []string{"", id[:63], id + "a", strings.Repeat("g", 64), id[:31] + " " + id[32:], id[:31] + "\n" + id[32:], "https://example.com/" + id, strings.Repeat(" ", 129) + id} {
		if _, err := NewBitcoinTransactionTarget(input); err == nil {
			t.Fatal("accepted invalid ID")
		}
	}
	legacy, err := LegacyTarget(id)
	if err != nil || legacy.Type() != TargetUsername {
		t.Fatal("legacy auto-detection changed")
	}
	target, _ := NewBitcoinTransactionTarget(id)
	row := NewResult("bitcoin-tx", SourceAPI, target)
	for status, want := range map[ResultStatus]EvidenceMeaning{StatusFound: MeaningObservation, StatusNotFound: MeaningAbsence, StatusError: MeaningError} {
		row.Status = status
		v := row.EvidenceSemantics()
		if v.Kind != ObservationBitcoinTransaction || v.Meaning != want {
			t.Fatal(v)
		}
	}
	if row.ConfidenceLabel() != "not scored" || row.ProviderLabelObservation() {
		t.Fatal("score/label contract")
	}
	raw, err := json.Marshal(row)
	if err != nil || strings.Contains(string(raw), `"confidence"`) {
		t.Fatal("fabricated score")
	}
	row.Source = "bitcoin"
	row.Confidence = 42
	if row.UnscoredObservation() || row.ConfidenceLabel() != "42%" || row.EvidenceSemantics().Kind == ObservationBitcoinTransaction {
		t.Fatal("contract leaked to other source")
	}
}
