package models

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEvidenceSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		sourceType   SourceType
		targetType   TargetType
		status       ResultStatus
		kind         ObservationKind
		meaning      EvidenceMeaning
	}{
		{"website positive", "Example", SourceWebsite, TargetUsername, StatusFound, ObservationWebsite, MeaningObservation},
		{"website negative inference", "Example", SourceWebsite, TargetEmail, StatusNotFound, ObservationWebsite, MeaningObservation},
		{"blocked is unknown", "Example", SourceWebsite, TargetUsername, StatusBlocked, ObservationWebsite, MeaningUnknown},
		{"website error", "Example", SourceWebsite, TargetUsername, StatusError, ObservationWebsite, MeaningError},
		{"breach association", "hibp", SourceAPI, TargetEmail, StatusFound, ObservationBreach, MeaningObservation},
		{"breach negative", "hibp", SourceAPI, TargetEmail, StatusNotFound, ObservationBreach, MeaningAbsence},
		{"breach error", "hibp", SourceAPI, TargetEmail, StatusError, ObservationBreach, MeaningError},
		{"domain profile", "securitytrails", SourceAPI, TargetDomain, StatusFound, ObservationDomain, MeaningObservation},
		{"domain lacks absence contract", "securitytrails", SourceAPI, TargetDomain, StatusNotFound, ObservationDomain, MeaningUnknown},
		{"domain error", "securitytrails", SourceAPI, TargetDomain, StatusError, ObservationDomain, MeaningError},
		{"remote corpus", "pwned-passwords", SourceAPI, TargetPassword, StatusFound, ObservationPassword, MeaningObservation},
		{"remote corpus negative", "pwned-passwords", SourceAPI, TargetPassword, StatusNotFound, ObservationPassword, MeaningAbsence},
		{"local corpus", "pwned-passwords-local", SourceLocal, TargetPassword, StatusFound, ObservationPassword, MeaningObservation},
		{"local corpus negative", "pwned-passwords-local", SourceLocal, TargetPassword, StatusNotFound, ObservationPassword, MeaningAbsence},
		{"local corpus failure", "pwned-passwords-local", SourceLocal, TargetPassword, StatusError, ObservationPassword, MeaningError},
		{"unknown negative contract", "custom", SourceAPI, TargetEmail, StatusNotFound, ObservationUnknown, MeaningUnknown},
		{"source name alone insufficient", "hibp", SourceLocal, TargetEmail, StatusNotFound, ObservationUnknown, MeaningUnknown},
		{"site called hibp", "hibp", SourceWebsite, TargetEmail, StatusNotFound, ObservationWebsite, MeaningObservation},
		{"no password hash expansion", "pwned-passwords", SourceAPI, TargetPasswordHash, StatusNotFound, ObservationUnknown, MeaningUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := Result{Source: tc.source, SourceType: tc.sourceType, TargetType: tc.targetType, Status: tc.status, Confidence: 73, Metadata: map[string]string{"verified": "false"}, Evidence: []Evidence{{Kind: "detail", Value: "source-specific"}}}.Normalized()
			before, _ := json.Marshal(row)
			view := row.EvidenceSemantics()
			if view != (EvidenceSemantics{tc.kind, tc.meaning}) {
				t.Fatalf("got %v", view)
			}
			after, _ := json.Marshal(row)
			if !bytes.Equal(before, after) || row.Source != tc.source || row.Status != tc.status || row.Confidence != 73 {
				t.Fatal("semantic interpretation changed result")
			}
			var decoded Result
			if err := json.Unmarshal(after, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.EvidenceSemantics() != view || !reflect.DeepEqual(row.Evidence, decoded.Evidence) || !reflect.DeepEqual(row.Metadata, decoded.Metadata) {
				t.Fatal("provenance lost on JSON round trip")
			}
		})
	}
	for _, row := range []Result{{}, {Source: "hibp", SourceType: SourceAPI, TargetType: TargetEmail}, {Status: "unsupported"}} {
		if row.EvidenceSemantics().Meaning != MeaningUnknown {
			t.Fatal("unspecified status invented evidence")
		}
	}
	if (Result{Error: "failed"}).EvidenceSemantics().Meaning != MeaningError || (Result{Found: true}).EvidenceSemantics().Meaning != MeaningObservation {
		t.Fatal("legacy positive/error signals lost")
	}
}

func TestEvidenceSemanticsSchemaAndSafety(t *testing.T) {
	row := Result{Source: "hibp", SourceType: SourceAPI, TargetType: TargetEmail, SiteName: "Have I Been Pwned / Fixture", Target: "fixture@example.test", URL: "https://haveibeenpwned.com/", Status: StatusFound, Found: true, Confidence: 100, Duration: time.Second, Evidence: []Evidence{{Kind: "compromised_data_class", Value: "Email addresses"}}, Metadata: map[string]string{"breach_date": "2020-01-02"}}
	raw, _ := json.Marshal(row)
	_ = row.EvidenceSemantics()
	after, _ := json.Marshal(row)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(after, &fields)
	expected := []string{"source", "source_type", "target_type", "site_name", "target", "url", "status", "found", "confidence", "duration", "evidence", "metadata"}
	if len(fields) != len(expected) || !bytes.Equal(raw, after) {
		t.Fatal("public schema changed")
	}
	for _, key := range expected {
		if _, ok := fields[key]; !ok {
			t.Fatal("existing field lost", key)
		}
	}
	// Acquisition time cannot be reconstructed from upstream dates or duration.
	for _, key := range []string{"observed_at", "observation_kind", "meaning", "provenance"} {
		if _, ok := fields[key]; ok {
			t.Fatal("internal interpretation leaked into result JSON")
		}
	}
	marker := strings.Repeat("private-password-hash-prefix-suffix-key-path-header-body", 1000)
	unsafe := Result{Source: marker, SourceType: SourceLocal, TargetType: TargetPassword, Target: marker, SiteName: marker, URL: marker, Error: marker, Status: StatusError, Evidence: []Evidence{{Kind: marker, Value: marker}}, Metadata: map[string]string{marker: marker}}
	view := unsafe.EvidenceSemantics()
	encoded, _ := json.Marshal(view)
	if len(encoded) > 100 || strings.Contains(string(encoded)+fmt.Sprintf("%+v", view), "private-") {
		t.Fatal("interpretation retained sensitive input")
	}
	if unsafe.Target != marker || unsafe.Metadata[marker] != marker {
		t.Fatal("interpretation mutated input")
	}
}
