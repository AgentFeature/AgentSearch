package models

import (
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/AgentFeature/agentsearch/internal/security"
)

// ResultStatus describes the source lookup outcome, not a security verdict.
// In particular, website not_found may be a detector inference. See EvidenceSemantics.
type ResultStatus string

const (
	StatusFound    ResultStatus = "found"
	StatusNotFound ResultStatus = "not_found"
	StatusBlocked  ResultStatus = "blocked"
	StatusError    ResultStatus = "error"
)

// Result is a normalized observation from any source. Legacy fields remain for
// existing writers and callers; sensitive input is never a result payload.
type Result struct {
	// Source is the service provider identifier or, for legacy website results,
	// the configured site identifier. SiteName retains the display label.
	Source     string     `json:"source,omitempty"`
	SourceType SourceType `json:"source_type,omitempty"`
	// Target and TargetType form a safe reference, preserving the legacy target string.
	TargetType TargetType        `json:"target_type,omitempty"`
	Evidence   []Evidence        `json:"evidence,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	SiteName   string            `json:"site_name" csv:"site_name"`
	Target     string            `json:"target" csv:"target"`
	URL        string            `json:"url" csv:"url"`
	Found      bool              `json:"found" csv:"found"`
	// Confidence is the existing deterministic score, not probability, source
	// trust or evidence quality. Interpretation depends on the source contract.
	Confidence int           `json:"confidence" csv:"confidence"`
	Status     ResultStatus  `json:"status" csv:"status"`
	Duration   time.Duration `json:"duration" csv:"duration"`
	Error      string        `json:"error,omitempty" csv:"error"`
	FinalURL   string        `json:"final_url,omitempty" csv:"final_url"`
}

// NewResult creates a safe result reference without copying sensitive input.
func NewResult(source string, sourceType SourceType, target Target) Result {
	return Result{Source: source, SourceType: sourceType, Target: target.String(), TargetType: target.Type()}
}

// Normalized adapts legacy results and returns an output-safe copy. Explicit
// status is authoritative. Confidence and the existing status vocabulary remain
// unchanged. Source implementations must never put secrets in observations.
func (r Result) Normalized() Result { return r.Redacted().normalized() }
func (r Result) normalized() Result {
	if r.Source == "" {
		r.Source = r.SiteName
	}
	if r.SiteName == "" {
		r.SiteName = r.Source
	}
	if r.TargetType == "" && r.Target != "" {
		t, _ := LegacyTarget(r.Target)
		r.TargetType = t.Type()
	}
	if r.Status == "" {
		switch {
		case r.Error != "":
			r.Status = StatusError
		case r.Found:
			r.Status = StatusFound
		default:
			r.Status = StatusNotFound
		}
	}
	r.Found = r.Status == StatusFound
	return r
}

// Redacted makes a copy, including maps/slices. Known secrets must be passed by
// the source dispatcher while it still holds input; they are never retained.
// Consuming password sources must construct safe observations directly because
// their plaintext is already destroyed when results reach the dispatcher.
func (r Result) Redacted(secrets ...string) Result {
	if r.TargetType.Sensitive() {
		secrets = append(append([]string(nil), secrets...), r.Target)
		r.Target = security.Redacted
	}
	clean := func(s string) string { return security.Redact(s, secrets...) }
	r.Source = clean(r.Source)
	r.SiteName = clean(r.SiteName)
	r.Target = clean(r.Target)
	r.URL = clean(r.URL)
	r.FinalURL = clean(r.FinalURL)
	r.Error = clean(r.Error)
	r.Metadata = security.Fields(r.Metadata, secrets...)
	if r.Evidence != nil {
		evidence := make([]Evidence, len(r.Evidence))
		for i, e := range r.Evidence {
			value := clean(e.Value)
			if security.SensitiveKey(e.Kind) {
				value = security.Redacted
			}
			evidence[i] = Evidence{Kind: clean(e.Kind), Value: value}
		}
		r.Evidence = evidence
	}
	return r
}

// MarshalJSON is a final safety net for callers not using the dispatcher.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	if r.UnscoredObservation() {
		// Unscored provider rows have no numeric confidence metric. Existing result
		// schemas retain their historical confidence field unchanged.
		return json.Marshal(struct {
			plain
			Confidence *int `json:"confidence,omitempty"`
		}{plain: plain(r.Normalized())})
	}
	return json.Marshal(plain(r.Normalized()))
}

// OutcomeLabel is a human-readable interpretation; machine statuses stay stable.
func (r Result) OutcomeLabel() string {
	r = r.Normalized()
	if r.TargetType == TargetPassword {
		switch r.Status {
		case StatusFound:
			return "PWNED"
		case StatusNotFound:
			return "NOT PWNED"
		default:
			return "ERROR"
		}
	}
	return string(r.Status)
}

// Details is the normalized semantic evidence and sorted metadata projection
// shared by text and document outputs. It contains no request state.
func (r Result) Details() []Evidence {
	r = r.Normalized()
	details := append([]Evidence(nil), r.Evidence...)
	keys := make([]string, 0, len(r.Metadata))
	for key := range r.Metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		details = append(details, Evidence{Kind: key, Value: r.Metadata[key]})
	}
	return details
}

// ProviderLabelObservation identifies this provider contract, never a free-form
// metadata claim. It does not assert that the provider label is correct.
func (r Result) ProviderLabelObservation() bool {
	return r.Source == "bitcoin-labels" && r.SourceType == SourceAPI && r.TargetType == TargetBitcoin
}

// ConfidenceLabel avoids inventing a percentage for an unscored provider.
func (r Result) ConfidenceLabel() string {
	if r.UnscoredObservation() {
		return "not scored"
	}
	return strconv.Itoa(r.Confidence) + "%"
}

// UnscoredObservation selects explicit provider contracts without invented scores.
func (r Result) UnscoredObservation() bool {
	return r.ProviderLabelObservation() || (r.Source == "bitcoin-tx" && r.SourceType == SourceAPI && r.TargetType == TargetBitcoinTransaction)
}
