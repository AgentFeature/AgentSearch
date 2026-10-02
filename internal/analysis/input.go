// Package analysis consumes completed canonical reports. It cannot invoke sources,
// tools, shell commands or model-selected network destinations.
package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/report"
	"github.com/AgentFeature/agentsearch/internal/security"
)

const MaxInputBytes = 64 << 10
const MaxOutputBytes = 32 << 10
const MaxRecords = 256
const MaxSources = 128
const MaxFieldBytes = 2048
const MaxFindings = 12
const MaxHypotheses = 8
const MaxQuestions = 8
const MaxRefs = 8
const MaxTotalRefs = 128
const MaxClaims = 32

type Record struct {
	ID             string `json:"id"`
	SourceID       string `json:"source_id"`
	Kind           string `json:"kind"`
	Value          string `json:"value"`
	Classification string `json:"classification"`
}
type Source struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	Partial   bool   `json:"partial"`
	Truncated bool   `json:"truncated"`
}
type Input struct {
	Version           string            `json:"version"`
	Mode              string            `json:"mode"`
	Target            string            `json:"target"`
	TargetType        models.TargetType `json:"target_type"`
	Status            string            `json:"investigation_status"`
	Partial           bool              `json:"partial"`
	CoverageTruncated bool              `json:"coverage_truncated"`
	Truncated         bool              `json:"input_truncated"`
	OmittedRecords    int               `json:"omitted_records"`
	Sources           []Source          `json:"sources"`
	Records           []Record          `json:"evidence"`
	Correlations      []string          `json:"correlations"`
	Warnings          []string          `json:"warnings"`
	Errors            []string          `json:"errors"`
}

// Drop common opaque hashes/tokens as a second safety net; satoshi decimal
// integers are deliberately not matched. No input field can configure a request.
var opaque = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b|\bsk-[A-Za-z0-9_-]+|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
var cryptoOpaque = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]+|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
var sensitiveText = regexp.MustCompile(`(?i)((?:session(?:[_-]?(?:id|token))?|secret|refresh[_-]?token)\s*[:=]\s*)[^\s,;&]+`)

func safeText(s string) string {
	return sensitiveText.ReplaceAllString(opaque.ReplaceAllString(security.Redact(s), security.Redacted), "${1}"+security.Redacted)
}
func safeValue(s string) string { return cleanValue(s, false) }
func cleanValue(s string, crypto bool) string {
	clean := safeText
	if crypto {
		clean = func(s string) string {
			return sensitiveText.ReplaceAllString(cryptoOpaque.ReplaceAllString(security.Redact(s), security.Redacted), "${1}"+security.Redacted)
		}
	}
	var v any
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	if d.Decode(&v) != nil {
		return clean(s)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return clean(s)
	}
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				lower := strings.ToLower(k)
				if security.SensitiveKey(k) || strings.Contains(lower, "session") || strings.Contains(lower, "credential") || strings.Contains(lower, "password") || strings.Contains(lower, "hash") {
					x[k] = security.Redacted
				} else {
					x[k] = walk(val)
				}
			}
			return x
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
			return x
		case string:
			return clean(x)
		default:
			return v
		}
	}
	raw, _ := json.Marshal(walk(v))
	return string(raw)
}

// Prepare uses canonical order and stable result/index references. Whole records
// are retained as an ordered prefix; values are never clipped or random-sampled.
func Prepare(r *report.Report, limit int) (Input, []byte, error) {
	var in Input
	if limit < 4096 || limit > MaxInputBytes {
		return in, nil, code("input_too_large")
	}
	snap, err := r.Snapshot()
	if err != nil {
		return in, nil, code("internal_error")
	}
	in = Input{Version: "agentsearch.analysis.input.v1", Mode: "investigation", Target: safeText(snap.Target), TargetType: snap.TargetType, Status: snap.Status, Partial: snap.Partial, CoverageTruncated: snap.Truncated, Sources: []Source{}, Records: []Record{}, Correlations: []string{}, Warnings: []string{}, Errors: []string{}}
	crypto := snap.TargetType == models.TargetBitcoin || snap.TargetType == models.TargetBitcoinTransaction
	if crypto {
		in.Target = cleanValue(snap.Target, true)
	}
	if len(in.Target) > MaxFieldBytes {
		in.Target = "[OMITTED: target exceeds analysis limit]"
		in.Truncated = true
	}
	if snap.TargetType.Sensitive() {
		in.Target = security.Redacted
	}
	if snap.Partial {
		in.Warnings = append(in.Warnings, "Partial investigation; failures are not absence.")
	}
	if snap.Truncated {
		in.Warnings = append(in.Warnings, "Upstream evidence coverage is truncated.")
	}
	if len(snap.Warnings) > 0 {
		in.Warnings = append(in.Warnings, "Investigation warnings exist; inspect the deterministic report.")
	}
	if len(snap.Errors) > 0 {
		in.Errors = append(in.Errors, "Investigation errors exist; inspect source statuses.")
	}
	total := 0
	for _, o := range snap.Results {
		total += len(o.Result.Evidence) + len(o.Result.Metadata)
	}
	stopped := false
	for _, o := range snap.Results {
		if stopped || len(in.Sources) >= MaxSources {
			in.Truncated = true
			break
		}
		name := safeText(o.Result.Source)
		if snap.TargetType.Sensitive() {
			name = "password-provider"
		}
		if len(name) > 256 {
			name = "[OMITTED]"
			in.Truncated = true
		}
		sourceType := string(o.Result.SourceType)
		if sourceType != "api" && sourceType != "local" && sourceType != "website" {
			sourceType = "unknown"
		}
		status := string(o.Result.Status)
		if status != "found" && status != "not_found" && status != "blocked" && status != "error" {
			status = "unknown"
		}
		src := Source{o.ID, name, sourceType, status, o.Partial, o.Truncated}
		in.Sources = append(in.Sources, src)
		if len(mustJSON(in)) > limit-256 {
			in.Sources = in.Sources[:len(in.Sources)-1]
			in.Truncated = true
			break
		}
		add := func(id, kind, value, class string) {
			if stopped {
				return
			}
			kind = safeText(kind)
			value = cleanValue(value, crypto)
			if len(kind) > 256 || len(value) > MaxFieldBytes || len(in.Records) >= MaxRecords {
				stopped = true
				in.Truncated = true
				return
			}
			if security.SensitiveKey(kind) || strings.Contains(strings.ToLower(kind), "session") || strings.Contains(strings.ToLower(kind), "password") || strings.Contains(strings.ToLower(kind), "hash") {
				value = security.Redacted
			}
			rec := Record{id, o.ID, kind, value, class}
			in.Records = append(in.Records, rec)
			if class == "correlated" {
				in.Correlations = append(in.Correlations, id)
			}
			if len(mustJSON(in)) > limit-256 {
				in.Records = in.Records[:len(in.Records)-1]
				if class == "correlated" {
					in.Correlations = in.Correlations[:len(in.Correlations)-1]
				}
				stopped = true
				in.Truncated = true
			}
		}
		if !snap.TargetType.Sensitive() {
			for i, e := range o.Result.Evidence {
				add(fmt.Sprintf("%s/e/%d", o.ID, i), e.Kind, e.Value, string(o.EvidenceClasses[i]))
			}
		}
		keys := make([]string, 0, len(o.Result.Metadata))
		for k := range o.Result.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			v := o.Result.Metadata[k]
			if snap.TargetType.Sensitive() {
				if k == "pwned" && (v == "true" || v == "false") {
				} else if k == "occurrences" && decimal.MatchString(v) {
				} else {
					continue
				}
			}
			add(fmt.Sprintf("%s/m/%d", o.ID, i), k, v, string(o.Classification))
		}
	}
	in.OmittedRecords = total - len(in.Records)
	in.Truncated = in.Truncated || in.OmittedRecords > 0
	raw := mustJSON(in)
	if len(raw) > limit {
		return in, nil, code("input_too_large")
	}
	return in, raw, nil
}

var decimal = regexp.MustCompile(`^[0-9]{1,20}$`)

func mustJSON(v any) []byte  { b, _ := json.Marshal(v); return b }
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
