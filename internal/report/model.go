package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

const (
	SchemaVersion  = "agentsearch.report.v1"
	MaxResults     = 10000
	MaxEvidence    = 20000
	MaxFieldBytes  = 64 << 10
	MaxInputBytes  = 8 << 20
	MaxOutputBytes = 32 << 20
	MaxLines       = 20000
	MaxPages       = 512
)

var ErrLimit = errors.New("report resource limit exceeded")

type Classification string

const (
	Observed   Classification = "observed"
	Correlated Classification = "correlated"
	Inferred   Classification = "inferred"
	Unknown    Classification = "unknown"
)

// Annotation is trusted application input, never interpreted from provider metadata.
type Annotation struct {
	Source, Kind   string
	Classification Classification
}
type Options struct {
	CreatedAt          time.Time
	Duration           time.Duration
	Warnings           []string
	Errors             []string
	Annotations        []Annotation
	Partial, Truncated bool
}
type Reference struct {
	ResultID      string `json:"result_id"`
	EvidenceIndex int    `json:"evidence_index"`
}
type ExecutionSummary struct {
	Results    int `json:"results"`
	Sources    int `json:"sources"`
	Successful int `json:"successful_sources"`
	Failed     int `json:"failed_sources"`
	Partial    int `json:"partial_sources"`
	Evidence   int `json:"evidence_count"`
}
type Observation struct {
	ID              string                 `json:"id"`
	Result          models.Result          `json:"result"`
	Classification  Classification         `json:"classification"`
	EvidenceClasses []Classification       `json:"evidence_classifications"`
	ObservationKind models.ObservationKind `json:"observation_kind"`
	Meaning         models.EvidenceMeaning `json:"meaning"`
	ErrorKind       string                 `json:"error_kind,omitempty"`
	Partial         bool                   `json:"partial"`
	Truncated       bool                   `json:"truncated"`
}
type document struct {
	Analysis        *models.Analysis  `json:"analysis,omitempty"`
	Schema          string            `json:"schema"`
	InvestigationID string            `json:"investigation_id"`
	TargetType      models.TargetType `json:"target_type"`
	Target          string            `json:"target"`
	CreatedAt       string            `json:"created_at"`
	DurationNS      int64             `json:"duration_ns"`
	Status          string            `json:"status"`
	Summary         ExecutionSummary  `json:"summary"`
	Results         []Observation     `json:"results"`
	Correlations    []Reference       `json:"correlations"`
	Warnings        []string          `json:"warnings"`
	Errors          []string          `json:"errors"`
	Partial         bool              `json:"partial"`
	Truncated       bool              `json:"truncated"`
}

// Report is an immutable, bounded snapshot. Renderers cannot mutate input and
// callers cannot bypass construction/redaction by populating exported fields.
type Report struct{ data document }

func (r *Report) MarshalJSON() ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(r.data)
}
func (r *Report) Target() string { return r.data.Target }
func (r *Report) ID() string     { return r.data.InvestigationID }
func digest(b []byte) string     { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func encoded(v any) []byte       { b, _ := json.Marshal(v); return b }
func validClass(c Classification) bool {
	return c == Observed || c == Correlated || c == Inferred || c == Unknown
}
func checkField(s string) error {
	if len(s) > MaxFieldBytes || !utf8.ValidString(s) {
		return ErrLimit
	}
	return nil
}

// ResultSize checks before copying/serializing collections. Shared by collectors.
func ResultSize(r models.Result) (int, error) {
	size := 0
	add := func(s string) error {
		if err := checkField(s); err != nil {
			return err
		}
		size += len(s)
		if size > MaxInputBytes {
			return ErrLimit
		}
		return nil
	}
	for _, s := range []string{r.Source, string(r.SourceType), r.SiteName, r.Target, string(r.TargetType), r.URL, r.FinalURL, r.Error, string(r.Status)} {
		if err := add(s); err != nil {
			return 0, err
		}
	}
	if len(r.Evidence) > MaxEvidence || len(r.Metadata) > 256 {
		return 0, ErrLimit
	}
	for _, e := range r.Evidence {
		if err := add(e.Kind); err != nil {
			return 0, err
		}
		if err := add(e.Value); err != nil {
			return 0, err
		}
	}
	for k, v := range r.Metadata {
		if err := add(k); err != nil {
			return 0, err
		}
		if err := add(v); err != nil {
			return 0, err
		}
	}
	return size, nil
}
func cleanValue(s string, secrets []string) (string, error) {
	// Inspect structured evidence before textual redaction can break its JSON.
	trim := strings.TrimSpace(s)
	if trim != security.Redacted && (strings.HasPrefix(trim, "{") || strings.HasPrefix(trim, "[")) {
		d := json.NewDecoder(strings.NewReader(s))
		d.UseNumber()
		var v any
		if d.Decode(&v) == nil {
			var extra any
			if d.Decode(&extra) == io.EOF {
				if err := checkJSONKeys(s); err != nil {
					return "", err
				}
				var walk func(any, int) (any, error)
				walk = func(v any, depth int) (any, error) {
					if depth > 16 {
						return nil, ErrLimit
					}
					switch x := v.(type) {
					case map[string]any:
						out := map[string]any{}
						for k, value := range x {
							key := security.Redact(k, secrets...)
							if _, ok := out[key]; ok {
								return nil, errors.New("redacted evidence keys collide")
							}
							if security.SensitiveKey(k) {
								out[key] = security.Redacted
							} else {
								clean, e := walk(value, depth+1)
								if e != nil {
									return nil, e
								}
								out[key] = clean
							}
						}
						return out, nil
					case []any:
						for i, c := range x {
							clean, e := walk(c, depth+1)
							if e != nil {
								return nil, e
							}
							x[i] = clean
						}
						return x, nil
					case string:
						return security.Redact(x, secrets...), nil
					default:
						return v, nil
					}
				}
				clean, err := walk(v, 0)
				if err != nil {
					return "", err
				}
				return string(encoded(clean)), nil
			}
		}
		return "", errors.New("malformed structured report value")
	}
	return security.Redact(s, secrets...), nil
}
func baseClass(r models.Result) Classification {
	if r.SourceType == models.SourceWebsite {
		return Inferred
	}
	view := r.EvidenceSemantics()
	if view.Kind != models.ObservationUnknown && (view.Meaning == models.MeaningObservation || view.Meaning == models.MeaningAbsence) {
		return Observed
	}
	return Unknown
}
func flags(r models.Result) (partial, truncated bool) {
	if r.Status == models.StatusError || r.Status == models.StatusBlocked {
		partial = true
	}
	for k, v := range r.Metadata {
		lower := strings.ToLower(v)
		if strings.Contains(k, "truncat") && lower == "true" || k == "history_stop" && (lower == "page_limit" || lower == "transaction_limit") {
			truncated = true
		}
		if k == "partial" && lower == "true" || strings.HasSuffix(k, "_status") && (lower == "partial" || lower == "unavailable" || lower == "unknown") {
			partial = true
		}
	}
	return partial || truncated, truncated
}

// New creates report-level concepts without introducing source-specific fields.
// Creation time belongs to the investigation; zero is the documented Unix epoch.
func New(kind models.TargetType, target string, results []models.Result, opts Options) (*Report, error) {
	if !kind.Valid() {
		return nil, errors.New("invalid report target type")
	}
	if len(results) > MaxResults || len(opts.Warnings) > 1000 || len(opts.Errors) > 1000 || len(opts.Annotations) > MaxEvidence || opts.Duration < 0 {
		return nil, ErrLimit
	}
	if err := checkField(target); err != nil {
		return nil, err
	}
	annotationBytes := 0
	annotations := map[[2]string]Classification{}
	for _, a := range opts.Annotations {
		annotationBytes += len(a.Source) + len(a.Kind)
		if annotationBytes > MaxInputBytes {
			return nil, ErrLimit
		}
		if !validClass(a.Classification) || checkField(a.Source) != nil || checkField(a.Kind) != nil {
			return nil, errors.New("invalid evidence annotation")
		}
		key := [2]string{a.Source, a.Kind}
		if previous, ok := annotations[key]; ok && previous != a.Classification {
			return nil, errors.New("conflicting evidence annotations")
		}
		annotations[key] = a.Classification
	}
	var secrets []string
	if kind.Sensitive() {
		secrets = append(secrets, target)
		target = security.Redacted
	}
	for _, r := range results {
		if r.TargetType.Sensitive() {
			secrets = append(secrets, r.Target)
		}
	}
	if kind.Sensitive() {
		for _, r := range results {
			if r.Target != "" {
				secrets = append(secrets, r.Target)
			}
		}
	}
	clean := func(s string) string { return security.Redact(s, secrets...) }
	if opts.CreatedAt.IsZero() {
		opts.CreatedAt = time.Unix(0, 0)
	}
	if opts.CreatedAt.Year() < 1970 || opts.CreatedAt.Year() > 9999 {
		return nil, errors.New("invalid report creation time")
	}
	d := document{Schema: SchemaVersion, TargetType: kind, Target: clean(target), CreatedAt: opts.CreatedAt.UTC().Format(time.RFC3339Nano), DurationNS: int64(opts.Duration), Status: "complete", Results: []Observation{}, Correlations: []Reference{}, Warnings: []string{}, Errors: []string{}, Partial: opts.Partial, Truncated: opts.Truncated}
	total, evidenceCount := len(target)+annotationBytes, 0
	for _, raw := range results {
		size, err := ResultSize(raw)
		if err != nil {
			return nil, err
		}
		total += size
		evidenceCount += len(raw.Evidence)
		if total > MaxInputBytes || evidenceCount > MaxEvidence {
			return nil, ErrLimit
		}
		// Copy and redact structured values first. Result.Normalized is the shared
		// CLI/API safety contract, and remains unchanged by reporting.
		r := raw
		r.Evidence = make([]models.Evidence, len(raw.Evidence))
		r.Metadata = map[string]string{}
		for i, e := range raw.Evidence {
			v, err := cleanValue(e.Value, secrets)
			if err != nil {
				return nil, err
			}
			if security.SensitiveKey(e.Kind) {
				v = security.Redacted
			}
			r.Evidence[i] = models.Evidence{Kind: clean(e.Kind), Value: v}
		}
		for k, v := range raw.Metadata {
			value, err := cleanValue(v, secrets)
			if err != nil {
				return nil, err
			}
			if security.SensitiveKey(k) {
				value = security.Redacted
			}
			key := clean(k)
			if _, ok := r.Metadata[key]; ok {
				return nil, errors.New("redacted metadata keys collide")
			}
			r.Metadata[key] = value
		}
		r.Error, err = cleanValue(r.Error, secrets)
		if err != nil {
			return nil, err
		}
		evidence, metadata, resultError := r.Evidence, r.Metadata, r.Error
		r.Evidence = nil
		r.Metadata = nil
		r = r.Redacted(secrets...).Normalized()
		r.Evidence, r.Metadata, r.Error = evidence, metadata, resultError
		// A public source must not reintroduce a sensitive investigation target.
		if kind.Sensitive() {
			r.Target = security.Redacted
			r.TargetType = kind
		}
		if r.Duration < 0 {
			return nil, errors.New("invalid result duration")
		}
		sort.SliceStable(r.Evidence, func(i, j int) bool {
			a, b := r.Evidence[i], r.Evidence[j]
			if a.Kind != b.Kind {
				return a.Kind < b.Kind
			}
			ai, bi := indexValue(a.Value), indexValue(b.Value)
			if (ai >= 0) != (bi >= 0) {
				return ai >= 0
			}
			if ai >= 0 && bi >= 0 && ai != bi {
				return ai < bi
			}
			return a.Value < b.Value
		})
		p, tr := flags(r)
		view := r.EvidenceSemantics()
		o := Observation{Result: r, Classification: baseClass(r), ObservationKind: view.Kind, Meaning: view.Meaning, ErrorKind: r.Metadata["error_kind"], Partial: p, Truncated: tr, EvidenceClasses: []Classification{}}
		for _, e := range r.Evidence {
			c := o.Classification
			if view.Kind == models.ObservationBitcoin && e.Kind == "crypto_counterparty" {
				c = Correlated
			}
			if supplied, ok := annotations[[2]string{raw.Source, e.Kind}]; ok {
				c = supplied
			}

			o.EvidenceClasses = append(o.EvidenceClasses, c)
		}
		o.ID = digest(encoded(reportResult(r)))
		d.Results = append(d.Results, o)
		d.Partial = d.Partial || p
		d.Truncated = d.Truncated || tr
	}
	sort.SliceStable(d.Results, func(i, j int) bool {
		a, b := d.Results[i], d.Results[j]
		if a.Result.Source != b.Result.Source {
			return a.Result.Source < b.Result.Source
		}
		if a.Result.SourceType != b.Result.SourceType {
			return a.Result.SourceType < b.Result.SourceType
		}
		return bytes.Compare(encoded(reportResult(a.Result)), encoded(reportResult(b.Result))) < 0
	})
	ids := map[string]int{}
	for i := range d.Results {
		id := d.Results[i].ID
		ids[id]++
		if ids[id] > 1 {
			d.Results[i].ID = fmt.Sprintf("%s-%d", id, ids[id])
		}
	}
	states := map[string]int{}
	d.Summary.Results = len(d.Results)
	d.Summary.Evidence = evidenceCount
	good := 0
	bad := 0
	for _, o := range d.Results {
		key := string(o.Result.SourceType) + "\x00" + o.Result.Source
		if o.Result.Status == models.StatusError || o.Result.Status == models.StatusBlocked {
			states[key] |= 2
			bad++
		} else if o.Result.Status == models.StatusFound || o.Result.Status == models.StatusNotFound {
			states[key] |= 1
			good++
		} else {
			d.Partial = true
			states[key] |= 2
		}
		if o.Partial && o.Result.Status != models.StatusError && o.Result.Status != models.StatusBlocked {
			states[key] |= 2
		}
		for i, c := range o.EvidenceClasses {
			if c == Correlated {
				d.Correlations = append(d.Correlations, Reference{o.ID, i})
			}
		}
	}
	d.Summary.Sources = len(states)
	for _, v := range states {
		switch v {
		case 1:
			d.Summary.Successful++
		case 2:
			d.Summary.Failed++
		case 3:
			d.Summary.Partial++
		}
	}
	for _, s := range opts.Warnings {
		total += len(s)
		if total > MaxInputBytes {
			return nil, ErrLimit
		}
		if err := checkField(s); err != nil {
			return nil, err
		}
		value, err := cleanValue(s, secrets)
		if err != nil {
			return nil, err
		}
		d.Warnings = append(d.Warnings, value)
	}
	for _, s := range opts.Errors {
		total += len(s)
		if total > MaxInputBytes {
			return nil, ErrLimit
		}
		if err := checkField(s); err != nil {
			return nil, err
		}
		value, err := cleanValue(s, secrets)
		if err != nil {
			return nil, err
		}
		d.Errors = append(d.Errors, value)
	}
	if d.Truncated {
		d.Partial = true
		d.Warnings = append(d.Warnings, "Truncated provider coverage or investigation collection; missing evidence is not proof of absence.")
	}
	if d.Partial {
		d.Warnings = append(d.Warnings, "Partial investigation: retain successful observations; provider failures are not absence.")
	}
	if len(d.Errors) > 0 {
		d.Partial = true
	}
	switch {
	case len(d.Results) == 0 && len(d.Errors) == 0 && !d.Partial && !d.Truncated:
		d.Status = "empty"
	case good == 0 && (bad > 0 || len(d.Errors) > 0):
		d.Status = "failed"
	case d.Partial || len(d.Errors) > 0:
		d.Status = "partial"
	}
	sort.Strings(d.Warnings)
	sort.Strings(d.Errors)
	d.InvestigationID = digest(encoded(d))
	if len(encoded(d)) > MaxInputBytes {
		return nil, ErrLimit
	}
	return &Report{data: d}, nil
}
func indexValue(s string) int64 {
	var index struct {
		Index *int64 `json:"index"`
	}
	if json.Unmarshal([]byte(s), &index) == nil && index.Index != nil && *index.Index >= 0 {
		return *index.Index
	}
	return -1
}
func (r *Report) results() []models.Result {
	out := make([]models.Result, 0, len(r.data.Results))
	for _, o := range r.data.Results {
		out = append(out, o.Result)
	}
	return out
}
func (r *Report) confidence(o Observation) string {
	if o.Result.Confidence == 0 && o.Result.SourceType != models.SourceWebsite && o.ObservationKind == models.ObservationUnknown {
		return "not scored"
	}
	return o.Result.ConfidenceLabel()
}
func metadataKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func (r *Report) validate() error {
	if r == nil || r.data.Schema != SchemaVersion {
		return fmt.Errorf("invalid canonical report")
	}
	return nil
}

// Canonical fields have already been normalized and structurally sanitized.
// Avoid reapplying textual model redaction to embedded JSON at serialization.
type reportResult models.Result

func (r reportResult) MarshalJSON() ([]byte, error) {
	type plain reportResult
	if models.Result(r).UnscoredObservation() {
		return json.Marshal(struct {
			plain
			Confidence *int `json:"confidence,omitempty"`
		}{plain: plain(r)})
	}
	return json.Marshal(plain(r))
}
func (o Observation) MarshalJSON() ([]byte, error) {
	type plain Observation
	return json.Marshal(struct {
		plain
		Result reportResult `json:"result"`
	}{plain: plain(o), Result: reportResult(o.Result)})
}

// Reject duplicate object keys rather than silently keeping only their last value.
func checkJSONKeys(s string) error {
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return ErrLimit
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				k := key.(string)
				if seen[k] {
					return errors.New("duplicate structured report key")
				}
				seen[k] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		} else if delim == '[' {
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		}
		_, err = d.Token()
		return err
	}
	return value(0)
}
