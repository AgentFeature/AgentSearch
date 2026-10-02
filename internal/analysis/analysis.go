package analysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/report"
)

// Provider receives only prepared JSON and returns model JSON, without tools.
// Implementations must honor context cancellation, bound allocation and redact
// credentials before returning bytes. Production HTTP implementation does so.
type Provider interface {
	Generate(context.Context, []byte) ([]byte, error)
}
type code string

func (e code) Error() string { return string(e) }

type Service struct {
	provider     Provider
	model        string
	timeout      time.Duration
	inputLimit   int
	unavailable  string
	providerName string
}

func New(provider Provider, model string) *Service {
	return &Service{provider: provider, model: safeText(model), timeout: 30 * time.Second, inputLimit: MaxInputBytes}
}
func Failed(reason string) models.Analysis {
	return models.Analysis{Status: "failed", ErrorCode: reason, Mode: "investigation", Summary: "AI analysis unavailable; deterministic evidence is unchanged.", Findings: []models.AnalysisFinding{}, Hypotheses: []models.AnalysisFinding{}, Anomalies: []models.AnalysisFinding{}, Relationships: []models.AnalysisFinding{}, UnansweredQuestions: []string{}, Limitations: []string{"AI analysis is not an authoritative source of facts."}}
}
func (s *Service) Analyze(ctx context.Context, r *report.Report) (out models.Analysis) {
	out = Failed("internal_error")
	// A faulty optional adapter must not destroy the completed investigation.
	defer func() {
		if recover() != nil {
			out = Failed("internal_error")
		}
	}()
	if s == nil || s.provider == nil {
		reason := "ai_not_configured"
		if s != nil && s.unavailable != "" {
			reason = s.unavailable
		}
		return Failed(reason)
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	if ctx.Err() != nil {
		return Failed(category(ctx.Err()))
	}
	in, raw, err := Prepare(r, s.inputLimit)
	if err != nil {
		return Failed(category(err))
	}
	out = Failed("provider_unavailable")
	if sanitizer, ok := s.provider.(interface{ SanitizeInput([]byte) []byte }); ok {
		raw = sanitizer.SanitizeInput(raw)
		if len(raw) > s.inputLimit || json.Unmarshal(raw, &in) != nil {
			return Failed("input_too_large")
		}
	}
	out.InputDigest = digest(raw)
	out.InputTruncated = in.Truncated
	out.RecordsSent = len(in.Records)
	if ctx.Err() != nil {
		out.ErrorCode = category(ctx.Err())
		return out
	}
	response, err := s.provider.Generate(ctx, append([]byte(nil), raw...))
	if ctx.Err() != nil {
		out.ErrorCode = category(ctx.Err())
		return out
	}
	if err != nil {
		out.ErrorCode = category(err)
		return out
	}
	parsed, err := Parse(response, in)
	if err != nil {
		out.ErrorCode = category(err)
		return out
	}
	parsed.InputDigest = out.InputDigest
	parsed.InputTruncated = in.Truncated
	parsed.RecordsSent = len(in.Records)
	parsed.Provider = s.providerName
	if parsed.Provider == "" {
		parsed.Provider = "configured-adapter"
	}
	parsed.Model = s.model
	if in.Truncated {
		parsed.Limitations = append(parsed.Limitations, "AI received only a bounded subset; missing evidence is not absence.")
	}
	return parsed
}
func category(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	var c code
	if errors.As(err, &c) {
		switch string(c) {
		case "internal_error", "timeout", "cancelled", "rate_limited", "invalid_response", "malformed_analysis", "input_too_large", "provider_unavailable", "ai_not_configured", "ai_disabled":
			return string(c)
		}
	}
	return "provider_unavailable"
}

// StrictJSON rejects duplicate keys, excessive nesting, invalid UTF-8, unknown
// fields and trailing values. Model output never gets a best-effort text fallback.
func StrictJSON(raw []byte, out any) error { return strictJSON(raw, out, true) }
func strictJSON(raw []byte, out any, rejectUnknown bool) error {
	if len(raw) == 0 || len(raw) > MaxOutputBytes || !utf8.Valid(raw) {
		return code("invalid_response")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 12 {
			return code("invalid_response")
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return code("invalid_response")
				}
				seen[s] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return code("invalid_response")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return code("invalid_response")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	if rejectUnknown {
		d.DisallowUnknownFields()
	}
	if d.Decode(out) != nil {
		return code("invalid_response")
	}
	return nil
}

type modelResult struct {
	Findings            []models.AnalysisFinding `json:"findings"`
	Hypotheses          []models.AnalysisFinding `json:"hypotheses"`
	Anomalies           []models.AnalysisFinding `json:"anomalies"`
	Relationships       []models.AnalysisFinding `json:"relationships"`
	UnansweredQuestions []string                 `json:"unanswered_questions"`
	Limitations         []string                 `json:"limitations"`
}

func Parse(raw []byte, in Input) (models.Analysis, error) {
	bad := func() (models.Analysis, error) { return models.Analysis{}, code("malformed_analysis") }
	var m modelResult
	if err := StrictJSON(raw, &m); err != nil {
		return models.Analysis{}, err
	}
	if m.Findings == nil || m.Hypotheses == nil || m.Anomalies == nil || m.Relationships == nil || m.UnansweredQuestions == nil || m.Limitations == nil {
		return bad()
	}
	if len(m.Findings) > MaxFindings || len(m.Hypotheses) > MaxHypotheses || len(m.Anomalies) > 8 || len(m.Relationships) > 8 || len(m.UnansweredQuestions) > MaxQuestions || len(m.Limitations) > 8 {
		return bad()
	}
	refs := map[string]Record{}
	for _, r := range in.Records {
		refs[r.ID] = r
	}
	seen := map[string]bool{}
	fingerprints := map[string]bool{}
	total, claims := 0, 0
	groups := []struct {
		items      []models.AnalysisFinding
		hypothesis bool
	}{{m.Findings, false}, {m.Hypotheses, true}, {m.Anomalies, false}, {m.Relationships, false}}
	for _, g := range groups {
		for i := range g.items {
			f := &g.items[i]
			claims++
			if claims > MaxClaims || len(f.Title) == 0 || len(f.Title) > 160 || len(f.Description) == 0 || len(f.Description) > MaxFieldBytes || len(f.Caveat) > 512 || len(f.EvidenceRefs) == 0 || len(f.EvidenceRefs) > MaxRefs {
				return bad()
			}
			switch f.Classification {
			case "observed", "correlated", "inferred", "hypothesis", "unknown":
			default:
				return bad()
			}
			title := strings.ToLower(strings.TrimSpace(f.Title))
			if seen[title] {
				return bad()
			}
			seen[title] = true
			used := map[string]bool{}
			for _, ref := range f.EvidenceRefs {
				if _, ok := refs[ref]; !ok || used[ref] {
					return bad()
				}
				used[ref] = true
				total++
				if total > MaxTotalRefs {
					return bad()
				}
			}
			sort.Strings(f.EvidenceRefs)
			// Model assertions are not evidence. Only an exact, single-record quotation
			// can retain observed/correlated, and only with the matching input class.
			if f.Classification == "observed" || f.Classification == "correlated" {
				r := refs[f.EvidenceRefs[0]]
				if len(f.EvidenceRefs) != 1 || f.Description != r.Value || f.Classification != r.Classification {
					f.Classification = "inferred"
					f.Caveat = "Model interpretation; evidence support has not been independently verified."
				} else {
					f.Title = "Quotation of evidence " + f.EvidenceRefs[0]
					f.Caveat = "Exact source quotation; not independent verification or ownership attribution."
				}
			}
			if g.hypothesis {
				f.Classification = "hypothesis"
			}
			f.Title = safeText(f.Title)
			f.Description = cleanValue(f.Description, in.TargetType == models.TargetBitcoin || in.TargetType == models.TargetBitcoinTransaction)
			f.Caveat = safeText(f.Caveat)
			if len(f.Title) > 160 || len(f.Description) > MaxFieldBytes || len(f.Caveat) > 512 {
				return bad()
			}
			fingerprint := digest(mustJSON(struct {
				Description string
				Refs        []string
			}{f.Description, f.EvidenceRefs}))
			if fingerprints[fingerprint] {
				return bad()
			}
			fingerprints[fingerprint] = true
		}
		sort.Slice(g.items, func(i, j int) bool { return g.items[i].Title < g.items[j].Title })
	}
	for _, list := range [][]string{m.UnansweredQuestions, m.Limitations} {
		for i, v := range list {
			if len(v) == 0 || len(v) > 512 {
				return bad()
			}
			list[i] = safeText(v)
			if len(list[i]) > 512 {
				return bad()
			}
		}
		sort.Strings(list)
	}
	out := Failed("")
	out.Status = "completed"
	out.Summary = fmt.Sprintf("AI interpretation: %d cited claims. Not independently verified.", claims)
	out.Findings = m.Findings
	out.Hypotheses = m.Hypotheses
	out.Anomalies = m.Anomalies
	out.Relationships = m.Relationships
	out.UnansweredQuestions = m.UnansweredQuestions
	out.Limitations = append(out.Limitations, m.Limitations...)
	return out, nil
}
