package monitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

const (
	MaxRows        = 2048
	MaxEvidence    = 8192
	MaxValueBytes  = 64 << 10
	MaxStateBytes  = 2 << 20
	MaxResultBytes = 4 << 20
)

type Provenance struct {
	Source     string            `json:"source"`
	SourceType models.SourceType `json:"source_type"`
	Provider   string            `json:"provider,omitempty"`
	URL        string            `json:"url,omitempty"`
}
type SourceState struct {
	Source     string            `json:"source"`
	Type       models.SourceType `json:"source_type"`
	Provenance []Provenance      `json:"provenance"`
	Evidence   []models.Evidence `json:"evidence"`
}
type Snapshot struct {
	Version    int               `json:"version"`
	Target     string            `json:"target"`
	TargetType models.TargetType `json:"target_type"`
	Revision   uint64            `json:"revision"`
	Sources    []SourceState     `json:"sources"`
}
type Change struct {
	ID            string            `json:"change_id"`
	Timestamp     string            `json:"timestamp"`
	Target        string            `json:"target"`
	TargetType    models.TargetType `json:"target_type"`
	Source        string            `json:"source"`
	EvidenceType  string            `json:"evidence_type"`
	Kind          string            `json:"change_kind"`
	Old           *models.Evidence  `json:"old_value,omitempty"`
	New           *models.Evidence  `json:"new_value,omitempty"`
	OldProvenance []Provenance      `json:"old_provenance,omitempty"`
	Provenance    []Provenance      `json:"provenance"`
}

func sourceKey(s string, t models.SourceType) string { return s + "\x00" + string(t) }
func marshal(v any) []byte                           { b, _ := json.Marshal(v); return b }

// Only comparison noise is excluded. Provider block/record timestamps remain
// meaningful evidence. Arrays retain order (transaction positions matter).
func runtimeField(s string) bool {
	switch strings.ToLower(s) {
	case "observation_time", "observed_at", "request_duration", "duration", "duration_ms", "run_id", "request_id", "random_id", "fetched_at":
		return true
	}
	return false
}
func canonicalValue(value string) (string, error) {
	if len(value) > MaxValueBytes || !utf8.ValidString(value) {
		return "", errors.New("evidence value exceeds monitor bound")
	}
	// Scalars are already normalized source values; never convert them through floats.
	if !strings.HasPrefix(strings.TrimSpace(value), "{") && !strings.HasPrefix(strings.TrimSpace(value), "[") {
		return value, nil
	}
	d := json.NewDecoder(strings.NewReader(value))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return value, nil
	} // Redacted JSON can legitimately be text.
	var extra any
	if d.Decode(&extra) != io.EOF {
		return value, nil
	}
	var clean func(any, int) error
	clean = func(v any, depth int) error {
		if depth > 16 {
			return errors.New("evidence nesting exceeds monitor bound")
		}
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				if runtimeField(k) {
					delete(x, k)
				} else if err := clean(c, depth+1); err != nil {
					return err
				}
			}
		case []any:
			for _, c := range x {
				if err := clean(c, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := clean(v, 0); err != nil {
		return "", err
	}
	return string(marshal(v)), nil
}
func evidenceLess(a, b models.Evidence) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.Value < b.Value
}
func canonicalEvidence(in []models.Evidence) ([]models.Evidence, error) {
	if len(in) > MaxEvidence {
		return nil, errors.New("too much evidence")
	}
	out := make([]models.Evidence, 0, len(in))
	seen := map[models.Evidence]bool{}
	for _, e := range in {
		e.Kind = security.Redact(e.Kind)
		e.Value = security.Redact(e.Value)
		if security.SensitiveKey(e.Kind) {
			e.Value = security.Redacted
		}
		if runtimeField(e.Kind) {
			continue
		}
		if len(e.Kind) == 0 || len(e.Kind) > 256 || !utf8.ValidString(e.Kind) {
			return nil, errors.New("invalid evidence kind")
		}
		value, err := canonicalValue(e.Value)
		if err != nil {
			return nil, err
		}
		e.Value = value
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return evidenceLess(out[i], out[j]) })
	return out, nil
}
func incomplete(r models.Result) bool {
	if r.Status != models.StatusFound && r.Status != models.StatusNotFound || r.Error != "" {
		return true
	}
	for k, v := range r.Metadata {
		k = strings.ToLower(k)
		v = strings.ToLower(v)
		if (strings.Contains(k, "truncat") || k == "partial") && v == "true" {
			return true
		}
		if strings.HasSuffix(k, "_status") && (v == "partial" || v == "unavailable" || v == "unknown") {
			return true
		}
		if k == "history_stop" && strings.HasSuffix(v, "_limit") {
			return true
		}
		if (k == "complete" || k == "input_values_complete") && v == "false" {
			return true
		}
	}
	return false
}

type projection struct {
	Good                       []SourceState
	Attempted, Failed, Partial []string
}

func project(rows []models.Result, searchErr error) (projection, error) {
	p := projection{}
	groups := map[string]*SourceState{}
	bad := map[string]bool{}
	reportedGood := map[string]bool{}
	explicitFailure := false
	for _, raw := range rows {
		r := raw.Normalized()
		key := sourceKey(r.Source, r.SourceType)
		if r.Source == "" || len(r.Source) > 256 {
			return p, errors.New("invalid source identity")
		}
		if groups[key] == nil {
			groups[key] = &SourceState{Source: r.Source, Type: r.SourceType}
		}
		if raw.Status == models.StatusFound || raw.Status == models.StatusNotFound {
			reportedGood[key] = true
		}
		// Never inherit Normalized's legacy implicit absence when status was unspecified.
		if raw.Status == "" || incomplete(r) {
			bad[key] = true
			explicitFailure = true
			continue
		}
		s := groups[key]
		s.Evidence = append(s.Evidence, r.Evidence...)
		s.Evidence = append(s.Evidence, models.Evidence{Kind: "result_status", Value: string(r.Status)})
		s.Provenance = append(s.Provenance, Provenance{Source: r.Source, SourceType: r.SourceType, Provider: r.Metadata["provider"], URL: r.URL})
	}
	keys := []string{}
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		s := groups[key]
		p.Attempted = append(p.Attempted, s.Source)
		// An unattributed error could invalidate any emitted row: fail conservatively.
		if bad[key] || (searchErr != nil && !explicitFailure) {
			if reportedGood[key] {
				p.Partial = append(p.Partial, s.Source)
			} else {
				p.Failed = append(p.Failed, s.Source)
			}
			continue
		}
		var err error
		s.Evidence, err = canonicalEvidence(s.Evidence)
		if err != nil {
			return p, err
		}
		sort.Slice(s.Provenance, func(i, j int) bool { return bytes.Compare(marshal(s.Provenance[i]), marshal(s.Provenance[j])) < 0 })
		unique := []Provenance{}
		for _, v := range s.Provenance {
			if len(unique) == 0 || unique[len(unique)-1] != v {
				unique = append(unique, v)
			}
		}
		s.Provenance = unique
		p.Good = append(p.Good, *s)
	}
	return p, nil
}

// Diff compares evidence sets within the same kind. One unmatched old/new value
// is MODIFIED; otherwise emit precise ADDED/REMOVED values without guessing
// correspondence between multi-valued observations.
func diff(old, now SourceState) []Change {
	oldSet := map[models.Evidence]bool{}
	newSet := map[models.Evidence]bool{}
	for _, e := range old.Evidence {
		oldSet[e] = true
	}
	for _, e := range now.Evidence {
		newSet[e] = true
	}
	removed := map[string][]models.Evidence{}
	added := map[string][]models.Evidence{}
	kinds := map[string]bool{}
	for _, e := range old.Evidence {
		if !newSet[e] {
			removed[e.Kind] = append(removed[e.Kind], e)
			kinds[e.Kind] = true
		}
	}
	for _, e := range now.Evidence {
		if !oldSet[e] {
			added[e.Kind] = append(added[e.Kind], e)
			kinds[e.Kind] = true
		}
	}
	keys := []string{}
	for k := range kinds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []Change{}
	for _, k := range keys {
		a, b := removed[k], added[k]
		base := Change{Source: now.Source, EvidenceType: k, Provenance: now.Provenance, OldProvenance: old.Provenance}
		if len(a) == 1 && len(b) == 1 {
			c := base
			c.Kind = "MODIFIED"
			c.Old = &a[0]
			c.New = &b[0]
			out = append(out, c)
			continue
		}
		for _, e := range b {
			c := base
			c.Kind = "ADDED"
			v := e
			c.New = &v
			out = append(out, c)
		}
		for _, e := range a {
			c := base
			c.Kind = "REMOVED"
			v := e
			c.Old = &v
			out = append(out, c)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.EvidenceType != b.EvidenceType {
			return a.EvidenceType < b.EvidenceType
		}
		key := func(c Change) string {
			if c.New != nil {
				return c.New.Value
			}
			if c.Old != nil {
				return c.Old.Value
			}
			return ""
		}
		if key(a) != key(b) {
			return key(a) < key(b)
		}
		return a.Kind < b.Kind
	})
	return out
}
func newSnapshot(t models.Target) Snapshot {
	return Snapshot{Version: 1, Target: t.Value(), TargetType: t.Type(), Sources: []SourceState{}}
}
func merge(old Snapshot, current []SourceState) (Snapshot, []Change, int) {
	next := old
	next.Sources = append([]SourceState(nil), old.Sources...)
	events := []Change{}
	created := 0
	for _, now := range current {
		found := -1
		for i, s := range next.Sources {
			if sourceKey(s.Source, s.Type) == sourceKey(now.Source, now.Type) {
				found = i
				break
			}
		}
		if found < 0 {
			next.Sources = append(next.Sources, now)
			created++
		} else {
			events = append(events, diff(next.Sources[found], now)...)
			next.Sources[found] = now
		}
	}
	sort.Slice(next.Sources, func(i, j int) bool {
		return sourceKey(next.Sources[i].Source, next.Sources[i].Type) < sourceKey(next.Sources[j].Source, next.Sources[j].Type)
	})
	if !bytes.Equal(marshal(old.Sources), marshal(next.Sources)) {
		next.Revision++
	}
	return next, events, created
}
func parseState(raw []byte, t models.Target) (Snapshot, error) {
	invalid := errors.New("corrupt monitoring baseline; new baseline required")
	if len(raw) > MaxStateBytes {
		return Snapshot{}, invalid
	}
	var s Snapshot
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || s.Revision == ^uint64(0) || s.Version != 1 || s.Target != t.Value() || s.TargetType != t.Type() || len(s.Sources) > MaxRows {
		return Snapshot{}, invalid
	}
	if !bytes.Equal(marshal(s), raw) {
		return Snapshot{}, invalid
	} // Canonical encoding, no trailing/duplicate keys.
	previous := ""
	total := 0
	for _, v := range s.Sources {
		key := sourceKey(v.Source, v.Type)
		if key <= previous || v.Source == "" || security.Redact(v.Source) != v.Source {
			return Snapshot{}, invalid
		}
		previous = key
		evidence, err := canonicalEvidence(v.Evidence)
		if err != nil || !bytes.Equal(marshal(evidence), marshal(v.Evidence)) {
			return Snapshot{}, invalid
		}
		total += len(v.Evidence)
		if total > MaxEvidence {
			return Snapshot{}, invalid
		}
		for _, p := range v.Provenance {
			if p.Source != v.Source || p.SourceType != v.Type || security.Redact(p.Provider) != p.Provider || security.Redact(p.URL) != p.URL {
				return Snapshot{}, invalid
			}
		}
	}
	return s, nil
}
func safeError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("monitor storage or configuration failure: %w", err)
}
