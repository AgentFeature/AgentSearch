// Package analysistest supplies a credential-free, network-free test adapter.
// Production commands do not import it.
package analysistest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
)

type Fake struct {
	Mode   string
	Delay  time.Duration
	mu     sync.Mutex
	inputs [][]byte
}

func (f *Fake) Inputs() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]byte, len(f.inputs))
	for i, b := range f.inputs {
		out[i] = append([]byte(nil), b...)
	}
	return out
}
func (f *Fake) Generate(ctx context.Context, input []byte) ([]byte, error) {
	f.mu.Lock()
	f.inputs = append(f.inputs, append([]byte(nil), input...))
	f.mu.Unlock()
	if f.Delay > 0 {
		timer := time.NewTimer(f.Delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	switch f.Mode {
	case "error":
		return nil, errors.New("test adapter unavailable")
	case "malformed":
		return []byte("not JSON"), nil
	case "oversized":
		return []byte(strings.Repeat("x", (32<<10)+1)), nil
	case "empty":
		return nil, nil
	case "panic":
		panic("test adapter panic")
	}
	var in struct {
		Evidence []struct {
			ID string `json:"id"`
		} `json:"evidence"`
	}
	if json.Unmarshal(input, &in) != nil {
		return nil, errors.New("invalid test input")
	}
	findings := []models.AnalysisFinding{}
	if len(in.Evidence) > 0 {
		findings = append(findings, models.AnalysisFinding{Title: "Evidence interpretation", Description: "Review the supplied observation in its source context.", Classification: "inferred", EvidenceRefs: []string{in.Evidence[0].ID}, Caveat: "This is a deterministic test interpretation, not an independently verified fact."})
	}
	return json.Marshal(struct {
		Findings      []models.AnalysisFinding `json:"findings"`
		Hypotheses    []models.AnalysisFinding `json:"hypotheses"`
		Anomalies     []models.AnalysisFinding `json:"anomalies"`
		Relationships []models.AnalysisFinding `json:"relationships"`
		Questions     []string                 `json:"unanswered_questions"`
		Limitations   []string                 `json:"limitations"`
	}{findings, []models.AnalysisFinding{}, []models.AnalysisFinding{}, []models.AnalysisFinding{}, []string{}, []string{"Local test adapter; no model-quality conclusion."}})
}
