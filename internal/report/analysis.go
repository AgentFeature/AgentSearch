package report

import (
	"encoding/json"
	"errors"
	"github.com/AgentFeature/agentsearch/internal/models"
)

// Snapshot is the existing canonical document, exported as a detached copy for
// downstream consumers. It does not expose mutable Report internals.
type Snapshot document

func (r *Report) Snapshot() (Snapshot, error) {
	var out Snapshot
	raw, err := r.MarshalJSON()
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(raw, &out)
	return out, err
}

// WithAnalysis creates a new report without changing its evidence or identity.
func (r *Report) WithAnalysis(a models.Analysis) (*Report, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(a)
	if err != nil || len(raw) > 64<<10 {
		return nil, errors.New("invalid analysis attachment")
	}
	clean, err := cleanValue(string(raw), nil)
	if err != nil {
		return nil, err
	}
	var copied models.Analysis
	if err = json.Unmarshal([]byte(clean), &copied); err != nil {
		return nil, err
	}
	out := *r
	out.data.Analysis = &copied
	return &out, nil
}
