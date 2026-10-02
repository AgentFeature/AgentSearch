package models

// Analysis is an optional interpretation, never a source Result or watch event.
// Provider metadata is supplied by the adapter, never trusted from model output.
type Analysis struct {
	Status              string            `json:"status"`
	ErrorCode           string            `json:"error_code,omitempty"`
	Mode                string            `json:"mode"`
	Provider            string            `json:"provider,omitempty"`
	Model               string            `json:"model,omitempty"`
	InputDigest         string            `json:"input_digest,omitempty"`
	InputTruncated      bool              `json:"input_truncated"`
	RecordsSent         int               `json:"records_sent"`
	Summary             string            `json:"summary"`
	Findings            []AnalysisFinding `json:"findings"`
	Hypotheses          []AnalysisFinding `json:"hypotheses"`
	Anomalies           []AnalysisFinding `json:"anomalies"`
	Relationships       []AnalysisFinding `json:"relationships"`
	UnansweredQuestions []string          `json:"unanswered_questions"`
	Limitations         []string          `json:"limitations"`
}
type AnalysisFinding struct {
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Classification string   `json:"classification"`
	EvidenceRefs   []string `json:"evidence_refs"`
	Caveat         string   `json:"caveat"`
}
