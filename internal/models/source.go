package models

// SourceType describes provenance, not a concrete integration.
type SourceType string

const (
	SourceWebsite SourceType = "website"
	SourceAPI     SourceType = "api"
	SourceLocal   SourceType = "local"
)

// Evidence contains source-specific, non-secret details, never raw response bodies.
// Interpret it with the enclosing result provenance/status, not as a security verdict.
type Evidence struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}
