package report

import (
	"github.com/AgentFeature/agentsearch/internal/models"
	"time"
)

// HTMLReport preserves the existing generator API through the canonical pipeline.
type HTMLReport struct{}

func NewHTMLReport() *HTMLReport { return &HTMLReport{} }
func (*HTMLReport) Generate(target string, results []models.Result, duration time.Duration) (string, error) {
	return generateLegacy("html", target, results, duration)
}
