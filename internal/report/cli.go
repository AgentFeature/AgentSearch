package report

import (
	"github.com/AgentFeature/agentsearch/internal/models"
	"time"
)

// CLIReport preserves the existing generator API through the canonical pipeline.
type CLIReport struct{}

func NewCLIReport() *CLIReport { return &CLIReport{} }
func (*CLIReport) Generate(target string, results []models.Result, duration time.Duration) (string, error) {
	return generateLegacy("txt", target, results, duration)
}
