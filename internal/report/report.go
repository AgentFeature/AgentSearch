package report

import (
	"encoding/json"
	"os"
	"sort"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

// Generator renders normalized search results.
type Generator interface {
	Generate(target string, results []models.Result, duration time.Duration) (string, error)
}

// Summary aggregates search results.
type Summary struct {
	Target       string
	Total        int
	Found        int
	NotFound     int
	Blocked      int
	Errors       int
	Duration     time.Duration
	TopSites     []SiteStat
	ByTag        map[string]TagStat
	BlockedHosts []string
}

// SiteStat contains per-source statistics; the name is retained for compatibility.
type SiteStat struct {
	Name       string
	Found      int
	Blocked    int
	AvgLatency time.Duration
}

// TagStat contains aggregate statistics for a tag.
type TagStat struct {
	Tag         string
	Total       int
	Found       int
	Blocked     int
	SuccessRate float64
}

// BuildSummary aggregates normalized results.
func BuildSummary(target string, results []models.Result, duration time.Duration) Summary {
	target, results = normalizeResults(target, results)
	s := Summary{
		Target:       target,
		Total:        len(results),
		Duration:     duration,
		ByTag:        make(map[string]TagStat),
		BlockedHosts: make([]string, 0),
	}

	siteMap := make(map[string]*SiteStat)
	counts := map[string]int{}
	blockedSet := make(map[string]struct{})

	for _, r := range results {
		switch r.Status {
		case models.StatusFound:
			s.Found++
		case models.StatusNotFound:
			s.NotFound++
		case models.StatusBlocked:
			s.Blocked++
			blockedSet[r.SiteName] = struct{}{}
		case models.StatusError:
			s.Errors++
		}

		counts[r.SiteName]++
		// Aggregate by display source.
		st, ok := siteMap[r.SiteName]
		if !ok {
			st = &SiteStat{Name: r.SiteName}
			siteMap[r.SiteName] = st
		}
		if r.Status == models.StatusFound {
			st.Found++
		}
		if r.Status == models.StatusBlocked {
			st.Blocked++
		}
		st.AvgLatency += r.Duration
	}

	for _, st := range siteMap {
		if st.Found > 0 || st.Blocked > 0 {
			st.AvgLatency = st.AvgLatency / time.Duration(counts[st.Name])
			s.TopSites = append(s.TopSites, *st)
		}
	}
	sort.Slice(s.TopSites, func(i, j int) bool {
		if s.TopSites[i].Found == s.TopSites[j].Found {
			return s.TopSites[i].Name < s.TopSites[j].Name
		}
		return s.TopSites[i].Found > s.TopSites[j].Found
	})

	for host := range blockedSet {
		s.BlockedHosts = append(s.BlockedHosts, host)
	}
	sort.Strings(s.BlockedHosts)

	return s
}

// WriteAll is the legacy -rf compatibility entry point.
func WriteAll(dir string, formats []string, target string, results []models.Result, duration time.Duration) error {
	r, err := legacyReport(target, results, duration)
	if err != nil {
		return err
	}
	return WriteOutputs(dir, nil, formats, r)
}

func summaryJSON(summary Summary) []byte {
	// Indented for readability; the field set and ordering are unchanged.
	b, _ := json.MarshalIndent(struct {
		Target   string `json:"target"`
		Total    int    `json:"total"`
		Found    int    `json:"found"`
		NotFound int    `json:"not_found"`
		Blocked  int    `json:"blocked"`
		Errors   int    `json:"errors"`
		Duration string `json:"duration"`
	}{summary.Target, summary.Total, summary.Found, summary.NotFound, summary.Blocked, summary.Errors, summary.Duration.String()}, "", "  ")
	return append(b, '\n')
}
func writeSummaryJSON(path string, summary Summary) error {
	return os.WriteFile(path, summaryJSON(summary), 0600)
}

func sanitizeFilename(name string) string { return SafeBase(name) }

// normalizeResults protects direct generator callers as well as the app path.
// The legacy string argument is a display label, never sensitive input.
func normalizeResults(target string, results []models.Result) (string, []models.Result) {
	var secrets []string
	for _, r := range results {
		if r.TargetType.Sensitive() {
			secrets = append(secrets, target, r.Target)
			target = security.Redacted
		}
	}
	out := make([]models.Result, len(results))
	for i, r := range results {
		out[i] = r.Redacted(secrets...).Normalized()
	}
	return security.Redact(target, secrets...), out
}
