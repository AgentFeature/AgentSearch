package report

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
)

func TestGenericReports(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("output", 0755); err != nil {
		t.Fatal(err)
	}
	results := []models.Result{{Source: "local-test", SourceType: models.SourceLocal, Target: "never-print-this", TargetType: models.TargetPassword, Status: models.StatusFound, Metadata: map[string]string{"safe-detail": "observation", "password": "never-print-this"}, Evidence: []models.Evidence{{Kind: "observation", Value: "<script>alert(1)</script>"}}}}
	for _, tt := range []struct {
		name string
		gen  Generator
	}{{"cli", NewCLIReport()}, {"html", NewHTMLReport()}, {"docx", NewDOCXReport()}} {
		t.Run(tt.name, func(t *testing.T) {
			path, err := tt.gen.Generate("never-print-this", results, time.Second)
			if err != nil {

				t.Fatal(err)
			}
			var data []byte
			if tt.name == "docx" {
				z, err := zip.OpenReader(path)
				if err != nil {
					t.Fatal(err)
				}
				defer z.Close()
				for _, f := range z.File {
					if f.Name == "word/document.xml" {
						r, err := f.Open()
						if err != nil {
							t.Fatal(err)
						}
						data, err = io.ReadAll(r)
						_ = r.Close()
						if err != nil {
							t.Fatal(err)
						}
					}
				}
			} else {
				data, err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			if strings.Contains(string(data), "never-print-this") || !strings.Contains(string(data), "local-test") {
				t.Fatal("unsafe or missing generic result")
			}
			if tt.name == "html" && (!strings.Contains(string(data), "safe-detail") || strings.Contains(string(data), "<script>alert(1)</script>")) {
				t.Fatal("missing or unescaped generic details")
			}
		})
	}
}
func TestSummaryJSONEscaping(t *testing.T) {
	path := t.TempDir() + "/summary.json"
	target := "alice\"\\\n"
	if err := writeSummaryJSON(path, BuildSummary(target, []models.Result{{Source: "local", Status: models.StatusFound}}, time.Second)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	if result["target"] != target || result["found"] != float64(1) {
		t.Fatal("summary changed", result)
	}
}

func TestPasswordReportData(t *testing.T) {
	for _, status := range []models.ResultStatus{models.StatusFound, models.StatusNotFound, models.StatusError} {
		result := models.Result{Source: "pwned-passwords", SourceType: models.SourceAPI, Target: "[REDACTED]", TargetType: models.TargetPassword, Status: status, Metadata: map[string]string{"method": "sha1-k-anonymity"}}
		if status != models.StatusError {
			result.Metadata["pwned"] = "false"
			result.Metadata["occurrences"] = "0"
			if status == models.StatusFound {
				result.Metadata["pwned"] = "true"
				result.Metadata["occurrences"] = "42"
			}
		}
		target, results := normalizeResults("[REDACTED]", []models.Result{result})
		data, err := json.Marshal(struct {
			Summary Summary
			Results []models.Result
			Details []models.Evidence
		}{BuildSummary(target, results, time.Second), results, result.Details()})
		if err != nil || !strings.Contains(string(data), "sha1-k-anonymity") {
			t.Fatal("report data lost password semantics")
		}
		for _, input := range []string{"correct horse battery staple", "ABF7A", "AD6438836DBE526AA231ABDE2D0EEF74D42"} {
			if strings.Contains(string(data), input) {
				t.Fatal("password material in report data")
			}
		}
	}
}
