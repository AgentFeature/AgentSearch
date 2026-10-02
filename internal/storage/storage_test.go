package storage

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/models"
)

func TestCommonWriters(t *testing.T) {
	for _, format := range []string{"json", "csv", "txt"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			m, err := NewManager(dir, []string{format}, "safe-label")
			if err != nil {
				t.Fatal(err)
			}
			m.Write(models.Result{Source: "local-test", SourceType: models.SourceLocal, Target: "alice", TargetType: models.TargetUsername, Status: models.StatusFound, Metadata: map[string]string{"count": "3"}})
			m.Write(models.Result{Source: "sensitive-test", SourceType: models.SourceLocal, Target: "never-persist-this", TargetType: models.TargetPassword, Error: "failed never-persist-this", Metadata: map[string]string{"raw": "never-persist-this"}})
			m.Close()
			b, err := os.ReadFile(filepath.Join(dir, "safe-label."+format))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "never-persist-this") || !strings.Contains(string(b), "local-test") {
				t.Fatal("unsafe or incomplete output", string(b))
			}
			switch format {
			case "json":
				var results []models.Result
				if err := json.Unmarshal(b, &results); err != nil || len(results) != 2 || results[0].Metadata["count"] != "3" {
					t.Fatal("invalid JSON", err)
				}
			case "csv":
				rows, err := csv.NewReader(strings.NewReader(string(b))).ReadAll()
				if err != nil || len(rows) != 3 || strings.Join(rows[0], ",") != "site_name,target,url,found,confidence,status,duration_ms,error,final_url" || rows[1][0] != "local-test" {
					t.Fatal("legacy CSV changed", err)
				}
			}
		})
	}
}
