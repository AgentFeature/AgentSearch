package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/analysis"
	"github.com/AgentFeature/agentsearch/internal/analysis/analysistest"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

func TestAPIAnalysisOptInAndFailureIsolation(t *testing.T) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatal(err)
	}
	key := hex.EncodeToString(keyBytes)
	for _, mode := range []string{"", "error", "malformed"} {
		fake := &analysistest.Fake{Mode: mode}
		var logs bytes.Buffer
		searcher := searchFunc(func(_ context.Context, target models.Target, emit sources.Emit) error {
			return emit(models.Result{Source: "fixture", Target: target.String(), TargetType: target.Type(), Status: models.StatusFound, Evidence: []models.Evidence{{Kind: "observation", Value: "supplied-evidence"}}, Metadata: map[string]string{"pwned": "true", "occurrences": "1"}})
		})
		h, err := New(searcher, security.NewSecret(key), config.DefaultServerConfig(), slog.New(slog.NewTextHandler(&logs, nil)), analysis.New(fake, "test-fake"))
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"username", "email", "domain", "ip", "bitcoin", "bitcoin_tx", "password"} {
			target := map[string]string{"username": "fixture", "email": "fixture@example.test", "domain": "example.test", "ip": "192.0.2.1", "bitcoin": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bitcoin_tx": strings.Repeat("a", 64), "password": key}[kind]
			for _, opt := range []string{"", `,"analysis":false`, `,"analysis":true`} {
				field := "target"
				if kind == "password" {
					field = "password"
				}
				raw := `{"type":"` + kind + `","` + field + `":"` + target + `"` + opt + `}`
				before := len(fake.Inputs())
				w := request(h, "POST", "/api/v1/search", raw, "Bearer "+key)
				if w.Code != 200 {
					t.Fatal(kind, w.Code, w.Body.String())
				}
				var payload struct {
					Results  []models.Result
					Analysis *models.Analysis
					Report   *struct{ Results []struct{ ID string } }
				}
				if err = json.Unmarshal(w.Body.Bytes(), &payload); err != nil || len(payload.Results) != 1 {
					t.Fatal("results lost", err)
				}
				if opt == `,"analysis":true` {
					if payload.Analysis == nil || payload.Report == nil || len(fake.Inputs()) != before+1 {
						t.Fatal("missing explicit analysis/canonical reference source")
					}
					if mode != "" && payload.Analysis.Status != "failed" {
						t.Fatal("AI failure missing")
					}
					if kind == "password" && bytes.Contains(fake.Inputs()[before], []byte(key)) {
						t.Fatal("password sent")
					}
				} else if payload.Analysis != nil || payload.Report != nil || len(fake.Inputs()) != before {
					t.Fatal("AI not opt-in")
				}
			}
		}
		if strings.Contains(logs.String(), key) || strings.Contains(logs.String(), "supplied-evidence") {
			t.Fatal("credentials or prompts logged")
		}
		for _, raw := range []string{`{"type":"username","target":"x","analysis":null}`, `{"type":"username","target":"x","analysis":"true"}`, `{"type":"username","target":"x","analysis":true,"analysis":false}`} {
			w := request(h, "POST", "/api/v1/search", raw, "Bearer "+key)
			if w.Code != 400 {
				t.Fatal("invalid option accepted")
			}
		}
	}
}
