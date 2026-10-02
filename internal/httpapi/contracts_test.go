package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/config"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
	"github.com/AgentFeature/agentsearch/internal/sources/hibp"
)

func TestCLIAndHTTPTargetContracts(t *testing.T) {
	longest := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, tc := range []struct{ name, kind, flag, input, want string }{
		{"username", "username", "-u", "Example_Name", "Example_Name"},
		{"email case and tags", "email", "-email", " Alice+tag@Example.test ", "Alice+tag@Example.test"},
		{"email normalized limit", "email", "-email", "  " + longest + "  ", longest},
		{"empty email", "email", "-email", "   ", ""},
		{"overlong email", "email", "-email", "x" + longest, ""},
		{"domain", "domain", "-domain", " Example.COM. ", "example.com"},
		{"invalid domain", "domain", "-domain", "https://example.com", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.ParseArgs([]string{tc.flag, tc.input})
			if tc.want == "" {
				if err == nil {
					t.Fatal("CLI accepted invalid input")
				}
			} else if err != nil || len(cfg.Targets) != 1 || cfg.Targets[0] != tc.want {
				t.Fatal("CLI normalization mismatch")
			}
			calls := 0
			h := handlerFor(t, func(_ context.Context, target models.Target, emit sources.Emit) error {
				calls++
				if target.Value() != tc.want || string(target.Type()) != tc.kind {
					t.Fatal("HTTP canonical target differs from CLI")
				}
				r := models.NewResult("fixture", models.SourceAPI, target)
				r.Status = models.StatusNotFound
				return emit(r)
			}, io.Discard, nil)
			body, _ := json.Marshal(map[string]string{"type": tc.kind, "target": tc.input})
			w := request(h, "POST", "/api/v1/search", string(body), "Bearer "+testToken)
			if tc.want == "" {
				if w.Code != 400 || calls != 0 {
					t.Fatal("invalid HTTP input reached search")
				}
				return
			}
			if w.Code != 200 || calls != 1 {
				t.Fatal("HTTP rejected a canonical CLI target")
			}
			var payload response
			if json.Unmarshal(w.Body.Bytes(), &payload) != nil || len(payload.Results) != 1 || payload.Results[0].Target != tc.want || payload.Results[0].Found || payload.Results[0].Status != models.StatusNotFound {
				t.Fatal("normalized output changed canonical target/status")
			}
		})
	}
}

type contextContractSource struct{ kind hibp.ErrorKind }

func (contextContractSource) Name() string            { return "context-contract" }
func (contextContractSource) Type() models.SourceType { return models.SourceAPI }
func (s contextContractSource) SearchEmail(context.Context, string, sources.Emit) error {
	return &hibp.Error{Kind: s.kind}
}
func TestProviderContextStatusThroughRunner(t *testing.T) {
	for _, tc := range []struct {
		kind   hibp.ErrorKind
		status int
		code   string
	}{{hibp.Timeout, 504, "timeout"}, {hibp.Cancelled, 408, "cancelled"}} {
		registry := sources.NewRegistry()
		if err := registry.Register(contextContractSource{tc.kind}); err != nil {
			t.Fatal(err)
		}
		runner := app.NewRunner(registry)
		h := handlerFor(t, runner.Search, io.Discard, nil)
		w := request(h, "POST", "/api/v1/search", `{"type":"email","target":"user@example.test"}`, "Bearer "+testToken)
		var payload response
		if w.Code != tc.status || json.Unmarshal(w.Body.Bytes(), &payload) != nil || payload.Error == nil || payload.Error.Code != tc.code || len(payload.Results) != 0 {
			t.Fatal("provider context failure lost across runner/HTTP boundary")
		}
	}
}
