package websites

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/network"
	"github.com/AgentFeature/agentsearch/internal/ratelimit"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

func newTestSource(t *testing.T, sites []models.SiteConfig, client *http.Client) *Source {
	t.Helper()
	ua, err := network.NewUARotator("")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(sites, 4, client, ua, ratelimit.NewHostLimiter(0))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestWebsiteAdapter(t *testing.T) {
	for _, tt := range []struct {
		name       string
		site       models.SiteConfig
		code       int
		body       string
		header     http.Header
		status     models.ResultStatus
		confidence int
	}{
		{"found", models.SiteConfig{CheckType: "status_code", ErrorCode: 404, Weight: 20}, 200, "", nil, models.StatusFound, 50},
		{"http-failure-is-unknown", models.SiteConfig{CheckType: "status_code"}, 500, "unretained body", nil, models.StatusError, 0},
		{"missing", models.SiteConfig{CheckType: "status_code", ErrorCode: 404}, 404, "", nil, models.StatusNotFound, 0},
		{"message-absence", models.SiteConfig{CheckType: "message", AbsenceStrs: []string{"missing"}}, 200, "missing", nil, models.StatusNotFound, 0},
		{"regex-absence", models.SiteConfig{CheckType: "message", AbsenceRegexes: []string{"not.*here"}}, 200, "not here", nil, models.StatusNotFound, 0},
		{"regex-presence", models.SiteConfig{CheckType: "message", PresenceRegexes: []string{"member.*since"}, Weight: 50}, 200, "member since", nil, models.StatusFound, 50},
		{"header", models.SiteConfig{CheckType: "header", RequiredHeaders: map[string]string{"X-Found": "yes"}}, 200, "", http.Header{"X-Found": []string{"yes"}}, models.StatusFound, 40},
		// A CDN header on an ordinary success is not blocking evidence;
		// blocking requires a challenge/deny status or challenge markers.
		{"cloudflare-fronted-ok", models.SiteConfig{CheckType: "status_code"}, 200, "", http.Header{"Cf-Ray": []string{"ray"}}, models.StatusFound, 40},
		{"cloudflare-blocked", models.SiteConfig{CheckType: "status_code"}, 403, "", http.Header{"Cf-Ray": []string{"ray"}}, models.StatusBlocked, 0},
		{"waf-body", models.SiteConfig{}, 200, "ddos-guard", nil, models.StatusBlocked, 0},
		{"custom-waf", models.SiteConfig{WAFIndicators: models.WAFConfig{BodySubstrings: []string{"custom block"}}}, 200, "CUSTOM BLOCK", nil, models.StatusBlocked, 0},
		{"rate-limit", models.SiteConfig{}, 429, "", nil, models.StatusBlocked, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/alice" {
					t.Errorf("bad URL: %s", r.URL.Path)
				}
				for k, vs := range tt.header {
					w.Header()[k] = vs
				}
				w.WriteHeader(tt.code)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()
			tt.site.Name = "Example"
			tt.site.URL = server.URL + "/{username}"
			s := newTestSource(t, []models.SiteConfig{tt.site}, server.Client())
			var results []models.Result
			err := s.SearchUsername(context.Background(), "alice", func(r models.Result) error { results = append(results, r); return nil })
			if err != nil || len(results) != 1 {
				t.Fatal(err, len(results))
			}
			r := results[0]
			meaning := models.MeaningObservation
			if tt.status == models.StatusBlocked {
				meaning = models.MeaningUnknown
			}
			if tt.status == models.StatusError {
				meaning = models.MeaningError
			}
			if r.EvidenceSemantics() != (models.EvidenceSemantics{Kind: models.ObservationWebsite, Meaning: meaning}) {
				t.Fatal("website inference became verified evidence")
			}
			if r.Status != tt.status || r.Confidence != tt.confidence || r.Source != "Example" || r.SourceType != models.SourceWebsite || r.TargetType != models.TargetUsername || r.Duration <= 0 {
				t.Fatalf("result: %+v", r)
			}
			if sources.Supports(s, models.TargetPassword) || sources.Supports(s, models.TargetPasswordHash) {
				t.Fatal("website supports secrets")
			}
		})
	}
}
func TestRequestTemplates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/probe/alice@example.test" || r.Method != "POST" || string(body) != "alice@example.test:alice@example.test" || r.Header.Get("X-Target") != "alice@example.test" || r.Header.Get("User-Agent") == "" {
			t.Errorf("bad request: %s %s %s", r.Method, r.URL, body)
		}
		_, _ = io.WriteString(w, "member")
	}))
	defer server.Close()
	site := models.SiteConfig{Name: "Probe", URL: server.URL + "/public/{username}", URLProbe: server.URL + "/probe/{target}", RequestMethod: "POST", RequestPayload: "{username}:{target}", Headers: map[string]string{"X-Target": "{username}"}, CheckType: "message", PresenceStrs: []string{"member"}}
	s := newTestSource(t, []models.SiteConfig{site}, server.Client())
	if err := s.SearchEmail(context.Background(), "alice@example.test", func(r models.Result) error {
		if r.TargetType != models.TargetEmail || !r.Found {
			t.Errorf("result: %+v", r)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func TestRedirectAndHead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect/alice" {
			http.Redirect(w, r, "/missing", http.StatusFound)
			return
		}
		if r.URL.Path == "/head/alice" && r.Method != "HEAD" {
			t.Error("HEAD not preserved")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	for _, follow := range []bool{false, true} {
		site := models.SiteConfig{Name: "Redirect", URL: server.URL + "/redirect/{username}", FollowRedirects: follow, CheckType: "response_url", ErrorURL: "/missing"}
		s := newTestSource(t, []models.SiteConfig{site}, server.Client())
		if err := s.SearchUsername(context.Background(), "alice", func(r models.Result) error {
			// Followed or not, a redirect to the configured error URL is a
			// negative: an unfollowed redirect classifies its destination.
			if r.Status != models.StatusNotFound || !strings.HasSuffix(r.FinalURL, "/missing") {
				t.Errorf("redirect result (follow=%v): %+v", follow, r)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	s := newTestSource(t, []models.SiteConfig{{Name: "Head", URL: server.URL + "/head/{username}", RequestHeadOnly: true}}, server.Client())
	if err := s.SearchUsername(context.Background(), "alice", func(models.Result) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
func TestCancellationAndConsumerFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	sites := make([]models.SiteConfig, 1000)
	for i := range sites {
		sites[i] = models.SiteConfig{Name: "Slow", URL: server.URL + "/{username}"}
	}
	s := newTestSource(t, sites, server.Client())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.SearchUsername(ctx, "alice", func(models.Result) error { return nil }) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("search deadlocked")
	}
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer fast.Close()
	for i := range sites {
		sites[i].URL = fast.URL + "/{username}"
	}
	s = newTestSource(t, sites, fast.Client())
	stop := errors.New("consumer stopped")
	n := 0
	if err := s.SearchUsername(context.Background(), "alice", func(models.Result) error { n++; return stop }); !errors.Is(err, stop) || n != 1 {
		t.Fatal("consumer failure ignored", err, n)
	}
}
func TestSkippedAndRequestError(t *testing.T) {
	s := newTestSource(t, []models.SiteConfig{{Name: "empty"}, {Name: "disabled", URL: "http://unused", Disabled: true}, {Name: "invalid", URL: "://{username}"}}, &http.Client{})
	n := 0
	if err := s.SearchUsername(context.Background(), "alice", func(r models.Result) error {
		n++
		if r.Status != models.StatusError || r.Error == "" || r.Duration <= 0 {
			t.Errorf("error result: %+v", r)
		}
		return nil
	}); err != nil || n != 1 {
		t.Fatal(err, n)
	}
}
