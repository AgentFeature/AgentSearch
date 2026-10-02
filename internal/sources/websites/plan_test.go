package websites

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/network"
)

func TestPlannerValidatesAndDeduplicates(t *testing.T) {
	sites := []models.SiteConfig{
		{Name: "Zeta", URL: "https://zeta.test/{username}", CheckType: "status_code", ErrorCode: 404},
		{Name: "Alpha", URL: "https://alpha.test/{username}", CheckType: "message", AbsenceStrs: []string{"gone"}},
		{Name: "Alpha", URL: "https://duplicate.test/{username}"}, // duplicate ID: first wins
		{Name: "Disabled", URL: "https://off.test/{username}", Disabled: true},
		{Name: "NoURL"},
		{Name: "BadRegex", URL: "https://bad.test/{username}", CheckType: "message", PresenceRegexes: []string{"profile-{username}(["}},
		{Name: "BadURL", URL: "://not-a-url/{username}"},
	}
	plans, index := buildPlans(sites)
	if len(plans) != 4 {
		t.Fatalf("expected 4 plans, got %d", len(plans))
	}
	// Deterministic name order.
	names := make([]string, 0, len(plans))
	for _, p := range plans {
		names = append(names, p.site.Name)
	}
	if strings.Join(names, ",") != "Alpha,BadRegex,BadURL,Zeta" {
		t.Fatalf("plan order not deterministic: %v", names)
	}
	if plans[index["Alpha"]].site.URL != "https://alpha.test/{username}" {
		t.Fatal("duplicate provider ID did not keep the first definition")
	}
	if !plans[index["Alpha"]].needsBody || plans[index["Zeta"]].needsBody {
		t.Fatal("body requirements not derived from check types")
	}
	if plans[index["BadRegex"]].invalid == "" || plans[index["BadURL"]].invalid == "" {
		t.Fatal("invalid configuration not rejected at plan time")
	}
}

func TestInvalidPlanYieldsDeterministicErrorWithoutRequests(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer server.Close()
	site := models.SiteConfig{Name: "Bad", URL: server.URL + "/{username}", CheckType: "message", PresenceRegexes: []string{"(["}}
	source := newTestSource(t, []models.SiteConfig{site}, network.NewRetryableClient(server.Client(), 0))
	var result models.Result
	if err := source.SearchUsername(context.Background(), "alice", func(r models.Result) error { result = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if result.Status != models.StatusError || !strings.Contains(result.Error, "invalid site configuration") {
		t.Fatalf("invalid plan misclassified: %+v", result)
	}
	if requests.Load() != 0 {
		t.Fatal("invalid plan still produced a network request")
	}
}

func TestIdenticalRequestsAreDeduplicatedPerSearch(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.WriteString(w, "shared page")
	}))
	defer server.Close()
	sites := []models.SiteConfig{
		{Name: "A", URL: server.URL + "/shared/{username}", CheckType: "status_code", ErrorCode: 404, Weight: 20},
		{Name: "B", URL: server.URL + "/shared/{username}", CheckType: "status_code", ErrorCode: 404, Weight: 5},
		{Name: "C", URL: server.URL + "/other/{username}", CheckType: "status_code", ErrorCode: 404},
	}
	source := newTestSource(t, sites, network.NewRetryableClient(server.Client(), 0))
	var results []models.Result
	if err := source.SearchUsername(context.Background(), "alice", func(r models.Result) error { results = append(results, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("each provider must keep its own result: %d", len(results))
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("expected 2 network requests after deduplication, got %d", got)
	}
	// Shared responses still classify per provider (different weights).
	if results[0].Confidence == results[1].Confidence {
		t.Fatalf("shared fetch must not share provider classification: %+v %+v", results[0], results[1])
	}
	// A fresh search must not reuse the previous run's responses.
	if err := source.SearchUsername(context.Background(), "alice", func(models.Result) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 4 {
		t.Fatalf("fetch cache leaked across searches: %d", got)
	}
}

func TestStatusContractTreatsUnlisted4xxAsError(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		want models.ResultStatus
	}{
		{"401-error", 401, models.StatusError},
		{"403-blocked-or-error", 403, models.StatusError},
		{"404-not-found", 404, models.StatusNotFound},
		{"410-error", 410, models.StatusError},
		{"429-blocked", 429, models.StatusBlocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
			}))
			defer server.Close()
			site := models.SiteConfig{Name: "S", URL: server.URL + "/{username}", CheckType: "status_code", ErrorCode: 404}
			// 429 is retried by the transport policy; classify it through a
			// plain client, exactly like the existing adapter tests.
			client := network.NewRetryableClient(server.Client(), 0)
			if tc.code == 429 {
				client = server.Client()
			}
			source := newTestSource(t, []models.SiteConfig{site}, client)
			var result models.Result
			if err := source.SearchUsername(context.Background(), "alice", func(r models.Result) error { result = r; return nil }); err != nil {
				t.Fatal(err)
			}
			if result.Status != tc.want || result.Found {
				t.Fatalf("status %d => %s found=%v, want %s", tc.code, result.Status, result.Found, tc.want)
			}
		})
	}
}

func TestStatusSitesClassifyDespiteOversizedBodies(t *testing.T) {
	big := strings.Repeat("y", 200*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "absent") {
			w.WriteHeader(404)
		}
		io.WriteString(w, big)
	}))
	defer server.Close()
	for _, tc := range []struct {
		name string
		site models.SiteConfig
		want models.ResultStatus
	}{
		// The status contract does not require body content: an oversized
		// body must not turn a definitive status into an error.
		{"status-found-huge-body", models.SiteConfig{Name: "S", URL: server.URL + "/found/{username}", CheckType: "status_code", ErrorCode: 404}, models.StatusFound},
		{"status-absent-huge-body", models.SiteConfig{Name: "S", URL: server.URL + "/absent/{username}", CheckType: "status_code", ErrorCode: 404}, models.StatusNotFound},
		// Message contracts still refuse truncated evidence.
		{"message-huge-body", models.SiteConfig{Name: "S", URL: server.URL + "/found/{username}", CheckType: "message", AbsenceStrs: []string{"gone"}}, models.StatusError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := newTestSource(t, []models.SiteConfig{tc.site}, network.NewRetryableClient(server.Client(), 0))
			var result models.Result
			if err := source.SearchUsername(context.Background(), "alice", func(r models.Result) error { result = r; return nil }); err != nil {
				t.Fatal(err)
			}
			if result.Status != tc.want {
				t.Fatalf("status=%s want=%s (%+v)", result.Status, tc.want, result)
			}
		})
	}
}

func TestDeterministicResultOrderAcrossRepeatedRuns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "profile-marker")
	}))
	defer server.Close()
	var sites []models.SiteConfig
	for i := 0; i < 12; i++ {
		sites = append(sites, models.SiteConfig{
			Name: fmt.Sprintf("Site%02d", i), URL: server.URL + fmt.Sprintf("/%02d/{username}", i),
			CheckType: "message", AbsenceStrs: []string{"gone"}, PresenceStrs: []string{"profile-marker"},
		})
	}
	source := newTestSource(t, sites, network.NewRetryableClient(server.Client(), 0))
	var baseline []string
	for run := 0; run < 100; run++ {
		var order []string
		var statuses []models.ResultStatus
		if err := source.SearchUsername(context.Background(), "alice", func(r models.Result) error {
			order = append(order, r.SiteName)
			statuses = append(statuses, r.Status)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for _, s := range statuses {
			if s != models.StatusFound {
				t.Fatalf("run %d produced unexpected status %s", run, s)
			}
		}
		if baseline == nil {
			baseline = order
			continue
		}
		if strings.Join(order, ",") != strings.Join(baseline, ",") {
			t.Fatalf("run %d emission order diverged:\n%v\n%v", run, order, baseline)
		}
	}
	if !strings.HasPrefix(strings.Join(baseline, ","), "Site00,Site01,Site02") {
		t.Fatalf("emission order is not the deterministic plan order: %v", baseline)
	}
}

// Deduplication may share a fetch only between genuinely equivalent
// requests: differing redirect policies or provider-configured request
// headers must produce separate fetches, while purely response-side
// differences (required response headers) still share one fetch.
func TestFetchCacheSeparatesNonEquivalentRequests(t *testing.T) {
	var shared atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/redir/"):
			shared.Add(1)
			http.Redirect(w, r, "/dest", http.StatusFound)
		case r.URL.Path == "/dest":
			io.WriteString(w, "<html>destination page</html>")
		case strings.HasPrefix(r.URL.Path, "/hdr/"):
			shared.Add(1)
			io.WriteString(w, "<html>variant "+r.Header.Get("X-Variant")+"</html>")
		default:
			w.Header().Set("X-Found", "yes")
			shared.Add(1)
			io.WriteString(w, "<html>plain page</html>")
		}
	}))
	defer server.Close()

	// Same URL, different redirect policy: two fetches, two behaviors.
	shared.Store(0)
	redirSites := []models.SiteConfig{
		{Name: "NoFollow", URL: server.URL + "/redir/{username}", CheckType: "message", AbsenceStrs: []string{"absent"}},
		{Name: "Follow", URL: server.URL + "/redir/{username}", CheckType: "message", AbsenceStrs: []string{"absent"}, PresenceStrs: []string{"destination page"}, FollowRedirects: true},
	}
	source := newTestSource(t, redirSites, network.NewRetryableClient(server.Client(), 0))
	got := map[string]models.ResultStatus{}
	if err := source.SearchUsername(context.Background(), "alice", func(r models.Result) error { got[r.SiteName] = r.Status; return nil }); err != nil {
		t.Fatal(err)
	}
	if got["Follow"] != models.StatusFound || got["NoFollow"] != models.StatusError {
		t.Fatalf("redirect policies shared one fetch: %v", got)
	}
	if shared.Load() != 2 {
		t.Fatalf("expected 2 origin fetches for differing redirect policies, got %d", shared.Load())
	}

	// Same URL, different provider request headers: two fetches.
	shared.Store(0)
	hdrSites := []models.SiteConfig{
		{Name: "VarA", URL: server.URL + "/hdr/{username}", CheckType: "message", AbsenceStrs: []string{"absent"}, PresenceStrs: []string{"variant A"}, Headers: map[string]string{"X-Variant": "A"}},
		{Name: "VarB", URL: server.URL + "/hdr/{username}", CheckType: "message", AbsenceStrs: []string{"absent"}, PresenceStrs: []string{"variant B"}, Headers: map[string]string{"X-Variant": "B"}},
	}
	source = newTestSource(t, hdrSites, network.NewRetryableClient(server.Client(), 0))
	got = map[string]models.ResultStatus{}
	if err := source.SearchUsername(context.Background(), "alice", func(r models.Result) error { got[r.SiteName] = r.Status; return nil }); err != nil {
		t.Fatal(err)
	}
	if got["VarA"] != models.StatusFound || got["VarB"] != models.StatusFound {
		t.Fatalf("header variants shared one fetch: %v", got)
	}
	if shared.Load() != 2 {
		t.Fatalf("expected 2 fetches for differing request headers, got %d", shared.Load())
	}

	// Same request, different RESPONSE needs: one fetch serves both, and
	// the header-check provider still sees its required response header.
	shared.Store(0)
	respSites := []models.SiteConfig{
		{Name: "Status", URL: server.URL + "/plain/{username}", CheckType: "status_code", ErrorCode: 404},
		{Name: "Header", URL: server.URL + "/plain/{username}", CheckType: "header", RequiredHeaders: map[string]string{"X-Found": "yes"}},
	}
	source = newTestSource(t, respSites, network.NewRetryableClient(server.Client(), 0))
	got = map[string]models.ResultStatus{}
	if err := source.SearchUsername(context.Background(), "alice", func(r models.Result) error { got[r.SiteName] = r.Status; return nil }); err != nil {
		t.Fatal(err)
	}
	if got["Status"] != models.StatusFound || got["Header"] != models.StatusFound {
		t.Fatalf("shared fetch lost response evidence for a group member: %v", got)
	}
	if shared.Load() != 1 {
		t.Fatalf("expected a single deduplicated fetch, got %d", shared.Load())
	}
}

// A challenge page whose marker sits beyond the old 4 KiB window must not
// become FOUND for a status-classified provider, and an ordinary large
// page must not become blocked.
func TestChallengeMarkerBeyondFourKiBBlocksStatusProvider(t *testing.T) {
	padding := strings.Repeat("<!-- filler -->", 400) // ~6 KiB before the marker
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/challenge/") {
			io.WriteString(w, "<html><head>"+padding+"<title>Just a moment...</title></head><body>cf-chl</body></html>")
			return
		}
		io.WriteString(w, "<html><body>"+strings.Repeat("plain content ", 2000)+"</body></html>")
	}))
	defer server.Close()
	for _, tc := range []struct {
		name string
		path string
		want models.ResultStatus
	}{
		{"late-challenge-marker-blocks", "/challenge/{username}", models.StatusBlocked},
		{"large-plain-page-found", "/plain/{username}", models.StatusFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := models.SiteConfig{Name: "S", URL: server.URL + tc.path, CheckType: "status_code", ErrorCode: 404}
			source := newTestSource(t, []models.SiteConfig{site}, network.NewRetryableClient(server.Client(), 0))
			var result models.Result
			if err := source.SearchUsername(context.Background(), "alice", func(r models.Result) error { result = r; return nil }); err != nil {
				t.Fatal(err)
			}
			if result.Status != tc.want {
				t.Fatalf("status=%s want=%s (%+v)", result.Status, tc.want, result)
			}
		})
	}
}
