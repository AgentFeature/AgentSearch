package websites

import (
	"compress/gzip"
	"context"
	"github.com/AgentFeature/agentsearch/internal/network"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
)

func TestRegressionWebsiteBodyAndFailureSemantics(t *testing.T) {
	for _, tc := range []struct {
		name           string
		status         int
		encoding, body string
		want           models.ResultStatus
	}{
		{"gzip-absence", 200, "gzip", "missing", models.StatusNotFound},
		{"oversized-body", 200, "", strings.Repeat("x", 128*1024+1) + "missing", models.StatusError},
		{"upstream-failure", 503, "", "maintenance", models.StatusError},
		{"unsupported-encoding", 200, "br", "compressed bytes", models.StatusError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Only compress when requested, as a normal origin would.
				if tc.encoding == "gzip" && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
					w.Header().Set("Content-Encoding", "gzip")
					z := gzip.NewWriter(w)
					io.WriteString(z, tc.body)
					z.Close()
					return
				}
				if tc.encoding != "gzip" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			source := newTestSource(t, []models.SiteConfig{{Name: "Local", URL: server.URL + "/{username}", CheckType: "message", AbsenceStrs: []string{"missing"}}}, server.Client())
			var result models.Result
			err := source.SearchUsername(context.Background(), "audit", func(r models.Result) error { result = r; return nil })
			if err != nil || result.Status != tc.want {
				t.Fatalf("status=%s want=%s err=%v", result.Status, tc.want, err)
			}
			if tc.want == models.StatusError && (result.Found || result.Error == "") {
				t.Fatal("incomplete response became a conclusive observation")
			}
		})
	}
}

func TestRegressionCrossOriginSensitiveHeaderNamesAreRemoved(t *testing.T) {
	for _, follow := range []bool{false, true} {
		var reached atomic.Int32
		destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached.Add(1)
			// Empty values test header forwarding without constructing credentials.
			for _, key := range []string{"X-API-Key", "Authorization", "Cookie"} {
				if _, ok := r.Header[http.CanonicalHeaderKey(key)]; ok {
					t.Errorf("sensitive header %s forwarded across origins", key)
				}
			}
		}))
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
		base := origin.Client()
		base.Timeout = time.Second
		source := newTestSource(t, []models.SiteConfig{{Name: "Local", URL: origin.URL, FollowRedirects: follow, Headers: map[string]string{"X-API-Key": "", "Authorization": "", "Cookie": ""}}}, network.NewRetryableClient(base, 0))
		err := source.SearchUsername(context.Background(), "audit", func(models.Result) error { return nil })
		origin.Close()
		destination.Close()
		want := int32(0)
		if follow {
			want = 1
		}
		if err != nil || reached.Load() != want {
			t.Fatalf("follow=%v reached=%d err=%v", follow, reached.Load(), err)
		}
	}
}

// An absent profile that redirects to an error page must never be reported
// as found when follow_redirects is false. The retry-wrapper hardening
// stopped silently following redirects; redirect-based absence rules must
// classify the redirect destination, and a redirect no rule classifies is
// unusable evidence, not a detection.
func TestRegressionUnfollowedRedirectIsNotFoundEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/u/"):
			http.Redirect(w, r, "/error/notfound", http.StatusFound)
		case r.URL.Path == "/error/notfound":
			io.WriteString(w, "<html><body>User not found</body></html>")
		default:
			io.WriteString(w, "<html><body>generic page</body></html>")
		}
	}))
	defer server.Close()
	for _, tc := range []struct {
		name      string
		site      models.SiteConfig
		want      models.ResultStatus
		wantFinal string
	}{
		// Explicit redirect rules classify the redirect destination.
		{"redirect-failure-pattern", models.SiteConfig{Name: "P", URL: server.URL + "/u/{username}", CheckType: "message", AbsenceStrs: []string{"User not found"}, RedirectFailurePatterns: []string{"/error/"}}, models.StatusNotFound, "/error/notfound"},
		{"response-url-error-url", models.SiteConfig{Name: "R", URL: server.URL + "/u/{username}", CheckType: "response_url", ErrorURL: "/error/notfound"}, models.StatusNotFound, "/error/notfound"},
		{"status-error-code-redirect", models.SiteConfig{Name: "C", URL: server.URL + "/u/{username}", CheckType: "status_code", ErrorCode: http.StatusFound}, models.StatusNotFound, "/error/notfound"},
		// Without a matching rule the unfetched destination is not evidence.
		{"message-without-rule", models.SiteConfig{Name: "M", URL: server.URL + "/u/{username}", CheckType: "message", AbsenceStrs: []string{"User not found"}}, models.StatusError, "/error/notfound"},
		{"status-without-rule", models.SiteConfig{Name: "S", URL: server.URL + "/u/{username}", CheckType: "status_code", ErrorCode: 404}, models.StatusError, "/error/notfound"},
		{"default-check-without-rule", models.SiteConfig{Name: "D", URL: server.URL + "/u/{username}"}, models.StatusError, "/error/notfound"},
		// Followed redirects keep their existing body-based classification.
		{"followed-absence-page", models.SiteConfig{Name: "F", URL: server.URL + "/u/{username}", CheckType: "message", AbsenceStrs: []string{"User not found"}, FollowRedirects: true}, models.StatusNotFound, "/error/notfound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := newTestSource(t, []models.SiteConfig{tc.site}, network.NewRetryableClient(server.Client(), 0))
			var result models.Result
			if err := source.SearchUsername(context.Background(), "ghost_user_404", func(r models.Result) error { result = r; return nil }); err != nil {
				t.Fatal(err)
			}
			if result.Status != tc.want || result.Found {
				t.Fatalf("status=%s found=%v want=%s", result.Status, result.Found, tc.want)
			}
			if !strings.HasSuffix(result.FinalURL, tc.wantFinal) {
				t.Fatalf("final URL %q does not expose the redirect destination", result.FinalURL)
			}
			if tc.want == models.StatusError && result.Error == "" {
				t.Fatal("unclassified redirect lacks an error explanation")
			}
		})
	}
}

// WAF/blocked classification takes precedence over other handling when
// genuine blocking evidence exists, a CDN header on a normal response is
// NOT blocking evidence, and repeated runs stay deterministic.
func TestRegressionRedirectBlockedPrecedenceAndDeterminism(t *testing.T) {
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-RAY", "fixture")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, "<html>blocked</html>")
	}))
	defer blocked.Close()
	source := newTestSource(t, []models.SiteConfig{{Name: "B", URL: blocked.URL + "/u/{username}", CheckType: "message", AbsenceStrs: []string{"User not found"}}}, network.NewRetryableClient(blocked.Client(), 0))
	var result models.Result
	if err := source.SearchUsername(context.Background(), "ghost_user_404", func(r models.Result) error { result = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if result.Status != models.StatusBlocked || result.Found {
		t.Fatalf("blocked response misclassified: %+v", result)
	}

	// A Cloudflare-fronted ordinary 404 carrying the configured absence
	// marker is a real negative, not a block (live-validated behavior).
	fronted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("CF-RAY", "fixture")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "<html>User not found</html>")
	}))
	defer fronted.Close()
	frontedSource := newTestSource(t, []models.SiteConfig{{Name: "F", URL: fronted.URL + "/u/{username}", CheckType: "message", AbsenceStrs: []string{"User not found"}}}, network.NewRetryableClient(fronted.Client(), 0))
	if err := frontedSource.SearchUsername(context.Background(), "ghost_user_404", func(r models.Result) error { result = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if result.Status != models.StatusNotFound || result.Found {
		t.Fatalf("CDN header on ordinary 404 misclassified: %+v", result)
	}

	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/error/notfound", http.StatusFound)
	}))
	defer redirecting.Close()
	site := models.SiteConfig{Name: "P", URL: redirecting.URL + "/u/{username}", CheckType: "message", AbsenceStrs: []string{"User not found"}, RedirectFailurePatterns: []string{"/error/"}}
	deterministic := newTestSource(t, []models.SiteConfig{site}, network.NewRetryableClient(redirecting.Client(), 0))
	for i := 0; i < 20; i++ {
		var repeat models.Result
		if err := deterministic.SearchUsername(context.Background(), "ghost_user_404", func(r models.Result) error { repeat = r; return nil }); err != nil {
			t.Fatal(err)
		}
		if repeat.Status != models.StatusNotFound || repeat.Found || !strings.HasSuffix(repeat.FinalURL, "/error/notfound") {
			t.Fatalf("run %d diverged: %+v", i, repeat)
		}
	}
}

// A message site that configures explicit presence indicators must not
// report found when neither an absence nor a presence rule matches: the
// generic-200/login/challenge/error-page fallthrough was a false-positive
// factory for every configured message site. Absence-only sites keep the
// documented low-confidence fallback on 2xx, and no message or
// response_url check may turn an unmatched HTTP error status into found.
func TestRegressionAmbiguousResponsesAreNotProfiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generic":
			io.WriteString(w, "<html><h1>Welcome to ExampleSite</h1><p>ordinary homepage</p></html>")
		case "/login":
			io.WriteString(w, "<html>Log in to continue</html>")
		case "/absent404":
			w.WriteHeader(404)
			io.WriteString(w, "<html>The specified profile could not be found</html>")
		case "/plain404":
			w.WriteHeader(404)
			io.WriteString(w, "gone")
		default:
			io.WriteString(w, "<html><h1 class=\"user-title\">Real User</h1></html>")
		}
	}))
	defer server.Close()
	presence := []string{"user-title"}
	absence := []string{"The specified profile could not be found"}
	for _, tc := range []struct {
		name string
		site models.SiteConfig
		want models.ResultStatus
	}{
		{"presence-match-profile", models.SiteConfig{Name: "s", URL: server.URL + "/profile", CheckType: "message", AbsenceStrs: absence, PresenceStrs: presence}, models.StatusFound},
		{"presence-rules-generic-200", models.SiteConfig{Name: "s", URL: server.URL + "/generic", CheckType: "message", AbsenceStrs: absence, PresenceStrs: presence}, models.StatusError},
		{"presence-rules-login-200", models.SiteConfig{Name: "s", URL: server.URL + "/login", CheckType: "message", AbsenceStrs: absence, PresenceStrs: presence}, models.StatusError},
		{"presence-rules-plain-404", models.SiteConfig{Name: "s", URL: server.URL + "/plain404", CheckType: "message", AbsenceStrs: absence, PresenceStrs: presence}, models.StatusError},
		{"absence-string-on-404-page", models.SiteConfig{Name: "s", URL: server.URL + "/absent404", CheckType: "message", AbsenceStrs: absence, PresenceStrs: presence}, models.StatusNotFound},
		{"absence-only-generic-200-fallback", models.SiteConfig{Name: "s", URL: server.URL + "/generic", CheckType: "message", AbsenceStrs: absence}, models.StatusFound},
		{"absence-only-plain-404", models.SiteConfig{Name: "s", URL: server.URL + "/plain404", CheckType: "message", AbsenceStrs: absence}, models.StatusError},
		{"response-url-plain-404", models.SiteConfig{Name: "s", URL: server.URL + "/plain404", CheckType: "response_url", ErrorURL: "/blank.php"}, models.StatusError},
		{"response-url-200", models.SiteConfig{Name: "s", URL: server.URL + "/profile", CheckType: "response_url", ErrorURL: "/blank.php"}, models.StatusFound},
		{"status-code-contract-unchanged", models.SiteConfig{Name: "s", URL: server.URL + "/generic", CheckType: "status_code", ErrorCode: 404}, models.StatusFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := newTestSource(t, []models.SiteConfig{tc.site}, network.NewRetryableClient(server.Client(), 0))
			var result models.Result
			if err := source.SearchUsername(context.Background(), "realuser", func(r models.Result) error { result = r; return nil }); err != nil {
				t.Fatal(err)
			}
			if result.Status != tc.want {
				t.Fatalf("status=%s found=%v conf=%d want=%s", result.Status, result.Found, result.Confidence, tc.want)
			}
			if tc.want == models.StatusError && (result.Found || result.Error == "") {
				t.Fatalf("ambiguous response became a conclusive observation: %+v", result)
			}
		})
	}
}

// Detection rule strings substitute {username}/{target} per request, so a
// configured positive marker matches the requested profile and never a
// page describing a different user. Regex rules receive a quoted target.
func TestRegressionRuleStringsSubstituteTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/u/realuser":
			io.WriteString(w, `<html>"screen_name":"realuser" profile</html>`)
		case "/u/ghost":
			io.WriteString(w, `<html>"screen_name":"someoneelse" suggestion page</html>`)
		case "/re/real.user":
			io.WriteString(w, `<html>profile-realXuser</html>`)
		default:
			w.WriteHeader(404)
			io.WriteString(w, "gone")
		}
	}))
	defer server.Close()
	site := models.SiteConfig{Name: "s", URL: server.URL + "/u/{username}", CheckType: "message", AbsenceStrs: []string{"account doesn't exist"}, PresenceStrs: []string{`"screen_name":"{username}"`}, Weight: 25}
	for _, tc := range []struct {
		target string
		want   models.ResultStatus
	}{
		{"realuser", models.StatusFound}, // substituted marker matches the requested profile
		{"ghost", models.StatusError},    // a different user's page is not this profile
	} {
		source := newTestSource(t, []models.SiteConfig{site}, network.NewRetryableClient(server.Client(), 0))
		var result models.Result
		if err := source.SearchUsername(context.Background(), tc.target, func(r models.Result) error { result = r; return nil }); err != nil {
			t.Fatal(err)
		}
		if result.Status != tc.want || (tc.want == models.StatusFound && !result.Found) {
			t.Fatalf("target=%s status=%s found=%v want=%s", tc.target, result.Status, result.Found, tc.want)
		}
	}
	// Regex substitution quotes the target: "." must not act as a wildcard.
	regexSite := models.SiteConfig{Name: "s", URL: server.URL + "/re/{username}", CheckType: "message", PresenceRegexes: []string{"profile-{username}"}}
	source := newTestSource(t, []models.SiteConfig{regexSite}, network.NewRetryableClient(server.Client(), 0))
	var result models.Result
	if err := source.SearchUsername(context.Background(), "real.user", func(r models.Result) error { result = r; return nil }); err != nil {
		t.Fatal(err)
	}
	if result.Status == models.StatusFound {
		t.Fatalf("unquoted regex substitution matched a different page: %+v", result)
	}
	// The shared site configuration must not be mutated by substitution.
	if site.PresenceStrs[0] != `"screen_name":"{username}"` || regexSite.PresenceRegexes[0] != "profile-{username}" {
		t.Fatal("substitution mutated shared site configuration")
	}
}
