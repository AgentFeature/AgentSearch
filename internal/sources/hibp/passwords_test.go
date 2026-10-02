package hibp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

// These are public SHA-1 vectors, not dynamically computed test expectations.
func TestPasswordSHA1KnownVectors(t *testing.T) {
	for _, tc := range []struct{ name, input, prefix, suffix string }{
		{"common", "password", "5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"},
		{"spaces", " password ", "E6EE5", "DBAB4167ECE69097D192D7EE8B3B5AA5292"},
		{"unicode", "p\u00e4ssw\u00f6rd", "F517D", "DF1D32A112FF1AD55C66D1B12CB38E7E8F7"},
		{"case", "Password", "8BE3C", "943B1609FFFBFC51AAD666D0A04ADF83C9D"},
		{"abc", "abc", "A9993", "E364706816ABA3E25717850C26C9CD0D89D"},
		{"empty", "", "DA39A", "3EE5E6B4B0D3255BFEF95601890AFD80709"},
		{"sentence", "The quick brown fox jumps over the lazy dog", "2FD4E", "1C67A2D28FCED849EE1BB76E7391B93EB12"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, s := passwordSHA1([]byte(tc.input))
			if p != tc.prefix || s != tc.suffix {
				t.Fatal("SHA-1 prefix/suffix vector mismatch")
			}
		})
	}
	p, s := passwordSHA1([]byte(" password "))
	p2, s2 := passwordSHA1([]byte("password"))
	if p == p2 && s == s2 {
		t.Fatal("password whitespace was normalized")
	}
	p3, s3 := passwordSHA1([]byte("Password"))
	if p3 == p2 && s3 == s2 {
		t.Fatal("password case was normalized")
	}
}

const publicSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
const otherSuffix = "00000000000000000000000000000000000"

func TestRangeParsing(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		count      uint64
		bad        bool
	}{
		{"match", otherSuffix + ":1\r\n" + publicSuffix + ":42\r\n", 42, false},
		{"lowercase", strings.ToLower(publicSuffix) + ":9", 9, false},
		{"no-match", otherSuffix + ":3", 0, false},
		{"padding", publicSuffix + ":0", 0, false},
		{"blank-lines", "\r\n" + publicSuffix + ":2\n\n", 2, false},
		{"empty", "", 0, true}, {"only-blanks", "\r\n\n", 0, true},
		{"whitespace-line", otherSuffix + ":1\n \n", 0, true},
		{"missing-colon", publicSuffix, 0, true}, {"short", publicSuffix[:34] + ":1", 0, true},
		{"long", publicSuffix + "A:1", 0, true}, {"nonhex", "Z" + publicSuffix[1:] + ":1", 0, true},
		{"negative", publicSuffix + ":-1", 0, true}, {"signed", publicSuffix + ":+1", 0, true},
		{"count-space", publicSuffix + ": 1", 0, true}, {"count-empty", publicSuffix + ":", 0, true},
		{"count-float", publicSuffix + ":1.2", 0, true}, {"extra-colon", publicSuffix + ":1:2", 0, true},
		{"overflow", publicSuffix + ":18446744073709551616", 0, true},
		{"max-count", publicSuffix + ":18446744073709551615", ^uint64(0), false},
		{"malformed-tail", publicSuffix + ":3\ninvalid", 0, true},
		{"duplicate", publicSuffix + ":1\n" + strings.ToLower(publicSuffix) + ":1", 0, true},
		{"long-line", strings.Repeat("A", 200), 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count, err := matchRange([]byte(tc.body), strings.ToLower(publicSuffix))
			if (err != nil) != tc.bad || count != tc.count {
				t.Fatal("unexpected range parsing outcome")
			}
		})
	}
}
func passwordSourceForTest(t *testing.T, url string, client *http.Client) *PasswordSource {
	t.Helper()
	c, err := NewPasswordClient(url, client)
	if err != nil {
		t.Fatal("client initialization failed")
	}
	s, err := NewPasswordSource(c)
	if err != nil {
		t.Fatal("source initialization failed")
	}
	return s
}
func TestPasswordRequestBoundaryAndSafeResult(t *testing.T) {
	t.Setenv("HIBP_API_KEY", "")
	secret := security.NewSecret("password")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !secret.Empty() {
			t.Error("plaintext retained at network boundary")
		}
		if r.Method != http.MethodGet || r.URL.Path != "/range/5BAA6" || r.RequestURI != "/range/5BAA6" || r.URL.RawQuery != "" || r.URL.User != nil {
			t.Error("incorrect range request")
		}
		if r.Header.Get("Hibp-Api-Key") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("credentials crossed password boundary")
		}
		if r.Header.Get("Add-Padding") != "true" || r.UserAgent() != userAgent || r.Header.Get("Accept") != "text/plain" {
			t.Error("missing privacy or identification headers")
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Error("range request has a body")
		}
		boundary := r.RequestURI + fmt.Sprint(r.Header) + string(body)
		for _, forbidden := range []string{"password", "5BAA6" + publicSuffix, publicSuffix} {
			if strings.Contains(boundary, forbidden) {
				t.Error("sensitive request leakage")
			}
		}
		fmt.Fprint(w, otherSuffix+":0\n"+strings.ToLower(publicSuffix)+":42\n")
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = time.Second
	client.Jar, _ = cookiejar.New(nil) // Constructor must discard any injected jar.
	cookieURL, _ := url.Parse(server.URL)
	client.Jar.SetCookies(cookieURL, []*http.Cookie{{Name: "fixture", Value: "must-not-be-sent"}})
	source := passwordSourceForTest(t, server.URL+"/range", client)
	if len(sources.Capabilities(source)) != 1 || !sources.Supports(source, models.TargetPassword) || sources.Supports(source, models.TargetEmail) {
		t.Fatal("password capability not isolated")
	}
	var got models.Result
	if err := source.SearchPassword(context.Background(), secret, func(r models.Result) error { got = r; return nil }); err != nil {
		t.Fatal("lookup failed")
	}
	if calls.Load() != 1 || got.Status != models.StatusFound || got.Metadata["pwned"] != "true" || got.Metadata["occurrences"] != "42" || got.Confidence != 100 {
		t.Fatal("incorrect exact match result")
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal("serialization failed")
	}
	var logs bytes.Buffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("fixture", "result", got, "secret", secret)
	for _, forbidden := range []string{"password", publicSuffix, "5BAA6"} {
		// The source ID legitimately contains the word passwords; compare plaintext
		// only in case-sensitive diagnostic fields, not that static source label.
		if forbidden == "password" {
			if got.Target != security.Redacted || got.Error != "" {
				t.Fatal("unsafe diagnostic fields")
			}
			continue
		}
		if strings.Contains(string(encoded)+logs.String()+fmt.Sprintf("%#v", got), forbidden) {
			t.Fatal("lookup material reached normalized output")
		}
	}
}
func TestPasswordStatuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   int
		body   string
		status models.ResultStatus
		kind   ErrorKind
		count  string
	}{
		{"found", 200, publicSuffix + ":2", models.StatusFound, "", "2"},
		{"no-match", 200, otherSuffix + ":1", models.StatusNotFound, "", "0"},
		{"padding", 200, publicSuffix + ":0", models.StatusNotFound, "", "0"},
		{"empty", 200, "", models.StatusError, InvalidResponse, ""},
		{"malformed", 200, "invalid", models.StatusError, InvalidResponse, ""},
		{"bad-request", 400, "remote private body", models.StatusError, BadRequest, ""},
		{"unauthorized", 401, "remote private body", models.StatusError, Unauthorized, ""},
		{"forbidden", 403, "remote private body", models.StatusError, Forbidden, ""},
		{"not-found-is-error", 404, "remote private body", models.StatusError, UnexpectedStatus, ""},
		{"throttled", 429, "remote private body", models.StatusError, RateLimited, ""},
		{"server-error", 500, "remote private body", models.StatusError, Unavailable, ""},
		{"unavailable", 503, "remote private body", models.StatusError, Unavailable, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Retry-After", "4")
				w.Header().Set("Set-Cookie", "private=remote")
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			client := server.Client()
			client.Timeout = time.Second
			source := passwordSourceForTest(t, server.URL+"/range", client)
			var result models.Result
			err := source.SearchPassword(context.Background(), security.NewSecret("password"), func(r models.Result) error { result = r; return nil })
			meaning := models.MeaningObservation
			if result.Status == models.StatusNotFound {
				meaning = models.MeaningAbsence
			}
			if result.Status == models.StatusError {
				meaning = models.MeaningError
			}
			if result.EvidenceSemantics() != (models.EvidenceSemantics{Kind: models.ObservationPassword, Meaning: meaning}) {
				t.Fatal("password corpus semantics changed")
			}
			if calls.Load() != 1 || result.Status != tc.status || result.Metadata["occurrences"] != tc.count || result.Metadata["error_kind"] != string(tc.kind) || (err != nil) != (tc.kind != "") {
				t.Fatal("unexpected response outcome")
			}
			if tc.code == 429 || tc.code == 503 {
				if result.Metadata["retry_after_seconds"] != "4" {
					t.Error("missing Retry-After")
				}
			} else if result.Metadata["retry_after_seconds"] != "" {
				t.Error("unexpected retry metadata")
			}
			if tc.kind != "" && result.Metadata["pwned"] != "" {
				t.Error("error misrepresented as clean password")
			}
			b, _ := json.Marshal(result)
			if strings.Contains(string(b), "remote") {
				t.Fatal("remote payload reached results")
			}
		})
	}
}
func TestPasswordCancellationTimeoutAndRedirect(t *testing.T) {
	t.Run("cancelled", func(t *testing.T) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
		defer srv.Close()
		client := srv.Client()
		client.Timeout = time.Second
		s := passwordSourceForTest(t, srv.URL+"/range", client)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		secret := security.NewSecret("password")
		err := s.SearchPassword(ctx, secret, func(r models.Result) error {
			if r.Metadata["error_kind"] != string(Cancelled) {
				t.Error("wrong cancellation")
			}
			return nil
		})
		if !errors.Is(err, context.Canceled) || calls.Load() != 0 || !secret.Empty() {
			t.Fatal("cancellation not honored")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer srv.Close()
		client := srv.Client()
		client.Timeout = 20 * time.Millisecond
		s := passwordSourceForTest(t, srv.URL+"/range", client)
		err := s.SearchPassword(context.Background(), security.NewSecret("password"), func(r models.Result) error {
			if r.Metadata["error_kind"] != string(Timeout) {
				t.Error("wrong timeout")
			}
			return nil
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("timeout not honored")
		}
	})
	t.Run("redirect", func(t *testing.T) {
		var redirected atomic.Int32
		dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
		defer dest.Close()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, dest.URL+"/private", http.StatusFound)
		}))
		defer srv.Close()
		client := srv.Client()
		client.Timeout = time.Second
		s := passwordSourceForTest(t, srv.URL+"/range", client)
		if s.SearchPassword(context.Background(), security.NewSecret("password"), func(models.Result) error { return nil }) == nil || redirected.Load() != 0 {
			t.Fatal("redirect was followed or accepted")
		}
	})
	t.Run("network", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close()
		s := passwordSourceForTest(t, url+"/range", &http.Client{Timeout: time.Second})
		if s.SearchPassword(context.Background(), security.NewSecret("password"), func(r models.Result) error {
			if r.Metadata["error_kind"] != string(NetworkFailure) {
				t.Error("wrong network error")
			}
			return nil
		}) == nil {
			t.Fatal("network error ignored")
		}
	})
}
func TestPasswordClientValidation(t *testing.T) {
	client := &http.Client{Timeout: time.Second}
	for _, url := range []string{"http://example.com/range", "https://user:pass@example.com/range", "https://example.com/range?q=x", "https://example.com/range#fragment", "https://example.com/not-range", "https://example.com/%72ange"} {
		if _, err := NewPasswordClient(url, client); err == nil {
			t.Error("unsafe endpoint accepted")
		}
	}
	c, err := NewPasswordClient("", client)
	if err != nil || c.baseURL != DefaultPasswordsURL {
		t.Fatal("default password endpoint invalid")
	}
	// Even a broken validation regression must only reach a local fixture,
	// never the official endpoint configured above.
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	c, err = NewPasswordClient(server.URL+"/range", client)
	if err != nil {
		t.Fatal("local client initialization failed")
	}
	if _, err = c.getRange(context.Background(), "5BAA6"+publicSuffix); err == nil || calls.Load() != 0 {
		t.Fatal("full hash accepted by request boundary")
	}
	if _, err = c.lookup(context.Background(), "5BAA6", "invalid"); err == nil || calls.Load() != 0 {
		t.Fatal("invalid local suffix made a request")
	}
	if _, err = NewPasswordClient("", &http.Client{}); err == nil {
		t.Fatal("missing timeout accepted")
	}
}

func TestPasswordBodyBoundsAndCancellation(t *testing.T) {
	for _, name := range []string{"oversized", "truncated", "body-timeout", "mid-request-cancel"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch name {
				case "oversized":
					fmt.Fprint(w, strings.Repeat("0", 2*1024*1024+1))
				case "truncated":
					w.Header().Set("Content-Length", "100")
					fmt.Fprint(w, publicSuffix+":1")
				case "body-timeout":
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				case "mid-request-cancel":
					cancel()
					<-r.Context().Done()
				}
			}))
			defer server.Close()
			client := server.Client()
			client.Timeout = time.Second
			if name == "body-timeout" {
				client.Timeout = 20 * time.Millisecond
			}
			source := passwordSourceForTest(t, server.URL+"/range", client)
			want := InvalidResponse
			if name == "truncated" {
				want = NetworkFailure
			}
			if name == "body-timeout" {
				want = Timeout
			}
			if name == "mid-request-cancel" {
				want = Cancelled
			}
			if source.SearchPassword(ctx, security.NewSecret("password"), func(r models.Result) error {
				if r.Status != models.StatusError || r.Metadata["error_kind"] != string(want) {
					t.Error("wrong bounded/cancelled response")
				}
				return nil
			}) == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
}
func TestPasswordConsumerAndEmptyInput(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, publicSuffix+":1") }))
	defer server.Close()
	client := server.Client()
	client.Timeout = time.Second
	source := passwordSourceForTest(t, server.URL+"/range", client)
	secret := security.NewSecret("password")
	if source.SearchPassword(context.Background(), secret, nil) == nil || !secret.Empty() || calls.Load() != 0 {
		t.Fatal("nil consumer leaked input or made a request")
	}
	if source.SearchPassword(context.Background(), security.Secret{}, func(r models.Result) error {
		if r.Status != models.StatusError {
			t.Error("empty input accepted")
		}
		return nil
	}) == nil || calls.Load() != 0 {
		t.Fatal("empty input made a request")
	}
	consumerErr := errors.New("fixture consumer failure")
	emitted := 0
	if source.SearchPassword(context.Background(), security.NewSecret("password"), func(models.Result) error { emitted++; return consumerErr }) != consumerErr || emitted != 1 || calls.Load() != 1 {
		t.Fatal("consumer backpressure lost")
	}
}
