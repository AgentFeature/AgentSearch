package hibp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/network"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

// Runtime-generated test-only values never authenticate to a real service.
func testSecret(t *testing.T) security.Secret {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal("generate test value")
	}
	return security.NewSecret(hex.EncodeToString(b[:]))
}
func testClient(t *testing.T, base string, key security.Secret) *Client {
	t.Helper()
	client, err := NewClient(base, key, network.NewServiceClient(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.http.CloseIdleConnections)
	return client
}

const breachFixture = `[
 {"Name":"ExampleBreach","Title":"Example Service","Domain":"example.test","BreachDate":"2020-01-02","AddedDate":"2020-02-01T00:00:00Z","ModifiedDate":"2020-03-01T00:00:00Z","IsVerified":true,"IsFabricated":false,"DataClasses":["Email addresses","Passwords"],"Description":"UNRETAINED_REMOTE_HTML","LogoPath":"UNRETAINED_LOGO"},
 {"Name":"OtherBreach","Title":"Other Service","Domain":"other.test","IsVerified":false,"IsFabricated":true,"DataClasses":["Usernames"]}
]`

func TestBreachLookupAndDispatch(t *testing.T) {
	key := testSecret(t)
	var calls atomic.Int32
	email := "Alice+tag/?#%@example.test"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/api/v3/breachedaccount/"+email || r.URL.Query().Get("truncateResponse") != "false" || len(r.URL.Query()) != 1 {
			t.Error("wrong endpoint or email encoding")
		}
		if r.Header.Get("hibp-api-key") != key.Reveal() {
			t.Error("API key header missing")
		}
		if !strings.HasPrefix(r.UserAgent(), "AgentSearch") || r.Header.Get("Accept") != "application/json" {
			t.Error("required headers missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, breachFixture)
	}))
	defer server.Close()
	client := testClient(t, server.URL+"/api/v3/", key)
	source, err := NewSource(client)
	if err != nil {
		t.Fatal(err)
	}
	registry := sources.NewRegistry()
	if err := registry.Register(source); err != nil {
		t.Fatal(err)
	}
	if sources.Supports(source, models.TargetUsername) || sources.Supports(source, models.TargetPassword) || sources.Supports(source, models.TargetPasswordHash) {
		t.Fatal("unexpected capability")
	}
	target, err := models.NewEmailTarget("  " + email + "  ")
	if err != nil {
		t.Fatal(err)
	}
	var results []models.Result
	err = sources.NewManager(registry).Search(context.Background(), target, func(r models.Result) error { results = append(results, r); return nil })
	if err != nil || calls.Load() != 1 || len(results) != 2 {
		t.Fatal("lookup failed", err, len(results))
	}
	for _, row := range results {
		if row.EvidenceSemantics() != (models.EvidenceSemantics{Kind: models.ObservationBreach, Meaning: models.MeaningObservation}) {
			t.Fatal("breach provenance lost")
		}
	}
	first := results[0]
	if first.Source != "hibp" || first.SourceType != models.SourceAPI || first.TargetType != models.TargetEmail || first.Target != email || first.Status != models.StatusFound || !first.Found || first.Confidence != 100 || first.Duration <= 0 {
		t.Fatal("incorrect normalized fields")
	}
	for k, v := range map[string]string{"breach_name": "ExampleBreach", "breach_title": "Example Service", "domain": "example.test", "breach_date": "2020-01-02", "added_date": "2020-02-01T00:00:00Z", "modified_date": "2020-03-01T00:00:00Z", "verified": "true", "fabricated": "false", "breach_count": "2"} {
		if first.Metadata[k] != v {
			t.Errorf("missing mapped field %s", k)
		}
	}
	if len(first.Evidence) != 2 || first.Evidence[1].Kind != "compromised_data_class" || first.Evidence[1].Value != "Passwords" || results[1].Metadata["fabricated"] != "true" {
		t.Fatal("incorrect evidence")
	}
	data, _ := json.Marshal(results)
	if bytes.Contains(data, []byte("UNRETAINED")) || bytes.Contains(data, []byte(key.Reveal())) {
		t.Fatal("unexpected remote data or key retained")
	}
}
func TestResponseSemantics(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		kind   ErrorKind
		count  int
	}{
		{"not-found", 404, "ignored", "", 1}, {"empty-array", 200, "[]", "", 1},
		{"unauthorized", 401, "do not retain", Unauthorized, 1}, {"forbidden", 403, "do not retain", Forbidden, 1},
		{"rate-limited", 429, "do not retain", RateLimited, 1}, {"bad-request", 400, "do not retain", BadRequest, 1},
		{"unavailable", 503, "do not retain", Unavailable, 1}, {"server-error", 500, "do not retain", Unavailable, 1},
		{"unexpected", 418, "do not retain", UnexpectedStatus, 1}, {"redirect", 302, "do not retain", UnexpectedStatus, 1},
		{"malformed", 200, "{", InvalidResponse, 1}, {"null", 200, "null", InvalidResponse, 1},
		{"missing-name", 200, "[{}]", InvalidResponse, 1}, {"trailing-json", 200, "[] []", InvalidResponse, 1},
		{"oversized", 200, strings.Repeat(" ", maxBreachResponse) + "[]", InvalidResponse, 1},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Retry-After", "12")
				w.Header().Set("Authorization", "ignored")
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer server.Close()
			source, _ := NewSource(testClient(t, server.URL, testSecret(t)))
			var results []models.Result
			err := source.SearchEmail(context.Background(), "alice@example.test", func(r models.Result) error { results = append(results, r); return nil })
			if len(results) != tt.count || calls.Load() != 1 {
				t.Fatal("unexpected request/result count")
			}
			r := results[0]
			meaning := models.MeaningError
			if tt.kind == "" {
				meaning = models.MeaningAbsence
			}
			if r.EvidenceSemantics() != (models.EvidenceSemantics{Kind: models.ObservationBreach, Meaning: meaning}) {
				t.Fatal("breach absence/error semantics lost")
			}
			if tt.kind == "" {
				if err != nil || r.Status != models.StatusNotFound || r.Found || r.Metadata["breach_count"] != "0" {
					t.Fatal("no breach became an error")
				}
				return
			}
			var apiErr *Error
			if !errors.As(err, &apiErr) || apiErr.Kind != tt.kind || apiErr.StatusCode != tt.status || r.Status != models.StatusError || r.Metadata["error_kind"] != string(tt.kind) || r.Found {
				t.Fatal("failure misclassified", err)
			}
			if tt.status == 429 && r.Metadata["retry_after_seconds"] != "12" {
				t.Fatal("retry timing lost")
			}
			if strings.Contains(r.Error, "do not retain") {
				t.Fatal("remote error body exposed")
			}
		})
	}
}
func TestClientValidation(t *testing.T) {
	if _, err := NewClient("", security.NewSecret(""), network.NewServiceClient(time.Second)); err == nil {
		t.Fatal("missing key accepted")
	} else {
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Kind != MissingKey {
			t.Fatal(err)
		}
	}
	for _, base := range []string{"http://example.test/api/v3", "https://user:password@example.test/api", "https://example.test/api?token=value", "https://example.test/api#fragment", "not a URL"} {
		if _, err := NewClient(base, testSecret(t), network.NewServiceClient(time.Second)); err == nil {
			t.Error("unsafe base URL accepted")
		}
	}
	if _, err := NewClient("", testSecret(t), &http.Client{}); err == nil {
		t.Fatal("unbounded client accepted")
	}
}
func TestInvalidEmailDoesNotMakeRequest(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	source, _ := NewSource(testClient(t, server.URL, testSecret(t)))
	for _, input := range []string{"", " ", "alice", "@example.test", "alice@", "Alice <alice@example.test>", "alice@example.test\r\nHeader:value"} {
		err := source.SearchEmail(context.Background(), input, func(r models.Result) error {
			if r.Status != models.StatusError || r.Metadata["error_kind"] != string(BadRequest) {
				t.Error("invalid input misclassified")
			}
			return nil
		})
		if err == nil {
			t.Error("invalid email accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input sent to network")
	}
}
func TestCancellationAndTimeout(t *testing.T) {
	for _, mode := range []string{"cancel-before", "cancel-in-flight", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
			defer server.Close()
			httpClient := network.NewServiceClient(time.Second)
			if mode == "timeout" {
				httpClient.Timeout = 25 * time.Millisecond
			}
			client, err := NewClient(server.URL, testSecret(t), httpClient)
			if err != nil {
				t.Fatal(err)
			}
			defer client.http.CloseIdleConnections()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancel-before" {
				cancel()
			}
			done := make(chan error, 1)
			go func() { _, err := client.Breaches(ctx, "alice@example.test"); done <- err }()
			if mode == "cancel-in-flight" {
				select {
				case <-entered:
					cancel()
				case <-time.After(2 * time.Second):
					t.Fatal("request never started")
				}
			}
			select {
			case err := <-done:
				want := context.Canceled
				if mode == "timeout" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) {
					t.Fatal("wrong context classification", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("request did not stop")
			}
		})
	}
}

type failingTransport struct{ message string }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New(f.message)
}
func TestNetworkFailureRedaction(t *testing.T) {
	key := testSecret(t)
	client, err := NewClient("", key, &http.Client{Timeout: time.Second, Transport: failingTransport{message: "transport echoed " + key.Reveal()}})
	if err != nil {
		t.Fatal(err)
	}
	source, _ := NewSource(client)
	var result models.Result
	err = source.SearchEmail(context.Background(), "alice@example.test", func(r models.Result) error { result = r; return nil })
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Kind != NetworkFailure {
		t.Fatal("network error lost")
	}
	for _, text := range []string{err.Error(), fmt.Sprintf("%+v %#v", err, err), result.Error, fmt.Sprintf("%+v %#v", client, client)} {
		if strings.Contains(text, key.Reveal()) {
			t.Fatal("key leaked through diagnostics")
		}
	}
}
func TestRedirectCannotForwardKey(t *testing.T) {
	var forwarded atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1) }))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer origin.Close()
	_, err := testClient(t, origin.URL, testSecret(t)).Breaches(context.Background(), "alice@example.test")
	if err == nil || forwarded.Load() != 0 {
		t.Fatal("redirect followed with credential-bearing request")
	}
}
func TestEchoedKeyIsRedacted(t *testing.T) {
	key := testSecret(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]Breach{{Name: key.Reveal(), Title: key.Reveal(), Domain: key.Reveal(), DataClasses: []string{key.Reveal()}}})
	}))
	defer server.Close()
	source, _ := NewSource(testClient(t, server.URL, key))
	var result models.Result
	var log bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := source.SearchEmail(context.Background(), "alice@example.test", func(r models.Result) error { result = r; logger.Debug("result", "result", r); return nil }); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(result)
	if bytes.Contains(data, []byte(key.Reveal())) || strings.Contains(log.String(), key.Reveal()) {
		t.Fatal("API key leaked through results or logs")
	}
}
func TestConsumerFailureAndConcurrency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, breachFixture) }))
	defer server.Close()
	source, _ := NewSource(testClient(t, server.URL, testSecret(t)))
	stop := errors.New("stop")
	count := 0
	err := source.SearchEmail(context.Background(), "alice@example.test", func(models.Result) error { count++; return stop })
	if !errors.Is(err, stop) || count != 1 {
		t.Fatal("consumer failure ignored")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := source.SearchEmail(context.Background(), "alice@example.test", func(models.Result) error { return nil }); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		value string
		want  time.Duration
	}{{"20", 20 * time.Second}, {now.Add(time.Minute).Format(http.TimeFormat), time.Minute}, {"-1", 0}, {"invalid", 0}, {"9223372036854775807", 0}, {now.Add(-time.Hour).Format(http.TimeFormat), 0}} {
		if got := parseRetryAfter(tt.value, now); got != tt.want {
			t.Errorf("Retry-After %q: %s", tt.value, got)
		}
	}
}
