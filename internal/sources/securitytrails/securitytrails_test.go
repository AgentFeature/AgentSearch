package securitytrails

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/network"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

func fixtureKey() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:]) + ".example"
}
func testClient(t *testing.T, handler http.HandlerFunc, interval time.Duration) (*Client, string) {
	t.Helper()
	key := fixtureKey()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, e := NewClient(server.URL+"/v1", security.NewSecret(key), network.NewServiceClient(time.Second), interval)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	return client, key
}
func TestSuccessfulDomainObservation(t *testing.T) {
	var expectedKey string
	client, key := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/domain/example.com" || r.URL.RawQuery != "" || r.Header.Get("APIKEY") != expectedKey || r.Header.Get("Authorization") != "" {
			t.Error("request boundary/authentication incorrect")
		}
		fmt.Fprintf(w, `{"hostname":"EXAMPLE.COM.","current_dns":{"a":{"values":[{"ip":"192.0.2.2","ip_count":5},{"ip":"192.0.2.1"}]},"aaaa":{"values":[{"ip":"2001:db8::1"}]},"mx":{"values":[{"priority":10,"host":"%s"}]},"ns":{"values":[{"nameserver":"ns.example.com"}]},"txt":{"values":[{"value":"discard-me"}]}},"future_field":true}`, expectedKey)
	}, time.Millisecond)
	expectedKey = key
	source, _ := NewSource(client)
	registry := sources.NewRegistry()
	if e := registry.Register(source); e != nil {
		t.Fatal(e)
	}
	target, _ := models.NewDomainTarget(" EXAMPLE.COM. ")
	var rows []models.Result
	err := sources.NewManager(registry).Search(context.Background(), target, func(r models.Result) error { rows = append(rows, r); return nil })
	if err != nil || len(rows) != 1 {
		t.Fatal("dispatch failed")
	}
	r := rows[0]
	if r.EvidenceSemantics() != (models.EvidenceSemantics{Kind: models.ObservationDomain, Meaning: models.MeaningObservation}) {
		t.Fatal("domain profile provenance lost")
	}
	if r.Source != "securitytrails" || r.TargetType != models.TargetDomain || r.Status != models.StatusFound || r.Confidence != 100 || r.Metadata["dns_record_count"] != "5" || r.Evidence[1].Value != "192.0.2.1" {
		t.Fatal("normalization mismatch")
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), key) || strings.Contains(string(raw), "discard-me") {
		t.Fatal("credential/unselected remote field leaked")
	}
	consumer := errors.New("consumer stopped")
	if e := source.SearchDomain(context.Background(), "example.com", func(models.Result) error { return consumer }); !errors.Is(e, consumer) {
		t.Fatal("consumer failure lost")
	}
}
func TestEmptyProfileIsNotVerifiedAbsence(t *testing.T) {
	client, _ := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"hostname":"example.com","current_dns":{"a":null,"ns":{"values":[]}}}`)
	}, time.Millisecond)
	source, _ := NewSource(client)
	err := source.SearchDomain(context.Background(), "example.com", func(r models.Result) error {
		if r.Status != models.StatusFound || r.Metadata["dns_record_count"] != "0" || r.EvidenceSemantics().Meaning != models.MeaningObservation {
			t.Fatal("empty DNS profile misrepresented as absence")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestHTTPFailuresRemainErrors(t *testing.T) {
	cases := []struct {
		status int
		kind   string
	}{{400, "bad_request"}, {401, "unauthorized"}, {403, "forbidden"}, {404, "unexpected_status"}, {429, "rate_limited"}, {500, "service_unavailable"}, {503, "service_unavailable"}, {302, "unexpected_status"}}
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			client, key := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "3")
				w.Header().Set("Location", destination.URL)
				w.WriteHeader(tc.status)
				fmt.Fprint(w, `{"message":"private upstream diagnostics"}`)
			}, time.Millisecond)
			source, _ := NewSource(client)
			var rows []models.Result
			err := source.SearchDomain(context.Background(), "example.com", func(r models.Result) error { rows = append(rows, r); return nil })
			if len(rows) != 1 || rows[0].EvidenceSemantics() != (models.EvidenceSemantics{Kind: models.ObservationDomain, Meaning: models.MeaningError}) {
				t.Fatal("provider failure became negative evidence")
			}
			var classified *Error
			if !errors.As(err, &classified) || classified.Kind != tc.kind || len(rows) != 1 || rows[0].Status != models.StatusError || rows[0].Metadata["error_kind"] != tc.kind {
				t.Fatal("provider status became a non-error")
			}
			if tc.status == 429 || tc.status == 503 {
				if rows[0].Metadata["retry_after_seconds"] != "3" {
					t.Fatal("Retry-After lost")
				}
			}
			raw, _ := json.Marshal(rows)
			for _, secret := range []string{key, "private upstream diagnostics", client.baseURL} {
				if strings.Contains(string(raw)+err.Error(), secret) {
					t.Fatal("unsafe error output")
				}
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("credential-bearing redirect followed")
	}
}
func TestMalformedAndMissingFields(t *testing.T) {
	for _, body := range []string{``, `null`, `{}`, `{"hostname":"example.com"}`, `{"hostname":"example.com","current_dns":null}`, `{"hostname":"other.example","current_dns":{}}`, `{"hostname":"example.com","current_dns":{"a":{}}}`, `{"hostname":"example.com","current_dns":{"a":{"values":[null]}}}`, `{"hostname":"example.com","current_dns":{"a":{"values":[{"ip":"not-an-ip"}]}}}`, `{"hostname":"example.com","current_dns":{"mx":{"values":[{"host":"mx.example.com"}]}}}`, `{"hostname":7,"current_dns":{}}`} {
		client, _ := testClient(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }, time.Millisecond)
		_, err := client.lookup(context.Background(), "example.com")
		var e *Error
		if !errors.As(err, &e) || e.Kind != "invalid_response" {
			t.Fatal("malformed response accepted")
		}
	}
}
func TestContextCancellationAndTimeout(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		entered := make(chan struct{})
		client, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }, time.Millisecond)
		var ctx context.Context
		var cancel context.CancelFunc
		if deadline {
			ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
		} else {
			ctx, cancel = context.WithCancel(context.Background())
		}
		done := make(chan error, 1)
		go func() { _, e := client.lookup(ctx, "example.com"); done <- e }()
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatal("request not started")
		}
		expected := context.Canceled
		if deadline {
			expected = context.DeadlineExceeded
		} else {
			cancel()
		}
		select {
		case err := <-done:
			if !errors.Is(err, expected) {
				t.Fatal("context error lost")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cancellation not honored")
		}
		cancel()
	}
}
func TestBoundedResponse(t *testing.T) {
	client, _ := testClient(t, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, strings.Repeat(" ", MaxResponseBytes+1)) }, time.Millisecond)
	_, err := client.lookup(context.Background(), "example.com")
	var e *Error
	if !errors.As(err, &e) || e.Kind != "invalid_response" {
		t.Fatal("oversized response accepted")
	}
}
func TestPacingAndRateLimitCooldown(t *testing.T) {
	var calls atomic.Int32
	client, _ := testClient(t, func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(429) }, time.Millisecond)
	_, err := client.lookup(context.Background(), "example.com")
	var e *Error
	if !errors.As(err, &e) || e.RetryAfter < time.Second {
		t.Fatal("minimum 429 cooldown missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err = client.lookup(ctx, "example.com"); !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatal("cooldown retried or failed to cancel")
	}
	client.mu.Lock()
	next := client.next
	client.mu.Unlock()
	if time.Until(next) <= 0 {
		t.Fatal("cancelled wait consumed cooldown")
	}
	paced, _ := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"hostname":"example.com","current_dns":{}}`)
	}, time.Second)
	if _, err = paced.lookup(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	if _, err = paced.lookup(ctx2, "example.com"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("configured pacing bypassed")
	}
}
func TestClientConfigurationAndCredentialOwnership(t *testing.T) {
	for _, endpoint := range []string{"http://example.com/v1", "https://example.com/v1?apikey=bad", "https://user@example.com/v1", "https://example.com/other"} {
		key := security.NewSecret(fixtureKey())
		if _, e := NewClient(endpoint, key, network.NewServiceClient(time.Second), time.Second); e == nil || !key.Empty() {
			t.Fatal("invalid endpoint accepted or owned key retained")
		}
	}
	key := security.NewSecret(fixtureKey())
	c, e := NewClient("", key, network.NewServiceClient(time.Second), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if !key.Empty() {
		t.Fatal("key retained after close")
	}
	if _, e = NewClient("", security.Secret{}, network.NewServiceClient(time.Second), time.Second); e == nil {
		t.Fatal("missing key accepted")
	}
}
