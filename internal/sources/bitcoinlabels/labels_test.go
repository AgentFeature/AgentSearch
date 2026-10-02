package bitcoinlabels

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/network"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

const address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
const labeled = `{"found":true,"label":"Example Exchange","wallet_id":"000003a2f31608c0","updated_to_block":967461}`

func TestParser(t *testing.T) {
	for _, tc := range []struct{ name, raw, label, id, category, kind string }{
		{"label", labeled, "Example Exchange", "000003a2f31608c0", "", ""},
		{"category", `{"found":true,"label":"John's Wallet","wallet_id":"ABCD","category":"undocumented-provider-category"}`, "John's Wallet", "abcd", "undocumented-provider-category", ""},
		{"no label", `{"found":false,"updated_to_block":967461}`, "", "", "", ""},
		{"unnamed wallet", `{"found":true,"wallet_id":"9155adea5d855091","updated_to_block":967461}`, "", "9155adea5d855091", "", ""},
		{"empty label", `{"found":true,"wallet_id":"abcd","label":""}`, "", "abcd", "", ""},
		{"missing found", `{}`, "", "", "", "invalid_response"},
		{"missing id", `{"found":true,"label":"Name"}`, "", "", "", "invalid_response"},
		{"error", `{"error":"upstream-sensitive-marker"}`, "", "", "", "provider_error"},
		{"error with false", `{"found":false,"error":"not supported"}`, "", "", "", "provider_error"},
		{"contradiction", `{"found":false,"label":"Name","wallet_id":"abcd"}`, "", "", "", "invalid_response"},
		{"error with true", `{"found":true,"error":"oops"}`, "", "", "", "invalid_response"},
		{"malformed", `{"found":`, "", "", "", "invalid_response"},
		{"trailing", `{"found":false} {}`, "", "", "", "invalid_response"},
		{"duplicate", `{"found":false,"found":true}`, "", "", "", "invalid_response"},
		{"null", `{"found":null}`, "", "", "", "invalid_response"},
		{"null label", `{"found":true,"wallet_id":"abcd","label":null}`, "", "", "", "invalid_response"},
		{"nested", `{"found":false,"unexpected":{"label":"Name"}}`, "", "", "", "unsupported_response"},
		{"labels array", `{"found":true,"wallet_id":"abcd","label":["one","two"]}`, "", "", "", "unsupported_response"},
		{"many labels", `{"found":false,"labels":[` + strings.Repeat(`"Name",`, 16) + `"Name"]}`, "", "", "", "unsupported_response"},
		{"id array", `{"found":true,"wallet_id":["abcd","def0"]}`, "", "", "", "unsupported_response"},
		{"long label", `{"found":true,"wallet_id":"abcd","label":"` + strings.Repeat("a", MaxLabelBytes+1) + `"}`, "", "", "", "invalid_response"},
		{"long UTF8", `{"found":true,"wallet_id":"abcd","label":"` + strings.Repeat("é", 129) + `"}`, "", "", "", "invalid_response"},
		{"long id", `{"found":true,"wallet_id":"` + strings.Repeat("a", MaxIdentifierBytes+1) + `"}`, "", "", "", "invalid_response"},
		{"unsafe id", `{"found":true,"wallet_id":"https://example.test/"}`, "", "", "", "invalid_response"},
		{"credential-shaped", `{"found":true,"wallet_id":"abcd","label":"Authorization: sensitive-marker"}`, "", "", "", "invalid_response"},
		{"control", `{"found":true,"wallet_id":"abcd","label":"Name\nOwner: X"}`, "", "", "", "invalid_response"},
		{"bidi", `{"found":true,"wallet_id":"abcd","label":"Name\u202e"}`, "", "", "", "invalid_response"},
		{"bad surrogate", `{"found":true,"wallet_id":"abcd","label":"\ud800"}`, "", "", "", "invalid_response"},
		{"negative height", `{"found":false,"updated_to_block":-1}`, "", "", "", "invalid_response"},
		{"overflow height", `{"found":false,"updated_to_block":9223372036854775808}`, "", "", "", "invalid_response"},
		{"fraction height", `{"found":false,"updated_to_block":1.5}`, "", "", "", "invalid_response"},
		{"unsupported category", `{"found":true,"wallet_id":"abcd","category":{"value":"exchange"}}`, "", "", "", "unsupported_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := parse([]byte(tc.raw))
			if tc.kind != "" {
				var e *failure
				if !errors.As(err, &e) || e.kind != tc.kind {
					t.Fatalf("error: %v", err)
				}
				return
			}
			if err != nil || a.Label != tc.label || a.WalletID != tc.id || a.Category != tc.category {
				t.Fatalf("%+v %v", a, err)
			}
		})
	}
}

func fixture(t *testing.T, handler http.HandlerFunc) (*Source, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.URL.Path != "/api/1/address-lookup" || len(r.URL.Query()) != 1 || r.URL.Query().Get("address") != address {
			t.Errorf("unexpected request")
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("APIKEY") != "" || r.Header.Get("Cookie") != "" {
			t.Error("credentials/cookies sent")
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	client := network.NewServiceClient(time.Second)
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(server.URL)
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "sensitive-marker"}})
	client.Jar = jar
	s, err := New(server.URL+"/api/1/address-lookup", client, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, calls
}
func run(t *testing.T, s *Source) (models.Result, error) {
	t.Helper()
	reg := sources.NewRegistry()
	if err := reg.Register(s); err != nil {
		t.Fatal(err)
	}
	target, _ := models.NewBitcoinTarget(address)
	var rows []models.Result
	err := sources.NewManager(reg).Search(context.Background(), target, func(r models.Result) error { rows = append(rows, r); return nil })
	if len(rows) != 1 {
		t.Fatalf("expected one result, got %d", len(rows))
	}
	return rows[0], err
}
func TestProvenanceAndDeterminism(t *testing.T) {
	s, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, labeled) })
	var previous []byte
	for i := 0; i < 4; i++ {
		row, err := run(t, s)
		if err != nil {
			t.Fatal(err)
		}
		if row.Source != "bitcoin-labels" || row.SourceType != models.SourceAPI || row.TargetType != models.TargetBitcoin || row.Target != address || row.Metadata["provider"] != "WalletExplorer" || row.Metadata["label_age"] != "unknown" || row.Metadata["ownership"] != "not independently verified" {
			t.Fatal("provenance missing")
		}
		if row.Status != models.StatusFound || row.Metadata["label_status"] != "provider_label" || row.Confidence != 0 || len(row.Evidence) != 1 {
			t.Fatal("incorrect association")
		}
		raw, e := json.Marshal(row)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(raw), `"confidence":`) || strings.Contains(string(raw), "updated_to_block") {
			t.Fatal("invented confidence/freshness")
		}
		if i > 0 && !reflect.DeepEqual(previous, raw) {
			t.Fatal("unstable output")
		}
		previous = raw
		if row.EvidenceSemantics().Kind != models.ObservationBitcoinLabels {
			t.Fatal("label conflated with blockchain")
		}
	}
	if calls.Load() != 4 {
		t.Fatal("more than one request/lookup")
	}
}
func TestNoLabel(t *testing.T) {
	for _, raw := range []string{`{"found":false}`, `{"found":true,"wallet_id":"abcd"}`} {
		s, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, raw) })
		row, err := run(t, s)
		if err != nil || row.Status != models.StatusNotFound || row.Metadata["label_status"] != "no_label" || calls.Load() != 1 {
			t.Fatal("provider absence mishandled")
		}
		if strings.Contains(raw, "wallet_id") && len(row.Evidence) != 1 {
			t.Fatal("lost unnamed wallet identifier")
		}
	}
}
func TestProviderFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		raw, kind string
	}{
		{"404", 404, "sensitive-marker", "http_error"}, {"429", 429, "sensitive-marker", "rate_limited"}, {"500", 500, "sensitive-marker", "http_error"},
		{"malformed", 200, "not-json-sensitive-marker", "invalid_response"},
		{"huge", 200, strings.Repeat("x", MaxResponseBytes+1), "response_too_large"},
		{"unsupported", 200, `{"found":false,"nested":{}}`, "unsupported_response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "2")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.raw)
			})
			row, err := run(t, s)
			if err == nil || row.Status != models.StatusError || row.Metadata["error_kind"] != tc.kind || row.Metadata["label_status"] != "unavailable" || len(row.Evidence) != 0 || calls.Load() != 1 {
				t.Fatalf("%+v %v", row, err)
			}
			raw, _ := json.Marshal(row)
			if strings.Contains(string(raw)+err.Error(), "sensitive-marker") {
				t.Fatal("error body leaked")
			}
		})
	}
}
func TestTimeoutAndCancellation(t *testing.T) {
	s, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	s.http.Timeout = 20 * time.Millisecond
	row, err := run(t, s)
	if !errors.Is(err, context.DeadlineExceeded) || row.Metadata["error_kind"] != "timeout" || calls.Load() != 1 {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = s.SearchBitcoin(ctx, address, func(r models.Result) error {
		if r.Metadata["error_kind"] != "cancelled" {
			t.Error("lost cancellation")
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatal("cancelled request sent")
	}
}
func TestSafeTransportAndFields(t *testing.T) {
	raw := strings.TrimSuffix(labeled, "}") + `,"api_key":"sensitive-marker","cookie":"sensitive-marker","url":"https://evil.test","confidence":97,"updated_at":"2020-01-01"}`
	s, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "secret=sensitive-marker")
		w.Header().Set("Authorization", "sensitive-marker")
		fmt.Fprint(w, raw)
	})
	for i := 0; i < 2; i++ {
		row, err := run(t, s)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(row)
		for _, bad := range []string{"sensitive-marker", "evil.test", "updated_at", `"confidence":97`} {
			if strings.Contains(string(body), bad) {
				t.Fatal("untrusted extra persisted")
			}
		}
	}
	if calls.Load() != 2 || s.http.Jar != nil {
		t.Fatal("transport contract")
	}
	before := calls.Load()
	if err := s.SearchBitcoin(context.Background(), "invalid address", func(models.Result) error { return nil }); err == nil || calls.Load() != before {
		t.Fatal("invalid target queried")
	}
	sentinel := errors.New("consumer stopped")
	if err := s.SearchBitcoin(context.Background(), address, func(models.Result) error { return sentinel }); err != sentinel {
		t.Fatal("consumer error swallowed")
	}
	redirect, n := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://evil.test")
		w.WriteHeader(302)
	})
	if _, err := run(t, redirect); err == nil || n.Load() != 1 {
		t.Fatal("followed redirect")
	}
	for _, endpoint := range []string{"http://example.com/api/1/address-lookup", "https://user:sensitive-marker@example.com/api/1/address-lookup", DefaultURL + "?key=sensitive-marker", DefaultURL + "#sensitive-marker", "https://example.com/api/1/wallet-addresses"} {
		if _, err := New(endpoint, network.NewServiceClient(time.Second), time.Second); err == nil || strings.Contains(err.Error(), "sensitive-marker") {
			t.Fatal("unsafe endpoint accepted/leaked")
		}
	}
	s2, err := New("", network.NewServiceClient(time.Hour), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.http.Timeout != RequestTimeout {
		t.Fatal("timeout unbounded")
	}
}
func TestRetryAfter(t *testing.T) {
	s, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Retry-After", "60"); w.WriteHeader(429) })
	row, err := run(t, s)
	if err == nil || row.Metadata["retry_after_seconds"] != "60" {
		t.Fatal("rate-limit classification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = s.SearchBitcoin(ctx, address, func(models.Result) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatal("Retry-After ignored")
	}
	if MaxRequests != 1 || MaxRetries != 0 || MaxLabels != 1 || MaxIdentifiers != 1 {
		t.Fatal("bounds changed")
	}
}
func FuzzParse(f *testing.F) {
	f.Add(labeled)
	f.Add(`{"found":false}`)
	f.Add(`{"found":true,"wallet_id":"abcd"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > MaxResponseBytes {
			return
		}
		a, e := parse([]byte(raw))
		if e == nil {
			if !safeText(a.Label, MaxLabelBytes) || len(a.WalletID) > MaxIdentifierBytes {
				t.Fatal("unbounded parser output")
			}
		}
	})
}

func TestParserBoundaryValues(t *testing.T) {
	raw := `{"found":true,"label":"` + strings.Repeat("a", MaxLabelBytes) + `","category":"` + strings.Repeat("b", MaxLabelBytes) + `","wallet_id":"` + strings.Repeat("f", MaxIdentifierBytes) + `"}`
	a, err := parse([]byte(raw))
	if err != nil || len(a.Label) != MaxLabelBytes || len(a.Category) != MaxLabelBytes || len(a.WalletID) != MaxIdentifierBytes {
		t.Fatal("boundary rejected/truncated")
	}
	for _, raw := range []string{
		`{"found":true,"label":"Name","wallet_id":"abcd","category":"` + strings.Repeat("c", MaxLabelBytes+1) + `"}`,
		`{"found":false,"updated_to_block":null}`,
		`{"found":"false"}`,
		`{"found":true,"wallet_id":123}`,
		"{\"found\":false,\"label\":\"\xff\"}",
	} {
		if _, err := parse([]byte(raw)); err == nil {
			t.Fatal("invalid boundary accepted")
		}
	}
	fields := `{"found":false`
	for i := 0; i < 32; i++ {
		fields += fmt.Sprintf(`,"extra%d":true`, i)
	}
	fields += "}"
	if _, err := parse([]byte(fields)); err == nil {
		t.Fatal("field budget exceeded")
	}
	if _, err := parse([]byte(strings.Repeat(" ", MaxResponseBytes+1))); err == nil {
		t.Fatal("parser byte limit exceeded")
	}
}
