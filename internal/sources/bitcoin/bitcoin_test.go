package bitcoin

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/network"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

const targetAddress = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
const peerAddress = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
const otherAddress = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"

func ptr[T any](v T) *T { return &v }
func stats(count int) string {
	return fmt.Sprintf(`{"address":%q,"chain_stats":{"tx_count":%d,"funded_txo_sum":%d,"spent_txo_sum":0}}`, targetAddress, count, count*100)
}
func tx(id int) wireTransaction {
	w := wireTransaction{ID: fmt.Sprintf("%064x", id), Inputs: []input{{Coinbase: ptr(false), Prevout: &output{Address: peerAddress, Value: ptr(int64(110))}}}, Outputs: []output{{Address: targetAddress, Value: ptr(int64(100))}}}
	// JSON fixture status, without relying on anonymous type identity.
	raw := fmt.Sprintf(`{"confirmed":true,"block_time":%d}`, 1700000000+id)
	if err := json.Unmarshal([]byte(raw), &w.Status); err != nil {
		panic(err)
	}
	return w
}
func fixture(t *testing.T, fn http.HandlerFunc) (*Source, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("APIKEY") != "" || r.Header.Get("Cookie") != "" {
			t.Error("unexpected method/credentials")
		}
		fn(w, r)
	}))
	t.Cleanup(server.Close)
	source, err := New(server.URL+"/api", network.NewServiceClient(time.Second), time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(source.Close)
	return source, calls
}
func search(t *testing.T, s *Source) ([]models.Result, error) {
	t.Helper()
	registry := sources.NewRegistry()
	if err := registry.Register(s); err != nil {
		t.Fatal(err)
	}
	target, err := models.NewBitcoinTarget(targetAddress)
	if err != nil {
		t.Fatal(err)
	}
	var rows []models.Result
	err = sources.NewManager(registry).Search(context.Background(), target, func(r models.Result) error { rows = append(rows, r); return nil })
	return rows, err
}
func evidence(rows []models.Result, kind string) []string {
	var out []string
	for _, r := range rows {
		for _, e := range r.Evidence {
			if e.Kind == kind {
				out = append(out, e.Value)
			}
		}
	}
	return out
}
func writeJSON(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
func TestNormalDeterminismAndProvenance(t *testing.T) {
	a, b := tx(1), tx(2)
	b.Status.Time = nil
	s, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/txs/chain") {
			writeJSON(w, []wireTransaction{b, a, a})
		} else {
			fmt.Fprint(w, stats(2))
		}
	})
	var previous string
	for i := 0; i < 4; i++ {
		rows, err := search(t, s)
		if err != nil || len(rows) != 1 {
			t.Fatalf("%v %+v", err, rows)
		}
		raw := encode(rows)
		if i > 0 && raw != previous {
			t.Fatal("nondeterministic output")
		}
		previous = raw
		r := rows[0]
		if r.Source != "bitcoin" || r.SourceType != models.SourceAPI || r.TargetType != models.TargetBitcoin || r.Status != models.StatusFound || r.EvidenceSemantics().Kind != models.ObservationBitcoin {
			t.Fatal("provenance")
		}
		if len(evidence(rows, "crypto_transaction")) != 2 || len(evidence(rows, "crypto_counterparty")) != 1 {
			t.Fatal("deduplication")
		}
		var cp counterparty
		_ = json.Unmarshal([]byte(evidence(rows, "crypto_counterparty")[0]), &cp)
		if cp.Count != 2 || cp.Value == nil || *cp.Value != 200 || cp.Direction != "inbound" {
			t.Fatalf("%+v", cp)
		}
		if got := evidence(rows, "crypto_sample_first_seen"); len(got) != 1 || got[0] != "2023-11-14T22:13:21Z" {
			t.Fatal(got)
		}
	}
	if calls.Load() != 8 {
		t.Fatal("requests")
	}
}
func TestZeroAndErrorSemantics(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		kind       string
		history    bool
	}{
		{"zero", stats(0), 200, "", false},
		{"HTTP", "credential-marker", 500, "http_error", false},
		{"rate limit", "credential-marker", 429, "rate_limited", false},
		{"malformed", "{}", 200, "invalid_response", false},
		{"null", "null", 200, "invalid_response", false},
		{"negative", strings.Replace(stats(1), `"funded_txo_sum":100`, `"funded_txo_sum":-1`, 1), 200, "invalid_response", false},
		{"overflow", strings.Replace(stats(1), `"funded_txo_sum":100`, `"funded_txo_sum":9223372036854775808`, 1), 200, "invalid_response", false},
		{"fraction", strings.Replace(stats(1), `"funded_txo_sum":100`, `"funded_txo_sum":0.1`, 1), 200, "invalid_response", false},
		{"oversized", strings.Repeat(" ", MaxResponseBytes+1), 200, "response_too_large", false},
		{"partial", "credential-marker", 503, "http_error", true},
		{"null history", "null", 200, "invalid_response", true},
		{"inconsistent empty", "[]", 200, "invalid_response", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.history && !strings.Contains(r.URL.Path, "/txs/") {
					fmt.Fprint(w, stats(1))
					return
				}
				if !tc.history && strings.Contains(r.URL.Path, "/txs/") {
					fmt.Fprint(w, "[]")
					return
				}
				if tc.status == 429 {
					w.Header().Set("Retry-After", "2")
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			rows, err := search(t, s)
			if tc.kind == "" {
				if err != nil || len(rows) != 1 || evidence(rows, "crypto_confirmed_balance_sats")[0] != "0" || evidence(rows, "crypto_confirmed_transaction_count")[0] != "0" {
					t.Fatalf("zero not observed: %v", err)
				}
			} else {
				if err == nil || len(rows) != 2 || rows[1].Metadata["error_kind"] != tc.kind {
					t.Fatalf("%v %+v", err, rows)
				}
				if rows[0].Status != models.StatusFound || rows[1].Status != models.StatusError {
					t.Fatal("partial-result contract")
				}
				if !tc.history && len(evidence(rows, "crypto_confirmed_balance_sats")) != 0 {
					t.Fatal("failure became zero")
				}
				if tc.history && evidence(rows, "crypto_confirmed_balance_sats")[0] != "100" {
					t.Fatal("lost stats")
				}
				if strings.Contains(encode(rows), "credential-marker") || strings.Contains(err.Error(), "credential-marker") {
					t.Fatal("error body leak")
				}
			}
			max := int32(1)
			if tc.history || tc.kind == "" {
				max = 2
			}
			if calls.Load() != max {
				t.Fatalf("retry/request budget: %d", calls.Load())
			}
		})
	}
}
func TestTimeoutCancellationAndConsumerError(t *testing.T) {
	s, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	s.http.Timeout = 20 * time.Millisecond
	rows, err := search(t, s)
	if !errors.Is(err, context.DeadlineExceeded) || rows[1].Metadata["error_kind"] != "timeout" {
		t.Fatalf("%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var got []models.Result
	err = s.SearchBitcoin(ctx, targetAddress, func(r models.Result) error { got = append(got, r); return nil })
	if !errors.Is(err, context.Canceled) || got[1].Metadata["error_kind"] != "cancelled" {
		t.Fatal(err)
	}
	sentinel := errors.New("consumer stopped")
	if e := s.SearchBitcoin(ctx, targetAddress, func(models.Result) error { return sentinel }); e != sentinel {
		t.Fatal("consumer identity lost")
	}
}
func TestPagesTransactionsAndRequestsBound(t *testing.T) {
	for _, mode := range []string{"transactions", "pages", "repeated", "partial"} {
		t.Run(mode, func(t *testing.T) {
			page := 0
			s, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.URL.Path, "/txs/") {
					fmt.Fprint(w, stats(1000))
					return
				}
				page++
				if mode == "partial" && page == 2 {
					w.WriteHeader(500)
					return
				}
				batch := make([]wireTransaction, PageSize)
				for i := range batch {
					id := (page-1)*PageSize + i + 1
					if mode == "pages" {
						id = i + 1
						if i == PageSize-1 {
							id = 100 + page
						}
					}
					if mode == "repeated" {
						id = i + 1
					}
					batch[i] = tx(id)
				}
				writeJSON(w, batch)
			})
			rows, err := search(t, s)
			switch mode {
			case "transactions":
				if err != nil || page != 4 || len(evidence(rows, "crypto_transaction")) != MaxTransactions || rows[0].Metadata["history_stop"] != "transaction_limit" {
					t.Fatalf("%v page %d", err, page)
				}
			case "pages":
				if err != nil || page != MaxPages || rows[0].Metadata["history_stop"] != "page_limit" {
					t.Fatalf("%v page %d", err, page)
				}
			case "repeated":
				if err == nil || page != 2 {
					t.Fatal("repeated cursor not stopped")
				}
			case "partial":
				if err == nil || len(evidence(rows, "crypto_transaction")) != 25 || rows[0].Metadata["history_status"] != "partial" {
					t.Fatal("lost valid first page")
				}
			}
			if calls.Load() > MaxRequests || len(evidence(rows, "crypto_transaction")) > MaxTransactions {
				t.Fatal("budget exceeded")
			}
			n := MaxRequests
			var dst any
			if e := s.get(context.Background(), "/address/"+targetAddress, &n, &dst); e == nil || n != MaxRequests {
				t.Fatal("request cap")
			}
		})
	}
}

func TestTransactionValidation(t *testing.T) {
	cases := map[string]func(*wireTransaction){
		"txid":             func(w *wireTransaction) { w.ID = "not-a-tx" },
		"missing input":    func(w *wireTransaction) { w.Inputs = nil },
		"missing prevout":  func(w *wireTransaction) { w.Inputs[0].Prevout = nil },
		"missing value":    func(w *wireTransaction) { w.Outputs[0].Value = nil },
		"negative":         func(w *wireTransaction) { w.Outputs[0].Value = ptr(int64(-1)) },
		"overflow":         func(w *wireTransaction) { w.Outputs[0].Value = ptr(int64(9223372036854775807)) },
		"overspend":        func(w *wireTransaction) { w.Outputs[0].Value = ptr(int64(111)) },
		"bad address":      func(w *wireTransaction) { w.Outputs[0].Address = "secret-marker" },
		"missing status":   func(w *wireTransaction) { w.Status = nil },
		"unconfirmed":      func(w *wireTransaction) { w.Status.Confirmed = ptr(false) },
		"bad time":         func(w *wireTransaction) { w.Status.Time = ptr(int64(-1)) },
		"long time":        func(w *wireTransaction) { w.Status.Time = ptr(int64(253402300800)) },
		"unrelated":        func(w *wireTransaction) { w.Outputs[0].Address = otherAddress },
		"too many outputs": func(w *wireTransaction) { w.Outputs = make([]output, MaxTransactionIO+1) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			w := tx(1)
			change(&w)
			if _, e := normalizeTransaction(w, targetAddress); e == nil {
				t.Fatal("malformed record accepted")
			}
		})
	}
	w := tx(1)
	w.Status.Time = nil
	if got, e := normalizeTransaction(w, targetAddress); e != nil || got.tx.Timestamp != "" {
		t.Fatal("optional timestamp")
	}
	w = tx(1)
	w.Inputs = []input{{Coinbase: ptr(true)}}
	if got, e := normalizeTransaction(w, targetAddress); e != nil || len(got.edges) != 0 {
		t.Fatal("coinbase")
	}
}
func TestCounterpartySemantics(t *testing.T) {
	w := tx(1)
	w.Inputs[0].Prevout.Address = targetAddress
	w.Outputs = []output{{Address: peerAddress, Value: ptr(int64(40))}, {Address: peerAddress, Value: ptr(int64(20))}, {Address: targetAddress, Value: ptr(int64(40))}}
	got, e := normalizeTransaction(w, targetAddress)
	if e != nil || got.tx.Value != 70 || got.tx.Direction != "outbound" || len(got.edges) != 1 || *got.edges[0].value != 60 {
		t.Fatalf("%v %+v", e, got)
	}
	w.Inputs = append(w.Inputs, input{Coinbase: ptr(false), Prevout: &output{Address: otherAddress, Value: ptr(int64(1))}})
	got, e = normalizeTransaction(w, targetAddress)
	if e != nil {
		t.Fatal(e)
	}
	for _, edge := range got.edges {
		if edge.value != nil || edge.direction != "cooccurrence" {
			t.Fatal("ambiguous attribution")
		}
	}
	w = tx(1)
	w.Inputs[0].Prevout.Address = targetAddress
	w.Outputs[0].Value = ptr(int64(110))
	got, e = normalizeTransaction(w, targetAddress)
	if e != nil || got.tx.Direction != "self" || len(got.edges) != 0 {
		t.Fatal("self transfer")
	}
}

// Synthetic public script-hash fixtures only: no keys or wallet generation.
func fixtureAddress(n int) string {
	payload := make([]byte, 21)
	payload[0] = 5
	payload[17] = byte(n >> 24)
	payload[18] = byte(n >> 16)
	payload[19] = byte(n >> 8)
	payload[20] = byte(n)
	a := sha256.Sum256(payload)
	b := sha256.Sum256(a[:])
	raw := append(payload, b[:4]...)
	x := new(big.Int).SetBytes(raw)
	base := big.NewInt(58)
	rem := new(big.Int)
	var text []byte
	for x.Sign() > 0 {
		x.QuoRem(x, base, rem)
		text = append(text, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[rem.Int64()])
	}
	for i, j := 0, len(text)-1; i < j; i, j = i+1, j-1 {
		text[i], text[j] = text[j], text[i]
	}
	return string(text)
}
func TestCounterpartyCapAndSort(t *testing.T) {
	w := tx(1)
	w.Inputs[0].Prevout.Address = targetAddress
	w.Inputs[0].Prevout.Value = ptr(int64(1000))
	w.Outputs = nil
	for i := 0; i < MaxCounterparties+10; i++ {
		address := fixtureAddress(i)
		if _, _, err := models.BitcoinAddress(address); err != nil {
			t.Fatal(err)
		}
		w.Outputs = append(w.Outputs, output{Address: address, Value: ptr(int64(1))})
	}
	got, err := normalizeTransaction(w, targetAddress)
	if err != nil {
		t.Fatal(err)
	}
	ev, truncated := project(map[string]observedTransaction{w.ID: got})
	if !truncated {
		t.Fatal("missing truncation")
	}
	rows := []models.Result{{Evidence: ev}}
	peers := evidence(rows, "crypto_counterparty")
	if len(peers) != MaxCounterparties {
		t.Fatal(len(peers))
	}
	for i := 1; i < len(peers); i++ {
		if peers[i-1] > peers[i] {
			t.Fatal("not sorted")
		}
	}
	for i, j := 0, len(w.Outputs)-1; i < j; i, j = i+1, j-1 {
		w.Outputs[i], w.Outputs[j] = w.Outputs[j], w.Outputs[i]
	}
	got, _ = normalizeTransaction(w, targetAddress)
	again, _ := project(map[string]observedTransaction{w.ID: got})
	if !reflect.DeepEqual(ev, again) {
		t.Fatal("order changes projection")
	}
}
func TestMalformedPagesAndDuplicateConflict(t *testing.T) {
	for _, mode := range []string{"oversized page", "conflict", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.URL.Path, "/txs/") {
					fmt.Fprint(w, stats(2))
					return
				}
				batch := []wireTransaction{tx(1), tx(1)}
				switch mode {
				case "oversized page":
					batch = make([]wireTransaction, PageSize+1)
				case "conflict":
					batch[1].Status.Time = nil
				case "malformed":
					batch[1].ID = "invalid"
				}
				writeJSON(w, batch)
			})
			rows, e := search(t, s)
			if e == nil || len(evidence(rows, "crypto_transaction")) != 0 {
				t.Fatal("bad page retained")
			}
		})
	}
}
func TestSecretsUnknownFieldsAndRedirects(t *testing.T) {
	s, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Authorization", "secret-marker")
		w.Header().Set("Set-Cookie", "token=secret-marker")
		if strings.Contains(r.URL.Path, "/txs/") {
			fmt.Fprint(w, "[]")
			return
		}
		body := strings.TrimSuffix(stats(0), "}") + `,"api_key":"secret-marker","seed":"secret-marker","private_key":"secret-marker","raw":"secret-marker"}`
		fmt.Fprint(w, body)
	})
	rows, e := search(t, s)
	if e != nil || strings.Contains(encode(rows), "secret-marker") {
		t.Fatal("unknown data persisted")
	}
	for _, key := range []string{"api_key", "private_key", "seed", "authorization"} {
		if strings.Contains(encode(rows), key) {
			t.Fatal("sensitive field")
		}
	}
	before := calls.Load()
	if e = s.SearchBitcoin(context.Background(), "seed words are not a Bitcoin address", func(models.Result) error { return nil }); e == nil || calls.Load() != before {
		t.Fatal("invalid target queried")
	}
	redir, count := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/api/secret-marker")
		w.WriteHeader(302)
	})
	rows, e = search(t, redir)
	if e == nil || count.Load() != 1 || strings.Contains(encode(rows), "secret-marker") {
		t.Fatal("redirect followed/leaked")
	}
	for _, u := range []string{"http://example.com/api", "https://user:password@example.com/api", "https://example.com/api?api_key=secret-marker", "https://example.com/api#secret-marker", "https://example.com/not-api"} {
		if _, e := New(u, network.NewServiceClient(time.Second), time.Second); e == nil || strings.Contains(e.Error(), "secret-marker") {
			t.Fatal("unsafe endpoint")
		}
	}
}
func TestRetryAfterPacesLaterInvestigations(t *testing.T) {
	s, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Retry-After", "60"); w.WriteHeader(429) })
	rows, e := search(t, s)
	if e == nil || rows[1].Metadata["retry_after_seconds"] != "60" {
		t.Fatal("rate-limit metadata")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	e = s.SearchBitcoin(ctx, targetAddress, func(models.Result) error { return nil })
	if !errors.Is(e, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatal("Retry-After bypassed")
	}
	if MaxRetries != 0 || MaxRequests != MaxPages+1 {
		t.Fatal("budget contract")
	}
}
func FuzzTransactionParsing(f *testing.F) {
	f.Add(encode(tx(1)))
	f.Add(`{"txid":"bad"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > MaxResponseBytes {
			return
		}
		var w wireTransaction
		if json.Unmarshal([]byte(raw), &w) == nil {
			got, err := normalizeTransaction(w, targetAddress)
			if err == nil {
				if !validID(got.tx.ID) || got.tx.Value < 0 || got.tx.Value > maxMoney {
					t.Fatal(strconv.FormatInt(got.tx.Value, 10))
				}
			}
		}
	})
}

func TestConcurrentInvestigations(t *testing.T) {
	s, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/txs/") {
			fmt.Fprint(w, "[]")
			return
		}
		fmt.Fprint(w, stats(0))
	})
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			n := 0
			err := s.SearchBitcoin(context.Background(), targetAddress, func(r models.Result) error {
				n++
				if r.Status != models.StatusFound {
					return errors.New("unexpected failure")
				}
				return nil
			})
			if n != 1 && err == nil {
				err = errors.New("missing result")
			}
			done <- err
		}()
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 16 {
		t.Fatal("cross-investigation request budget")
	}
}

func TestRetryAfterDateAndTimeoutCap(t *testing.T) {
	for _, header := range []string{"invalid", time.Now().Add(2 * time.Minute).UTC().Format(http.TimeFormat), "999999"} {
		s, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", header)
			w.WriteHeader(429)
		})
		rows, err := search(t, s)
		if err == nil {
			t.Fatal("rate limit became success")
		}
		n, e := strconv.Atoi(rows[1].Metadata["retry_after_seconds"])
		if e != nil || n < 1 || n > 86400 {
			t.Fatal("invalid cooldown")
		}
	}
	s, err := New("", network.NewServiceClient(time.Hour), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.http.Timeout != RequestTimeout {
		t.Fatal("unbounded request timeout")
	}
}
