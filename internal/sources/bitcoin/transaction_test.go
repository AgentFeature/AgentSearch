package bitcoin

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

var transactionID = strings.Repeat("a", 64)

func transactionFixture(t testing.TB) transactionWire {
	t.Helper()
	raw, err := os.ReadFile("testdata/transaction.json")
	if err != nil {
		t.Fatal(err)
	}
	var w transactionWire
	if err = json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	return w
}
func transactionBytes(t testing.TB, w transactionWire) []byte {
	t.Helper()
	b, e := json.Marshal(w)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func summaryOf(t testing.TB, ev []models.Evidence) transactionSummary {
	t.Helper()
	var s transactionSummary
	if len(ev) == 0 || ev[0].Kind != "crypto_transaction_summary" || json.Unmarshal([]byte(ev[0].Value), &s) != nil {
		t.Fatal("missing summary")
	}
	return s
}
func TestTransactionParserObservations(t *testing.T) {
	for _, name := range []string{"confirmed", "unconfirmed", "coinbase", "missing-address", "missing-value", "missing-prevout", "missing-fee", "multiple", "exact-max-money", "missing-block-fields"} {
		t.Run(name, func(t *testing.T) {
			w := transactionFixture(t)
			switch name {
			case "unconfirmed":
				w.Status = &txStatusWire{Confirmed: ptr(false)}
			case "coinbase":
				w.Inputs = []txInputWire{{Coinbase: ptr(true), ID: strings.Repeat("0", 64), Vout: ptr(int64(4294967295))}}
				w.Fee = ptr(int64(0))
			case "missing-address":
				w.Inputs[0].Prevout.Address = ""
				w.Outputs[0].Address = ""
				w.Outputs[0].ScriptType = "nonstandard"
			case "missing-value":
				w.Inputs[0].Prevout.Value = nil
			case "missing-prevout":
				w.Inputs[0].Prevout = nil
			case "missing-fee":
				w.Fee = nil
			case "multiple":
				in := w.Inputs[0]
				in.Vout = ptr(int64(2))
				w.Inputs = append(w.Inputs, in)
				w.Outputs = append(w.Outputs, txOutputWire{Value: ptr(int64(110)), Address: targetAddress, ScriptType: "p2pkh"})
			case "exact-max-money":
				w.Inputs[0].Prevout.Value = ptr(int64(maxMoney))
				w.Outputs[0].Value = ptr(int64(maxMoney - 1))
				w.Fee = ptr(int64(1))
			case "missing-block-fields":
				w.Status = &txStatusWire{Confirmed: ptr(true)}
			}
			raw := transactionBytes(t, w)
			ev, err := parseTransaction(raw, transactionID)
			if err != nil {
				t.Fatal(err)
			}
			again, err := parseTransaction(raw, transactionID)
			if err != nil || !reflect.DeepEqual(ev, again) {
				t.Fatal("nondeterministic")
			}
			s := summaryOf(t, ev)
			missing := name == "missing-value" || name == "missing-prevout" || name == "coinbase"
			if s.InputValuesComplete == missing || (s.InputTotal == nil) != missing {
				t.Fatalf("input completeness %+v", s)
			}
			if missing && strings.Contains(ev[0].Value, "input_total_sats") {
				t.Fatal("fabricated total")
			}
			if name == "missing-fee" && (s.Fee != nil || s.FeeCheck != "unavailable") {
				t.Fatal("fabricated fee")
			}
			if name == "coinbase" && (!s.Coinbase || s.FeeCheck != "not_applicable") {
				t.Fatal("coinbase accounted as normal")
			}
			if name == "exact-max-money" && (*s.InputTotal != maxMoney || s.OutputTotal != maxMoney-1) {
				t.Fatal("inexact satoshis")
			}
			if name == "unconfirmed" && (ev[1].Value != `{"confirmed":false}` || strings.Contains(fmt.Sprint(ev), "crypto_transaction_block")) {
				t.Fatal("unconfirmed fabricated block")
			}
			if name == "multiple" {
				if s.InputCount != 2 || s.OutputCount != 2 || *s.InputTotal != 220 || s.OutputTotal != 210 {
					t.Fatal(s)
				}
				var prev string
				addresses := 0
				inputs := 0
				outputs := 0
				for _, e := range ev {
					switch e.Kind {
					case "crypto_transaction_input":
						var in transactionInput
						_ = json.Unmarshal([]byte(e.Value), &in)
						if in.Index != inputs {
							t.Fatal("input order")
						}
						inputs++
					case "crypto_transaction_output":
						var out transactionOutput
						_ = json.Unmarshal([]byte(e.Value), &out)
						if out.Index != outputs {
							t.Fatal("output order")
						}
						outputs++
					case "crypto_transaction_address_observed":
						var a transactionAddress
						_ = json.Unmarshal([]byte(e.Value), &a)
						if a.Address <= prev {
							t.Fatal("address order/duplicate")
						}
						prev = a.Address
						addresses++
						if a.Address == targetAddress && (!a.InInput || !a.InOutput) {
							t.Fatal("neutral dual context lost")
						}
					}
				}
				if addresses != 2 {
					t.Fatal("observed set")
				}
			}
		})
	}
}
func TestTransactionParserRejects(t *testing.T) {
	cases := map[string]func(*transactionWire){
		"wrong-id":  func(w *transactionWire) { w.ID = strings.Repeat("d", 64) },
		"no-status": func(w *transactionWire) { w.Status = nil }, "no-confirmed": func(w *transactionWire) { w.Status.Confirmed = nil },
		"contradictory-status": func(w *transactionWire) { w.Status.Confirmed = ptr(false) },
		"bad-height":           func(w *transactionWire) { w.Status.Height = ptr(int64(-1)) }, "bad-hash": func(w *transactionWire) { w.Status.Hash = "bad" }, "bad-time": func(w *transactionWire) { w.Status.Time = ptr(int64(-1)) },
		"no-version": func(w *transactionWire) { w.Version = nil }, "version-overflow": func(w *transactionWire) { w.Version = ptr(int64(2147483648)) }, "locktime-negative": func(w *transactionWire) { w.Locktime = ptr(int64(-1)) },
		"no-size": func(w *transactionWire) { w.Size = nil }, "bad-weight": func(w *transactionWire) { w.Weight = ptr(int64(1)) },
		"empty-inputs": func(w *transactionWire) { w.Inputs = nil }, "empty-outputs": func(w *transactionWire) { w.Outputs = nil },
		"no-coinbase-flag": func(w *transactionWire) { w.Inputs[0].Coinbase = nil }, "coinbase-prevout": func(w *transactionWire) { w.Inputs[0].Coinbase = ptr(true) },
		"bad-prev-id": func(w *transactionWire) { w.Inputs[0].ID = "bad" }, "no-prev-index": func(w *transactionWire) { w.Inputs[0].Vout = nil }, "bad-prev-index": func(w *transactionWire) { w.Inputs[0].Vout = ptr(int64(4294967296)) },
		"no-output-value": func(w *transactionWire) { w.Outputs[0].Value = nil }, "negative-value": func(w *transactionWire) { w.Outputs[0].Value = ptr(int64(-1)) },
		"overflow-value": func(w *transactionWire) { w.Outputs[0].Value = ptr(int64(9223372036854775807)) },
		"input-sum-overflow": func(w *transactionWire) {
			w.Inputs[0].Prevout.Value = ptr(int64(maxMoney))
			in := w.Inputs[0]
			in.Vout = ptr(int64(2))
			w.Inputs = append(w.Inputs, in)
		},
		"output-sum-overflow": func(w *transactionWire) {
			w.Outputs[0].Value = ptr(int64(maxMoney))
			w.Outputs = append(w.Outputs, w.Outputs[0])
		},
		"duplicate-reference": func(w *transactionWire) { w.Inputs = append(w.Inputs, w.Inputs[0]) },
		"fee-mismatch":        func(w *transactionWire) { w.Fee = ptr(int64(11)) }, "negative-fee": func(w *transactionWire) { w.Fee = ptr(int64(-1)) }, "outputs-exceed-inputs": func(w *transactionWire) { w.Outputs[0].Value = ptr(int64(120)) },
		"bad-address": func(w *transactionWire) { w.Outputs[0].Address = "<script>" }, "bad-script-type": func(w *transactionWire) { w.Outputs[0].ScriptType = "<script>" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			w := transactionFixture(t)
			mutate(&w)
			ev, err := parseTransaction(transactionBytes(t, w), transactionID)
			if err == nil || len(ev) != 0 {
				t.Fatal("accepted invalid/partial response")
			}
		})
	}
	good := string(transactionBytes(t, transactionFixture(t)))
	for _, bad := range []string{"", "null", "[]", "{", good + "{}", strings.Replace(good, `"version":2`, `"version":2,"version":3`, 1), strings.Replace(good, `"value":100`, `"value":1.1`, 1), strings.Replace(good, `"value":100`, `"value":"100"`, 1), strings.Replace(good, `"value":100`, `"value":9223372036854775808`, 1)} {
		if _, err := parseTransaction([]byte(bad), transactionID); err == nil {
			t.Fatal("accepted malformed numeric/JSON", bad)
		}
	}
}
func TestTransactionLimits(t *testing.T) {
	for _, input := range []bool{true, false} {
		for _, n := range []int{MaxTransactionIO, MaxTransactionIO + 1} {
			w := transactionFixture(t)
			w.Fee = nil
			if input {
				w.Inputs = nil
				for i := 0; i < n; i++ {
					w.Inputs = append(w.Inputs, txInputWire{ID: strings.Repeat("b", 64), Vout: ptr(int64(i)), Coinbase: ptr(false), Prevout: &txOutputWire{Value: ptr(int64(1))}})
				}
			} else {
				w.Outputs = nil
				for i := 0; i < n; i++ {
					w.Outputs = append(w.Outputs, txOutputWire{Value: ptr(int64(0))})
				}
			}
			_, err := parseTransaction(transactionBytes(t, w), transactionID)
			if n == MaxTransactionIO && err != nil {
				t.Fatal(err)
			}
			if n > MaxTransactionIO {
				var e *failure
				if !errors.As(err, &e) || e.kind != "data_limit" {
					t.Fatal("limit not enforced", err)
				}
			}
		}
	}
	if _, err := parseTransaction(make([]byte, MaxResponseBytes+1), transactionID); err == nil {
		t.Fatal("oversize accepted")
	}
}
func TestTransactionSourceHTTP(t *testing.T) {
	good := string(transactionBytes(t, transactionFixture(t)))
	for _, tc := range []struct {
		name       string
		status     int
		body, kind string
	}{
		{"ok", 200, good, ""}, {"absent", 404, "Transaction not found", "not_found"}, {"unrelated-404", 404, "proxy unavailable", "http_error"}, {"padded-404", 404, "Transaction not found" + strings.Repeat(" ", 60) + "bad", "http_error"},
		{"limited", 429, "private-marker", "rate_limited"}, {"server", 500, "private-marker", "service_unavailable"}, {"malformed", 200, "{", "invalid_response"}, {"oversize", 200, strings.Repeat(" ", MaxResponseBytes+1), "response_too_large"}, {"redirect", 302, "private-marker", "http_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/tx/"+transactionID {
					t.Error("wrong endpoint")
				}
				w.Header().Set("Location", "/api/tx/other")
				w.Header().Set("Retry-After", "2")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			source := &TransactionSource{client: base}
			if cap := sources.Capabilities(source); !reflect.DeepEqual(cap, []models.TargetType{models.TargetBitcoinTransaction}) {
				t.Fatal(cap)
			}
			registry := sources.NewRegistry()
			if err := registry.Register(source); err != nil {
				t.Fatal(err)
			}
			target, _ := models.NewBitcoinTransactionTarget(" \n" + strings.ToUpper(transactionID) + " ")
			var rows []models.Result
			err := sources.NewManager(registry).Search(context.Background(), target, func(r models.Result) error { rows = append(rows, r); return nil })
			if len(rows) != 1 || calls.Load() != 1 {
				t.Fatalf("rows/requests %d/%d", len(rows), calls.Load())
			}
			r := rows[0]
			if r.Source != "bitcoin-tx" || r.Target != transactionID || r.TargetType != models.TargetBitcoinTransaction || r.URL != base.baseURL+"/tx/"+transactionID || r.Metadata["provider"] != "esplora" {
				t.Fatal("provenance")
			}
			if tc.kind == "" {
				if err != nil || r.Status != models.StatusFound {
					t.Fatal(r, err)
				}
				summaryOf(t, r.Evidence)
			} else if tc.kind == "not_found" {
				if err != nil || r.Status != models.StatusNotFound || r.EvidenceSemantics().Meaning != models.MeaningAbsence {
					t.Fatal(r, err)
				}
			} else {
				if err == nil || r.Status != models.StatusError || r.Metadata["error_kind"] != tc.kind || len(r.Evidence) != 0 {
					t.Fatal(r, err)
				}
			}
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), "private-marker") || strings.Contains(string(raw), `"confidence"`) {
				t.Fatal("raw provider body/score leaked")
			}
			if tc.status == 429 && r.Metadata["retry_after_seconds"] != "2" {
				t.Fatal("retry metadata")
			}
		})
	}
}
func TestTransactionInvalidBeforeNetworkAndDeadlines(t *testing.T) {
	base, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	s := &TransactionSource{client: base}
	for _, bad := range []string{"", "bad", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 64), strings.Repeat("a", 31) + " " + strings.Repeat("a", 32), "https://example.com/"} {
		if err := s.SearchBitcoinTransaction(context.Background(), bad, func(models.Result) error { t.Fatal("emitted invalid target"); return nil }); err == nil {
			t.Fatal("invalid target accepted")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid target made request")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var row models.Result
	err := s.SearchBitcoinTransaction(ctx, transactionID, func(r models.Result) error { row = r; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || row.Status != models.StatusError || row.Metadata["error_kind"] != "timeout" {
		t.Fatal(row, err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	err = s.SearchBitcoinTransaction(ctx2, transactionID, func(r models.Result) error { row = r; return nil })
	if !errors.Is(err, context.Canceled) || row.Metadata["error_kind"] != "cancelled" {
		t.Fatal(row, err)
	}
	if calls.Load() != 1 {
		t.Fatal("unexpected requests", calls.Load())
	}
}
func FuzzTransactionParser(f *testing.F) {
	f.Add(transactionBytes(f, transactionFixture(f)))
	f.Add([]byte(`{"vin":null}`))
	f.Add([]byte(`{"status":{"confirmed":false}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxResponseBytes+1 {
			return
		}
		ev, err := parseTransaction(raw, transactionID)
		if err != nil {
			if len(ev) != 0 {
				t.Fatal("partial result")
			}
			return
		}
		if len(ev) > 3+2*MaxTransactionIO+TransactionMaxObservedAddresses {
			t.Fatal("evidence bound")
		}
		again, e := parseTransaction(raw, transactionID)
		if e != nil || !reflect.DeepEqual(ev, again) {
			t.Fatal("nondeterministic")
		}
		for _, v := range ev {
			if !json.Valid([]byte(v.Value)) {
				t.Fatal("invalid evidence JSON")
			}
		}
	})
}

type transactionFailTransport struct {
	err   error
	calls int
}

func (t *transactionFailTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, t.err
}
func TestTransactionTransportErrorsAndLimits(t *testing.T) {
	for _, cause := range []error{&net.DNSError{Err: "private-marker", Name: "private-host", IsNotFound: true}, x509.UnknownAuthorityError{}, errors.New("private-marker")} {
		transport := &transactionFailTransport{err: cause}
		s, err := NewTransactionSource("https://example.test/api", &http.Client{Timeout: time.Minute, Transport: transport}, time.Nanosecond)
		if err != nil {
			t.Fatal(err)
		}
		if s.client.http.Timeout != 15*time.Second {
			t.Fatal("request timeout not clamped")
		}
		var row models.Result
		err = s.SearchBitcoinTransaction(context.Background(), transactionID, func(r models.Result) error { row = r; return nil })
		s.Close()
		if err == nil || row.Status != models.StatusError || row.Metadata["error_kind"] != "network_failure" || transport.calls != 1 || strings.Contains(row.Error, "private") {
			t.Fatal(row, err)
		}
	}
	w := transactionFixture(t)
	w.Outputs[0].Address = "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs"
	_, err := parseTransaction(transactionBytes(t, w), transactionID)
	var e *failure
	if !errors.As(err, &e) || e.kind != "unsupported_response" {
		t.Fatal("unsupported address misclassified", err)
	}
	base, calls := fixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("exhausted budget made request") })
	requests := TransactionMaxRequests
	var raw json.RawMessage
	err = base.getBounded(context.Background(), "/tx/"+transactionID, &requests, TransactionMaxRequests, "Transaction not found", &raw)
	if !errors.As(err, &e) || e.kind != "request_limit" || calls.Load() != 0 {
		t.Fatal("request cap")
	}
}
func TestTransactionDiscardsScriptsAndAmbiguousKeys(t *testing.T) {
	good := string(transactionBytes(t, transactionFixture(t)))
	raw := strings.Replace(good, `"value":100`, `"scriptpubkey":"private-raw-script","witness":["private-witness"],"value":100`, 1)
	ev, err := parseTransaction([]byte(raw), transactionID)
	if err != nil || strings.Contains(fmt.Sprint(ev), "private-") {
		t.Fatal("raw fields retained", err)
	}
	for _, raw := range []string{strings.Replace(good, `"version":2`, `"version":2,"VERSION":3`, 1), strings.Replace(good, `"size":200`, `"size":200,"ſize":201`, 1)} {
		if _, err := parseTransaction([]byte(raw), transactionID); err == nil {
			t.Fatal("ambiguous keys accepted")
		}
	}
}
