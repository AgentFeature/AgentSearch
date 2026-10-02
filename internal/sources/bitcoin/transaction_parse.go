package bitcoin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/AgentFeature/agentsearch/internal/models"
)

// boundedTransactionList stops before decoding or allocating entry 1001.
// It is local to this endpoint, not a provider abstraction.
type boundedTransactionList[T any] []T

func (list *boundedTransactionList[T]) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('[') {
		return invalid()
	}
	for d.More() {
		if len(*list) >= MaxTransactionIO {
			return &failure{kind: "data_limit"}
		}
		var value T
		if err = d.Decode(&value); err != nil {
			return err
		}
		*list = append(*list, value)
	}
	if _, err = d.Token(); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return invalid()
	}
	return nil
}

type txOutputWire struct {
	Value      *int64 `json:"value"`
	Address    string `json:"scriptpubkey_address"`
	ScriptType string `json:"scriptpubkey_type"`
}
type txInputWire struct {
	ID       string        `json:"txid"`
	Vout     *int64        `json:"vout"`
	Coinbase *bool         `json:"is_coinbase"`
	Prevout  *txOutputWire `json:"prevout"`
}
type txStatusWire struct {
	Confirmed *bool  `json:"confirmed"`
	Height    *int64 `json:"block_height"`
	Hash      string `json:"block_hash"`
	Time      *int64 `json:"block_time"`
}
type transactionWire struct {
	ID       string                               `json:"txid"`
	Version  *int64                               `json:"version"`
	Locktime *int64                               `json:"locktime"`
	Size     *int64                               `json:"size"`
	Weight   *int64                               `json:"weight"`
	Fee      *int64                               `json:"fee"`
	Inputs   boundedTransactionList[txInputWire]  `json:"vin"`
	Outputs  boundedTransactionList[txOutputWire] `json:"vout"`
	Status   *txStatusWire                        `json:"status"`
}

// Small evidence projections preserve wire indexes, not provider response blobs.
type transactionSummary struct {
	ID                  string `json:"txid"`
	Version             int64  `json:"version"`
	Locktime            int64  `json:"locktime"`
	Size                int64  `json:"size"`
	Weight              int64  `json:"weight"`
	Fee                 *int64 `json:"fee_sats,omitempty"`
	InputCount          int    `json:"input_count"`
	OutputCount         int    `json:"output_count"`
	Coinbase            bool   `json:"coinbase"`
	InputValuesComplete bool   `json:"input_values_complete"`
	InputTotal          *int64 `json:"input_total_sats,omitempty"`
	OutputTotal         int64  `json:"output_total_sats"`
	FeeCheck            string `json:"fee_check"`
}
type transactionInput struct {
	Index              int    `json:"index"`
	Coinbase           bool   `json:"coinbase"`
	PreviousID         string `json:"previous_txid,omitempty"`
	PreviousVout       *int64 `json:"previous_vout,omitempty"`
	PreviousValue      *int64 `json:"previous_value_sats,omitempty"`
	PreviousAddress    string `json:"previous_address,omitempty"`
	PreviousScriptType string `json:"previous_script_type,omitempty"`
}
type transactionOutput struct {
	Index      int    `json:"index"`
	Value      int64  `json:"value_sats"`
	Address    string `json:"address,omitempty"`
	ScriptType string `json:"script_type,omitempty"`
}
type transactionBlock struct {
	Height *int64 `json:"height,omitempty"`
	Hash   string `json:"hash,omitempty"`
	Time   string `json:"time,omitempty"`
}
type transactionAddress struct {
	Address  string `json:"address"`
	InInput  bool   `json:"in_input_previous_output"`
	InOutput bool   `json:"in_output"`
}

func scriptTypeValid(value string) bool {
	if len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true // Unknown bounded tokens remain provider tokens, not our categories.
}
func txAddress(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	a, _, err := models.BitcoinAddress(value)
	if errors.Is(err, models.ErrUnsupportedBitcoinAddress) {
		return "", &failure{kind: "unsupported_response"}
	}
	if err != nil {
		return "", invalid()
	}
	return a, nil
}
func checkedValue(total, value int64) (int64, error) {
	if value < 0 || value > maxMoney || total > maxMoney-value {
		return 0, invalid()
	}
	return total + value, nil
}

func parseTransaction(raw []byte, expected string) ([]models.Evidence, error) {
	if len(raw) > MaxResponseBytes {
		return nil, &failure{kind: "response_too_large"}
	}
	if !utf8.Valid(raw) || !validID(expected) {
		return nil, invalid()
	}
	if err := checkTransactionJSON(raw); err != nil {
		return nil, err
	}
	var w transactionWire
	if err := json.Unmarshal(raw, &w); err != nil {
		var e *failure
		if errors.As(err, &e) {
			return nil, e
		}
		return nil, invalid()
	}
	w.ID = strings.ToLower(w.ID)
	if !validID(w.ID) || w.ID != expected || w.Status == nil || w.Status.Confirmed == nil || len(w.Inputs) == 0 || len(w.Outputs) == 0 {
		return nil, invalid()
	}
	if w.Version == nil || *w.Version < -2147483648 || *w.Version > 2147483647 || w.Locktime == nil || *w.Locktime < 0 || *w.Locktime > 4294967295 {
		return nil, invalid()
	}
	if w.Size == nil || *w.Size < 10 || *w.Size > 4000000 || w.Weight == nil || *w.Weight < *w.Size || *w.Weight > 4*(*w.Size) || *w.Weight > 4000000 {
		return nil, invalid()
	}
	if w.Fee != nil && (*w.Fee < 0 || *w.Fee > maxMoney) {
		return nil, invalid()
	}
	status := w.Status
	if !*status.Confirmed && (status.Height != nil || status.Hash != "" || status.Time != nil) {
		return nil, invalid()
	}
	block := transactionBlock{Height: status.Height, Hash: strings.ToLower(status.Hash)}
	if block.Height != nil && (*block.Height < 0 || *block.Height > 2147483647) {
		return nil, invalid()
	}
	if block.Hash != "" && !validID(block.Hash) {
		return nil, invalid()
	}
	if status.Time != nil {
		if *status.Time < 1231006505 || *status.Time > 253402300799 {
			return nil, invalid()
		}
		block.Time = time.Unix(*status.Time, 0).UTC().Format(time.RFC3339)
	}
	summary := transactionSummary{ID: w.ID, Version: *w.Version, Locktime: *w.Locktime, Size: *w.Size, Weight: *w.Weight, Fee: w.Fee, InputCount: len(w.Inputs), OutputCount: len(w.Outputs), InputValuesComplete: true, FeeCheck: "unavailable"}
	inputs := make([]transactionInput, 0, len(w.Inputs))
	outputs := make([]transactionOutput, 0, len(w.Outputs))
	addresses := map[string]transactionAddress{}
	observe := func(address string, input bool) {
		if address == "" {
			return
		}
		a := addresses[address]
		a.Address = address
		if input {
			a.InInput = true
		} else {
			a.InOutput = true
		}
		addresses[address] = a
	}
	var inputTotal int64
	references := map[string]bool{}
	for i, in := range w.Inputs {
		if in.Coinbase == nil {
			return nil, invalid()
		}
		item := transactionInput{Index: i, Coinbase: *in.Coinbase}
		if *in.Coinbase {
			if len(w.Inputs) != 1 || in.Prevout != nil || in.ID != "" && in.ID != strings.Repeat("0", 64) || in.Vout != nil && *in.Vout != 4294967295 {
				return nil, invalid()
			}
			summary.Coinbase = true
			summary.InputValuesComplete = false
			summary.FeeCheck = "not_applicable"
			if w.Fee != nil && *w.Fee != 0 {
				return nil, invalid()
			}
		} else {
			id := strings.ToLower(in.ID)
			if !validID(id) || id == strings.Repeat("0", 64) || in.Vout == nil || *in.Vout < 0 || *in.Vout > 4294967295 {
				return nil, invalid()
			}
			reference := fmt.Sprintf("%s:%d", id, *in.Vout)
			if references[reference] {
				return nil, invalid()
			}
			references[reference] = true
			item.PreviousID = id
			item.PreviousVout = in.Vout
			if in.Prevout == nil {
				summary.InputValuesComplete = false
			} else {
				prev := in.Prevout
				if !scriptTypeValid(prev.ScriptType) {
					return nil, invalid()
				}
				address, err := txAddress(prev.Address)
				if err != nil {
					return nil, err
				}
				item.PreviousAddress = address
				item.PreviousScriptType = prev.ScriptType
				observe(address, true)
				if prev.Value == nil {
					summary.InputValuesComplete = false
				} else {
					inputTotal, err = checkedValue(inputTotal, *prev.Value)
					if err != nil {
						return nil, err
					}
					item.PreviousValue = prev.Value
				}
			}
		}
		inputs = append(inputs, item)
	}
	for i, out := range w.Outputs {
		if out.Value == nil || !scriptTypeValid(out.ScriptType) {
			return nil, invalid()
		}
		var err error
		summary.OutputTotal, err = checkedValue(summary.OutputTotal, *out.Value)
		if err != nil {
			return nil, err
		}
		address, err := txAddress(out.Address)
		if err != nil {
			return nil, err
		}
		observe(address, false)
		outputs = append(outputs, transactionOutput{Index: i, Value: *out.Value, Address: address, ScriptType: out.ScriptType})
	}
	if summary.InputValuesComplete {
		if inputTotal < summary.OutputTotal {
			return nil, invalid()
		}
		summary.InputTotal = &inputTotal
		if w.Fee != nil {
			if inputTotal-summary.OutputTotal != *w.Fee {
				return nil, &failure{kind: "inconsistent_fee"}
			}
			summary.FeeCheck = "consistent"
		}
	}
	// Never sort inputs or outputs by value/address: their positions have meaning.
	evidence := []models.Evidence{{Kind: "crypto_transaction_summary", Value: encode(summary)}, {Kind: "crypto_transaction_status", Value: encode(struct {
		Confirmed bool `json:"confirmed"`
	}{*status.Confirmed})}}
	if block.Height != nil || block.Hash != "" || block.Time != "" {
		evidence = append(evidence, models.Evidence{Kind: "crypto_transaction_block", Value: encode(block)})
	}
	for _, in := range inputs {
		evidence = append(evidence, models.Evidence{Kind: "crypto_transaction_input", Value: encode(in)})
	}
	for _, out := range outputs {
		evidence = append(evidence, models.Evidence{Kind: "crypto_transaction_output", Value: encode(out)})
	}
	keys := make([]string, 0, len(addresses))
	for key := range addresses {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		evidence = append(evidence, models.Evidence{Kind: "crypto_transaction_address_observed", Value: encode(addresses[key])})
	}
	return evidence, nil
}

// Reject ambiguous duplicate keys before decoding selected fields. The body
// limit also bounds ignored script/witness data; recursion depth is capped.
func checkTransactionJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return &failure{kind: "unsupported_response"}
		}
		token, err := d.Token()
		if err != nil {
			return invalid()
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return invalid()
				}
				name, ok := key.(string)
				for _, c := range name {
					if c > 127 {
						return invalid()
					}
				}
				name = strings.ToLower(name)
				if !ok || seen[name] {
					return invalid()
				}
				seen[name] = true
				if len(seen) > 64 {
					return &failure{kind: "unsupported_response"}
				}
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			if _, err = d.Token(); err != nil {
				return invalid()
			}
		case json.Delim('['):
			for d.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			if _, err = d.Token(); err != nil {
				return invalid()
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return invalid()
	}
	return nil
}
