package bitcoin

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
)

const maxMoney int64 = 21_000_000 * 100_000_000

type addressData struct {
	Address string      `json:"address"`
	Chain   *chainStats `json:"chain_stats"`
}
type chainStats struct {
	Count    *int64 `json:"tx_count"`
	Received *int64 `json:"funded_txo_sum"`
	Sent     *int64 `json:"spent_txo_sum"`
}

func (p addressData) valid(target string) bool {
	address, _, err := models.BitcoinAddress(p.Address)
	if err != nil || address != target || p.Chain == nil {
		return false
	}
	c := p.Chain
	if c.Count == nil || c.Received == nil || c.Sent == nil {
		return false
	}
	// Lifetime received/sent sums may exceed the money supply through reuse.
	return *c.Count >= 0 && *c.Count <= 1_000_000_000_000 && *c.Sent >= 0 && *c.Received >= *c.Sent && *c.Received-*c.Sent <= maxMoney && (*c.Count != 0 || (*c.Received == 0 && *c.Sent == 0))
}

type output struct {
	Address string `json:"scriptpubkey_address"`
	Value   *int64 `json:"value"`
}
type input struct {
	Coinbase *bool   `json:"is_coinbase"`
	Prevout  *output `json:"prevout"`
}
type wireTransaction struct {
	ID      string   `json:"txid"`
	Inputs  []input  `json:"vin"`
	Outputs []output `json:"vout"`
	Status  *struct {
		Confirmed *bool  `json:"confirmed"`
		Time      *int64 `json:"block_time"`
	} `json:"status"`
}

// These are selected normalized evidence values, not provider payloads.
type transaction struct {
	ID        string `json:"txid"`
	Timestamp string `json:"timestamp,omitempty"`
	Direction string `json:"direction"`
	Value     int64  `json:"value_sats"` // Absolute target net UTXO change, including fees.
}
type counterparty struct {
	Address   string `json:"address"`
	Count     int    `json:"interaction_count"`
	First     string `json:"sample_first_seen,omitempty"`
	Last      string `json:"sample_last_seen,omitempty"`
	Value     *int64 `json:"observed_value_sats,omitempty"`
	Direction string `json:"direction"`
}
type edge struct {
	address, direction string
	value              *int64
}
type observedTransaction struct {
	tx    transaction
	edges []edge
}

func validID(id string) bool {
	if len(id) != 64 || id != strings.ToLower(id) {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
func normalizeOutput(o output) (output, error) {
	if o.Value == nil || *o.Value < 0 || *o.Value > maxMoney {
		return o, invalid()
	}
	if o.Address != "" {
		address, _, err := models.BitcoinAddress(o.Address)
		if err != nil {
			return o, invalid()
		}
		o.Address = address
	}
	return o, nil
}
func normalizeTransaction(w wireTransaction, target string) (observedTransaction, error) {
	bad := func() (observedTransaction, error) { return observedTransaction{}, invalid() }
	if !validID(w.ID) || w.Status == nil || w.Status.Confirmed == nil || !*w.Status.Confirmed || len(w.Inputs) == 0 || len(w.Inputs) > MaxTransactionIO || len(w.Outputs) == 0 || len(w.Outputs) > MaxTransactionIO {
		return bad()
	}
	tx := transaction{ID: w.ID}
	if w.Status.Time != nil {
		if *w.Status.Time < 1231006505 || *w.Status.Time > 253402300799 {
			return bad()
		}
		tx.Timestamp = time.Unix(*w.Status.Time, 0).UTC().Format(time.RFC3339)
	}
	in, out := make(map[string]int64), make(map[string]int64)
	var inputSum, outputSum int64
	coinbase, unknownInput := false, false
	for _, v := range w.Inputs {
		if v.Coinbase == nil {
			return bad()
		}
		if *v.Coinbase {
			if len(w.Inputs) != 1 || v.Prevout != nil {
				return bad()
			}
			coinbase = true
			continue
		}
		if v.Prevout == nil {
			return bad()
		}
		o, err := normalizeOutput(*v.Prevout)
		if err != nil {
			return bad()
		}
		if inputSum > maxMoney-*o.Value {
			return bad()
		}
		inputSum += *o.Value
		if o.Address == "" {
			unknownInput = true
		} else {
			in[o.Address] += *o.Value
		}
	}
	for _, v := range w.Outputs {
		o, err := normalizeOutput(v)
		if err != nil {
			return bad()
		}
		if outputSum > maxMoney-*o.Value {
			return bad()
		}
		outputSum += *o.Value
		if o.Address != "" {
			out[o.Address] += *o.Value
		}
	}
	if !coinbase && outputSum > inputSum {
		return bad()
	}
	_, hasIn := in[target]
	_, hasOut := out[target]
	if !hasIn && !hasOut {
		return bad()
	}
	delta := out[target] - in[target]
	tx.Direction, tx.Value = "self", delta
	if delta > 0 {
		tx.Direction = "inbound"
	}
	if delta < 0 {
		tx.Direction, tx.Value = "outbound", -delta
	}
	edges := map[string]edge{}
	// Only a single known funding address permits assigning output amounts.
	// Multi-input transactions yield co-occurrence only, without value attribution.
	if len(in) == 1 && !unknownInput && !coinbase {
		for from := range in {
			if from == target {
				for to, value := range out {
					if to != target {
						v := value
						edges[to] = edge{to, "outbound", &v}
					}
				}
			} else if hasOut {
				v := out[target]
				edges[from] = edge{from, "inbound", &v}
			}
		}
	} else if !coinbase {
		if hasOut {
			for address := range in {
				if address != target {
					edges[address] = edge{address: address, direction: "cooccurrence"}
				}
			}
		}
		if hasIn {
			for address := range out {
				if address != target {
					edges[address] = edge{address: address, direction: "cooccurrence"}
				}
			}
		}
	}
	observed := observedTransaction{tx: tx}
	for _, e := range edges {
		observed.edges = append(observed.edges, e)
	}
	sort.Slice(observed.edges, func(i, j int) bool { return observed.edges[i].address < observed.edges[j].address })
	return observed, nil
}
func encode(v any) string { b, _ := json.Marshal(v); return string(b) }

func project(txs map[string]observedTransaction) ([]models.Evidence, bool) {
	ordered := make([]observedTransaction, 0, len(txs))
	for _, tx := range txs {
		ordered = append(ordered, tx)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i].tx, ordered[j].tx
		if a.Timestamp != b.Timestamp {
			return a.Timestamp > b.Timestamp
		}
		return a.ID < b.ID
	})
	var evidence []models.Evidence
	peers := map[string]*counterparty{}
	first, last := "", ""
	for _, tx := range ordered {
		evidence = append(evidence, models.Evidence{Kind: "crypto_transaction", Value: encode(tx.tx)})
		stamp := tx.tx.Timestamp
		if stamp != "" {
			if first == "" || stamp < first {
				first = stamp
			}
			if stamp > last {
				last = stamp
			}
		}
		for _, e := range tx.edges {
			p := peers[e.address]
			if p == nil {
				zero := int64(0)
				p = &counterparty{Address: e.address, Direction: e.direction, Value: &zero}
				peers[e.address] = p
			}
			p.Count++
			if p.Direction != e.direction {
				p.Direction = "mixed"
			}
			if e.value == nil {
				p.Value = nil
			} else if p.Value != nil {
				*p.Value += *e.value
			} // <= MaxTransactions * maxMoney, below int64.
			if stamp != "" {
				if p.First == "" || stamp < p.First {
					p.First = stamp
				}
				if stamp > p.Last {
					p.Last = stamp
				}
			}
		}
	}
	if first != "" {
		evidence = append(evidence, models.Evidence{Kind: "crypto_sample_first_seen", Value: first}, models.Evidence{Kind: "crypto_sample_last_seen", Value: last})
	}
	keys := make([]string, 0, len(peers))
	for k := range peers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	truncated := len(keys) > MaxCounterparties
	for _, k := range keys[:min(len(keys), MaxCounterparties)] {
		evidence = append(evidence, models.Evidence{Kind: "crypto_counterparty", Value: encode(peers[k])})
	}
	sort.Slice(evidence, func(i, j int) bool {
		if evidence[i].Kind != evidence[j].Kind {
			return evidence[i].Kind < evidence[j].Kind
		}
		return evidence[i].Value < evidence[j].Value
	})
	return evidence, truncated
}
