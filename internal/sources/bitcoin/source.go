package bitcoin

import (
	"context"
	"errors"
	"sort"
	"strconv"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

func (*Source) Name() string            { return "bitcoin" }
func (*Source) Type() models.SourceType { return models.SourceAPI }

var _ sources.BitcoinSearcher = (*Source)(nil)

// SearchBitcoin emits bounded observations and a separate error row on failure.
// This preserves partial evidence through the API, which scrubs error rows.
func (s *Source) SearchBitcoin(parent context.Context, value string, emit sources.Emit) error {
	if emit == nil {
		return errors.New("Bitcoin requires a result consumer")
	}
	target, err := models.NewBitcoinTarget(value)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, InvestigationTimeout)
	defer cancel()
	_, kind, _ := models.BitcoinAddress(target.Value())
	row := models.NewResult(s.Name(), s.Type(), target)
	row.SiteName = "Bitcoin (Esplora)"
	row.URL = s.baseURL + "/address/" + target.Value()
	row.Metadata = map[string]string{
		"provider": "esplora", "scope": "confirmed_provider_observation", "address_validation": "local_checksum",
		"history_scope": "bounded_confirmed_sample", "history_status": "unavailable",
		"transaction_value_semantics": "absolute_target_net_utxo_change_including_fees",
		"counterparty_semantics":      "single_funding_address_output_values_otherwise_cooccurrence_only; no_identity_inference",
	}
	row.Evidence = []models.Evidence{{Kind: "crypto_address", Value: target.Value()}, {Kind: "crypto_network", Value: "bitcoin_mainnet"}, {Kind: "crypto_address_type", Value: kind}}
	row.Metadata["statistics_status"] = "unavailable"
	requests := 0
	var data addressData
	err = s.get(ctx, "/address/"+target.Value(), &requests, &data)
	if err == nil && !data.valid(target.Value()) {
		err = invalid()
	}
	if err == nil {
		row.Metadata["statistics_status"] = "observed"
		c := data.Chain
		for _, field := range []struct {
			kind  string
			value int64
		}{
			{"crypto_confirmed_transaction_count", *c.Count}, {"crypto_confirmed_received_sats", *c.Received},
			{"crypto_confirmed_sent_sats", *c.Sent}, {"crypto_confirmed_balance_sats", *c.Received - *c.Sent},
		} {
			row.Evidence = append(row.Evidence, models.Evidence{Kind: field.kind, Value: strconv.FormatInt(field.value, 10)})
		}
		txs, stop, historyErr := s.history(ctx, target.Value(), &requests)
		if historyErr == nil && ((len(txs) == 0 && *c.Count > 0) || (len(txs) > 0 && *c.Count == 0)) {
			historyErr = invalid()
			stop = "inconsistent_statistics"
		}
		history, truncated := project(txs)
		row.Evidence = append(row.Evidence, history...)
		row.Metadata["history_stop"] = stop
		row.Metadata["retained_transactions"] = strconv.Itoa(len(txs))
		row.Metadata["counterparties_truncated"] = strconv.FormatBool(truncated)
		row.Metadata["history_status"] = "observed"
		if historyErr != nil {
			row.Metadata["history_status"] = "partial"
			if len(txs) == 0 {
				row.Metadata["history_status"] = "unavailable"
			}
		}
		err = historyErr
	}
	if row.Metadata["statistics_status"] == "unavailable" {
		row.Metadata["scope"] = "local_address_validation_only"
	}
	row.Metadata["provider_requests"] = strconv.Itoa(requests)
	row.Status = models.StatusFound
	sort.Slice(row.Evidence, func(i, j int) bool {
		if row.Evidence[i].Kind != row.Evidence[j].Kind {
			return row.Evidence[i].Kind < row.Evidence[j].Kind
		}
		return row.Evidence[i].Value < row.Evidence[j].Value
	})
	if e := emit(row.Normalized()); e != nil {
		return e
	}
	if err != nil {
		failed := models.NewResult(s.Name(), s.Type(), target)
		failed.SiteName, failed.URL = row.SiteName, row.URL
		failed.Status, failed.Error = models.StatusError, err.Error()
		failed.Metadata = map[string]string{"scope": "provider_failure"}
		var e *failure
		if errors.As(err, &e) {
			failed.Metadata["error_kind"] = e.kind
			if e.status != 0 {
				failed.Metadata["http_status"] = strconv.Itoa(e.status)
			}
			if e.retry != 0 {
				failed.Metadata["retry_after_seconds"] = strconv.FormatUint(e.retry, 10)
			}
		}
		if e := emit(failed.Normalized()); e != nil {
			return e
		}
	}

	return err
}

func (s *Source) history(ctx context.Context, target string, requests *int) (map[string]observedTransaction, string, error) {
	txs := map[string]observedTransaction{}
	cursor := ""
	cursors := map[string]bool{}
	for page := 0; page < MaxPages; page++ {
		path := "/address/" + target + "/txs/chain"
		if cursor != "" {
			path += "/" + cursor
		}
		var wire []wireTransaction
		if err := s.get(ctx, path, requests, &wire); err != nil {
			return txs, "provider_error", err
		}
		if wire == nil || len(wire) > PageSize {
			return txs, "invalid_page", invalid()
		}
		// Validate the whole page before committing any of its observations.
		batch := map[string]observedTransaction{}
		for _, w := range wire {
			tx, err := normalizeTransaction(w, target)
			if err != nil {
				return txs, "invalid_page", err
			}
			for _, seen := range []map[string]observedTransaction{batch, txs} {
				if old, ok := seen[w.ID]; ok && !sameTransaction(old, tx) {
					return txs, "conflicting_transaction", invalid()
				}
			}
			batch[w.ID] = tx
		}
		for id, tx := range batch {
			txs[id] = tx
		}
		if len(txs) >= MaxTransactions {
			// Sort/deduplicate before truncation; ties use txid, never map order.
			ids := make([]string, 0, len(txs))
			for id := range txs {
				ids = append(ids, id)
			}
			sort.Slice(ids, func(i, j int) bool {
				a, b := txs[ids[i]].tx, txs[ids[j]].tx
				if a.Timestamp != b.Timestamp {
					return a.Timestamp > b.Timestamp
				}
				return a.ID < b.ID
			})
			for _, id := range ids[MaxTransactions:] {
				delete(txs, id)
			}
			return txs, "transaction_limit", nil
		}
		if len(wire) < PageSize {
			return txs, "page_end", nil
		}
		// The cursor is the provider's last record, not our presentation ordering.
		cursor = wire[len(wire)-1].ID
		if cursors[cursor] {
			return txs, "repeated_cursor", invalid()
		}
		cursors[cursor] = true
	}
	return txs, "page_limit", nil
}

func sameTransaction(a, b observedTransaction) bool {
	if a.tx != b.tx || len(a.edges) != len(b.edges) {
		return false
	}
	for i, e := range a.edges {
		f := b.edges[i]
		if e.address != f.address || e.direction != f.direction || (e.value == nil) != (f.value == nil) {
			return false
		}
		if e.value != nil && *e.value != *f.value {
			return false
		}
	}
	return true
}
