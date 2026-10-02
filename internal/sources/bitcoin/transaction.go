package bitcoin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

const TransactionMaxRequests = 1
const TransactionMaxObservedAddresses = 2 * MaxTransactionIO

// TransactionSource reuses the existing Esplora client without embedding the
// address source's capabilities. It never dispatches address or label lookups.
type TransactionSource struct{ client *Source }

func NewTransactionSource(endpoint string, client *http.Client, interval time.Duration) (*TransactionSource, error) {
	c, err := New(endpoint, client, interval)
	if err != nil {
		return nil, err
	}
	return &TransactionSource{client: c}, nil
}
func (s *TransactionSource) Close()                { s.client.Close() }
func (*TransactionSource) Name() string            { return "bitcoin-tx" }
func (*TransactionSource) Type() models.SourceType { return models.SourceAPI }

var _ sources.BitcoinTransactionSearcher = (*TransactionSource)(nil)

func (s *TransactionSource) SearchBitcoinTransaction(parent context.Context, value string, emit sources.Emit) error {
	if emit == nil {
		return errors.New("Bitcoin transaction source requires a result consumer")
	}
	target, err := models.NewBitcoinTransactionTarget(value)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, InvestigationTimeout)
	defer cancel()
	row := models.NewResult(s.Name(), s.Type(), target)
	row.SiteName = "Bitcoin Transaction (Esplora)"
	path := "/tx/" + target.Value()
	row.URL = s.client.baseURL + path
	row.Metadata = map[string]string{
		"provider":        "esplora",
		"network":         "bitcoin_mainnet",
		"scope":           "provider_transaction_observation",
		"verification":    "structure_and_arithmetic_only; no_independent_chain_verification",
		"derived_fields":  "input_count,output_count,coinbase,input_values_complete,input_total_sats,output_total_sats,fee_check,address_set",
		"observed_fields": "txid,version,locktime,size,weight,fee_sats,status,block,inputs,outputs",
		"attribution":     "none; observed addresses do not establish ownership or transfer direction",
	}
	requests := 0
	var raw json.RawMessage
	err = s.client.getBounded(ctx, path, &requests, TransactionMaxRequests, "Transaction not found", &raw)
	if err == nil {
		row.Evidence, err = parseTransaction(raw, target.Value())
	}
	clear(raw)
	if err == nil && ctx.Err() != nil {
		row.Evidence = nil
		err = requestFailure(ctx, ctx.Err())
	}
	row.Metadata["provider_requests"] = strconv.Itoa(requests)
	row.Status = models.StatusFound
	if err != nil {
		var e *failure
		if errors.As(err, &e) && e.kind == "not_found" {
			row.Status = models.StatusNotFound
			row.Metadata["absence_scope"] = "provider_lookup_only"
			err = nil
		} else {
			row.Status = models.StatusError
			if errors.As(err, &e) {
				kind := e.kind
				if e.status >= 500 {
					kind = "service_unavailable"
				}
				row.Metadata["error_kind"] = kind
				if e.status != 0 {
					row.Metadata["http_status"] = strconv.Itoa(e.status)
				}
				if e.retry != 0 {
					row.Metadata["retry_after_seconds"] = strconv.FormatUint(e.retry, 10)
				}
			}
			row.Error = err.Error()
		}
	}
	if e := emit(row.Normalized()); e != nil {
		return e
	}
	return err
}
