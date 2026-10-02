# Bitcoin Address Intelligence

This is an opt-in passive source in the existing AgentSearch pipeline. It performs
read-only requests for one Bitcoin mainnet address using Blockstream's public
Esplora API. It never follows discovered addresses or queries mempool history.
Provider data is an observation, not independently verified blockchain truth.
Review the provider's current terms, availability and rate policy before use.

## Enable and run

In your operator-owned services file:

```yaml
services:
  bitcoin:
    enabled: true
    api_url: "https://blockstream.info/api"
    min_interval: "1s"
```

No provider key is required or read. `api_key_env` is rejected for this source.
The optional request interval must be between 1s and 30s. This configuration
uses the existing services schema; disabled sources make no requests.

```sh
go run ./cmd/agentsearch -bitcoin 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa \
  -services configs/services.yaml -of json,txt -rf cli,html
```

`-bitcoin` accepts exactly one address and only services, timeout, output and
report options. It cannot be mixed with other target modes, proxy settings or
website retry/worker flags. `-u` and `-f` retain their legacy website behavior.
The legacy `-rf` bridge writes to `./output/`; all six `-of` formats honor `-o`.
See [reporting](reporting.md). `-o` controls
storage output and summary JSON, as before this feature.

The existing authenticated HTTP server also supports:

```json
{"type":"bitcoin","target":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}
```

Send that body to `POST /api/v1/search` after enabling the service through the
server's `-services` configuration. Existing API authentication, admission,
request deadlines and response error semantics remain unchanged. No provider,
endpoint, key, seed, private-key or wallet fields are accepted in this request.

## Address contract

Supported mainnet addresses:

- P2PKH and P2SH: Base58Check version and double-SHA256 checksum validation.
- P2WPKH and P2WSH: BIP173 Bech32 v0 and witness-program length validation.
- P2TR: BIP350 Bech32m v1 with a 32-byte witness program.

Witness addresses are canonicalized to lowercase; mixed case is invalid.
Base58 case is preserved. Surrounding whitespace is trimmed, input length is
bounded, and paths/URIs are not accepted as addresses. Wrong networks and valid
but unsupported witness versions/programs return an unsupported-address error;
malformed encodings/checksums return an invalid-address error. Validation does
not imply the address has activity, an owner, or spendable funds.

## Source and evidence contract

`source=bitcoin`, `source_type=api`, `target_type=bitcoin`. The result URL records
the configured provider's address endpoint; source code contains no attribution
labels. `address_validation=local_checksum` distinguishes locally derived address
metadata from the provider's observations. `scope=local_address_validation_only`
is used if statistics fail. The existing semantic view recognizes
`bitcoin_address` observations.

The existing `Evidence{kind,value}` model is unchanged:

| Kind | Value |
| --- | --- |
| `crypto_address` | Canonical address |
| `crypto_network` | `bitcoin_mainnet` |
| `crypto_address_type` | `p2pkh`, `p2sh`, `p2wpkh`, `p2wsh`, `p2tr` |
| `crypto_confirmed_transaction_count` | Exact decimal integer |
| `crypto_confirmed_received_sats` | Exact decimal integer, confirmed funded-output sum |
| `crypto_confirmed_sent_sats` | Exact decimal integer, confirmed spent-output sum |
| `crypto_confirmed_balance_sats` | Received minus sent, excluding unconfirmed changes |
| `crypto_sample_first_seen` | Earliest available timestamp in retained transactions |
| `crypto_sample_last_seen` | Latest available timestamp in retained transactions |
| `crypto_transaction` | Compact normalized JSON string: txid, optional UTC RFC3339 timestamp, direction, integer value_sats |
| `crypto_counterparty` | Compact normalized JSON string: address, interaction_count, optional sample_first_seen/sample_last_seen, optional integer observed_value_sats, direction |

These small JSON strings are selected normalized records, **not raw provider
JSON**. Scripts, witnesses, headers and unknown fields are discarded. Existing
JSON/API, TXT, CLI, HTML and DOCX detail projections can expose this evidence.
Legacy CSV intentionally retains its summary-only schema. Canonical amounts are
integer satoshis; this version does not add a BTC-specific renderer.

### Interpretation and limitations

- Only confirmed transactions/statistics are requested. Balance is not an
  unconfirmed or spendable-wallet balance. Lifetime funded/spent totals count
  address reuse; they are not net wealth.
- Sample dates describe only retained transactions with available timestamps.
  They are **not lifetime first/last activity**, and missing timestamps are
  omitted rather than synthesized. Empty samples have no dates.
- Transaction value is the absolute difference between target outputs and target
  input prevouts, including any fee debit. Direction is `inbound`, `outbound` or
  `self` relative to that net difference, not a claim about the user's intent.
- Counterparty interaction count is one per distinct retained transaction, even
  when several outputs use the same address. Sampled totals are not lifetime
  counterparty totals.
- If there is exactly one known funding address, relevant output amounts and
  directions can be represented. If funding is ambiguous (multiple addresses or
  an input without an address), counterparties are labeled `cooccurrence` with
  no amount attribution. Combined differing directions are `mixed`; any ambiguous
  interaction removes the aggregate value rather than claiming a complete total.
  Coinbase and addressless scripts do not invent counterparties. No address
  co-occurrence proves which person or organization sent funds to another.
- Valid but unsupported address encodings in provider transactions fail that page
  conservatively; earlier validated pages remain available. Oversized transactions
  likewise fail their page rather than being silently represented as complete.
- A capped or partially failed query is never evidence that older activity or
  counterparties disappeared. Statistics/history are separate provider requests,
  not an atomic chain snapshot. Obvious empty/nonempty inconsistencies are errors.

## Failure and partial results

The source emits at most two result rows: an observation row containing only
validated facts, followed by an error row if a provider stage failed. The source
also returns the error through the dispatcher. This uses the existing partial
result contract and preserves successful evidence when HTTP output scrubs error
rows. A successful local-validation row alone does not mean the provider worked:
inspect `statistics_status`, `history_status`, and the separate error row/API error.

`statistics_status` is `observed` or `unavailable`; `history_status` is `observed`,
`partial` or `unavailable`. `retained_transactions` measures this result's retained
sample, not lifetime activity. `history_stop` identifies page end, a cap, or a
failure. `counterparties_truncated` marks lexical truncation of the sampled set.
No failed statistic is replaced by a zero. Valid explicit zero statistics are
preserved as zero. Malformed data, HTTP failure, rate limit, cancellation, timeout,
response-size limit and request-budget exhaustion have separate safe error kinds.
Provider body/error strings and response headers are never used as diagnostics.

## Hard bounds

| Resource | Limit |
| --- | --- |
| Confirmed history pages | 5 |
| Transactions per page | 25, Esplora's fixed page size |
| Transactions received in accepted pages | At most 125 |
| Retained transactions | 100 |
| Retained counterparties | 256 |
| Provider HTTP requests | 6 (one statistics request plus up to five pages) |
| Automatic retries | 0, matching the service-client policy |
| Each response body | 1,048,576 bytes (one extra sentinel byte detects overflow) |
| Inputs / outputs per transaction | 1,000 each |
| Per-request deadline including pacing/body | At most 15 seconds; `-rt` can shorten it |
| Investigation deadline | 90 seconds; caller/CLI/API deadlines can shorten it |
| Request-start interval | 1 second by default, configurable to 30 seconds |

The composition root uses `network.NewServiceClient`, not the website retry or
proxy client. It reuses `ratelimit.HostLimiter`, including a minimal shared helper
to defer the next request after Retry-After. No retry loop, new HTTP stack or global
limiter was added. Redirects and cookies are disabled. Retry-After on 429/503 is
honored for later investigations sharing the client (integer or HTTP-date, bounded
to 24h; absent/invalid values default to 60s). Waiting remains cancellable and
subject to the request/investigation deadlines. Pacing is per configured source
instance, not an account-wide quota shared across processes.

Records are deduplicated by transaction ID. Conflicting normalized duplicates and
repeated cursors are rejected. Retention sorts by available timestamp descending,
then txid; counterparties sort by address before truncation. Final evidence sorts
by kind/value, independent of Go map iteration. No observed-at clock or wall-time
Duration is inserted into evidence; existing diagnostics measure execution time.

## Tests and scope

Focused tests are in `internal/models/bitcoin_test.go`,
`internal/sources/bitcoin/bitcoin_test.go`, and Bitcoin-specific config/app/HTTP/CLI
tests. They use local deterministic fixtures. Witness vectors come from BIP173,
BIP350 and Bitcoin Core's key_io_valid.json; synthetic public script-hash fixtures
exercise the counterparty cap without private keys. Fuzz targets cover address
validation and transaction normalization.

No live-provider verification was performed during implementation. Provider
contracts were checked against https://github.com/Blockstream/esplora/blob/master/API.md .
No Snapshot/Diff, recursive traversal, wallet functionality, key/seed handling,
signing, broadcasting, identity inference, attribution database, other chains or
continuous monitoring is implemented.

## Optional external provider labels

[Bitcoin Address Label Intelligence](bitcoin-labels.md) adds an independent,
opt-in WalletExplorer source to the same Bitcoin workflow. Enable
`services.bitcoin_labels.enabled` to query only the target address for a provider
association. The blockchain source remains separately enableable. No discovered
counterparties are queried for labels. A label is an external provider observation,
not independently verified ownership or an AgentSearch inference.
