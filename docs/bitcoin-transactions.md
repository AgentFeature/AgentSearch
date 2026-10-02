# Bitcoin Transaction Investigation

A passive, opt-in mainnet transaction lookup. Source `bitcoin-tx` accepts target
`bitcoin_tx` and requests exactly one transaction from the configured Esplora
endpoint. It does not activate address history or WalletExplorer label lookups.
Provider observations are not independent proof of chain inclusion, transaction
validity, ownership, identity, or transfer direction.

## Enable and invoke

In the operator-owned services file (disabled in the shipped example):

```yaml
services:
  bitcoin_tx:
    enabled: true
    api_url: "https://blockstream.info/api"
    min_interval: "1s"
```

`bitcoin`, `bitcoin_labels`, and `bitcoin_tx` are independent opt-ins. The
transaction mode works when both other Bitcoin services are disabled or absent.
No provider key is needed; `api_key_env` is rejected. Server bearer authentication
is separate and is never forwarded to Esplora.

```sh
# Public genesis transaction ID; this example is not a live verification claim.
TXID=4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
agentsearch -bitcoin-tx "$TXID" -services configs/services.yaml \
  -of json,txt -rf cli,html
```

The existing authenticated `POST /api/v1/search` accepts:

```json
{"type":"bitcoin_tx","target":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"}
```

Use the server's existing `-services` option to load the enabled service. There
is no new route or request schema. Invalid IDs and password/private-key/seed
fields are rejected before a provider request. The ID must have exactly 64
hexadecimal characters after trimming surrounding whitespace; it is stored in
lowercase. Internal whitespace, prefixes, URLs, and nonhex characters fail.
Raw input longer than 128 bytes fails even if padded only with whitespace.
Identifier syntax alone does not establish existence or mainnet membership.

Only services, positive timeout, output, and report flags can accompany
`-bitcoin-tx`. It cannot be combined with `-bitcoin`, `-u`, `-f`, other search
modes, website proxies, or retry flags. Legacy `-u`/`-f` never auto-detect TXIDs.

## Provider and bounds

Default provider: Blockstream's public Esplora mainnet API.
Contract: https://github.com/Blockstream/esplora/blob/master/API.md
Only `GET /api/tx/<validated-txid>` is requested. The endpoint is operator
configuration, not user input; HTTPS is required except literal-loopback HTTP
fixtures. A custom endpoint must actually serve mainnet: no second request is
made to attest its chain or honesty.

| Resource | Hard bound |
| --- | --- |
| Provider requests per investigation | 1 |
| Application retries | 0 |
| Request deadline, including pacing | 15 seconds, or shorter configured timeout |
| Investigation deadline | 90 seconds, or earlier caller deadline |
| Response body | 1 MiB (one extra byte detects excess) |
| Inputs / outputs | 1,000 each |
| Distinct observed addresses | 2,000, implied by the input/output limits |
| Evidence records | At most 4,003 |
| Pacing interval | Default 1 second; operator range 1–30 seconds |

The existing service transport, limiter, cancellation and redirect rejection are
reused. No pagination, recursion, address expansion, graph traversal, batch
history, labels, wallet enumeration, transaction construction, signing, or
broadcasting occurs. Scripts and witnesses may arrive inside the bounded JSON
body but are discarded and never emitted. Custom transports are not a supported
operator configuration mechanism.

## Normalized evidence

One enclosing result carries `source=bitcoin-tx`, `source_type=api`, the canonical
TXID and target type, `metadata.provider=esplora`, mainnet scope, and the trusted
endpoint URL. That provenance applies to every evidence item. Each item has a
stable kind and a compact JSON object value, using the existing evidence model:

- `crypto_transaction_summary`: TXID, version, locktime, size, weight, optional
  `fee_sats`; input/output counts and coinbase flag; `input_values_complete`,
  optional `input_total_sats`, `output_total_sats`, and `fee_check`.
- `crypto_transaction_status`: explicit `confirmed` boolean. An unconfirmed
  transaction is a **found** provider observation, never a not-found result.
- `crypto_transaction_block`: only supplied height, hash, or UTC timestamp.
  Missing fields are omitted. Contradictory block fields on an unconfirmed
  transaction fail validation. No confirmation count or block data is invented.
- `crypto_transaction_input`: zero-based provider index, coinbase flag; for
  normal inputs, previous TXID/vout and available previous value/address/script
  type. Coinbase is not an ordinary previous-output input.
- `crypto_transaction_output`: zero-based provider index, integer `value_sats`,
  available address, and bounded provider script-type token. Missing addresses
  and nonstandard scripts are valid. Raw script bytes are not retained.
- `crypto_transaction_address_observed`: sorted, deduplicated addresses with
  neutral `in_input_previous_output` and `in_output` flags. Both may be true.
  No address is classified as sender, recipient, change, owner, or counterparty.

Input and output entries retain provider order. Direct observations and derived
fields are explicitly listed in result metadata. Counts, the coinbase summary,
value completeness, totals, fee consistency, and the observed-address set are
**derived** from the validated transaction, not extra provider assertions.

All values and totals use exact integer satoshis, with negative, type, overflow,
and 21-million-BTC monetary-range checks. Output values are required. A normal
input may lack its previous value or whole previous output: this leaves the
input total absent and `input_values_complete=false`, never a fabricated zero.
No fee is synthesized when the provider omits it. If every normal input value
and the provider fee exist, input total minus output total must equal that fee;
otherwise the transaction fails closed. `fee_check` is `consistent`,
`unavailable`, or `not_applicable` for coinbase. Coinbase has no ordinary input
total, and a supplied coinbase fee must be zero. Output totals remain exact.

## Failure semantics

Only provider HTTP 404 with the bounded explicit Esplora message
`Transaction not found` produces `not_found`, scoped to that provider lookup.
An arbitrary proxy HTML/404 response is an error, not evidence of absence.
Timeout/cancellation, DNS/TLS/network failures, HTTP 429, HTTP 5xx, redirects,
malformed JSON, numeric violations, inconsistent fees, oversized responses and
unsupported formats never become not-found or truncated success.

Source error metadata uses `timeout`, `cancelled`, `network_failure` (including
DNS/TLS), `rate_limited`, `service_unavailable` (5xx), `http_error`,
`invalid_response` (malformed/incomplete essential structures),
`inconsistent_fee`, `response_too_large`, `data_limit`, or
`unsupported_response`. Retry-After is retained as bounded metadata but never
causes a retry. Error bodies and arbitrary transport error strings are not
exposed. The HTTP API retains its established error sanitization and mapping:
429 rate limit, 504 timeout, 408 cancellation, 503 service unavailability, and
502 other upstream failures; explicit absence returns a normal 200 result.

The parser rejects absent status/version/locktime/size/weight, empty input or
output lists, missing required normal-input references or output values,
duplicate references, ambiguous duplicate JSON keys, and unsupported addresses.
Array limits stop decoding before entry 1,001 is appended. JSON nesting is capped
at 16 and object keys at 64; non-ASCII keys are rejected to avoid ambiguous
case-folded field matching. Unknown bounded script-type tokens are kept without
interpretation. This is structural/arithmetic validation, **not** script
execution, signature validation, merkle-proof verification, or an independent
recomputation of the transaction ID.

## Outputs and verification

All six canonical report formats retain neutral evidence and exact satoshi values.
Legacy CSV remains summary-only and is accompanied by complete `_report.csv`.
Transaction observations are not scored: JSON omits confidence, human formats say
`not scored`, and legacy CSV leaves its confidence cell blank. The old DOCX licensing
failure has been replaced by verified local OOXML generation. See [reporting](reporting.md)
for package/parser checks, PDF font limits and unverified Office interoperability.

Deterministic local tests cover confirmed/unconfirmed and coinbase observations,
multiple inputs/outputs, missing values and addresses, nonstandard scripts,
exact arithmetic and fee failures, bounded lists/bodies, HTTP and transport
failures, provenance, ordering, duplicate keys, independent service selection,
CLI JSON/TXT/CSV/HTML reports, API authentication and serialization, and legacy
regressions. `FuzzTransactionParser` is bounded by the response limit. Synthetic
fixtures do not claim to be real transactions. No live transaction request was
performed for this feature; documentation fetches are not live verification.

The provider learns the queried public TXID. Availability, freshness and chain
claims depend on the chosen provider. There is no ownership attribution, entity
correlation, graph expansion, clustering, monitoring, risk scoring, or label
enrichment.
