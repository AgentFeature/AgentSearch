# Bitcoin Address Label Intelligence

WalletExplorer labels are **external provider observations**, not independently
verified ownership claims. AgentSearch does not infer identities, categories,
risk, criminality, or relationships to usernames, people, companies or domains.
A provider may have stale, ambiguous or incorrect associations.

## Configuration and usage

Use the existing operator-owned services file:

```yaml
services:
  bitcoin:
    enabled: true
  bitcoin_labels:
    enabled: true
    api_url: "https://www.walletexplorer.com/api/1/address-lookup"
    min_interval: "1s"
```

Both sources default to disabled. Enable either or both independently. The same
existing CLI flag selects a Bitcoin mainnet target:

```sh
go run ./cmd/agentsearch -bitcoin 16SbwNa22nBwhLtg6HzWVYFQiUxtNzAUpt \
  -services configs/services.yaml -of json,txt -rf cli,html
```

The existing authenticated `POST /api/v1/search` also accepts
`{"type":"bitcoin","target":"16SbwNa22nBwhLtg6HzWVYFQiUxtNzAUpt"}` when either
Bitcoin service is enabled through the server's `-services` option. There is no
new API route, flag, request schema, or source selector. Legacy `-u` / `-f` remain
website searches. Source IDs distinguish `bitcoin` from `bitcoin-labels`.

The optional pacing interval is 1s by default, configurable from 1s to 30s.
The label lookup's deadline includes pacing, so short deadlines can expire
while waiting. Credentials are neither required nor read; configuring
`api_key_env` for this provider is rejected. API server bearer authentication
remains separate and is never forwarded to WalletExplorer.

## Provider contract

Documentation: https://www.walletexplorer.com/api

Only `GET /api/1/address-lookup?address=ADDRESS` is implemented. No wallet, wallet
address list, transaction, batch, prefix, or alternative-name endpoint is queried.
The provider documentation specifies a boolean `found`, or a string `error` for
bad input. Bounded checks of the public documentation examples confirmed:

```json
{"found":true,"label":"BTC-e.com","wallet_id":"000003a2f31608c0","updated_to_block":967461}
```

and an unnamed wallet response containing `found:true` and `wallet_id` without a
label. These illustrate the response shape only, not verified ownership or a
current entity relationship. The implementation also successfully queried the
first public example through the actual AgentSearch CLI. Normal automated tests
make **no live requests**.

The current endpoint returns at most one scalar label and one hexadecimal wallet
identifier. It does not supply a documented category, confidence metric, or label
update timestamp. If an optional `category` string is returned, it is preserved
verbatim as a bounded provider category, without interpreting its meaning or
inferring a category from the name. Tests of that optional field use synthetic
fixtures, not a claim that it was returned live.

`updated_to_block` is checked for a bounded nonnegative integer but discarded:
it describes chain coverage, **not label freshness**. No query timestamp is used
as a provider timestamp. `label_age=unknown` is explicit.

## Normalized evidence and status

Each source lookup emits one result with:

- `source=bitcoin-labels`, `source_type=api`, `target_type=bitcoin`;
- the canonical target address from the existing mainnet validator;
- a locally constructed provenance URL for the configured address-lookup endpoint;
- `provider=WalletExplorer`, `scope=external_provider_association`;
- `ownership=not independently verified`;
- `confidence_basis=provider-reported; not scored`, `label_age=unknown`.

Named and unnamed wallet associations use the existing repeatable
`Evidence{kind,value}` structure:

```json
{
  "kind": "crypto_provider_association",
  "value": "{\"label\":\"Example Service\",\"category\":\"service\",\"provider_wallet_id\":\"abcd\"}"
}
```

The optional label and category are omitted when absent. This compact normalized
record is not raw provider JSON. Enclosing source, provider, target and URL supply
its provenance. The evidence collection can hold separate provider observations;
there is no unique address-to-entity mapping and no cross-provider conflict
resolution or name-only deduplication.

| Provider outcome | Result status | Metadata `label_status` |
| --- | --- | --- |
| Named label and identifier | `found` | `provider_label` |
| `found:false`, without contradictory association fields | `not_found` | `no_label` |
| `found:true` and identifier only | `not_found` | `no_label`; identifier still retained as an unnamed provider association |
| HTTP/transport/parse failure | `error` | `unavailable` |

`no_label` means only that this provider returned no named label. It does not mean
that no entity exists, no other provider knows a label, or that the address is safe.
HTTP 404, HTTP 429, HTTP 500, timeouts, malformed JSON, unsupported response schemas,
oversized responses, and a JSON `error` are **not** no-label results.

The source returns safe errors through the existing dispatcher. Blockchain and
label sources run independently in the existing bounded orchestration. A runtime
failure of either preserves the other's valid observations; the overall search
still reports failure. Invalid enabled-provider configuration fails application
initialization according to the existing composition policy. Disable a provider
that should not be initialized.

## Existing output and confidence compatibility

The existing JSON, TXT, CLI, HTML and DOCX detail projections consume the label
record as a separate source result. No new renderer was added. HTML continues to
escape provider strings. Reports name the source as WalletExplorer provider
associations and explicitly disclaim verified ownership.

No numerical confidence is assigned:

- JSON/API label rows omit `confidence`; the existing internal integer stays unset.
- TXT, CLI, HTML, PDF and DOCX label rows display `not scored`.
- Legacy CSV keeps its header and summary-only layout; its confidence cell is empty
  for label rows. Use JSON/TXT/reports for full evidence.
- Other source rows retain their existing numerical confidence behavior and schema.

API error-row sanitization is unchanged: HTTP clients receive the existing safe
API error classification; raw provider messages and error metadata are not exposed.
Successful observations from the independent source remain in the same response.

## Hard resource and security limits

| Resource | Bound |
| --- | --- |
| Provider requests per target | 1 |
| Automatic retries | 0 |
| Request/lookup deadline, including pacing and body | At most 15 seconds; caller and `-rt` may shorten it |
| Response body | 262,144 bytes; one sentinel byte detects overflow |
| Labels retained | 1 (the scalar provider contract; arrays are unsupported) |
| Label length | 256 UTF-8 bytes; overlong labels are rejected, never silently truncated |
| Optional category length | 256 UTF-8 bytes |
| Provider identifiers retained | 1 |
| Identifier length | 64 hexadecimal characters, canonicalized to lowercase |
| Top-level JSON fields | 32 |

The source uses the existing `network.NewServiceClient` and
`ratelimit.HostLimiter`. There is no retry loop or additional HTTP framework.
429/503 Retry-After (seconds or HTTP-date) postpones subsequent requests sharing
that source client, bounded to 24h; missing/invalid values default to 60s. Waits
remain deadline-bound. Pacing is per source instance, not a global account quota.

Redirects are not followed. Cookies, credentials, arbitrary headers, arbitrary
provider URLs, scripts, and raw response bodies are never persisted. Endpoint
configuration must use HTTPS, except literal loopback HTTP for fixtures, and
cannot contain userinfo, query arguments, fragments, or an unrelated API path.
Labels are data, not HTML or commands; control characters, bidi/format characters,
invalid UTF-8, malformed surrogate replacements and credential-shaped text detected
by the existing security redactor are rejected. This also keeps the normalized
record intact when it passes through the shared output redaction layer. JSON must be one
object with no duplicate keys or trailing document. Required fields, types,
identifiers and numeric ranges are validated. Unknown nested schemas, including
label lists, are unsupported; unknown scalar fields are ignored and never emitted.
Errors retain only fixed classifications, status codes, bounded retry delays and
standard cancellation identity, not provider text or network error chains.

## Verification and limitations

Deterministic fixture tests cover named labels, unnamed wallets, no label,
optional categories, partial source failures in both directions, independent
source enablement, error classifications, bounds, duplicate keys, safe transport,
provenance, deterministic output and parser fuzzing. CLI/TXT/HTML/CSV and HTTP
integration are tested. The old DOCX license failure was reproduced and fixed by
the canonical reporting subsystem. Current local DOCX package/parser and six-format
checks are described in [reporting](reporting.md); no Office application was tested.

Provider coverage is not complete, and live compatibility checks do not establish
label accuracy or freshness. Unexpected future schemas fail explicitly rather than
being converted to global absence. The suite is independent of live availability.

No Snapshot/Diff, counterparties' label lookups, wallet enumeration, address
clustering, identity correlation, attribution verification, risk scores, sanctions
screening, private-key/seed handling, signing, broadcasting, recursive graph work,
other chains, continuous monitoring, or dashboard is implemented.
