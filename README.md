# AgentSearch

AgentSearch is a Go command-line tool, with an optional operator HTTP API, for
authorized account discovery and exposure checks. It searches configurable
website profile databases for usernames, performs authenticated email breach
lookups and key-free password exposure checks through
[Have I Been Pwned (HIBP)](https://haveibeenpwned.com/), and offers opt-in
passive domain, IP, and Bitcoin intelligence — all through one normalized
result model and a common reporting pipeline.

It is intended for defensive investigations, personal exposure checks, and
security research where you have permission to query the target. A match is
evidence to review, not proof of identity or of a currently compromised
account.

## Features

- Username/email profile checks across configurable website databases
  (native YAML/JSON, Sherlock, and Maigret formats)
- HIBP email breach lookup (API subscription key, supplied via environment)
- Pwned Passwords checks: key-free k-anonymity API lookup or an explicit
  offline snapshot backend; passwords are read from a no-echo prompt
- Opt-in SecurityTrails domain/DNS intelligence
- Opt-in IPinfo Lite passive IP profiles
- Opt-in Bitcoin mainnet address observations, provider label associations,
  and single-transaction lookups
- Continuous watch mode with persistent baselines and bounded change logs
- Reports in JSON, CSV, TXT, HTML, PDF, and DOCX with a canonical schema,
  stable investigation IDs, and evidence provenance
- Optional AI interpretation of a bounded, redacted evidence snapshot
- A separate authenticated HTTP API server over the same engine

## Architecture

```text
CLI (agentsearch) / HTTP API (agentsearch-server)
        ↓
application orchestration (target validation, diagnostics, shutdown)
        ↓
source dispatcher (capability-based registry)
        ↓
source implementations (websites, HIBP, passwords, domain, IP, bitcoin)
        ↓
normalized results with evidence and provenance
        ↓
deterministic aggregation
        ↓
reporting (canonical + legacy outputs) / API responses
        ↓
optional AI analysis of the completed report
```

Individual sources have specialized internals; the username/website source
follows this more specific pipeline:

```text
username
→ compiled provider plan (validated once, deterministic order)
→ bounded concurrent execution (worker pool + per-host pacing)
→ transport (hardened redirects, timeouts, bounded responses)
→ response acquisition (deduplicated identical requests)
→ detector (explicit per-provider contracts)
→ normalized result
→ deterministic emission and aggregation
```

## Supported Intelligence

| Area | Description | Activation |
| --- | --- | --- |
| Username/email websites | Profile checks across configured sites | `-u`, `-f` |
| Email breach exposure | HIBP authenticated breach lookup | `-email` + service config |
| Password exposure | Pwned Passwords API or offline snapshot | `-password-prompt` |
| Domain/DNS | SecurityTrails Get Domain observations | `-domain` + service config |
| IP profile | IPinfo Lite passive observations | `-ip` + service config |
| Bitcoin address | Confirmed-mainnet activity observations | `-bitcoin` + service config |
| Bitcoin labels | Provider label associations (not ownership) | separate service entry |
| Bitcoin transaction | One bounded TXID lookup | `-bitcoin-tx` + service config |
| Continuous watch | Repeated investigation of a watchlist | `-watch-file` |
| AI analysis | Optional interpretation of finished evidence | `-ai` + `configs/ai.yaml` |

All external providers default to disabled and are enabled explicitly in
`configs/services.yaml`. API keys are referenced by environment variable
name only; no key values belong in configuration files.

## Username Search

The username pipeline compiles the configured site list into a validated
provider plan when the source starts: duplicate provider names keep their
first definition, URL templates and detection-rule regular expressions are
verified up front, and providers are ordered deterministically. Execution is
concurrent within a bounded worker pool with per-host pacing; identical
requests (same method, URL, payload, redirect policy, and request headers)
are fetched once per search and classified separately for each provider.
Response bodies are downloaded only when a provider's detection contract
reads them; status-based providers classify from the status line, bounded
headers, and redirect metadata. Results are always emitted in plan order, so
repeated runs produce identical output.

Each result carries one of four statuses:

- `found` — an explicit detection rule matched (or, for status-contract
  sites, the configured existence status was returned);
- `not_found` — an explicit absence rule, absence status, or redirect
  absence rule matched;
- `error` — the provider failed, returned unusable or ambiguous evidence
  (including unmatched responses for sites with explicit presence rules,
  oversized bodies for body-reading contracts, and unfollowed redirects no
  rule classifies);
- `blocked` — genuine WAF/challenge evidence was observed (challenge/deny
  status with CDN markers, challenge-page markers, or operator-configured
  WAF rules). A CDN header alone on an ordinary response is not treated as
  a block.

Ambiguous evidence is never silently reported as `found`, and provider
failures are never silently reported as `not_found`. External sites change
their pages, walls, and status behavior over time; the bundled
`configs/sites.yaml` is a maintained example set, and detection accuracy for
any specific site depends on its current live behavior. Review `found`
results as evidence, not as certainty.

## Email and Password Exposure

- `-email ADDRESS` queries the official HIBP v3 breach API. It requires an
  HIBP subscription key exposed through the environment variable named in
  `configs/services.yaml` (default `HIBP_API_KEY`). No-result and error
  outcomes are reported distinctly.
- `-password-prompt` reads one password from an interactive terminal
  without echo, hashes it locally with SHA-1, and sends only the first five
  hash characters to the key-free Pwned Passwords range API. The full
  password and full hash never leave the process.
- `-password-backend local -password-db ROOT` checks against an explicit
  offline snapshot instead; nothing is downloaded automatically, and the
  backend never falls back silently. Snapshots are prepared and activated
  with the separate `agentsearch-corpus` command. See
  [docs/offline-passwords.md](docs/offline-passwords.md).

## Domain, IP, and Bitcoin Intelligence

- `-domain HOSTNAME` returns sorted, normalized DNS observations from the
  read-only SecurityTrails Get Domain endpoint.
- `-ip ADDRESS` returns passive IPinfo Lite profile observations. No
  scanning is performed.
- `-bitcoin ADDRESS` validates the address locally (Base58Check/Bech32) and
  returns bounded confirmed-mainnet activity observations via a
  Blockstream Esplora-compatible endpoint, with exact integer satoshi
  arithmetic. Optional WalletExplorer label lookups report provider
  associations, never verified ownership.
- `-bitcoin-tx TXID` performs one bounded transaction lookup with neutral
  evidence for inputs, outputs, status, and observed addresses.

Details and semantics: [docs/external-intelligence.md](docs/external-intelligence.md),
[docs/bitcoin.md](docs/bitcoin.md), [docs/bitcoin-labels.md](docs/bitcoin-labels.md),
[docs/bitcoin-transactions.md](docs/bitcoin-transactions.md).

## Monitoring / Watch

`-watch-file watchlist.yaml` repeatedly investigates a YAML list of public
targets through the same sources, maintaining persistent per-target
baselines and appending bounded `ADDED`/`REMOVED`/`MODIFIED` change records
to JSONL logs under the state directory. Cycle interval and concurrency are
bounded flags; partial provider failures are recorded without corrupting
baselines. Durable storage requires Linux. See [docs/watch.md](docs/watch.md).

## Reporting

Every investigation produces a canonical report snapshot with a stable
investigation ID, per-source results, typed evidence with provenance,
correlations, warnings, and errors. Formats:

- **JSON** — pretty-printed and human-readable: the canonical
  `<target>_report.json`, a legacy result array `<target>.json`, and a
  compact `<target>_summary.json`;
- **CSV** — a canonical typed-record file and a legacy nine-column file;
- **TXT** — sectioned plain text with bounded line width;
- **HTML** — a single self-contained offline file (inline CSS, no scripts,
  no external resources, strict CSP meta tag);
- **PDF** — embedded font, no external assets;
- **DOCX** — standard OOXML readable by python-docx and common editors.

Select formats with `-of json,csv,txt,html,pdf,docx` and the output
directory with `-o`. Legacy `-rf` bridge outputs (CLI text and reports under
`./output`) are preserved for compatibility. See
[docs/reporting.md](docs/reporting.md).

## Optional AI Analysis

AI analysis is an optional interpretation layer, not the reconnaissance
engine. With `-ai` (CLI) or `analysis: true` (API) *and* `enabled: true` in
`configs/ai.yaml`, a bounded, redacted projection of the completed canonical
report is sent to an operator-configured OpenAI-compatible HTTPS endpoint.
The response is parsed into a structured analysis whose statements carry
explicit references to evidence items; unreferenced claims are rejected.
Input and output sizes are bounded, secrets are redacted before submission,
and failures are fail-soft: deterministic results are always reported, with
analysis errors recorded separately. The AI layer selects no sources,
executes no tools or shell commands, and performs no discovery of its own.
See [docs/ai-analysis.md](docs/ai-analysis.md).

## Installation and Build

Requirements: Go 1.24 or later and network access to the sources you query.

```sh
cd AgentSearch
go build -o agentsearch ./cmd/agentsearch
go build -o agentsearch-server ./cmd/agentsearch-server
go build -o agentsearch-corpus ./cmd/agentsearch-corpus
go build -o convert ./cmd/convert
```

Run commands from the repository root so relative configuration paths
resolve. On Windows, build the corresponding `.exe` binaries.

## Usage

```sh
# Username search across the configured sites
./agentsearch -u johndoe

# Multiple targets from a file (one per line)
./agentsearch -f targets.txt

# Select output formats and directory
./agentsearch -u johndoe -of json,html,pdf -o results

# Email breach lookup (requires enabled service + HIBP_API_KEY in the environment)
./agentsearch -email user@example.com

# Password exposure check (no-echo prompt, k-anonymity API)
./agentsearch -password-prompt

# Explicit offline password backend
./agentsearch -password-prompt -password-backend local -password-db ./pwned-db

# Domain, IP and Bitcoin intelligence (each requires an enabled service entry)
./agentsearch -domain example.com
./agentsearch -ip 203.0.113.7
./agentsearch -bitcoin bc1q...
./agentsearch -bitcoin-tx <64-hex-txid>

# Continuous monitoring
./agentsearch -watch-file watchlist.yaml -watch-interval 60s

# Optional AI interpretation of the finished report
./agentsearch -u johndoe -ai
```

Frequently used options: `-s` sites database, `-services` service
configuration, `-w` workers, `-rl` per-host delay, `-rt` request timeout,
`-retries` retry limit, `-p` proxies file, `-ua` User-Agent list, `-utls`
experimental browser-like TLS (HTTP/1.1, not an anti-bot bypass). Run
`./agentsearch -h` for the complete list. The `-d` flag is a retained
compatibility stub.

**Never put passwords in website targets, target files, email input, or
service YAML — use `-password-prompt`.**

### HTTP API

`agentsearch-server` exposes the same engine over HTTP: public
`GET /health` and authenticated `POST /api/v1/search` (JSON body with
`type` and `target`, optional `analysis: true`). The bearer token is
supplied only through an environment variable (default
`AGENTSEARCH_API_TOKEN`); the server listens on loopback by default,
bounds request sizes and concurrency, and shuts down gracefully. Use TLS
termination in front of any non-loopback deployment.

## Configuration

| File | Purpose |
| --- | --- |
| `configs/sites.yaml` | Website database: URL templates, check types (`status_code`, `message`, `response_url`, `header`), absence/presence rules, redirect rules, WAF indicators, weights. Sherlock/Maigret databases can be converted with `./convert`. |
| `configs/services.yaml` | External providers for `-email`, `-domain`, `-ip`, `-bitcoin`, `-bitcoin-tx`, and explicit password settings. All disabled by default; API keys referenced by environment variable name only. |
| `configs/ai.yaml` | Optional AI analysis: provider endpoint, model, input/output bounds, timeout, and the API-key environment variable name. |

`{username}` and `{target}` placeholders are substituted into site URL
templates, request payloads, and detection rule strings/regexes (regex
substitution quotes the target). Detection semantics — including why
ambiguous responses become errors rather than findings — are documented in
the configuration reference section of this repository's docs and enforced
by regression tests.

## Security and Privacy

AgentSearch is designed to keep reconnaissance bounded and to avoid
handling or exposing secrets unnecessarily:

- All requests carry timeouts; retries are bounded and disabled with
  `-retries 0`; response bodies are capped at 128 KiB.
- Redirects are validated: the retry transport never follows redirects
  itself, per-site redirect policy is enforced, redirect chains are capped,
  HTTPS→HTTP downgrades are refused, and sensitive header values are
  stripped on cross-origin redirects.
- Proxy entries are validated rather than silently bypassed; an
  unavailable SOCKS proxy is never dialed past.
- TLS validation is standard Go; the experimental uTLS path verifies the
  destination server name and is pinned to HTTP/1.1.
- API keys and tokens are read from environment variables only and are
  redacted from results, logs, and reports.
- Passwords are read without echo, hashed locally, and only five SHA-1
  prefix characters ever leave the process (or nothing, in local mode).
- Concurrency is bounded (worker pool, per-host pacing, server admission
  limits). There is no crawling, no path fuzzing, no username enumeration,
  no credential attacks, and no exploit functionality.

These are engineering bounds, not an absolute security guarantee. Review
provider terms (including HIBP and SecurityTrails) before public or
commercial deployment.

## Project Structure

```text
cmd/agentsearch/         CLI entrypoint and watch mode
cmd/agentsearch-server/  authenticated HTTP API server
cmd/agentsearch-corpus/  offline password snapshot maintenance
cmd/convert/             Sherlock/Maigret site-database converter
configs/                 sites.yaml, services.yaml, ai.yaml
docs/                    feature documentation
internal/app/            orchestration, runner, search service
internal/analysis/       optional AI analysis layer
internal/config/         configuration loading and validation
internal/detector/       website detection contracts
internal/models/         targets, results, evidence, site schema
internal/network/        HTTP clients, retry, proxy, uTLS, UA rotation
internal/ratelimit/      per-host pacing
internal/report/         canonical report model and renderers
internal/sources/        source implementations and registry
internal/storage/        legacy streamed outputs
internal/watch/          continuous monitoring
internal/worker/         bounded worker pool
tests/                   smoke test and report validators
```

## Testing

```sh
go test ./...            # unit, integration and regression tests
go test -race ./...      # race detector
go vet ./...
python3 tests/smoke.py   # offline end-to-end CLI/server smoke test
```

`tests/validate_reports.py` and `tests/validate_ai_reports.py` structurally
validate generated report artifacts (pypdf, PyMuPDF, python-docx). All
tests run offline against local fixtures; no live provider calls are made
by the test suite.

## Limitations

- Detection accuracy against live websites depends on their current
  behavior; sites change layouts, add challenge walls, or alter status
  semantics without notice.
- Bundled provider entries in `configs/sites.yaml` are examples, not a
  maintained guarantee of coverage.
- Native Windows/macOS runtime behavior, live paid-provider calls, and
  production-scale load are not exercised by the local test suite.
- Durable watch storage requires Linux.
- Word/LibreOffice interoperability of DOCX output is validated
  structurally, not visually.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the implemented/planned breakdown.

## License

MIT — see [LICENSE](LICENSE).
