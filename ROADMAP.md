# AgentSearch roadmap

This roadmap distinguishes implemented behavior from separately scoped future work.
"Implemented" means the feature exists in this source tree and is covered by local
tests; it does not imply that every external service, platform or network combination
has been live-tested.

## Implemented

- **Source architecture:** typed targets, normalized results, capability-specific
  sources, registry, source-neutral runner and legacy output adapters.
- **Website intelligence:** configurable website profile searches with native
  YAML/JSON, Sherlock and Maigret databases; compiled, validated provider plans
  with deterministic result ordering and identical-request deduplication; worker
  pool, host pacing, proxy and User-Agent rotation, retries, explicit detection
  contracts and evidence-based WAF heuristics.
- **HIBP email breach lookup:** official authenticated endpoint, environment-based
  API keys, normalized breach evidence, distinct no-result/error semantics, bounded
  responses and redirect protection.
- **Pwned Passwords (API):** key-free k-anonymity range lookup, local SHA-1,
  non-echoing prompt, shared consumable secret buffers, strict bounded parsing.
- **Pwned Passwords (offline):** immutable verified snapshots, bounded concurrent
  reads, separate corpus maintenance command, explicit backend selection with no
  fallback. No corpus is bundled or automatically downloaded.
- **Unified HTTP API:** separate `agentsearch-server` with public `GET /health` and
  authenticated `POST /api/v1/search` over the same engine; bounded JSON input,
  environment bearer token, loopback default, admission bounds, graceful shutdown
  and safe diagnostics.
- **Domain intelligence:** opt-in read-only SecurityTrails Get Domain provider with
  sorted normalized DNS observations.
- **IP intelligence:** opt-in passive IPinfo Lite IP profile observations.
- **Bitcoin intelligence:** opt-in bounded confirmed-mainnet address observations
  with local checksum validation, provider label associations (reported as
  associations, never verified ownership) and an independent one-TXID transaction
  lookup with exact integer satoshi arithmetic.
- **Unified reporting:** canonical report snapshot with a stable investigation ID
  and evidence classes, rendered to JSON, CSV, TXT, HTML, PDF and DOCX, plus legacy
  compatibility outputs.
- **Continuous watch:** persistent baselines, bounded ADDED/REMOVED/MODIFIED change
  logs and fail-safe partial results (durable storage requires Linux).
- **Optional AI analysis:** a bounded, redacted projection of a completed canonical
  report may be interpreted by an operator-configured HTTPS provider. AI never
  selects sources, executes tools or changes deterministic evidence; failures are
  reported separately from deterministic results.
- **Hardening:** deterministic cross-source aggregation, evidence/provenance
  semantics, safe operational diagnostics, redaction, bounded operator file reads
  and shutdown/failure-ownership fixes, each with regression tests.

## Planned

- Further external providers through capability-specific interfaces.

## Not planned in this release

- Bulk password checking, corpus downloading, scanning/exploitation features,
  browser CORS, accounts/multi-tenancy, notification/alerting services and
  autonomous AI reconnaissance.

## Standing verification limits

Native Windows/macOS runtime execution, live provider calls against paid
subscriptions, production-scale load, power-loss durability and legal suitability
remain **UNVERIFIED** by the local test suite. Durable watch storage is Linux-only.
Review the applicable provider terms (including HIBP and SecurityTrails) before
public or commercial deployment.
