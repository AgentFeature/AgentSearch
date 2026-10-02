# Evidence-based AI analysis

> AI analysis is an interpretation layer over deterministic AgentSearch evidence.
> It is not an authoritative source of facts.

AI is disabled by default. Updating AgentSearch, loading reconnaissance services,
performing an ordinary search or running watch mode does not enable it. AI analysis
provides one mode, `investigation`, with no tools, autonomous decisions or discovery.

## Architecture

```text
Existing target / source selection / deterministic investigation
  -> normalized Result / Evidence
  -> canonical report snapshot
  -> analysis.Prepare -> Provider.Generate -> strict analysis validation
  -> optional structured analysis on the report / API response
```

The reporting layer already provides a private, immutable `report.Report` with
stable result IDs, ordered evidence, classifications, coverage flags and source
semantics. `Report.Snapshot()` exports a detached copy of that same schema; it is
not a parallel evidence store. `WithAnalysis` creates a new report without changing
its investigation ID, deterministic status, results, warnings or correlations.
Existing AI output is ignored when preparing a new input, preventing feedback into
the evidence stream.

`internal/analysis` owns input preparation, validation, the one-shot service and the
OpenAI-compatible HTTP adapter. Its small provider interface is:

```go
type Provider interface {
    Generate(context.Context, []byte) ([]byte, error)
}
```

The bytes are prepared JSON, not internal source state. The returned bytes are
untrusted model JSON, not an accepted result. Providers must honor cancellation and
bound allocation; the production adapter does both. Shared optional result DTOs
live in `internal/models/analysis.go` so report rendering does not import or call AI.
Sources do not import analysis. The test-only helper package `analysistest` is not
imported by production commands.

Implemented: one OpenAI-compatible, non-streaming Chat Completions adapter using
standard Go HTTP, existing YAML support and no new SDK/dependency. Anthropic and
Ollama adapters are not implemented; the byte-oriented interface permits future
local adapters without changing source execution. Configured compatible endpoints
are treated as potentially external; a loopback endpoint is not proof that its
backend keeps data local.

## Explicit opt-in and configuration

AI configuration is separate from `configs/services.yaml`:

```yaml
ai:
  enabled: false
  provider: openai-compatible
  endpoint: https://api.openai.com/v1/chat/completions
  model: gpt-4o-mini
  api_key_env: OPENAI_API_KEY
  timeout: 30s
  max_input_bytes: 65536
  max_output_tokens: 2048
```

`model` is an operator-selected model identifier, not a verified availability claim.
Choose a model/endpoint supporting Chat Completions, `response_format: json_object`,
`max_tokens` and the system/user role separation used here. Provider variations,
subscription access, rate limits and model availability are environment-dependent.

The YAML reader accepts one document, rejects unknown fields and reads at most
8 KiB. Only the environment-variable **name** belongs in YAML. Supply its value
through the process environment or your secret manager, not command arguments,
YAML, a checked-in fixture or a report. Missing/invalid configuration becomes
`ai_not_configured`; an explicit request with `enabled: false` gets `ai_disabled`.
Neither prevents deterministic reconnaissance.

CLI requires **both** `enabled: true` and `-ai`:

```sh
agentsearch -u alice -ai -ai-config configs/ai.yaml \
  -of json,csv,txt,html,pdf,docx -rf '' -o results
agentsearch -domain example.org -ai -ai-config configs/ai.yaml \
  -of json,html -rf '' -o results
```

Existing `-u`, `-f`, service-specific target flags and source selection remain intact.
`-ai-config` alone never runs analysis. `-ai` requires at least one selected output
or report format. Password flags also accept AI options, but the password itself is
never included in prepared input. Password-hash remains an internal target capability;
there is no password-hash CLI or HTTP mode.

Watch rejects AI flags. It does not invoke analysis per cycle or change observations,
changes, baselines, scheduling or source selection.

## Authenticated HTTP API

Enable operator support separately when starting the existing server:

```sh
agentsearch-server -ai-config configs/ai.yaml
```

The server's existing authentication and source configuration still apply. Each
request must also opt in:

```json
{"type":"domain","target":"example.org","analysis":true}
```

With the field absent or `false`, response shape and behavior remain unchanged.
The optional field must be a JSON boolean; null, strings and duplicates are rejected.
With `true`, the response retains its existing results/error and adds:

- `analysis`: the structured interpretation or a safe failure state;
- `report`: the canonical report including the interpretation, when snapshot
  construction succeeded. This supplies the actual result IDs/evidence needed to
  resolve citations, instead of exposing references without their source records.

No request can select the AI provider, model, endpoint, credential, headers or tools.
A missing operator configuration returns failed analysis, not an AI network request.
HTTP status and deterministic errors remain governed by reconnaissance; an AI
failure after successful reconnaissance does not turn HTTP 200 into an upstream
reconnaissance error. Analysis shares the request's existing overall deadline and
admission slot, plus its own shorter timeout. Clients must budget for the additional
latency. The server does not persist prompts, conversations or report files.

## Data sent and deterministic selection

`agentsearch.analysis.input.v1` contains only:

- mode, safe target/type, investigation status and coverage flags;
- bounded source identities/types/statuses;
- records projected from canonical evidence and sorted metadata, with ID, source ID,
  kind, value and observed/correlated/inferred/unknown classification;
- references to selected correlated records;
- safe warning/error presence messages, not raw provider diagnostics;
- explicit input truncation and omitted-record counts.

Source URLs, internal request objects, credentials, raw HTTP bodies, report rendering,
wall-clock timestamps and prior AI analysis are not serialized wholesale into input.
Structured evidence stays JSON text with `json.Number`, never floating-point satoshis.
Bitcoin transaction identifiers are retained in the Bitcoin projection; password/hash
material is not needed to explain a transaction. Redacted placeholders must not be
interpreted as equal identifiers or ownership evidence.

Selection is a deterministic **prefix** of canonical sources and evidence, followed
by sorted metadata within each source. On an oversized record, exhausted byte/record
budget or source limit, selection stops. Values are not randomly sampled or silently
clipped. Privacy-omitted records count as omitted. An oversized target is replaced
with an explicit omission marker. `input_truncated`, `omitted_records` and final
analysis limitations disclose incomplete context. Upstream coverage truncation is
separate from the AI input budget's truncation.

The input digest is SHA-256 of the actual sanitized JSON data before the fixed chat
wrapper. The same snapshot/configuration yields the same input bytes and selection.
This does **not** promise deterministic output from a real model, even with temperature
zero. Metadata duration changes in a newly collected investigation may change its
canonical IDs; repeat rendering is not a new investigation.

## References and interpretation semantics

Evidence IDs reuse the canonical result ID:

- `<result-id>/e/<index>`: zero-based canonical evidence index;
- `<result-id>/m/<index>`: zero-based index in lexically sorted metadata keys.

References must exist in the exact selected input. Each claim has a title,
description, classification, references and caveat. Output contains findings,
hypotheses, anomalies, relationships, unanswered questions and limitations. Its
summary is an application-generated count/disclaimer, not uncited model prose.
Provider/model metadata is supplied by the adapter, never accepted from the model.

Accepted classifications: `observed`, `correlated`, `inferred`, `hypothesis`, `unknown`.
Only an exact single-record quotation with the same supplied observed/correlated
classification can retain that label. Its title and caveat are replaced with explicit
quotation attribution. Otherwise that claim becomes `inferred`. Hypotheses are always
labelled `hypothesis`. This validates quotation/reference structure, not the truth of
the source or whether an inference actually follows from it.

Unsupported classifications, missing/invented/repeated references, duplicate titles
or equivalent description/reference claims, excessive collections, unknown JSON
fields, duplicate JSON keys, excessive nesting, invalid UTF-8, trailing values and
malformed output are rejected. There is no free-text fallback to a successful result.
Questions/limitations are bounded AI-authored prose, explicitly separate from facts.

## Security and privacy boundary

Evidence and targets are untrusted data. A fixed system message establishes the
analysis task and limitations; a separate user message contains a labelled JSON data
block. Instructions explicitly prohibit invented facts, ownership from co-occurrence,
identity from username similarity, compromise from generic indicators and maliciousness
from unusual infrastructure. Scores are not converted into probabilities.

The model receives no tools, source credentials, filesystem handles or execution
interface. Its output cannot select URLs, invoke sources, execute shell commands,
crawl, scan or make monitoring decisions. Suggested follow-up questions remain text.
Local tests prove structural separation and rejection/demotion rules, **not** that a
real model will always resist prompt injection or produce correct reasoning.

Preparation starts with reporting's redacted snapshot, then applies additional
sensitive-key/session/token/hash filtering. Password and password-hash inputs are
more restrictive: a redacted target, generic provider names, source statuses, and
only valid `pwned` booleans / `occurrences` decimal counts; arbitrary evidence and
metadata are excluded. The adapter additionally removes its known credential from
JSON/URL-escaped input and model content before acceptance. Integer precision is
preserved during this additional pass.

No automatic logs contain full prompts, model responses or credentials. Only the
accepted interpretation is persisted when the user requests report files. Provider
errors expose allowlisted categories, not response bodies or HTTP error chains.
Redaction is defense-in-depth, not general-purpose secret discovery: arbitrary
unlabelled secrets cannot always be recognized. Sources must maintain the existing
contract to keep credentials out of evidence. This feature is not a DLP guarantee.

The HTTP adapter uses an operator-fixed HTTPS endpoint, normal certificate checking,
no URL credentials/query/fragment, no redirects, no cookies, no environment proxies,
no compression and zero retries. Headers are fixed by code. Requests and responses
are bounded, with explicit request/analysis deadlines. No model-selected destination
or arbitrary model/header execution is supported. Public provider terms, retention
and data residency remain the operator's responsibility.

## Bounds

| Resource | Bound |
|---|---:|
| Prepared JSON input | default/hard maximum 64 KiB; configurable down to 4 KiB |
| Selected sources / records | 128 / 256 |
| Evidence value / kind | 2,048 / 256 UTF-8 bytes after sanitization |
| HTTP request body | 512 KiB |
| HTTP response body / model JSON | 32 KiB each |
| Response headers | 16 KiB |
| Attached analysis | report attachment capped at 64 KiB |
| Findings / hypotheses / anomalies / relationships | 12 / 8 / 8 / 8 |
| All claims combined | 32 |
| References per claim / total | 8 / 128 |
| Questions / model limitations | 8 / 8, plus application disclaimers |
| Title / description / caveat | 160 / 2,048 / 512 bytes |
| Question / limitation | 512 bytes |
| Structured response nesting | 12 levels |
| Output token request | default 2,048; configurable 128-4,096 |
| Request and overall analysis timeout | default 30s; configurable 1s-60s |
| Retries / HTTP connections per adapter host | 0 / 4 |

The parent CLI/API deadline can expire earlier. There is no model-specific input
tokenizer dependency: input token use is constrained conservatively by the byte
budget, not an exact tokenizer estimate. Providers that ignore the requested output
token limit are still constrained by the response byte limit. Internal test/future
adapters are trusted Go implementations required to honor their context; Go cannot
safely preempt an arbitrary noncooperative implementation.

## Reports and failures

Canonical JSON adds optional `analysis` without changing deterministic records or
IDs. Canonical CSV keeps its documented columns and embeds the bounded analysis
object in its existing `report` record's JSON value. Legacy JSON arrays and the
nine-column legacy CSV remain unchanged; use their `_report` companions for AI data.

HTML/TXT/PDF/DOCX append **AI Analysis (interpretation, not source evidence)** after
the deterministic sections. Model text uses the same escaping/inert rendering as
other untrusted values. PDF visibly escapes unsupported characters in the AI-only
section rather than losing the existing deterministic PDF over AI font coverage.
Existing overall report/file/page limits still apply; analysis does not bypass them.

Analysis status is separate from investigation status. Safe codes include
`ai_disabled`, `ai_not_configured`, `provider_unavailable`, `rate_limited`, `timeout`,
`cancelled`, `invalid_response`, `malformed_analysis`, `input_too_large`, `internal_error`.
Failures retain deterministic records and attach failed analysis. They do not change
source outcomes or erase healthy evidence. Existing output destination/resource
errors remain output errors, not successful report publication. This is not a
transactional multi-file output system.

## Executed verification

Linux, Go 1.24.13. The expected clean starting HEAD was verified. The previous
nonpersistent toolchain was absent; after restoring Go, baseline full tests, vet and
build passed before repository edits.

- Full tests, vet, build and full race suite passed during implementation.
- Credential-free fake-provider tests cover all eight internal target types, all six
  formats, disabled/opted-in operation, malformed/empty/oversized responses, provider
  errors, panic isolation, timeout and cancellation.
- Authenticated API integration covers its seven existing request target types,
  false/absent/true options, failures, citations' canonical source and password privacy.
- CLI flag parsing and the production app/output path run end-to-end with the fake;
  existing executable CLI regression tests also pass. No fake-provider production
  flag or new reconnaissance source was added.
- Real adapter/configuration/HTTP behavior was exercised against local TLS servers,
  including redirects, errors, bounds, prompt separation and runtime-generated
  credentials. Tests trust only their ephemeral certificate; production TLS is unchanged.
- 48 actual artifacts (eight targets x six formats) were externally validated.
  JSON/CSV semantics, HTML inertness, PDF parsing/extraction/text bounds and DOCX
  ZIP/XML/python-docx opening passed. All eight fixture PDFs have three pages;
  a rasterized AI section was visually inspected. No Office application was tested.
- Final 10-second fuzz runs: analysis parser 51,525 executions; input preparation
  18,676; provider envelope 25,570 (95,771 total). All passed. Earlier runs also passed
  with 85,317 / 27,982 / 50,476 executions. Fuzzing does not establish model quality.

Reproduce:

```sh
go test ./...
go vet ./...
go build ./cmd/agentsearch
go test -race ./...
go test ./internal/analysis -run '^$' -fuzz '^FuzzAnalysisParser$' -fuzztime=10s -parallel=2
go test ./internal/analysis -run '^$' -fuzz '^FuzzInputPreparation$' -fuzztime=10s -parallel=2
go test ./internal/analysis -run '^$' -fuzz '^FuzzProviderEnvelope$' -fuzztime=10s -parallel=2
AGENTSEARCH_AI_FIXTURES=/var/tmp/ai-fixtures go test ./internal/analysis -run TestFakeFailuresAndAllTargetFormats -count=1
python3 tests/validate_ai_reports.py /var/tmp/ai-fixtures
```

The optional Python check requires pypdf, PyMuPDF and python-docx. Go tests require
none of them. Generated artifacts and credentials are not committed.

**Verified:** local structural/transport/privacy/integration behavior described above.
**Measured:** bounded fuzz execution counts and fixture artifact/page counts.
**Environment-dependent:** remote endpoint/model compatibility, access, quotas, latency,
retention and deployment policy; native operating systems other than the tested Linux.
**Unverified:** live OpenAI or other external model calls, reasoning accuracy, actual
prompt-injection resistance of a model, hallucination elimination, reliability and
Word/LibreOffice interoperability. No live external AI request was performed.
