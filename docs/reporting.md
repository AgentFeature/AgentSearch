# Target-independent reporting

## Architecture and compatibility

The existing dispatcher already supported typed investigations. Reporting now uses:

`investigation -> normalized Result/Evidence -> immutable report snapshot -> renderer`

`internal/report/model.go` constructs the bounded, redacted snapshot; `render.go`
contains JSON/CSV/TXT/HTML projections; `documents.go` contains PDF/DOCX;
`output.go` owns names and atomic publication. Existing generator entry points are
adapters. Sources, models, HTTP API and monitoring do not depend on presentation.
The deprecated streaming storage writers remain for compatibility; one-shot app
output no longer uses their independently finalized files. CSV formatting is shared.

There are no new providers, investigation capabilities, network calls or correlations.
POST `/api/v1/search` retains its existing request/response schema and result array.
Watch `observations.jsonl`, `changes.jsonl`, baselines and change semantics remain
separate. No report envelope is added to either API responses or watch events.

```sh
agentsearch -u alice -f usernames.txt -of json,csv,txt,html,pdf,docx -rf '' -o results
agentsearch -domain example.org -of json,html,pdf,docx -rf '' -o results
```

Existing target/service restrictions still apply. Password-hash is an existing
internal target capability, not a newly added CLI mode.

| Option | Files |
|---|---|
| `-of json` | `<safe-target>.json` legacy normalized array **and** `<safe-target>_report.json` canonical report |
| `-of csv` | `<safe-target>.csv` legacy nine columns **and** `<safe-target>_report.csv` complete flattened report |
| `-of txt,html,pdf,docx` | `<safe-target>.<format>` in `-o` |
| `-rf cli` | readable stdout and historical `./output/<safe-target>_report.txt` |
| `-rf json,csv,txt,html,pdf,docx` | historical `./output/<safe-target>_report.<format>`; JSON/CSV here are canonical |
| any `-rf` | legacy `<safe-target>_summary.json` in `-o` |

Defaults remain `-of json,csv,txt -rf cli,html`. Use `-rf ''` to avoid the historical
working-directory bridge. `-u`, `-f` and comma-separated `-of` remain supported.
All six formats are validated for every applicable CLI target mode. Output errors
now reach the caller, including website mode. Ordinary source failure exit policies
are not changed. Files are published individually, not as an all-or-nothing bundle:
other valid formats can remain when one renderer fails. A rerun can overwrite an
existing regular report; use separate directories to retain investigations. Legacy
and companion names are reserved output names, so avoid targets whose literal names
collide with another target's `_report` or `_summary` companion in a shared directory.

## Canonical schema

`agentsearch.report.v1` is a **new companion schema**, not a replacement API schema.
It includes a content-derived investigation ID, target/type, UTC creation timestamp,
nanosecond duration, status, source execution summary, observations, correlations,
warnings/errors and explicit `partial`/`truncated` flags. Each observation contains:

- a stable result ID and the normalized source-specific Result;
- observation kind/meaning and default classification;
- a classification parallel to each evidence entry;
- provider error kind and partial/truncated flags.

The snapshot deeply copies input. Result IDs derive from sanitized normalized data;
identical duplicate rows get deterministic ordinal suffixes, rather than ambiguous
correlation references. Evidence keeps its `kind`/`value` shape. Structured values
are still strings containing deterministic JSON, not a large union of provider fields.
JSON numbers are decoded with `UseNumber`: satoshi integers never pass through float.

Classification is conservative: known provider observations/absence are `observed`,
website detector output is `inferred`, existing Bitcoin address counterparty
cooccurrence is `correlated`, and unsupported semantics are `unknown`. Trusted
application annotations can classify individual evidence; provider metadata cannot
promote its own claim. Correlations reference existing evidence, not new graph edges.
A label remains a provider observation, never independently verified ownership.
Existing numeric scores are retained, not invented; unscored contracts omit numeric
confidence in JSON and show `not scored` in human formats.

`complete`, `partial`, `failed`, and `empty` are report execution statuses, not threat
verdicts. A provider failure is not `not_found`; healthy rows are retained alongside
failures. Source summaries count `(source_type, source)` identities, not HTTP calls.
Unknown outcome statuses imply partial execution. Truncation implies partial output.

Top-level results/correlations/warnings/errors and evidence classifications use empty
arrays, never null. Legacy Result optional metadata/evidence/error fields retain
`omitempty`; absent source values are not synthesized as evidence. Report flags and
summary counts are always present. Creation time is provided once by the app at
investigation start; a constructor's zero time deliberately means Unix epoch, not
"now". Duration zero is the supplied/default value, not a new timing measurement.
Renderers do not consult the clock. The ID changes when time, duration or content
changes; repeat rendering of the same snapshot is byte deterministic in the tested
Linux/toolchain/dependency environment.

Sources/results sort by source, type and normalized content. Evidence sorts by kind,
then indexed entries before unindexed entries, numeric index, then value. Map keys and report-level
warnings/errors sort deterministically. No renderer sorts/mutates caller-owned input.

## CSV and readable formats

Legacy header remains:

```text
site_name,target,url,found,confidence,status,duration_ms,error,final_url
```

The canonical companion has:

```text
record_type,investigation_id,target_type,target,result_id,source,source_type,status,evidence_type,classification,value,provenance
```

One `report` row stores canonical metadata in `value` (results is deliberately null
there); one `result` row per observation stores its metadata with evidence and
classifications omitted/null; each `evidence` row holds one complete value and
classification. Evidence order within each result supplies its zero-based index.
`provenance` is deterministic JSON with URL, final URL, provider, kind and meaning.
Warnings, errors, correlations and coverage flags survive in these structured cells.
Commas, quotes, CR and newlines are quoted by `encoding/csv`; records end in LF.
Some CSV readers normalize embedded CRLF to LF. JSON is preferable for byte-exact
text interchange. CSV cells are not altered with spreadsheet-specific apostrophes:
import untrusted CSV as **text**, not executable spreadsheet formulas.

TXT has sections, labels, provenance and explicit classifications, not a raw report
JSON dump. Source-specific structured evidence remains inspectable as JSON text.
Human lines wrap to 96 characters plus up to four indentation characters. Control
and bidi-control characters are visibly escaped. HTML is template-escaped, responsive,
self-contained and has a restrictive CSP: no scripts, links, remote styles, fonts or
resource loading. Hostile markup is text. HTML shows the same metadata and evidence,
grouped into one card per logical section (target/summary, each source, correlations,
warnings, errors, and the optional AI sections); a group heading without fields of its
own renders as a plain divider. Grouping is presentation-only and preserves field order.

Canonical and legacy JSON files, and the legacy `_summary.json`, are pretty-printed
with two-space indentation. Schemas, field sets and key order are unchanged from the
earlier compact encodings; only insignificant whitespace differs, and any JSON parser
reads both forms identically. The streamed legacy array written during live website
searches is indented per record and remains valid JSON after interruption handling.

## PDF and DOCX

PDF was absent before this change. `github.com/go-pdf/fpdf v0.9.0` provides layout,
wrapping, pagination and embedded fonts without external executables. The bundled
Go regular TrueType font from `golang.org/x/image v0.25.0` supports the tested Latin,
Greek and Cyrillic text. **It is not a universal Unicode font:** unsupported glyphs
(e.g. the tested CJK case) return an explicit renderer error, not missing-glyph boxes.
Use HTML/DOCX for scripts outside that font. Font data, metadata dates and catalog
ordering are fixed; there are no system-font or network dependencies.

The old UniOffice DOCX path was reproduced before replacement: an actual local
Unicode/long fixture returned `save docx: unioffice license required`, leaving a
zero-byte, non-ZIP file. The previous test skipped that license failure. That skip
and dependency are removed. DOCX now uses Go's ZIP/XML libraries to produce a small
OOXML package with seven parts: content types, package relationships, document,
styles, document relationships, core properties and application properties.
Paragraphs/styles are sufficient for this evidence layout; there are no tables,
numbering, images, external relationships, active hyperlinks or macros to resolve.
ZIP close/finalization errors propagate. Text is XML escaped; invalid XML controls
are rendered visibly. ZIP timestamps and document metadata are deterministic.

## Bounds and filesystem security

Limits are explicit errors, never invisible evidence dropping:

| Resource | Limit |
|---|---:|
| Results | 10,000 |
| Total evidence | 20,000 |
| Each input string | 64 KiB, valid UTF-8 |
| Input/canonical encoded size | 8 MiB |
| Metadata entries per result | 256 |
| Supplied warnings / errors | 1,000 each |
| Structured evidence nesting | 16 levels |
| Each output | 32 MiB |
| Human-rendered lines | 20,000 |
| PDF pages | 512 |
| Canonical CSV records | 1 + 10,000 + 20,000, plus header |

A collector limit stops accepting results and marks retained output partial/truncated;
a snapshot or renderer that cannot fit fails explicitly. Format limits can differ:
a valid bounded JSON report can be too long for PDF. No resource bound is a claim of
production-scale performance. Unknown unmarked upstream truncation cannot be inferred.

Shared redaction removes sensitive targets, known secrets, credentials in URLs,
recognized keys and authorization/cookie headers. Canonical construction also walks
structured evidence/metadata/errors to redact nested sensitive keys without converting
integers or breaking valid JSON. Duplicate structured keys and redacted-key collisions are errors. JSON-looking
values beginning with `{` or `[` must parse completely (except `[REDACTED]`); malformed
structured values fail explicitly, rather than guessing and leaking quoted credentials. Free-form redaction
cannot detect every unlabeled secret: providers must keep credentials out of evidence.
No provider strings are passed to a shell, browser or resource loader.

Ordinary safe filenames remain compatible; unsafe/reserved/long names use a bounded
slug plus a digest. Password outputs use `[REDACTED]`. Output files are mode 0600;
new directories are 0700, without changing existing directory permissions. Symlink
final directories/destinations and nonregular final files are refused. Linux writes
use root-relative exclusive temporary creation, sync, root-relative atomic rename
and directory sync; failed unpublished temporaries are removed. Final-file symlink
races replace the directory entry rather than following it. An operator-supplied
ancestor directory can itself resolve through a symlink. Multi-user output roots
must therefore still be private/trusted. Non-Linux uses the portable rename fallback:
its runtime and concurrent ancestor-rename behavior have **not** been verified.
Public output errors do not echo arbitrary filesystem paths or sensitive target names.

## Executed verification (Linux, Go 1.24.13)

Baseline full tests/vet/build passed before editing. After implementation:

- `go test ./...`, `go vet ./...`, `go build ./cmd/agentsearch`: passed.
- `go test -race ./...`: passed, including app, reporting, API and monitoring.
- Final reporting fuzz: 20-second budget, 10,132 executions, 35 new interesting inputs,
  39 cached baseline inputs (six original seeds); no failure. An earlier 20-second
  run completed 10,269 executions; combined measured executions: 20,401. Fuzz covers JSON/CSV/HTML/TXT/DOCX and malformed text;
  PDF is covered by bounded deterministic and concurrent-render tests, not that fuzz loop.
- Empty/mixed/error/partial/truncated/Unicode/hostile/long fixtures, immutable input,
  ordering, duplicate references, CSV multiline/CR preservation, output path/symlink
  refusal, secret redaction, invalid input and bounds are tested.
- Actual CLI tests retain `-u`/`-f` and exercise all six comma-separated formats;
  eight typed local application fixtures exercise the existing dispatcher and outputs.
- 54 actual artifacts parsed externally: eight targets times six formats, plus six
  long-evidence artifacts. PDF parsing/extraction uses pypdf; PyMuPDF checks text
  bounds and rasterization. The first page was visually inspected. Standard fixtures
  have two pages; the long fixture has ten, retaining all 1,200 repeated paragraphs.
- DOCX ZIP CRCs, all XML, required parts, internal relationship resolution, extracted
  text and python-docx opening passed. That is **not** Microsoft Word or LibreOffice
  interoperability certification; neither application was available.

| Local fixture target | JSON | CSV | TXT | HTML | PDF* | DOCX** |
|---|---|---|---|---|---|---|
| Username | Pass | Pass | Pass | Pass | Pass | Pass |
| Email | Pass | Pass | Pass | Pass | Pass | Pass |
| Domain | Pass | Pass | Pass | Pass | Pass | Pass |
| IP | Pass | Pass | Pass | Pass | Pass | Pass |
| Bitcoin address | Pass | Pass | Pass | Pass | Pass | Pass |
| Bitcoin transaction | Pass | Pass | Pass | Pass | Pass | Pass |
| Password, redacted | Pass | Pass | Pass | Pass | Pass | Pass |
| Password hash, internal capability | Pass | Pass | Pass | Pass | Pass | Pass |

*Supported-font fixture, not all Unicode scripts. **OOXML/independent parser validation,
not an executed Office application. These are deterministic local fixtures, not live
provider verification, performance benchmarks, cross-platform tests or ownership claims.

Reproduce optional external artifact checks (install `pypdf`, `PyMuPDF`, `python-docx`):

```sh
AGENTSEARCH_REPORT_FIXTURES=/var/tmp/report-fixtures go test ./internal/report -run TestWriteFixtureArtifacts -count=1
python3 tests/validate_reports.py /var/tmp/report-fixtures
go test ./internal/report -run '^$' -fuzz '^FuzzCanonicalReport$' -fuzztime=20s -parallel=2
```

Generated binaries, fixtures and raster images are not committed. The portable test
suite does not require Python or Office tools. No live provider calls were used for
this reporting validation. Current label freshness, Office rendering, unsupported
scripts and other operating systems remain unknown/environment-dependent.

## Optional AI attachment

Explicitly requested [AI analysis](ai-analysis.md) adds an optional structured `analysis`
field to canonical reports and a separate labelled section to human formats. It does
not change deterministic result IDs, investigation status or source evidence. Canonical
CSV retains its columns and carries the bounded attachment in the report metadata row.
Legacy JSON arrays and CSV projections remain unchanged. API requests without analysis
retain their prior contract; opted-in requests additionally receive the canonical report
so AI references can be resolved. Watch remains outside this analysis path.
