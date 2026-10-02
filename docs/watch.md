# Continuous watch (CLI v1)

Watch mode periodically reuses AgentSearch's existing target parser, configured
SearchService, Runner and source dispatcher. It adds no reconnaissance sources,
background daemon, monitoring API, external notifications or AI. Only the
explicit running CLI process performs monitoring.

## Start

Create `watchlist.yaml`:

```yaml
targets:
  - type: username
    value: example_user
  - type: domain
    value: example.com
  - type: ip
    value: 8.8.8.8
  - type: bitcoin
    value: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
  - type: bitcoin_tx
    value: 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
```

```sh
go run ./cmd/agentsearch \
  -watch-file ./watchlist.yaml \
  -watch-interval 60s \
  -watch-state-dir ./agentsearch-watch \
  -services configs/services.yaml
```

For reliable signal delivery in production, build and run `agentsearch` directly
rather than relying on a `go run` wrapper. Ctrl+C/SIGINT and SIGTERM stop the CLI.

Supported public types in this checkout are `username`, `email`, `domain`, `ip`,
`bitcoin` and `bitcoin_tx`. Email means the configured HIBP email source, not
password testing. Existing service opt-ins and environment credentials still
apply. Enable each required service in the services file; watch mode does not
automatically enable providers. Username searches use `-s configs/sites.yaml` by
default; use `-s ""` when not monitoring usernames. All enabled service settings
are initialized using the existing shared service composition. A missing or
invalid configured backend is a startup error, not a polling failure.

The example addresses are public examples, not live verification claims. IP
targets must pass the existing public-IP validator; reserved documentation
addresses such as `203.0.113.10` are not operational watch targets.

Watchlists contain only `targets` and string-valued `type`/`value` pairs. They are
read **once**. Every entry is validated before monitoring, normalized with the
existing parser, deduplicated by type and normalized value, and sorted by type
then value. Username case remains meaningful. Unknown fields, aliases/anchors,
multiple YAML documents, malformed targets, sensitive password/password-hash
types, and non-regular/symlinked watchlist files are rejected. There are no hooks,
commands, schedules, hot reload, target discovery or arbitrary URL targets.

## Scheduling and resource limits

| Setting/resource | Bound |
| --- | --- |
| Interval after a finished cycle | Default 60s; minimum 30s; maximum 299s |
| Watchlist | 256 entries before deduplication; 256 KiB input |
| Target concurrency | Default 4; `-watch-concurrency` allows 1–4 |
| Cycle deadline | Default/max 10m; positive shorter `-tt` accepted |
| Per-target deadline | At most 90s, shortened to reserve time for every batch |
| HTTP timeout | Default 15s; positive `-rt` up to 15s |
| Website workers | Fixed 4 per target (at most 16 across four targets) |
| Website configuration | At most 256 sites; GET/HEAD only, no payloads |
| Website retries / host pacing | Zero retries; shared 1-second host pacing |
| Collected results per target | 2,048 rows, 8,192 evidence entries, 4 MiB JSON |
| Individual evidence value | 64 KiB; structured comparison depth at most 16 |
| Persistent baseline | 2 MiB per target, at most 256 retained target files |
| Each log generation | 8 MiB, current plus one archive |
| Single log batch | 4 MiB; excess stops safely without replacing the baseline |

All source-level timeouts, response limits, pacing and request budgets remain in
force. Cycles do not overlap: finish the batch/cycle, then wait the interval.
The cycle budget is divided among batches (with a reserve); large lists may give
each target substantially less than 90 seconds. An exhausted cycle reports that
unstarted targets were not observed. There are at most four bounded result
collections in memory, not 256 full investigations buffered at once. Existing
providers must honor context cancellation; Go cannot forcibly preempt a broken
provider implementation that ignores its context.

## Files and privacy

The state directory defaults to `./agentsearch-watch`, which is gitignored. The
current durable filesystem implementation requires **Linux and a local filesystem
with working flock, fsync and atomic rename semantics**. Other platforms fail
closed; network filesystems and power-loss behavior have not been verified.
Use a private directory (0700); created files are 0600. Do not share ownership
with untrusted users or edit live files. Existing files must also be private.

```text
agentsearch-watch/
  watch.lock
  state/<sha256-of-type-and-normalized-target>.json
  observations.jsonl
  observations.1.jsonl       # after rotation
  changes.jsonl
  changes.1.jsonl            # after rotation
```

A kernel lock excludes concurrent processes using the same directory and is
released even on process death. Target values never become filenames. File
opens reject symlinks and special files; state access is directory-rooted.
State is written to a bounded temporary file, synced, closed, atomically renamed,
and its directory synced. Unchanged state is not rewritten. Stale managed
`.tmp` files are discarded on startup, never used as baselines.

Only the latest baseline is retained. Removed watchlist targets are not silently
deleted; their files count toward the 256-file directory capacity. If changing
watchlists would exceed that capacity, use a new directory or explicitly remove
inactive hashed baseline files while stopped. This avoids both silent deletion
and unlimited retention. Normal maximum persistent allocation is approximately
512 MiB of baselines plus 32 MiB of logs and one temporary baseline.

Observations and changes can contain public usernames, email addresses and
provider associations. Existing AgentSearch redaction rules apply, but these are
still investigation data: protect the directory and its backups. The provider
learns the queried targets. No credentials, scripts or raw provider responses are
intentionally added to monitoring storage.

## Observations, baselines and changes

`observations.jsonl` records one compact entry for each actually started target
investigation: UTC RFC3339 timestamp, random `run_id`, target/type, duration in
milliseconds, `complete`/`partial`/`failed` status, outcome, source lists, baseline
count and change count. It does not repeat the snapshot. `sources_attempted`
identifies sources/sites that emitted results; the dispatcher cannot identify a
source that fails silently before emitting. Such unclassified search failures
set `unattributed_failure`, not invented source counts.

Baselines are per target **and per source identity/type**. The first complete
observation from a source creates its baseline without synthetic ADDED alerts.
Healthy sources can progress while another source fails. Missing source results
never imply removal. Timeout, cancellation, rate limiting, blocked/error rows,
explicit partial/unavailable/truncated markers and capped Bitcoin address
history preserve the affected source's entire previous baseline. V1 deliberately
skips even the successful subset of an affected source rather than guessing
which evidence is complete. This means a Bitcoin address whose history always
hits a cap may not acquire a blockchain-source baseline; independent label or
transaction sources can still be monitored. Resolve source coverage limitations
rather than interpreting `skipped` as absence.

Snapshots compare normalized evidence sets, not reports or raw provider JSON.
Evidence is sorted and deduplicated. JSON object keys are canonicalized using
exact JSON numbers, without float conversion; array order is preserved.
Known runtime fields (`observation_time`, `observed_at`, `request_duration`,
`duration`, `duration_ms`, `run_id`, `request_id`, `random_id`, `fetched_at`) are
excluded. Other result metadata, durations, scores and log timestamps do not
participate. Actual block/record timestamps remain meaningful provider evidence.
A `result_status` evidence item captures website found/not-found observations
even when their result contains no detailed evidence. It is still a detector
observation, not verified identity or universal absence.

Within each source and evidence kind, identical values cancel out. One unmatched
old value and one new value produce `MODIFIED`; otherwise unmatched values are
`ADDED` or `REMOVED`, without guessing correspondence between multiple values.
Each event retains target/type, source, evidence kind, old/new `models.Evidence`
values, current/previous provenance, a stable `change_id`, and UTC timestamp.
The existing evidence model uses strings: integer satoshis remain exact decimal
strings and structured evidence remains canonical JSON inside that string.
Provider/source/type/URL provenance is retained, not an independent-verification
claim. No changes means no empty change event. A→B→B alerts once; A→B→A records
both real transitions.

## Durability, alerts and shutdown

Changes are synced to the bounded log before the baseline is replaced. Stable
change IDs suppress replay after a crash between log append and state update
while those IDs remain in retained log generations. This is not an unlimited
exactly-once event database. Observations describe the actual investigation and
may record its proposed outcome even if a later storage operation fails.
Incomplete trailing JSONL records are trimmed with a warning; invalid complete
log records stop startup for operator repair. Corrupt/oversized baseline contents
are reported and treated as needing a new baseline, never as evidence removals.
Filesystem access errors remain fatal rather than silently losing state.

After persistence, stdout prints escaped, bounded `[CHANGE]` messages with old
and new values. Large terminal values are abbreviated; retained change logs have
the full normalized values. stdout is not a durable delivery channel: a crash
can occur after persistence but before printing. Consult `changes.jsonl` as the
persistent notification record. There are no external notification requests.

SIGINT, SIGTERM and explicit context cancellation stop new work, cancel and join
active investigations, finish bounded synchronous persistence, close storage,
and exit cleanly. Provider failures do not terminate the loop. Unsafe config,
storage, resource-capacity or output failures stop rather than corrupting a
baseline. Existing one-shot CLI/API/report behavior is unchanged, and watch mode
does not regenerate HTML/DOCX reports.

Verification uses deterministic local providers, including an existing
SecurityTrails-source fixture through SearchService/Runner/dispatcher and actual
CLI subprocess SIGINT/SIGTERM tests. No live-provider check was performed.
