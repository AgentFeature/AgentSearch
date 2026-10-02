# Offline Pwned Passwords operations

AgentSearch provides an offline backend for **one supplied password**. It uses the
existing `PasswordSearcher`, consuming `security.Secret`, runner and normalized
results. It does not implement a downloader, password-file checks, cracking,
credential testing, a public HTTP API, or AI.

## Choose the backend explicitly

```sh
# Unchanged API default; sends only the five-character SHA-1 prefix.
agentsearch -password-prompt
agentsearch -password-prompt -password-backend api

# Offline; path names a managed root, not a text export.
agentsearch -password-prompt -password-backend local -password-db /srv/pwned-db
```

Windows:

```powershell
agentsearch.exe -password-prompt -password-backend local -password-db C:\Data\Pwned
```

`-password VALUE` remains available with the same argument-exposure warning;
prompt input is recommended. Local prompt mode opens/validates the snapshot
before asking for the password. Once supplied, the source consumes the bytes,
hashes them locally without trimming/case/Unicode normalization, and only then
calls the corpus lookup. The app explicitly closes its snapshot on every exit.

API is always the default. A database path alone is an error, not automatic
selection. Local mode never constructs a password HTTP client, reads email
credentials, downloads data or falls back to the API. Missing/corrupt local data
is an error. Initialization failure can occur before a result file exists.

Optional explicitly loaded YAML:

```yaml
services:
  hibp:
    enabled: false # Email setting only.
    passwords_database_path: "./pwned-db"
```

```sh
agentsearch -password-prompt -password-backend local -services configs/services.yaml
```

An explicit `-password-db` overrides the YAML path. Both relative paths are
relative to the working directory, not the YAML directory. The default services
file is not automatically loaded in password mode. No environment variable,
`~` expansion or database discovery is added. Explicit YAML still uses strict
known fields. `-rt` remains positively validated but has no HTTP effect locally;
`-tt` controls context, not a guaranteed interrupt of blocked kernel file I/O.

## Acquire and attest an artifact separately

Obtain data yourself using the [official downloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)
and [current HIBP documentation](https://haveibeenpwned.com/API/v3#PwnedPasswords).
Use SHA-1 **single-file** output, not NTLM and not the directory-mode suffix files.
For example, the official tool supports:

```sh
haveibeenpwned-downloader acquired-sha1 --single --max-retries 5
```

This command is external to AgentSearch and is not run by tests or lookup.
Acquire into a fresh, monitored location with enough disk space. Confirm the
complete job succeeded; do not attest a stopped, failed or partial job. Record
the actual tool/package identity and acquisition time separately. Freeze the
artifact and record its SHA-256 after successful acquisition, for example with
`sha256sum` or PowerShell `Get-FileHash -Algorithm SHA256` (use lowercase hex).

Import requires that expected digest, a completion time and explicit `-complete`
attestation. **These do not authenticate HIBP or independently prove global corpus
completeness.** A checksum calculated after whole records were lost will not
reveal their loss. Preserve trusted acquisition evidence outside the database.
The manifest records the artifact identity and operator assertion, not an
upstream signature or an exact globally simultaneous HIBP snapshot timestamp.

The supported profile, `hibp-sha1-ordered-v1`, is precisely:

- Full 40-character ASCII SHA-1 hexadecimal hash, colon, positive decimal uint64.
- Upper/lowercase hex, LF/CRLF, final newline required, no blank records/headers.
- No zero counts, negative/sign/overflow counts, extra colon, field whitespace,
  embedded NUL, NTLM or suffix-only rows. Leading decimal zeroes are accepted
  within the 20-digit limit only when the resulting count is positive.
- Prefix groups ascend; rows inside a group may be unsorted. The importer sorts
  one bounded group and rejects duplicates rather than merging counts.
- Optional UTF-8 BOM only before the first record or the first record of an
  advancing prefix group. BOMs inside a group or record are rejected.
- Missing prefix groups encode empty ranges **in the attested input artifact**.
  Prefix coverage is not used to invent upstream completeness. A sparse synthetic
  fixture is valid; an accidentally incomplete acquisition must not be called a
  complete HIBP corpus. Negative results always concern the supplied snapshot.

The BOM profile follows source inspection of official downloader commit
`3e26e1882c1917abdbf767c1e62521dcc6f1b918`: separate per-range UTF-8 writers and
platform line endings. Synthetic compatibility cases pass; actual .NET exporter
execution and a full current HIBP corpus are **UNVERIFIED**. Directory-mode ETags
are not a content-integrity manifest; this importer does not consume that cache.

## Build, import, verify, activate

```sh
go build ./cmd/agentsearch
go build ./cmd/agentsearch-corpus

agentsearch-corpus import -db /srv/pwned-db -input /acquisition/acquired-sha1.txt \
  -sha256 LOWERCASE_EXPECTED_SHA256 -acquired-at 2026-09-10T12:00:00Z -complete
```

Replace the digest/time with actual acquisition evidence. Import prints a random
32-character dataset ID. It creates an **unpublished** generation, performs full
verification, and marks its payload files read-only. It does not activate it.

```sh
agentsearch-corpus verify -db /srv/pwned-db -version DATASET_ID
agentsearch-corpus activate -db /srv/pwned-db -version DATASET_ID
agentsearch -password-prompt -password-backend local -password-db /srv/pwned-db
```

`activate` independently performs a complete semantic/checksum verification before
publication. Import, verification, activation and pruning are serialized by the
updater lock; normal lookups continue on their pinned immutable generations.
Only one maintenance process runs at a time; a second gets a safe `busy` error.
Use Ctrl+C/SIGTERM to cancel at safe points. Kernel file operations may complete
before cancellation can be observed; there is no per-read goroutine workaround.

## Layout and binary contract

```text
root/
  update.lock
  control.lock
  active-a
  active-b
  versions/<dataset-id>/
    lease.lock
    hashes.bin
    prefix.idx
    manifest.json
```

Both data and index have 128-byte headers:

| Bytes | Meaning |
|---|---|
| 0–7 | `ASPWNDAT` for data; `ASPWNIDX` for index |
| 8–11 | Big-endian uint32 format version, currently 1 |
| 12 | Hash algorithm 1: SHA-1 |
| 13 | Prefix bits: 20 |
| 14–15 | Big-endian uint16 record width: 28 |
| 16–31 | Random 16-byte dataset ID (directory name is lowercase hex) |
| 32–39 | Big-endian uint64 record count |
| 40–127 | Reserved, must be zero |

Data records are explicitly encoded **20-byte digest + 8-byte big-endian count**.
No native structs are serialized. Counts must be positive; digests are strictly
sorted and unique. The index has `P+1` uint64 **row offsets**, then `P` SHA-256
values, where `P=1,048,576`. Digests cover each prefix's exact encoded record bytes.
An empty range has equal offsets and SHA-256 of empty input. Full index size is
**41,943,176 bytes**; it is kept in one approximately 40 MiB buffer.

Manifest JSON is capped at 64 KiB, with no unknown/duplicate fields or trailing
document. It binds IDs, format/builder/profile, counts, sizes, maximum range,
whole-file SHA-256 values, acquisition/built times and artifact digest/completion.
No lookup-derived password, SHA-1, prefix or suffix is written to it.

A snapshot validates manifest, index digest, headers, lengths, offset monotonicity
and bounds at open. Lookup checks data length, reads the selected range using
`ReadAt`, verifies its SHA-256 **before searching**, and binary-searches the
verified records. No full data scan occurs on ordinary startup. Full scrubs check
all range checksums, ordering, uniqueness, prefix assignments and counts.
Corruption in an unaccessed range may remain undiscovered until a scrub or lookup;
a successful result does not certify every other byte of the database.

A range cannot exceed **2 MiB** (74,898 encoded records). This is an AgentSearch
capacity limit, not an HIBP guarantee. Larger ranges fail explicitly; none are
silently omitted. At most eight private lookup buffers are admitted concurrently.
There is no shared Seek cursor, mmap, embedded database engine, query cache,
full-corpus map or whole-corpus in-memory sort. Import retains a bounded group,
the constant-size index and buffered I/O; verification reuses a bounded buffer.
Runtime/GC and operating-system page cache are additional memory, not free RAM.

## Activation, leases and recovery

Each 4 KiB activation record contains magic `ASPWNACT`, version at bytes 8–11,
sequence at 16–23, dataset ID at 24–39, manifest SHA-256 at 40–71 and a SHA-256 over
the first 4,064 bytes in the final 32 bytes. Other bytes must be zero.

Activation fully verifies outside the control gate, takes the exclusive gate,
updates only the older/invalid slot with a new sequence, syncs it, and releases
the gate. It does not rely on Unix symlinks or Windows rename atomicity. Readers
hold a shared gate only while selecting the highest valid slot and acquiring a
shared OS generation lease. Large index loading happens after releasing the gate.

Existing readers stay on their original version. New readers see the newly
selected version. Close drains in-flight lookups, closes data handles and releases
the generation lease. Lock files are stable OS-lock objects, not stale PID markers;
never remove them to “unlock” a database.

A torn/checksum-invalid slot can recover its valid counterpart. A warning and
`activation_recovered` result metadata disclose recovery. Equal-sequence conflicts
or unsupported control versions fail. A valid selected slot pointing to missing
or corrupt data **fails closed**: no older-database or API fallback occurs.

A slot write/Sync failure reports `activation_outcome_uncertain`. The candidate
may have become selected: retain it and inspect/explicitly reactivate a verified
version. If both slots are invalid, ordinary open fails; an explicit activation
of a verified retained ID can establish a new selection. Unknown-format slots,
equal-sequence conflicts and unreadable control files require administrative
inspection rather than silent overwrite.

## Rollback and cleanup

```sh
agentsearch-corpus rollback -db /srv/pwned-db -version RETAINED_DATASET_ID
agentsearch-corpus prune -db /srv/pwned-db
```

Rollback is explicit activation of a verified retained version with a new
sequence, not decrementing the counter. Prune retains **both slot targets** and
all live leases. It removes other generations, **including unpublished candidates**;
use it only when those are no longer needed. Keep separate backups for longer
retention. No retention is inferred from timestamps.

After A→B, A is still protected by the older control slot even after its readers
close. Publishing another version, or explicitly activating B again, retires
that reference. A live A lease still prevents deletion; after Close, a later
prune can remove it. This intentionally preserves redundant recovery data.
Prune refuses damaged/uninitialized activation state; repair selection explicitly
first. Interrupted, unreferenced creation directories can be removed under the
maintenance locks. Failed deletion leaves an error/extra files; do not force-close
readers or remove their leases. Root recovery with no trusted version may require
manual administrative cleanup and a fresh acquisition.

## Disk and permissions

Let `T` be export size, `N` validated records, `R` other retained/leased versions:

```text
new version = 128 + 28*N + 41,943,176 + small manifest/lock overhead
peak = export + old active + new version + R + other workspace/archive + reserve
```

The selected single-file workflow has no archive/extraction stage inside
AgentSearch. Existing files already consume available space; do not double-count
them when comparing new allocations to free space. Import preflights a conservative
record bound `floor(T/43)`, the output/index, metadata and 64 MiB headroom against
caller-available space. This is not a reservation or protection from other writers:
write/Sync failures still abort safely. Budget acquisition separately and monitor
space. Never delete active/leased data to make an update fit.

Use an operator-controlled directory **outside Git, release archives and Docker
layers**. The corpus is not bundled. The maintenance identity needs write access;
lookup identities need read access plus shared-lock access. Default creation is
owner-only; grant additional Unix group permissions or Windows ACLs deliberately.
Do not edit sealed files. SHA-256 detects changes relative to trusted metadata,
not an administrator replacing data and all its checksums. Trusted-parent path
ownership is required; this is not a hostile-filesystem sandbox.

Linux uses flock and directory fsync. Windows uses LockFileEx and file Sync;
Windows directory-entry power-loss durability is not claimed. Windows sharing,
AV/indexers and deletion may require operational attention. Use local filesystems;
known Linux NFS/CIFS and Windows UNC paths are rejected, but detection is not a
complete guarantee against remote mounts, mapped drives or cloud-sync folders.

## Results, limitations and verification scope

- Local present: `found`, confidence 100, `pwned="true"`, occurrence count.
- Local verified absent: `not_found`, confidence 100, `pwned="false"`, count 0.
- Technical failure: `error`; success pwned/count metadata omitted. Never “safe.”
- Source `pwned-passwords-local`, type `local`, method `sha1-offline`; target remains
  `[REDACTED]`. Existing remote negative confidence remains **0**, deliberately.
- Confidence describes deterministic membership in the selected supplied dataset,
  not probability of account compromise. Absence is not proof of password safety.
- No plaintext or query digest/prefix/suffix is placed in generic outputs, errors
  or logs. Secret cleanup is best-effort, not secure-memory or GC-erasure proof.
- Legacy CSV retains nine columns and gains a complete canonical companion. All six
  `-of` formats honor `-o`, and one-shot output failures propagate. DOCX no longer
  requires a runtime license; see [reporting](reporting.md) for verification limits.
- Native Windows runtime, actual full-corpus compatibility, power-loss laboratory
  behavior and production-scale performance are **UNVERIFIED**. Cross-compilation
  is not native testing. These are operational follow-ups, not implemented features.

Focused synthetic tests cover encoding, parser strictness/BOMs, both lookup
outcomes, corruption/truncation/manifest/index/ID errors, activation/rollback and
recovery, leases/pruning, concurrent reads, cross-process updater exclusion,
secret destruction and explicit backend isolation. The normal full test/race/vet
and Linux/Windows build gate must pass before handing off a release.

Review [current HIBP Terms](https://haveibeenpwned.com/TermsOfUse) and distribution
rules before public/commercial deployment, redistribution or re-serving. Password
offline documentation and a downloader software license are not blanket legal
permission for every business model. No legal certification or production-readiness
claim is made here.
