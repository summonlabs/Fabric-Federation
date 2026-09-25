# Persistence

## Layout

```
header : magic "FFEDJRNL" | u32 format_version | u32 flags | 32-byte sha256 over the header
record : u32 payload_length | u16 record_type | u16 record_version | u64 sequence
         | payload | 32-byte sha256 over the record header and payload | u32 trailer magic
```

Record types: federation identity, genesis, policy, artefact, lease, lease revocation,
request decision, partition observation, tick high-water, coordinator incarnation, epoch
state.

## Bounds

* record payload: 1 MiB
* journal file: 2 GiB (a write that would cross it is refused with `CAPACITY_EXCEEDED`, and
  the caller is told to compact)
* records loaded: 4 × the artefact bound
* recovered artefacts, leases, replay entries, observations: each bounded and enforced

Every declared length is validated against its bound before any allocation happens.

## Recovery

Recovery is conservative and always reported. `JournalRecovery` carries the outcome, the
number of records recovered, the good byte count and a diagnostic list.

| Situation | Outcome | Writable afterwards |
| --- | --- | --- |
| Complete, digest-verified history | `CLEAN` | yes |
| Final record incomplete (torn tail) | `TORN_TAIL_RECOVERED` | yes, after truncating back to the last complete record |
| Torn tail but truncation disabled | `TORN_TAIL_RECOVERED` | no |
| Complete record fails its digest | `CORRUPT_RECORD` | **no** — the file is never silently rewritten |
| Record sequence not strictly increasing | `CORRUPT_RECORD` | no |
| Unknown record type or newer record version | `UNSUPPORTED_RECORD` | no |
| Header missing, short, or wrong magic/digest | `INVALID_HEADER` | no |
| Format version this build does not implement | `UNSUPPORTED_RECORD` | no |
| Record or byte bound exceeded | `BOUNDS_EXCEEDED` | no |

A non-writable journal is refused at open time by the coordinator: it does not silently
start a new history next to an inconsistent one.

## Compaction

`Journal::compact` writes the retained records to a sibling temporary file, flushes it, and
atomically replaces the original. A crash leaves either the old or the new complete history.

## What recovery means for authority

Recovered dynamic evidence is **historical**. On restart:

* the coordinator runs a fresh **incarnation**, so every lease issued by the previous
  incarnation is `STALE_ISSUER` and cannot be spent;
* revocations are durable tombstones and are reapplied, so a revoked lease stays revoked;
* the replay ledger is restored, so a request identifier decided before the restart is
  answered `REPLAYED` rather than granted a second time;
* the logical clock resumes from the highest persisted tick and never moves backwards, so
  expired leases stay expired.

There is no scenario in which a restart revives authority that was fenced, expired or
revoked before it.
