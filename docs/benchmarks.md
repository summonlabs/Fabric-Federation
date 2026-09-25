# Benchmarks

These are completed-work measurements from the programs in `benchmarks/`, run on the
machine described in [environment.md](environment.md) in the Release configuration. They
are the exact numbers the programs printed; nothing is extrapolated and no number appears
here that the programs did not produce.

Reproduce with:

```sh
cmake --preset release && cmake --build --preset release
build/release/benchmarks/ffed_bench_state_digest
build/release/benchmarks/ffed_bench_authority
build/release/benchmarks/ffed_bench_journal
build/release/benchmarks/ffed_bench_transport
```

## State derivation and canonical digest

`ffed_bench_state_digest` builds a federation of N members through the full multi-party
join, then derives the whole state and computes the canonical digest 20 times per size.
Derivation is a full recomputation by design, so this is the honest cost of the
determinism guarantee: the digest is a pure function of the accepted evidence set, not an
incremental counter.

| Members | Artefacts | Operations | Total | Per operation |
| --- | --- | --- | --- | --- |
| 1 | 6 | 20 | 5.477 ms | 273.860 µs |
| 4 | 18 | 20 | 14.701 ms | 735.050 µs |
| 16 | 66 | 20 | 46.972 ms | 2 348.600 µs |
| 64 | 258 | 20 | 172.576 ms | 8 628.775 µs |
| 128 | 514 | 20 | 329.422 ms | 16 471.120 µs |

The cost grows with the number of members because the derived state covers every member's
lifecycle, authority, conflicts and provenance, and every call recomputes all of it.

## Authority evaluation

`ffed_bench_authority` evaluates one authority question 20 000 times, first with a fresh
request identifier (which commits a decision to the replay ledger and persists it) and then
with an identifier that is already in the ledger (which must be fenced).

| Path | Operations | Total | Per operation |
| --- | --- | --- | --- |
| First-time evaluation, commits to the ledger | 20 000 | 59 295.554 ms | 2 964.778 µs |
| Replayed identifier, fenced | 20 000 | 63 308.403 ms | 3 165.420 µs |

Both paths derive the current state before answering, which is what dominates the cost. The
replayed path is not faster, because a replay must still be answered from the state that
contains the original decision.

## Journal

`ffed_bench_journal` appends 2 000 records of 256 bytes, each flushed to the operating
system, then scans the resulting file 10 times.

| Operation | Count | Total | Per operation |
| --- | --- | --- | --- |
| Append and flush a 256-byte record | 2 000 | 1 612.641 ms | 806.321 µs |
| Recovery scan of 2 000 records | 10 | 54.302 ms | 5 430.160 µs |

The append number is a durability number: every record is flushed before the call returns,
so it reflects the cost of reaching the operating system rather than the cost of filling a
buffer.

## Transport

`ffed_bench_transport` performs framed round-trips over real loopback TCP against a real
listening socket in the same process.

| Operation | Count | Total | Per operation |
| --- | --- | --- | --- |
| Framed round-trip, 256-byte payload | 5 000 | 115.261 ms | 23.052 µs |

This measures framing and syscall cost. It is explicitly **not** a multi-process claim: the
multi-process proof is `tests/integration/test_multiprocess.cpp`, which runs separate
operating-system processes over the same transport.
