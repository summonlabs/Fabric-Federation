# Fabric Federation

Fabric Federation composes independently governed fabric domains into a larger authority
domain **without erasing local sovereignty**. Each member keeps its own identity,
generation, policies, capabilities and authority; the federation adds a governed way for
those members to delegate a named, bounded part of that authority to each other, and to
take it back.

The runtime answers one question, everywhere, with provenance:

> Given this member, presenting this exact revision of itself, asking for this scope and
> verb, under this evidence — may it act, and why?

Nothing about that answer is implicit. Membership is explicit and multi-party. Delegation
is scoped and bound to an exact generation and incarnation. A member that restarts, changes
its constitution, withdraws a delegation, or is fenced loses exactly the authority that was
tied to the old revision, and keeps everything else.

**Real:** the transport is real TCP over the loopback interface, driven by real, separate
operating-system processes in the multi-process tests. Persistence is a real versioned,
integrity-checked journal on disk. **Not claimed:** consensus, quorum, Byzantine tolerance,
cryptographic trust, multi-host operation or cross-site networking. See
[docs/limitations.md](docs/limitations.md) before you rely on anything here.

## What this repository owns

| Owned | Not owned (deliberately) |
| --- | --- |
| Federation composition and membership lifecycle | Member controllers and their local runtimes |
| Delegated authority: scopes, verbs, terms, leases | Global route computation |
| Federation policy, compatibility and admission rules | Physical connectivity |
| Cross-boundary provenance, fencing and conflict containment | Consensus, quorum, agreement protocols |
| Partition assessment and conservative reconciliation | Identity providers |
| Canonical, digestible federation state | Workload scheduling, site and inter-site runtimes |

## Build

```sh
cmake --preset release
cmake --build --preset release
ctest --preset release
```

Requirements: CMake 3.20+, a C++20 compiler, and the platform's socket library. MSVC is
built with `/W4 /WX`; GCC and Clang are built with `-Wall -Wextra -Wpedantic -Werror` plus
the warnings listed in `CMakeLists.txt`. There are no third-party runtime dependencies.

Presets: `release`, `debug`, `asan` (AddressSanitizer where the toolchain supports it).

## Install and consume

```sh
cmake --install build/release --prefix /path/to/prefix
```

The install exports `SummonSoftwareLabs::FabricFederation`:

```cmake
find_package(FabricFederation 1.0 REQUIRED)
target_link_libraries(your_target PRIVATE SummonSoftwareLabs::FabricFederation)
```

`consumer/` is a complete downstream project that does exactly this and is built in CI
against an installed prefix only.

## Try it

```sh
ffed-cli demo          # whole lifecycle in one process, over real loopback TCP
ffed-cli permutation   # canonical state is permutation independent
ffed-cli transport     # what the transport actually is
```

Run a federation as separate processes:

```sh
ffed-coordinator --federation fed-... --state ./federation.fedjournal --listen --port 0 \
                 --bootstrap --founder-member mbr-... --founder-domain dom-... --founder-spec "gen=1"
ffed-member --federation fed-... --member mbr-... --domain dom-... --spec "gen=1;..." \
            --coordinator-port <port> --control-port 0 --listen-for-probes
```

Each daemon prints a `READY` line and, with `--control-port`, serves a newline-delimited
operator channel (`stats`, `state`, `fence`, `advance-epoch`, `reconcile`, `stop`).

## The model in one page

**Identities.** A federation has a `FederationId`, an `Epoch` and a coordinator
`Incarnation`. A member has a `MemberId`, a `FabricDomainId`, a `Generation` (the revision
of its constitution), an `Incarnation` (one run of its controller process) and a
`Digest` (the canonical digest of its constitution). Authority is always bound to all
three of generation, incarnation and digest.

**Lifecycle.** `absent → proposed → admitted → active → degraded → fenced (isolated) →
leaving → retired`. A member is never conscripted: it consents, and the admission is
derived from evidence contributed by at least two distinct member identities. The shipped
policy requires exactly that; a federation may raise the bar and also require third-party
endorsements.

**Authority.** A grant is a `(scope, verb)` pair with verb in
`observe | write | mutate | administer`. A member declares, explicitly and separately,
the grants it **retains locally** and the grants it **delegates**. The two sets must be
disjoint and a member may never delegate anything inside its own `domain.*` namespace.
Everything that is not delegated stays local, and local authority is granted by the member
itself without asking the federation — including while the federation has fenced it.

**Fencing.** A generation change, a new incarnation, a withdrawal, a lease that expired or
was revoked, a lease issued by a previous coordinator incarnation, a fence order, or a
stale epoch all remove exactly the authority bound to the superseded revision. Fenced
authority is sticky: it comes back only through fresh evidence.

**Conflicts.** Overlapping delegations that disagree are *preserved*, never resolved by
recency. No claimant is granted the disputed grant. A disagreement is resolved only by a
party changing its declaration, or by a precedence order that the policy configured before
the disagreement existed and that names exactly one claimant.

**Partition.** Members probe each other over the real transport. An edge exists only when
both endpoints confirm each other at the incarnation the federation believes is running. If
the active set splits, or if the observation set is incomplete, **global-mutation authority
is suspended for every side**. Recovery advances the epoch, requires every established
member to re-attest, and only then lifts the suspension; leases from the previous epoch stay
fenced.

**Determinism.** Federation state is a pure function of the accepted evidence set, the
policy and the catalogue. Applying the same evidence in any order produces the same derived
state and the same canonical digest. `ffed-cli permutation` and
`ffed_state.canonical_digest_is_permutation_independent` both check that directly.

**Persistence.** One append-only journal, versioned, with a digest per record. A torn tail
is truncated back to the last complete record and reported; a record that fails its digest
makes the journal read-only and is never silently repaired; an unknown record type or an
unsupported version stops recovery. A restart always runs a fresh coordinator incarnation,
so leases issued by the previous incarnation become historical evidence rather than live
authority. Revocations are durable tombstones and are never revived.

## Repository layout

```
include/fabric_federation/   public headers: ids, scopes, capabilities, policy, evidence,
                             membership, leases, partition, authority, state, journal,
                             transport, protocol, coordinator, member runtime, client
src/                         the library implementation
apps/                        ffed-coordinator, ffed-member, ffed-cli
examples/                    one-process and multi-process worked examples
tests/unit/                  model, lifecycle, authority, state, journal, protocol, concurrency
tests/integration/           multi-process proof over loopback TCP
benchmarks/                  completed-work measurements
consumer/                    downstream find_package consumer
docs/                        architecture, authority model, canonical form, concurrency
                             audit, persistence, limitations, environment
```

## Documentation

* [docs/architecture.md](docs/architecture.md) — components, ownership, threading
* [docs/authority-model.md](docs/authority-model.md) — the evaluation order and every
  outcome it can produce
* [docs/canonical-form.md](docs/canonical-form.md) — encoding and digest rules
* [docs/concurrency.md](docs/concurrency.md) — locking, ownership and shutdown audit
* [docs/persistence.md](docs/persistence.md) — journal layout, recovery and bounds
* [docs/limitations.md](docs/limitations.md) — what is not implemented, and what is
  therefore not claimed
* [docs/environment.md](docs/environment.md) — the exact toolchain used for the results in
  this repository, and the measured platform behaviour that shapes the tests
* [docs/benchmarks.md](docs/benchmarks.md) — completed-work measurements, exactly as the
  benchmark programs printed them

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are accepted under Apache-2.0 with
no copyright assignment and no CLA.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
