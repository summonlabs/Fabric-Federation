# Architecture

## Components

```
        +---------------------------+
        |  ffed-coordinator process |
        |                           |
        |  FederationCoordinator    |
        |    evidence set           |
        |    derive_state()  <------+---- pure function
        |    policy + catalogue     |
        |    journal (optional)     |
        |    framed TCP listener    |
        +-------------+-------------+
                      |  loopback TCP, framed
        +-------------+-------------+-------------+
        |                           |             |
  +-----v------+             +------v-----+  +----v-------+
  | ffed-member|             | ffed-member|  | ffed-member|
  | process A  | <---------> | process B  |  | process C  |
  | identity   | peer probes | identity   |  | identity   |
  | constitution             | constitution | constitution |
  +------------+             +------------+  +------------+
```

**`FederationCoordinator`** is the single logical authority. It holds the accepted evidence
set, derives state from it, answers authority questions, issues the decision records that
follow from policy, issues and revokes leases, assesses partitions and persists everything
it commits. It computes no routes and schedules no work.

**`MemberFabricRuntime`** represents one independently governed fabric domain inside one
process. It owns its constitution (identity, generation, capabilities, retained authority,
delegated authority), builds the artefacts it is entitled to issue, submits them, answers
authority questions about its own local authority without consulting the federation, and
probes its peers over the transport.

**`CoordinatorClient`** is a connection to a coordinator: one request at a time under a
mutex.

**`Journal`** is the durable, versioned, integrity-checked append-only log.

**The tools** are thin: `ffed-coordinator` and `ffed-member` are daemons that expose the
library over the framed protocol plus a newline-delimited control channel; `ffed-cli`
inspects a running federation and can run two self-contained commands (`demo`,
`permutation`) that exercise the whole model in one process.

## The derivation is the model

`derive_state()` is a pure function:

```
FederationState = f(federation, coordinator identity, epoch, policy, catalogue,
                    accepted evidence set, observations, leases, replay ledger,
                    journal recovery facts)
```

It performs a full recomputation on every call. Nothing is cached between calls and nothing
is mutated in place. That has a cost — `benchmarks/state_digest_bench.cpp` reports it — and
it buys the property the whole design rests on: two parties holding equivalent accepted
evidence compute the same state and the same canonical digest, whatever order the evidence
arrived in.

### Order of operations inside the derivation

1. **Prepare evidence.** De-duplicate by evidence identifier. Identical duplicates are
   counted once; the same identifier with different content quarantines *both* copies and
   records the disagreement. Every remaining artefact is structurally validated.
2. **Federation genesis.** Exactly one genesis record establishes the founder. Zero means
   an empty federation; more than one is an ambiguous founder and is reported as such.
3. **Policy.** The highest-generation policy record wins; otherwise the genesis policy;
   otherwise the configured policy.
4. **Epoch and clock.** The epoch is one plus the highest epoch advance. The logical clock
   is driven by the coordinator's own records; a member-supplied stamp never moves
   federation time.
5. **Standing fixpoint.** Membership is derived in rounds: a sponsor or endorser must itself
   be *established*, which starts from the bootstrap founder. The fixpoint converges
   monotonically and is bounded.
6. **Partition assessment.** See below.
7. **Final per-member derivation.** Lifecycle, delegated terms, withdrawals, conflicts,
   effective authority, fencing.
8. **Conflict detection** over live delegation claims, then withholding.
9. **Canonical encoding** for the digest.

## Partition assessment

Members report what they actually reached. `assess_partition` builds an edge between two
active members only when **both** endpoints reported the other reachable *and* the reported
incarnation matches the incarnation the federation currently believes is running. An
observation from a previous epoch, or older than the policy's freshness bound, does not
count. An active member covered by no usable observation makes the whole assessment
`INDETERMINATE`.

`SPLIT` and `INDETERMINATE` both suspend global-mutation authority for **every**
component. No side keeps it. A single active member is reported `CONNECTED`, because a
graph with one node has no edges that could be missing.

Recovery is conservative: the federation advances to a new epoch, stays in a reconciling
state, and requires every established member to re-attest before global mutation resumes.
The derivation re-checks that condition itself; a reconciliation record alone does not lift
the suspension.

## Threading and ownership

* One state mutex guards the evidence set, the derived inputs and the journal.
* One connection-registry mutex guards the set of live connection sockets.
* The accept loop and a bounded worker pool own the sockets. Shutdown closes the listener,
  shuts the surviving sockets down (not closes them) so the owning worker observes the
  error and releases its own handle, wakes the workers, and joins them.
* No callback, socket write or thread join ever happens while the state mutex is held.

The full audit is in [concurrency.md](concurrency.md).

## What a decision contains

Every `AuthorityDecision` carries the outcome, the reason list with typed codes, the
contributing members with their exact generation, incarnation and constitution digest, the
grants that were considered and the grants that are effective, every conflict found, and
the quality of the evidence. The canonical digest of a decision covers all of it, so two
coordinators that answer the same question from the same evidence produce the same digest.
