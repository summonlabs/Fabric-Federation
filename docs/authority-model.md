# Authority model

This is the exact order in which `evaluate_authority` decides. Every branch records a typed
reason, so a decision can always be explained rather than guessed at.

| # | Check | Outcome on failure | Recorded reason |
| --- | --- | --- | --- |
| 1 | The request names this federation | `REFUSED` | `FEDERATION_IDENTITY_MISMATCH` |
| 2 | The request identifier is not in the replay ledger | `REPLAYED` | `REQUEST_REPLAYED` |
| 3 | The requester's epoch is not ahead of the coordinator's | `REFUSED` | `EPOCH_AHEAD_OF_COORDINATOR` |
| 4 | The requester's epoch is not behind the coordinator's | `STALE` | `EPOCH_STALE` |
| 5 | The scope is local authority | `GRANTED` | `SCOPE_LOCAL_AUTHORITY_ALWAYS_GRANTED` |
| 6 | The scope is in the catalogue | `UNSUPPORTED` | `SCOPE_UNKNOWN_TO_CATALOGUE` |
| 7 | The member is known | `UNKNOWN` | `IDENTITY_MEMBER_UNKNOWN` |
| 8 | Lifecycle holds federation authority | `FENCED`/`REFUSED`/`INCOMPLETE`/`UNKNOWN` | membership reasons |
| 9 | Generation, incarnation and digest all match | `FENCED` (authority held) or `STALE` | `IDENTITY_*_STALE` |
| 10 | No conflict covers the grant | `CONFLICTING` | `DELEGATION_CONFLICT_CONTAINED` |
| 11 | The grant is delegated and not withheld | `REFUSED`/`FENCED`/`DEGRADED` | `SCOPE_NOT_DELEGATED`, `DELEGATION_WITHDRAWN`, `SCOPE_DELEGATION_FORBIDDEN_BY_POLICY`, partition or degraded reasons |
| 12 | A lease is valid, bound to this identity, and covers the grant (when policy requires one) | `REFUSED`/`FENCED`/`STALE` | `LEASE_*` |
| 13 | Global-mutation authority is not suspended | `FENCED` | `PARTITION_*` |
| 14 | A degraded member may mutate | `DEGRADED` | `MEMBERSHIP_DEGRADED_OBSERVATION_GAP` |
| — | otherwise | `GRANTED` | positive reasons |

Outcomes are deliberately distinct and none of them is a synonym for another:

`GRANTED`, `DEGRADED`, `REFUSED`, `FENCED`, `STALE`, `CONFLICTING`,
`INCOMPLETE`, `INDETERMINATE`, `INVALID`, `UNSUPPORTED`, `CANCELLED`, `REPLAYED`,
`UNKNOWN`.

`UNKNOWN` means the federation holds no evidence at all; `INCOMPLETE` means evidence exists
but is not sufficient; `REFUSED` means a decision was made and it was no. Missing evidence
never becomes success.

## Local authority

`evaluate_local_authority` answers questions about the member's own retained authority. It
never consults the federation, and it is unaffected by membership state: a fenced member
still holds every bit of its local authority. The federation has no standing over it.

## Leases

A lease binds: the holder's generation, incarnation and constitution digest; the federation
epoch (both the issuing epoch and an inclusive expiry epoch); the issuing coordinator
incarnation; a logical-tick deadline; and the exact set of grants it covers. Every binding
is re-checked on use. A lease that fails one is reported with the specific reason
(`LEASE_EXPIRED`, `LEASE_REVOKED`, `LEASE_STALE_ISSUER`, `LEASE_EPOCH_MISMATCH`,
`LEASE_HOLDER_MISMATCH`, `LEASE_SCOPE_NOT_COVERED`) and never silently dropped.

A coordinator restart always runs a fresh incarnation. Leases issued by the previous
incarnation become `STALE_ISSUER` — historical evidence rather than live authority — and
must be re-issued. Revocations are durable: a revoked lease is never revived by a restart.

## Conflicts

Two live delegations of the same grant conflict when they disagree: two exclusive claims,
mixed exclusive and shared claims, or shared claims with different weights. The runtime
records the conflict with its claimants and **withholds the grant from every claimant**.
Other grants held by the same members are unaffected, so a conflict is contained to the
grant it is about.

A conflict is resolved only by:

* a claimant withdrawing its delegation, or
* a policy precedence rule that was configured before the conflict existed and that names
  **exactly one** of the claimants. Naming none or several produces
  `PRECEDENCE_UNSATISFIABLE` and the grant stays withheld.

Nothing is ever resolved by which claim arrived last.

## Multi-party admission

Admission requires evidence from at least `required_distinct_parties` distinct member
identities (shipped default: 2 — the sponsor and the candidate), the candidate's own
consent to the exact constitution proposed, and `required_endorsements` endorsements from
members that are neither the sponsor nor the candidate (shipped default: 0). A member can
never sponsor itself, a member that is not established in the federation cannot sponsor or
endorse, and the derivation re-checks all of this itself — a record claiming an admission
the evidence does not support grants nothing.

The federation genesis record establishes the founder and is explicitly single-party. It is
reported as `MULTIPARTY_BOOTSTRAP_GENESIS` and marked `bootstrap` in the state, so a
bootstrap can never be mistaken for multi-party authority.
