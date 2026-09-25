# Canonical form and digests

Two parties that hold equivalent accepted evidence must be able to compare states by
comparing one value. That is what the canonical form is for.

## Encoding rules

* Little-endian fixed-width integers (`u8`, `u16`, `u32`, `u64`).
* Length-prefixed byte strings and text; text must be valid UTF-8 (overlong forms,
  surrogate halves and values above U+10FFFF are rejected).
* Collection counts are encoded before the elements, and every count is validated against a
  bound **before** anything is allocated.
* Collections are sorted and de-duplicated before encoding, so insertion order cannot reach
  the bytes.
* A decoder must consume its input exactly; trailing bytes are a corruption, not something
  to ignore.
* An empty identifier means "unset" and is a legal encoding for optional fields.

## Digests

SHA-256 (FIPS 180-4), implemented in this repository and checked against the published test
vectors, including the 1,000,000 × 'a' vector.

A digest here is an **integrity and determinism primitive**. It is not an authentication
mechanism: transfers are unauthenticated, and there is no signature, key exchange or trust
anchor anywhere in this runtime.

The **canonical state digest** covers the derived logical state: federation, coordinator
identity and incarnation, epoch, reconciling flag, policy identity and generation, logical
clock, genesis digest, description, every member's lifecycle, lineage, identity, retained
and effective authority, withheld grants, fenced incarnations, admission digest, evidence
quality and reasons, every lease view, every conflict, the partition assessment, the replay
ledger and the federation-level reasons.

It deliberately does **not** cover:

* the number of artefacts applied, rejected or de-duplicated — those are coordinator
  bookkeeping, and the number of decision records a coordinator accumulates depends on the
  order evidence arrived;
* operational counters such as connection and protocol-error counts.

Covering them would make the digest order-dependent, which would defeat its purpose.

## Why the state is order independent

Membership, activation and admission are derived from the **evidence**, not from the
decision records a coordinator happens to have written. A coordinator still issues and
journals admission and activation records as an audit trail, and they are persisted and
replayed, but the derived state does not depend on whether — or when — they were written.
That is what lets two coordinators that received the same evidence in different orders
produce the same canonical digest, and it is checked directly in
`tests/unit/test_state.cpp` and by `ffed-cli permutation`.
