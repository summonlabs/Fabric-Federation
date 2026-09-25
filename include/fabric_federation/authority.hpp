// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The authority evaluator.
//
// This is the single place where the question "may this member, presenting this
// identity, exercise this grant, under this evidence?" is answered. The answer
// is a typed outcome plus an explanation that names the contributing members,
// their exact generations, incarnations and digests, the matched policy rules,
// every conflict that was found, and every piece of evidence that was stale,
// unknown or missing.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "fabric_federation/codec.hpp"
#include "fabric_federation/digest.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/explanation.hpp"
#include "fabric_federation/export.hpp"
#include "fabric_federation/ids.hpp"
#include "fabric_federation/identity.hpp"
#include "fabric_federation/lease.hpp"
#include "fabric_federation/policy.hpp"
#include "fabric_federation/scope.hpp"
#include "fabric_federation/state.hpp"

namespace fabric_federation {

struct AuthorityRequest {
  // Replay fence key. A repeated identifier is answered with REPLAYED and the
  // first decision, never with fresh authority.
  RequestId id;
  FederationId federation;
  // The epoch the requester believes is current.
  Epoch epoch_seen;
  MemberIdentity actor;
  ScopeGrant requested;
  // Optional lease the requester presents. Nil means "none presented".
  LeaseId lease;
  Tick issued_at;
  ConstraintToken constraint;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<AuthorityRequest> decode(Reader& reader);
  [[nodiscard]] Digest digest() const;
  [[nodiscard]] std::string to_string() const;
};

struct AuthorityDecision {
  RequestId request;
  Outcome outcome = Outcome::Unknown;
  FederationId federation;
  Epoch epoch_seen;
  Epoch epoch_current;
  ScopeGrant requested;
  MemberIdentity actor_declared;
  MemberIdentity actor_current;
  MemberLifecycleState lifecycle = MemberLifecycleState::Absent;
  std::vector<ScopeGrant> effective_authority;
  Explanation explanation;
  Tick decided_at;

  [[nodiscard]] Digest digest() const;
  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<AuthorityDecision> decode(Reader& reader);
  [[nodiscard]] std::string to_string() const;
};

// Evaluates a federation authority request. The state, policy and catalogue are
// expected to be mutually consistent; the store guarantees that.
//
// Determinism: the evaluation consults only the supplied state (including its
// logical clock, epoch, replay ledger and partition assessment). It never reads
// the wall clock, the file system or any global.
[[nodiscard]] FFED_API AuthorityDecision evaluate_authority(const AuthorityRequest& request,
                                                            const FederationState& state,
                                                            const FederationPolicy& policy,
                                                            const ScopeCatalog& catalog);

// Local authority is never derived from the federation. This call is provided
// so that callers can show, and tests can prove, that a member retains its own
// authority even when the federation has fenced it completely.
[[nodiscard]] FFED_API AuthorityDecision evaluate_local_authority(
    const MemberConstitution& constitution, const ScopeGrant& requested, Tick now);

// Outcome for a grant the federation holds back, given the state. Used by the
// derivation to populate withheld_grants with a matching typed reason.
[[nodiscard]] FFED_API ReasonCode withholding_reason(const FederationState& state,
                                                     const ScopeGrant& grant) noexcept;

}  // namespace fabric_federation
