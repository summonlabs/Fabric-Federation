// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Federation authority leases.
//
// A lease is the coordinator's time- and epoch-bounded permission for one
// member identity to exercise named grants. It is bound to the holder's exact
// (generation, incarnation, digest) triple, to the federation epoch, to the
// issuing coordinator incarnation and to a logical-time bound. Every one of
// those bindings is checked before a lease can contribute authority, and a
// lease that fails any of them is reported as STALE rather than silently
// dropped.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/codec.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/explanation.hpp"
#include "fabric_federation/export.hpp"
#include "fabric_federation/ids.hpp"
#include "fabric_federation/identity.hpp"
#include "fabric_federation/scope.hpp"

namespace fabric_federation {

enum class LeaseState : std::uint8_t {
  Valid = 0,
  Unknown,
  Expired,
  Revoked,
  // Issued by a previous incarnation of the coordinator process. The current
  // incarnation cannot vouch for the liveness of the issuing one, so the lease
  // is historical evidence and must be re-issued.
  StaleIssuer,
  EpochMismatch,
  HolderMismatch,
  ScopeNotCovered,
};

[[nodiscard]] FFED_API std::string_view to_string(LeaseState state) noexcept;

struct AuthorityLease {
  LeaseId id;
  FederationId federation;
  MemberIdentity holder;
  std::vector<ScopeGrant> scopes;
  Epoch issued_epoch;
  // Inclusive upper bound on the epoch. Zero means "this epoch only".
  Epoch not_after_epoch;
  Tick issued_at;
  Tick not_after;
  NodeId issuer_node;
  Incarnation issuer_incarnation;
  bool revoked = false;
  Tick revoked_at;
  ReasonCode revoke_reason = ReasonCode::EvidenceUnknown;
  std::string revoke_detail;

  friend bool operator<(const AuthorityLease& a, const AuthorityLease& b) noexcept {
    return a.id < b.id;
  }
  friend bool operator==(const AuthorityLease& a, const AuthorityLease& b) noexcept;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<AuthorityLease> decode(Reader& reader);
  [[nodiscard]] Digest digest() const;
  [[nodiscard]] std::string to_string() const;
};

struct LeaseEvaluation {
  LeaseState state = LeaseState::Unknown;
  ReasonCode reason = ReasonCode::LeaseMissing;
  std::string detail;

  [[nodiscard]] bool valid() const noexcept { return state == LeaseState::Valid; }
};

// Evaluates a lease against the current coordinator context and a requested
// grant. Deterministic: the evaluation consults no clock other than the
// supplied logical time.
[[nodiscard]] FFED_API LeaseEvaluation evaluate_lease(const AuthorityLease& lease,
                                                      const ScopeGrant& requested,
                                                      Epoch current_epoch,
                                                      Incarnation coordinator_incarnation,
                                                      Tick now);

// Evaluates a lease without a specific requested grant (whole-lease validity).
[[nodiscard]] FFED_API LeaseEvaluation evaluate_lease(const AuthorityLease& lease,
                                                      Epoch current_epoch,
                                                      Incarnation coordinator_incarnation,
                                                      Tick now);

}  // namespace fabric_federation
