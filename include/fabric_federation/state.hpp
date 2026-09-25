// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Derived federation state.
//
// derive_state() is a pure function of the accepted evidence set. It performs a
// full recomputation from the canonicalised artefact set on every call, which
// is what makes permutation independence structural rather than a property that
// happens to hold for the orders a test tried.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "fabric_federation/digest.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/evidence.hpp"
#include "fabric_federation/explanation.hpp"
#include "fabric_federation/export.hpp"
#include "fabric_federation/identity.hpp"
#include "fabric_federation/journal.hpp"
#include "fabric_federation/json.hpp"
#include "fabric_federation/lease.hpp"
#include "fabric_federation/membership.hpp"
#include "fabric_federation/partition.hpp"
#include "fabric_federation/policy.hpp"
#include "fabric_federation/scope.hpp"

namespace fabric_federation {

// One entry of the replay fence. A request identifier that is already present
// is never re-evaluated into fresh authority.
struct ReplayEntry {
  RequestId request;
  Digest decision;
  Tick decided_at;

  friend bool operator<(const ReplayEntry& a, const ReplayEntry& b) noexcept {
    return a.request < b.request;
  }
  friend bool operator==(const ReplayEntry& a, const ReplayEntry& b) noexcept {
    return a.request == b.request && a.decision == b.decision && a.decided_at == b.decided_at;
  }
};

struct LeaseView {
  LeaseId id;
  MemberId holder;
  Incarnation holder_incarnation;
  Generation holder_generation;
  std::vector<ScopeGrant> scopes;
  Epoch issued_epoch;
  Tick not_after;
  LeaseState state = LeaseState::Unknown;
  ReasonCode reason = ReasonCode::LeaseMissing;
  bool revoked = false;

  friend bool operator<(const LeaseView& a, const LeaseView& b) noexcept { return a.id < b.id; }
};

struct MemberState {
  MemberId member;
  FabricDomainId domain;
  MemberLifecycleState lifecycle = MemberLifecycleState::Absent;
  Lineage lineage;
  LineageId lineage_id;
  bool bootstrap = false;
  PartitionState partition_state = PartitionState::Empty;

  MemberDeclaration declaration;
  MemberIdentity current_identity;
  MemberIdentity admitted_identity;
  bool admitted_identity_current = false;
  bool activation_current = false;

  std::vector<Contribution> contributing_parties;
  std::vector<Reason> reasons;
  std::vector<ConflictRecord> conflicts;
  std::vector<ArtifactKind> rejected_kinds;

  // Authority the member keeps no matter what the federation decides.
  std::vector<ScopeGrant> retained_local_authority;
  // What the member offered, as currently declared.
  std::vector<DelegationTerms> delegated_terms;
  // Grants withdrawn by the member. Never restored implicitly.
  std::vector<ScopeGrant> withdrawn_grants;
  // What the federation actually grants this member right now.
  std::vector<ScopeGrant> federation_authority;
  // Grants the member delegated that are withheld, with the reason.
  std::vector<ScopeGrant> withheld_grants;
  std::vector<ScopeGrant> withheld_global_mutation;
  // Incarnations whose federation authority has been fenced by this state.
  std::vector<Incarnation> fenced_incarnations;
  std::vector<LeaseId> lease_ids;

  Digest admission_digest;
  Epoch activated_epoch;
  Tick activated_at;
  Epoch admitted_epoch;
  EvidenceState evidence = EvidenceState::Unknown;
  bool limit_reached = false;

  friend bool operator<(const MemberState& a, const MemberState& b) noexcept {
    return a.member < b.member;
  }
};

struct FederationState {
  FederationId federation;
  NodeId coordinator;
  Incarnation coordinator_incarnation;

  Epoch epoch;
  // True between an epoch advance caused by partition recovery and the matching
  // reconciliation record. Global-mutation authority is suspended throughout.
  bool reconciling = false;

  PolicyId policy_id;
  Generation policy_generation;
  Digest policy_digest;

  Tick logical_time;
  Digest genesis_digest;
  std::string description;

  std::size_t artifact_count = 0;
  std::size_t rejected_artifact_count = 0;
  std::size_t duplicate_artifact_count = 0;

  std::vector<MemberState> members;
  std::vector<LeaseView> leases;
  std::vector<ConflictRecord> conflicts;
  std::vector<ReplayEntry> replay_ledger;
  PartitionAssessment partition;
  std::vector<Reason> global_reasons;
  std::vector<RecoveryDiagnostic> recovery;

  [[nodiscard]] const MemberState* find(const MemberId& member) const;
  [[nodiscard]] std::size_t active_member_count() const;
  [[nodiscard]] std::size_t member_count() const { return members.size(); }
  [[nodiscard]] bool has_replay(const RequestId& request) const;

  // Canonical digest over the whole derived state. Two processes holding
  // equivalent accepted evidence compute the same value.
  [[nodiscard]] Digest digest() const;
  [[nodiscard]] std::string digest_hex() const { return digest().to_hex(); }
};

struct DerivationInputs {
  FederationId federation;
  NodeId coordinator;
  Incarnation coordinator_incarnation;
  Tick logical_time;
  const FederationPolicy* policy = nullptr;
  const ScopeCatalog* catalog = nullptr;
  // Artefacts in any order. The derivation canonicalises them itself.
  std::vector<Artifact> artifacts;
  std::vector<MemberObservation> observations;
  std::vector<AuthorityLease> leases;
  std::vector<ReplayEntry> replay_ledger;
  std::vector<RecoveryDiagnostic> recovery;
};

struct DerivationResult {
  FederationState state;
  // Artefacts the derivation refused to apply, with the reason.
  std::vector<Reason> rejected;
};

[[nodiscard]] FFED_API Result<DerivationResult> derive_state(const DerivationInputs& inputs);

// Renders the state as stable text and as JSON for the inspection tools.
[[nodiscard]] FFED_API std::string render_state_text(const FederationState& state);
FFED_API void render_state_json(const FederationState& state, JsonWriter& writer);
// Compact single-line rendering used by `ffed-cli status`.
[[nodiscard]] FFED_API std::string summarize_state(const FederationState& state);

}  // namespace fabric_federation
