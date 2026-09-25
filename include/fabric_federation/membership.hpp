// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Membership derivation.
//
// Membership is explicit and multi-party. The derived lifecycle below is a pure
// function of the artefact set, the policy and the federation context. In
// particular the derivation re-checks the multi-party rules itself: a
// coordinator record that claims an admission the evidence does not support is
// recorded as rejected and grants nothing. One member cannot manufacture
// multi-party authority, not even by writing the record that says it did.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/digest.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/evidence.hpp"
#include "fabric_federation/explanation.hpp"
#include "fabric_federation/export.hpp"
#include "fabric_federation/identity.hpp"
#include "fabric_federation/partition.hpp"
#include "fabric_federation/policy.hpp"
#include "fabric_federation/scope.hpp"

namespace fabric_federation {

struct MembershipContext {
  FederationId federation;
  Epoch current_epoch;
  Tick now;
  const FederationPolicy* policy = nullptr;
  const ScopeCatalog* catalog = nullptr;
  PartitionAssessment partition;
  bool reconciling = false;
  // Members whose membership is established: admitted, active or degraded. A
  // sponsor or endorser must itself be established. derive_state() computes
  // this by fixpoint, starting from the bootstrap founder, so the derived state
  // stays a pure function of the artefact set.
  //
  // Established deliberately does not mean "currently activated": an epoch
  // advance makes every activation stale at once, and if standing depended on
  // activation currency the whole membership would unravel on every epoch
  // advance. Activation currency is checked separately, and a member whose
  // activation is stale is DEGRADED rather than un-admitted.
  std::vector<MemberId> established_members;
  // Members established by the federation genesis record. Bootstrap membership
  // is explicitly single-party and is reported as such.
  std::vector<MemberId> bootstrap_members;
  // The declarations those members were established with. A bootstrap member has
  // no proposal artefact, so its constitution comes from the genesis record.
  std::vector<MemberDeclaration> bootstrap_declarations;
};

// Facts the derivation extracted from the artefact set for one member.
struct MembershipFacts {
  bool has_proposal = false;
  bool has_acceptance = false;
  bool has_admission = false;
  bool has_activation = false;
  bool has_leave = false;
  bool has_fence = false;
  bool has_retirement = false;
  bool has_reattestation = false;
  bool bootstrap = false;
  // The acceptance echoes exactly the identity in the proposal.
  bool acceptance_matches_declaration = false;
  // The activation is bound to the member's current declared identity.
  bool activation_matches_identity = false;
  bool activation_at_current_epoch = false;
  bool generation_changed_since_admission = false;

  Lineage lineage;
  std::size_t endorsement_count = 0;
  std::size_t distinct_parties = 0;
  std::vector<MemberId> endorsers;

  MemberDeclaration declaration;
  MemberIdentity current_identity;
  MemberIdentity admitted_identity;
  std::vector<DelegationTerms> delegated_terms;
  std::vector<ScopeGrant> withdrawn_grants;
  std::vector<Contribution> contributions;
  std::vector<Reason> reasons;
  std::vector<ConflictRecord> conflicts;
  std::vector<ArtifactKind> rejected_kinds;
  Epoch activation_epoch;
  Tick activation_tick;
  Epoch admitted_epoch;
  Epoch fence_epoch;
  // Incarnations that once held an activation for this member and no longer do.
  // They are fenced: the federation will not honour authority presented under
  // them.
  std::vector<Incarnation> superseded_incarnations;
  ReasonCode fence_reason = ReasonCode::EvidenceUnknown;
  Digest admission_digest;
  EvidenceState evidence = EvidenceState::Unknown;
  bool limit_reached = false;
};

struct MembershipDerivation {
  MemberLifecycleState lifecycle = MemberLifecycleState::Absent;
  MembershipFacts facts;
  // Authority the member keeps regardless of any federation outcome.
  std::vector<ScopeGrant> retained_local_authority;
};

// Derives the lifecycle of one member.
//   `member_artifacts` must contain only artefacts whose subject is `member`
//   (plus federation-level records the caller chose to include).
[[nodiscard]] FFED_API MembershipDerivation derive_membership(
    const MemberId& member, const std::vector<Artifact>& member_artifacts,
    const MembershipContext& context);

// Multi-party evaluation, exposed so it can be tested directly.
struct MultiPartyAssessment {
  std::size_t distinct_parties = 0;
  std::size_t endorsements = 0;
  std::vector<MemberId> parties;
  bool proposer_is_candidate = false;
  bool proposer_active = false;
  bool bootstrap = false;
  bool satisfied = false;
  std::vector<Reason> reasons;
};

[[nodiscard]] FFED_API MultiPartyAssessment assess_multi_party(
    const MemberId& candidate, const MemberId& proposer, bool proposer_active,
    const std::vector<MemberId>& endorsers, const FederationPolicy& policy, bool bootstrap);

}  // namespace fabric_federation
