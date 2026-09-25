// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Derived federation state.
//
// The derivation is a pure function of the accepted artefact set. It never
// reads a clock, a file or a global: everything it can depend on arrives in
// DerivationInputs. It performs a full recomputation on every call, so
// permutation independence is a structural property rather than something that
// happens to hold for the orders a test happened to try.
#include "fabric_federation/state.hpp"

#include "fabric_federation/version.hpp"

#include <algorithm>
#include <map>
#include <set>

namespace fabric_federation {
namespace {

constexpr std::size_t kMaxDerivationRounds = kMaxMembers + 2;

template <class T>
void sort_unique(std::vector<T>& items) {
  std::sort(items.begin(), items.end());
  items.erase(std::unique(items.begin(), items.end()), items.end());
}

struct GrantClaim {
  MemberId member;
  DelegationTerms terms;
};

bool terms_equivalent(const DelegationTerms& a, const DelegationTerms& b) {
  return a.mode == b.mode && a.weight == b.weight && a.not_after == b.not_after &&
         a.constraint == b.constraint;
}

// Encodes the whole derived state canonically. Used for the state digest and by
// the inspection tools.
Status encode_member_state(Writer& writer, const MemberState& member) {
  Status status = writer.id16(member.member.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(member.domain.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u8(static_cast<std::uint8_t>(member.lifecycle));
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(member.lineage.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(member.lineage_id.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.boolean(member.bootstrap);
  if (!status.ok()) {
    return status;
  }
  status = writer.u8(static_cast<std::uint8_t>(member.partition_state));
  if (!status.ok()) {
    return status;
  }
  status = member.current_identity.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = member.admitted_identity.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = writer.boolean(member.admitted_identity_current);
  if (!status.ok()) {
    return status;
  }
  status = writer.boolean(member.activation_current);
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, member.retained_local_authority, kMaxScopesPerMember);
  if (!status.ok()) {
    return status;
  }
  status = encode_terms(writer, member.delegated_terms, kMaxDelegationTermsPerMember);
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, member.withdrawn_grants, kMaxScopesPerMember);
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, member.federation_authority, kMaxScopesPerMember);
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, member.withheld_grants, kMaxScopesPerMember);
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, member.withheld_global_mutation, kMaxScopesPerMember);
  if (!status.ok()) {
    return status;
  }
  std::vector<Incarnation> incarnations = member.fenced_incarnations;
  std::sort(incarnations.begin(), incarnations.end());
  incarnations.erase(std::unique(incarnations.begin(), incarnations.end()), incarnations.end());
  status = writer.count(incarnations.size(), kMaxMembers);
  if (!status.ok()) {
    return status;
  }
  for (const Incarnation& incarnation : incarnations) {
    status = writer.u64(incarnation.value());
    if (!status.ok()) {
      return status;
    }
  }
  std::vector<LeaseId> leases = member.lease_ids;
  std::sort(leases.begin(), leases.end());
  leases.erase(std::unique(leases.begin(), leases.end()), leases.end());
  status = writer.count(leases.size(), kMaxLeasesPerMember);
  if (!status.ok()) {
    return status;
  }
  for (const LeaseId& lease : leases) {
    status = writer.id16(lease.bytes());
    if (!status.ok()) {
      return status;
    }
  }
  status = writer.digest(member.admission_digest);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(member.activated_epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(member.admitted_epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u8(static_cast<std::uint8_t>(member.evidence));
  if (!status.ok()) {
    return status;
  }
  std::vector<Reason> reasons = member.reasons;
  std::sort(reasons.begin(), reasons.end());
  reasons.erase(std::unique(reasons.begin(), reasons.end()), reasons.end());
  status = writer.count(reasons.size(), kMaxReasonsPerDecision);
  if (!status.ok()) {
    return status;
  }
  for (const Reason& reason : reasons) {
    status = writer.u16(static_cast<std::uint16_t>(reason.code));
    if (!status.ok()) {
      return status;
    }
    status = writer.text(reason.detail, kMaxShortTextLength);
    if (!status.ok()) {
      return status;
    }
  }
  std::vector<ArtifactKind> rejected = member.rejected_kinds;
  std::sort(rejected.begin(), rejected.end());
  rejected.erase(std::unique(rejected.begin(), rejected.end()), rejected.end());
  status = writer.count(rejected.size(), kMaxArtifactsPerMember);
  if (!status.ok()) {
    return status;
  }
  for (const ArtifactKind kind : rejected) {
    status = writer.u16(static_cast<std::uint16_t>(kind));
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

Status encode_federation_state(Writer& writer, const FederationState& state) {
  Status status = writer.u32(kCanonicalStateVersion);
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(state.federation.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(state.coordinator.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(state.coordinator_incarnation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(state.epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.boolean(state.reconciling);
  if (!status.ok()) {
    return status;
  }
  status = writer.identifier(state.policy_id.str());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(state.policy_generation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.digest(state.policy_digest);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(state.logical_time.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.digest(state.genesis_digest);
  if (!status.ok()) {
    return status;
  }
  status = writer.text(state.description, kMaxTextLength);
  if (!status.ok()) {
    return status;
  }
  // Artefact counters are coordinator bookkeeping, not logical state, and the
  // number of coordinator-issued decision records depends on the order evidence
  // arrived. Encoding them would make the canonical digest order-dependent, so
  // only derived facts are encoded. The counters remain available through
  // stats() for operators.

  std::vector<MemberState> members = state.members;
  std::sort(members.begin(), members.end());
  status = writer.count(members.size(), kMaxMembers);
  if (!status.ok()) {
    return status;
  }
  for (const MemberState& member : members) {
    status = encode_member_state(writer, member);
    if (!status.ok()) {
      return status;
    }
  }

  std::vector<LeaseView> leases = state.leases;
  std::sort(leases.begin(), leases.end());
  status = writer.count(leases.size(), kMaxLeases);
  if (!status.ok()) {
    return status;
  }
  for (const LeaseView& lease : leases) {
    status = writer.id16(lease.id.bytes());
    if (!status.ok()) {
      return status;
    }
    status = writer.id16(lease.holder.bytes());
    if (!status.ok()) {
      return status;
    }
    status = writer.u64(lease.holder_incarnation.value());
    if (!status.ok()) {
      return status;
    }
    status = writer.u64(lease.holder_generation.value());
    if (!status.ok()) {
      return status;
    }
    status = encode_grants(writer, lease.scopes, kMaxScopesPerLease);
    if (!status.ok()) {
      return status;
    }
    status = writer.u64(lease.issued_epoch.value());
    if (!status.ok()) {
      return status;
    }
    status = writer.u64(lease.not_after.value());
    if (!status.ok()) {
      return status;
    }
    status = writer.u8(static_cast<std::uint8_t>(lease.state));
    if (!status.ok()) {
      return status;
    }
    status = writer.boolean(lease.revoked);
    if (!status.ok()) {
      return status;
    }
  }

  status = encode_conflicts(writer, state.conflicts, kMaxConflicts);
  if (!status.ok()) {
    return status;
  }

  std::vector<ReplayEntry> ledger = state.replay_ledger;
  std::sort(ledger.begin(), ledger.end());
  ledger.erase(std::unique(ledger.begin(), ledger.end()), ledger.end());
  status = writer.count(ledger.size(), kMaxReplayEntries);
  if (!status.ok()) {
    return status;
  }
  for (const ReplayEntry& entry : ledger) {
    status = writer.id16(entry.request.bytes());
    if (!status.ok()) {
      return status;
    }
    status = writer.digest(entry.decision);
    if (!status.ok()) {
      return status;
    }
    status = writer.u64(entry.decided_at.value());
    if (!status.ok()) {
      return status;
    }
  }

  status = writer.u8(static_cast<std::uint8_t>(state.partition.state));
  if (!status.ok()) {
    return status;
  }
  std::vector<PartitionComponent> components = state.partition.components;
  std::sort(components.begin(), components.end());
  status = writer.count(components.size(), kMaxMembers);
  if (!status.ok()) {
    return status;
  }
  for (const PartitionComponent& component : components) {
    std::vector<MemberId> members_of = component.members;
    std::sort(members_of.begin(), members_of.end());
    status = writer.count(members_of.size(), kMaxMembers);
    if (!status.ok()) {
      return status;
    }
    for (const MemberId& member : members_of) {
      status = writer.id16(member.bytes());
      if (!status.ok()) {
        return status;
      }
    }
  }

  std::vector<Reason> global = state.global_reasons;
  std::sort(global.begin(), global.end());
  global.erase(std::unique(global.begin(), global.end()), global.end());
  status = writer.count(global.size(), kMaxReasonsPerDecision);
  if (!status.ok()) {
    return status;
  }
  for (const Reason& reason : global) {
    status = writer.u16(static_cast<std::uint16_t>(reason.code));
    if (!status.ok()) {
      return status;
    }
    status = writer.text(reason.detail, kMaxShortTextLength);
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

struct PreparedArtifacts {
  std::vector<Artifact> accepted;
  std::vector<Reason> rejected;
  std::size_t duplicates = 0;
  std::vector<ConflictRecord> conflicts;
};

PreparedArtifacts prepare_artifacts(const DerivationInputs& inputs, const ScopeCatalog& catalog) {
  PreparedArtifacts prepared;
  std::map<EvidenceId, const Artifact*> by_id;
  std::set<EvidenceId> quarantined;
  for (const Artifact& artifact : inputs.artifacts) {
    const auto existing = by_id.find(artifact.envelope.evidence);
    if (existing == by_id.end()) {
      by_id[artifact.envelope.evidence] = &artifact;
      continue;
    }
    ++prepared.duplicates;
    if (existing->second->digest() == artifact.digest()) {
      Reason reason;
      reason.code = ReasonCode::EvidenceDuplicateIdentical;
      reason.detail = "evidence " + artifact.envelope.evidence.to_string() +
                      " arrived more than once with identical content";
      prepared.rejected.push_back(std::move(reason));
      continue;
    }
    // The same identifier with different content is equivocation. Neither copy
    // is applied: the federation records the disagreement instead of guessing.
    quarantined.insert(artifact.envelope.evidence);
    ConflictRecord conflict;
    conflict.grant = ScopeGrant{};
    conflict.kind = ConflictKind::DuplicateEvidence;
    conflict.claimants.push_back(existing->second->envelope.issuer.member);
    conflict.claimants.push_back(artifact.envelope.issuer.member);
    conflict.detail = "evidence " + artifact.envelope.evidence.to_string() +
                      " was presented twice with different content; both copies are quarantined";
    prepared.conflicts.push_back(std::move(conflict));
    Reason reason;
    reason.code = ReasonCode::EvidenceDuplicateConflicting;
    reason.detail = conflict.detail;
    prepared.rejected.push_back(std::move(reason));
  }

  for (const auto& entry : by_id) {
    if (quarantined.count(entry.first) != 0) {
      continue;
    }
    const Artifact& artifact = *entry.second;
    if (artifact.envelope.federation != inputs.federation) {
      Reason reason;
      reason.code = ReasonCode::FederationIdentityMismatch;
      reason.detail = "evidence " + artifact.envelope.evidence.to_string() +
                      " belongs to federation " + artifact.envelope.federation.to_string();
      prepared.rejected.push_back(std::move(reason));
      continue;
    }
    const Status status = artifact.validate(catalog);
    if (!status.ok()) {
      Reason reason;
      reason.code = ReasonCode::ArtifactMalformed;
      reason.detail = "evidence " + artifact.envelope.evidence.to_string() + ": " +
                      status.to_string();
      prepared.rejected.push_back(std::move(reason));
      continue;
    }
    prepared.accepted.push_back(artifact);
  }
  std::sort(prepared.accepted.begin(), prepared.accepted.end(),
            [](const Artifact& a, const Artifact& b) {
              return a.envelope.evidence < b.envelope.evidence;
            });
  canonicalize_conflicts(prepared.conflicts);
  return prepared;
}

}  // namespace

const MemberState* FederationState::find(const MemberId& member) const {
  for (const MemberState& candidate : members) {
    if (candidate.member == member) {
      return &candidate;
    }
  }
  return nullptr;
}

std::size_t FederationState::active_member_count() const {
  std::size_t count = 0;
  for (const MemberState& member : members) {
    if (member.lifecycle == MemberLifecycleState::Active ||
        member.lifecycle == MemberLifecycleState::Degraded) {
      ++count;
    }
  }
  return count;
}

bool FederationState::has_replay(const RequestId& request) const {
  for (const ReplayEntry& entry : replay_ledger) {
    if (entry.request == request) {
      return true;
    }
  }
  return false;
}

Digest FederationState::digest() const {
  Writer writer;
  if (!encode_federation_state(writer, *this).ok()) {
    return Digest();
  }
  return writer.sha256();
}

Result<DerivationResult> derive_state(const DerivationInputs& inputs) {
  if (inputs.policy == nullptr) {
    return Status::make(ErrorCode::InvalidArgument, "derivation requires a policy");
  }
  if (inputs.catalog == nullptr) {
    return Status::make(ErrorCode::InvalidArgument, "derivation requires a scope catalogue");
  }
  const FederationPolicy& catalog_policy = *inputs.policy;
  const ScopeCatalog& catalog = *inputs.catalog;

  DerivationResult result;
  FederationState& state = result.state;
  state.federation = inputs.federation;
  state.coordinator = inputs.coordinator;
  state.coordinator_incarnation = inputs.coordinator_incarnation;
  state.logical_time = inputs.logical_time;
  state.recovery = inputs.recovery;

  PreparedArtifacts prepared = prepare_artifacts(inputs, catalog);
  result.rejected = prepared.rejected;
  state.duplicate_artifact_count = prepared.duplicates;
  state.conflicts = prepared.conflicts;
  // Why an artefact was refused is part of the federation's observable state:
  // silently dropping evidence is exactly the failure mode this runtime exists
  // to avoid. The list is bounded so that hostile input cannot grow it without
  // limit.
  for (std::size_t i = 0; i < prepared.rejected.size(); ++i) {
    if (state.global_reasons.size() >= kMaxReasonsPerDecision) {
      Reason reason;
      reason.code = ReasonCode::LimitExceeded;
      reason.detail = "the rejection list was truncated at the configured bound";
      state.global_reasons.push_back(std::move(reason));
      break;
    }
    state.global_reasons.push_back(prepared.rejected[i]);
  }

  // ---- federation genesis -------------------------------------------------
  std::vector<const Artifact*> genesis_records;
  for (const Artifact& artifact : prepared.accepted) {
    if (artifact.envelope.kind == ArtifactKind::FederationGenesis) {
      genesis_records.push_back(&artifact);
    }
  }
  const FederationGenesis* genesis = nullptr;
  if (genesis_records.size() == 1) {
    genesis = &genesis_records.front()->body.genesis;
    state.genesis_digest = genesis_records.front()->digest();
    state.description = genesis->description;
  } else if (genesis_records.size() > 1) {
    ConflictRecord conflict;
    conflict.kind = ConflictKind::ConflictingIdentity;
    conflict.detail = "the federation carries more than one genesis record; the founder identity "
                      "is ambiguous and no member is bootstrapped";
    for (const Artifact* record : genesis_records) {
      conflict.claimants.push_back(record->envelope.subject);
    }
    state.conflicts.push_back(std::move(conflict));
    Reason reason;
    reason.code = ReasonCode::ArtifactRejected;
    reason.detail = conflict.detail;
    state.global_reasons.push_back(std::move(reason));
  }

  // ---- policy -------------------------------------------------------------
  const Artifact* newest_policy = nullptr;
  for (const Artifact& artifact : prepared.accepted) {
    if (artifact.envelope.kind != ArtifactKind::PolicyUpdate) {
      continue;
    }
    if (newest_policy == nullptr ||
        newest_policy->body.policy_generation < artifact.body.policy_generation ||
        (newest_policy->body.policy_generation == artifact.body.policy_generation &&
         artifact.envelope.evidence < newest_policy->envelope.evidence)) {
      newest_policy = &artifact;
    }
  }
  const FederationPolicy* policy = &catalog_policy;
  if (newest_policy != nullptr) {
    policy = &newest_policy->body.policy;
    state.policy_generation = newest_policy->body.policy_generation;
  } else if (genesis != nullptr) {
    policy = &genesis->policy;
    state.policy_generation = genesis->policy.generation;
  } else {
    state.policy_generation = catalog_policy.generation;
  }
  state.policy_id = policy->id;
  state.policy_digest = policy->digest();

  // ---- epoch and logical clock -------------------------------------------
  std::uint64_t epoch_value = 1;
  std::vector<const Artifact*> epoch_advances;
  for (const Artifact& artifact : prepared.accepted) {
    if (artifact.envelope.kind == ArtifactKind::EpochAdvance) {
      epoch_advances.push_back(&artifact);
      if (artifact.body.epoch.value() > epoch_value) {
        epoch_value = artifact.body.epoch.value();
      }
    }
    // The logical clock is driven by the coordinator's own records only. A
    // member-supplied issue stamp is metadata on the artefact and never moves
    // federation time.
    if (artifact.body.logical_time.value() > state.logical_time.value()) {
      state.logical_time = artifact.body.logical_time;
    }
  }
  state.epoch = Epoch(epoch_value);

  // ---- reconciliation -----------------------------------------------------
  bool needs_reconciliation = false;
  Epoch recovery_epoch;
  for (const Artifact* advance : epoch_advances) {
    if (advance->body.reason_code == ReasonCode::PartitionSplitSuspendsGlobalMutation ||
        advance->body.reason_code == ReasonCode::PartitionIndeterminateSuspendsGlobalMutation) {
      if (!needs_reconciliation || recovery_epoch < advance->body.epoch) {
        needs_reconciliation = true;
        recovery_epoch = advance->body.epoch;
      }
    }
  }
  bool reconciliation_recorded = false;
  if (needs_reconciliation) {
    for (const Artifact& artifact : prepared.accepted) {
      if (artifact.envelope.kind == ArtifactKind::ReconciliationComplete &&
          artifact.body.epoch >= recovery_epoch) {
        reconciliation_recorded = true;
      }
    }
  }
  state.reconciling = needs_reconciliation;
  if (needs_reconciliation) {
    Reason reason;
    reason.code = ReasonCode::PartitionReconcilingSuspendsGlobalMutation;
    reason.detail = "the federation advanced to epoch " +
                    std::to_string(recovery_epoch.value()) +
                    " after a partition and is reconciling";
    state.global_reasons.push_back(std::move(reason));
  }

  // ---- bootstrap members --------------------------------------------------
  std::vector<MemberId> bootstrap_members;
  std::vector<MemberDeclaration> bootstrap_declarations;
  if (genesis != nullptr) {
    bootstrap_members.push_back(genesis->founder.constitution.member);
    bootstrap_declarations.push_back(genesis->founder);
  }

  // ---- index artefacts by subject ----------------------------------------
  std::map<MemberId, std::vector<Artifact>> by_member;
  std::vector<MemberId> member_order;
  for (const Artifact& artifact : prepared.accepted) {
    if (artifact.envelope.subject.is_nil()) {
      continue;
    }
    auto& bucket = by_member[artifact.envelope.subject];
    bucket.push_back(artifact);
    member_order.push_back(artifact.envelope.subject);
  }
  for (const MemberId& bootstrap : bootstrap_members) {
    by_member[bootstrap];
    member_order.push_back(bootstrap);
  }
  for (const AuthorityLease& lease : inputs.leases) {
    if (!lease.holder.member.is_nil()) {
      by_member[lease.holder.member];
      member_order.push_back(lease.holder.member);
    }
  }
  sort_unique(member_order);
  if (member_order.size() > kMaxMembers) {
    return Status::make(ErrorCode::BoundsExceeded, "more members than the configured bound");
  }
  state.artifact_count = prepared.accepted.size();
  state.rejected_artifact_count = prepared.rejected.size();

  // ---- established-membership fixpoint ------------------------------------
  // Standing is computed before activation currency: an epoch advance makes
  // every activation stale simultaneously, and membership must not unravel
  // because of it.
  std::vector<MemberId> active_members;
  PartitionAssessment neutral;
  neutral.state = PartitionState::Connected;
  neutral.evidence = EvidenceState::Known;
  neutral.summary = "partition influence withheld during the standing fixpoint";

  std::map<MemberId, MembershipDerivation> derivation_by_member;
  bool converged = false;
  for (std::size_t round = 0; round < kMaxDerivationRounds; ++round) {
    MembershipContext context;
    context.federation = inputs.federation;
    context.current_epoch = state.epoch;
    context.now = state.logical_time;
    context.policy = policy;
    context.catalog = &catalog;
    context.partition = neutral;
    context.reconciling = false;
    context.established_members = active_members;
    context.bootstrap_members = bootstrap_members;
    context.bootstrap_declarations = bootstrap_declarations;

    std::map<MemberId, MembershipDerivation> next;
    std::vector<MemberId> next_established;
    for (const MemberId& member : member_order) {
      MembershipDerivation derivation =
          derive_membership(member, by_member[member], context);
      if (derivation.lifecycle == MemberLifecycleState::Active ||
          derivation.lifecycle == MemberLifecycleState::Degraded ||
          derivation.lifecycle == MemberLifecycleState::Admitted) {
        next_established.push_back(member);
      }
      next[member] = std::move(derivation);
    }
    sort_unique(next_established);
    const bool stable = next_established == active_members;
    active_members = next_established;
    derivation_by_member = std::move(next);
    if (stable) {
      converged = true;
      break;
    }
  }
  if (!converged) {
    Reason reason;
    reason.code = ReasonCode::LimitExceeded;
    reason.detail =
        "the established-member fixpoint did not converge within the configured bound";
    state.global_reasons.push_back(std::move(reason));
  }

  // ---- partition assessment ----------------------------------------------
  std::vector<Incarnation> active_incarnations;
  for (const MemberId& member : active_members) {
    const auto found = derivation_by_member.find(member);
    if (found == derivation_by_member.end()) {
      active_incarnations.push_back(Incarnation());
      continue;
    }
    active_incarnations.push_back(found->second.facts.current_identity.incarnation);
  }
  state.partition = assess_partition(active_members, active_incarnations, inputs.observations,
                                     state.epoch, state.logical_time,
                                     policy->observation_freshness_ticks());
  if (state.partition.state != PartitionState::Connected) {
    Reason reason;
    reason.code = state.partition.state == PartitionState::Split
                      ? ReasonCode::PartitionSplitSuspendsGlobalMutation
                      : ReasonCode::PartitionIndeterminateSuspendsGlobalMutation;
    reason.detail = state.partition.summary;
    state.global_reasons.push_back(std::move(reason));
  }

  // ---- reconcile clearance ------------------------------------------------
  if (state.reconciling && reconciliation_recorded) {
    bool all_reattested = true;
    for (const MemberId& member : active_members) {
      const auto found = derivation_by_member.find(member);
      if (found == derivation_by_member.end()) {
        all_reattested = false;
        break;
      }
      if (!found->second.facts.has_reattestation) {
        all_reattested = false;
        break;
      }
    }
    if (all_reattested) {
      state.reconciling = false;
    } else {
      Reason reason;
      reason.code = ReasonCode::PartitionReattestationMissing;
      reason.detail = "a reconciliation record exists but not every active member has re-attested";
      state.global_reasons.push_back(std::move(reason));
    }
  }

  // ---- final per-member derivation ---------------------------------------
  MembershipContext context;
  context.federation = inputs.federation;
  context.current_epoch = state.epoch;
  context.now = state.logical_time;
  context.policy = policy;
  context.catalog = &catalog;
  context.partition = state.partition;
  context.reconciling = state.reconciling;
  context.established_members = active_members;
  context.bootstrap_members = bootstrap_members;
  context.bootstrap_declarations = bootstrap_declarations;

  std::vector<MemberState> members;
  std::vector<GrantClaim> claims;
  for (const MemberId& member : member_order) {
    MembershipDerivation derivation = derive_membership(member, by_member[member], context);
    if (derivation.lifecycle == MemberLifecycleState::Active && !converged) {
      Reason reason;
      reason.code = ReasonCode::EvidenceIndeterminate;
      reason.detail = "the established-member fixpoint did not converge; this member's "
                      "activation is treated as indeterminate";
      derivation.facts.reasons.push_back(std::move(reason));
    }
    MemberState member_state;
    member_state.member = member;
    member_state.domain = derivation.facts.declaration.constitution.domain;
    member_state.lifecycle = derivation.lifecycle;
    member_state.lineage = derivation.facts.lineage;
    member_state.lineage_id = MembershipSlot::make(member, derivation.facts.lineage).lineage_id;
    member_state.bootstrap = derivation.facts.bootstrap;
    member_state.partition_state = state.partition.state;
    member_state.declaration = derivation.facts.declaration;
    member_state.current_identity = derivation.facts.current_identity;
    member_state.admitted_identity = derivation.facts.admitted_identity;
    member_state.admitted_identity_current =
        derivation.facts.admitted_identity.constitution ==
        derivation.facts.current_identity.constitution;
    member_state.activation_current = derivation.facts.activation_matches_identity &&
                                      derivation.facts.activation_at_current_epoch;
    member_state.contributing_parties = derivation.facts.contributions;
    member_state.reasons = derivation.facts.reasons;
    member_state.rejected_kinds = derivation.facts.rejected_kinds;
    member_state.retained_local_authority = derivation.retained_local_authority;
    member_state.delegated_terms = derivation.facts.delegated_terms;
    member_state.withdrawn_grants = derivation.facts.withdrawn_grants;
    member_state.admission_digest = derivation.facts.admission_digest;
    // Activation facts are derived: the epoch the member is activated at is
    // the epoch its evidence currently supports, so two coordinators that
    // received the same evidence in different orders agree.
    member_state.activated_epoch =
        derivation.facts.activation_at_current_epoch ? state.epoch : Epoch();
    member_state.activated_at = Tick();
    member_state.admitted_epoch = derivation.facts.admitted_epoch;
    member_state.evidence = derivation.facts.evidence;
    member_state.conflicts = derivation.facts.conflicts;
    member_state.fenced_incarnations = derivation.facts.superseded_incarnations;
    members.push_back(std::move(member_state));
  }

  for (const MemberState& member : members) {
    if (!lifecycle_holds_federation_authority(member.lifecycle)) {
      continue;
    }
    for (const DelegationTerms& terms : member.delegated_terms) {
      GrantClaim claim;
      claim.member = member.member;
      claim.terms = terms;
      claims.push_back(std::move(claim));
    }
  }

  // ---- conflict detection over live claims --------------------------------
  std::map<ScopeGrant, std::vector<GrantClaim>> claims_by_grant;
  for (const GrantClaim& claim : claims) {
    claims_by_grant[claim.terms.grant].push_back(claim);
  }

  std::set<ScopeGrant> conflicted_grants;
  std::map<ScopeGrant, MemberId> precedence_winner;
  for (const auto& entry : claims_by_grant) {
    const ScopeGrant& grant = entry.first;
    const std::vector<GrantClaim>& group = entry.second;
    if (group.size() < 2) {
      continue;
    }
    bool conflict = false;
    ConflictKind kind = ConflictKind::OverlappingExclusive;
    for (std::size_t i = 0; i < group.size() && !conflict; ++i) {
      for (std::size_t j = i + 1; j < group.size(); ++j) {
        const DelegationTerms& a = group[i].terms;
        const DelegationTerms& b = group[j].terms;
        if (a.mode != b.mode) {
          conflict = true;
          kind = ConflictKind::ModeMismatch;
        } else if (a.mode == DelegationMode::Exclusive) {
          conflict = true;
          kind = ConflictKind::OverlappingExclusive;
        } else if (!terms_equivalent(a, b)) {
          conflict = true;
          kind = ConflictKind::AmbiguousPrecedence;
        }
        if (conflict) {
          break;
        }
      }
    }
    if (!conflict) {
      continue;
    }
    std::vector<MemberId> claimants;
    for (const GrantClaim& claim : group) {
      claimants.push_back(claim.member);
    }
    sort_unique(claimants);
    const std::vector<MemberId>* precedence = policy->precedence_for(grant);
    if (precedence != nullptr) {
      std::vector<MemberId> matching;
      for (const MemberId& candidate : *precedence) {
        if (std::find(claimants.begin(), claimants.end(), candidate) != claimants.end()) {
          matching.push_back(candidate);
        }
      }
      if (matching.size() == 1) {
        precedence_winner[grant] = matching.front();
        continue;
      }
      ConflictRecord record;
      record.grant = grant;
      record.kind = ConflictKind::PrecedenceUnsatisfiable;
      record.claimants = claimants;
      record.detail = "configured precedence names " + std::to_string(matching.size()) +
                      " of the claimants, so it cannot order them";
      state.conflicts.push_back(std::move(record));
      conflicted_grants.insert(grant);
      continue;
    }
    ConflictRecord record;
    record.grant = grant;
    record.kind = kind;
    record.claimants = claimants;
    record.detail = "overlapping delegations of " + grant.to_string() +
                    " disagree; the grant is withheld from every claimant until a party changes "
                    "its declaration or policy configures precedence";
    state.conflicts.push_back(std::move(record));
    conflicted_grants.insert(grant);
  }

  // ---- effective authority -------------------------------------------------
  for (MemberState& member : members) {
    const auto derivation_entry = derivation_by_member.find(member.member);
    const bool needs_reactivation =
        derivation_entry != derivation_by_member.end() &&
        derivation_entry->second.facts.has_admission &&
        derivation_entry->second.facts.activation_matches_identity == false;
    std::vector<ScopeGrant> granted;
    std::vector<ScopeGrant> withheld;
    std::vector<ScopeGrant> withheld_global;
    const bool holds = lifecycle_holds_federation_authority(member.lifecycle) &&
                       !(needs_reactivation && member.lifecycle == MemberLifecycleState::Admitted);
    for (const DelegationTerms& terms : member.delegated_terms) {
      const ScopeGrant grant = terms.grant;
      bool known = false;
      const ScopeClass scope_class = catalog.classify(grant.scope, known);
      if (!known || scope_class == ScopeClass::Local) {
        withheld.push_back(grant);
        Reason reason;
        reason.code = ReasonCode::ScopeUnknownToCatalogue;
        reason.detail = grant.to_string() + " is not delegable in this build";
        member.reasons.push_back(std::move(reason));
        continue;
      }
      if (policy->scope_delegation_forbidden(grant.scope)) {
        withheld.push_back(grant);
        Reason reason;
        reason.code = ReasonCode::ScopeDelegationForbiddenByPolicy;
        reason.detail = "policy forbids delegating " + grant.scope.str();
        member.reasons.push_back(std::move(reason));
        continue;
      }
      bool withdrawn = false;
      for (const ScopeGrant& candidate : member.withdrawn_grants) {
        if (candidate.verb == grant.verb && candidate.scope.covers(grant.scope)) {
          withdrawn = true;
          break;
        }
      }
      if (withdrawn) {
        withheld.push_back(grant);
        Reason reason;
        reason.code = ReasonCode::DelegationWithdrawn;
        reason.detail = grant.to_string() + " was withdrawn by the member";
        member.reasons.push_back(std::move(reason));
        continue;
      }
      if (!terms.not_after.is_zero() && state.logical_time > terms.not_after) {
        withheld.push_back(grant);
        Reason reason;
        reason.code = ReasonCode::DelegationExpired;
        reason.detail = grant.to_string() + " expired at tick " +
                        std::to_string(terms.not_after.value());
        member.reasons.push_back(std::move(reason));
        continue;
      }
      if (conflicted_grants.count(grant) != 0) {
        withheld.push_back(grant);
        continue;
      }
      const auto winner = precedence_winner.find(grant);
      if (winner != precedence_winner.end() && winner->second != member.member) {
        withheld.push_back(grant);
        Reason reason;
        reason.code = ReasonCode::DelegationPrecedenceConfigured;
        reason.detail = grant.to_string() + " is held by " + winner->second.to_string() +
                        " under the configured precedence order";
        member.reasons.push_back(std::move(reason));
        continue;
      }
      if (winner != precedence_winner.end() && winner->second == member.member) {
        Reason reason;
        reason.code = ReasonCode::DelegationPrecedenceConfigured;
        reason.detail = grant.to_string() + " is held by this member under the configured "
                        "precedence order";
        member.reasons.push_back(std::move(reason));
      }
      if (!holds) {
        withheld.push_back(grant);
        continue;
      }
      if (scope_class == ScopeClass::GlobalMutation) {
        const bool suspended =
            (state.reconciling && policy->suspend_global_mutation_while_reconciling()) ||
            ((state.partition.state == PartitionState::Split ||
              state.partition.state == PartitionState::Indeterminate) &&
             policy->suspend_global_mutation_on_partition());
        if (suspended) {
          withheld_global.push_back(grant);
          continue;
        }
      }
      if (member.lifecycle == MemberLifecycleState::Degraded &&
          (grant.verb == AuthorityVerb::Mutate || grant.verb == AuthorityVerb::Administer)) {
        withheld.push_back(grant);
        continue;
      }
      granted.push_back(grant);
    }
    canonicalize_grants(granted);
    canonicalize_grants(withheld);
    canonicalize_grants(withheld_global);
    member.federation_authority = std::move(granted);
    member.withheld_grants = std::move(withheld);
    member.withheld_global_mutation = std::move(withheld_global);
  }

  // ---- leases --------------------------------------------------------------
  for (const AuthorityLease& lease : inputs.leases) {
    LeaseView view;
    view.id = lease.id;
    view.holder = lease.holder.member;
    view.holder_incarnation = lease.holder.incarnation;
    view.holder_generation = lease.holder.generation;
    view.scopes = lease.scopes;
    view.issued_epoch = lease.issued_epoch;
    view.not_after = lease.not_after;
    view.revoked = lease.revoked;
    LeaseEvaluation evaluation =
        evaluate_lease(lease, state.epoch, inputs.coordinator_incarnation, state.logical_time);
    view.state = evaluation.state;
    view.reason = evaluation.reason;
    state.leases.push_back(std::move(view));
  }
  std::sort(state.leases.begin(), state.leases.end());
  for (MemberState& member : members) {
    for (const LeaseView& lease : state.leases) {
      if (lease.holder == member.member) {
        member.lease_ids.push_back(lease.id);
      }
    }
  }

  // ---- replay ledger -------------------------------------------------------
  state.replay_ledger = inputs.replay_ledger;
  std::sort(state.replay_ledger.begin(), state.replay_ledger.end());
  state.replay_ledger.erase(
      std::unique(state.replay_ledger.begin(), state.replay_ledger.end()),
      state.replay_ledger.end());
  if (state.replay_ledger.size() > kMaxReplayEntries) {
    state.replay_ledger.resize(kMaxReplayEntries);
    Reason reason;
    reason.code = ReasonCode::LimitExceeded;
    reason.detail = "the replay ledger was truncated to the configured bound";
    state.global_reasons.push_back(std::move(reason));
  }

  canonicalize_conflicts(state.conflicts);
  // Every member that is a claimant of a federation-wide conflict carries it in
  // its own record, so an authority question about the disputed grant is
  // answered CONFLICTING rather than "not delegated".
  for (MemberState& member : members) {
    for (const ConflictRecord& conflict : state.conflicts) {
      if (std::find(conflict.claimants.begin(), conflict.claimants.end(), member.member) !=
          conflict.claimants.end()) {
        member.conflicts.push_back(conflict);
      }
    }
  }
  // The derived per-member records become part of the state here. Everything
  // above operates on a local vector so that the sorting and de-duplication
  // below happen exactly once, on the final data.
  state.members = std::move(members);
  std::sort(state.members.begin(), state.members.end());
  for (MemberState& member : state.members) {
    std::sort(member.reasons.begin(), member.reasons.end());
    member.reasons.erase(std::unique(member.reasons.begin(), member.reasons.end()),
                         member.reasons.end());
    canonicalize_conflicts(member.conflicts);
    std::sort(member.fenced_incarnations.begin(), member.fenced_incarnations.end());
    std::sort(member.lease_ids.begin(), member.lease_ids.end());
  }
  std::sort(state.global_reasons.begin(), state.global_reasons.end());
  state.global_reasons.erase(
      std::unique(state.global_reasons.begin(), state.global_reasons.end()),
      state.global_reasons.end());
  return result;
}

std::string summarize_state(const FederationState& state) {
  std::string out = "federation=";
  out.append(state.federation.to_string());
  out.append(" epoch=");
  out.append(std::to_string(state.epoch.value()));
  out.append(" members=");
  out.append(std::to_string(state.member_count()));
  out.append(" active=");
  out.append(std::to_string(state.active_member_count()));
  out.append(" partition=");
  out.append(fabric_federation::to_string(state.partition.state));
  if (state.reconciling) {
    out.append(" reconciling");
  }
  out.append(" digest=");
  out.append(state.digest_hex().substr(0, 16));
  return out;
}

std::string render_state_text(const FederationState& state) {
  std::string out;
  out.append("federation:        ");
  out.append(state.federation.to_string());
  out.append("\n");
  out.append("coordinator:       ");
  out.append(state.coordinator.to_string());
  out.append(" incarnation ");
  out.append(std::to_string(state.coordinator_incarnation.value()));
  out.append("\n");
  out.append("epoch:             ");
  out.append(std::to_string(state.epoch.value()));
  out.append(state.reconciling ? " (reconciling)" : "");
  out.append("\n");
  out.append("policy:            ");
  out.append(state.policy_id.str());
  out.append(" generation ");
  out.append(std::to_string(state.policy_generation.value()));
  out.append(" digest ");
  out.append(state.policy_digest.to_hex().substr(0, 16));
  out.append("\n");
  out.append("logical tick:      ");
  out.append(std::to_string(state.logical_time.value()));
  out.append("\n");
  out.append("partition:         ");
  out.append(fabric_federation::to_string(state.partition.state));
  out.append(" - ");
  out.append(state.partition.summary);
  out.append("\n");
  out.append("artefacts:         ");
  out.append(std::to_string(state.artifact_count));
  out.append(" applied, ");
  out.append(std::to_string(state.rejected_artifact_count));
  out.append(" rejected, ");
  out.append(std::to_string(state.duplicate_artifact_count));
  out.append(" duplicate\n");
  out.append("state digest:      ");
  out.append(state.digest_hex());
  out.append("\n");
  out.append("\nmembers:\n");
  if (state.members.empty()) {
    out.append("  (none)\n");
  }
  for (const MemberState& member : state.members) {
    out.append("  - ");
    out.append(member.member.to_string());
    out.append(" [");
    out.append(fabric_federation::to_string(member.lifecycle));
    out.append("] lineage=");
    out.append(std::to_string(member.lineage.value()));
    if (member.bootstrap) {
      out.append(" bootstrap");
    }
    out.append("\n");
    out.append("      identity: gen=");
    out.append(std::to_string(member.current_identity.generation.value()));
    out.append(" inc=");
    out.append(std::to_string(member.current_identity.incarnation.value()));
    out.append(" digest=");
    out.append(member.current_identity.constitution.to_hex().substr(0, 16));
    out.append("\n");
    out.append("      local authority: ");
    out.append(render_grants(member.retained_local_authority));
    out.append("\n");
    out.append("      federation authority: ");
    out.append(render_grants(member.federation_authority));
    out.append("\n");
    if (!member.withheld_grants.empty()) {
      out.append("      withheld: ");
      out.append(render_grants(member.withheld_grants));
      out.append("\n");
    }
    if (!member.withheld_global_mutation.empty()) {
      out.append("      withheld (global mutation): ");
      out.append(render_grants(member.withheld_global_mutation));
      out.append("\n");
    }
    if (!member.fenced_incarnations.empty()) {
      out.append("      fenced incarnations:");
      for (const Incarnation& incarnation : member.fenced_incarnations) {
        out.append(" ");
        out.append(std::to_string(incarnation.value()));
      }
      out.append("\n");
    }
    if (!member.contributing_parties.empty()) {
      out.append("      contributing parties:\n");
      for (const Contribution& contribution : member.contributing_parties) {
        out.append("        * ");
        out.append(contribution.member.to_string());
        out.append(" as ");
        out.append(fabric_federation::to_string(contribution.role));
        out.append(" gen=");
        out.append(std::to_string(contribution.generation.value()));
        out.append(" inc=");
        out.append(std::to_string(contribution.incarnation.value()));
        out.append(" digest=");
        out.append(contribution.constitution.to_hex().substr(0, 16));
        out.append("\n");
      }
    }
  }
  out.append("\nconflicts:\n");
  if (state.conflicts.empty()) {
    out.append("  (none)\n");
  }
  for (const ConflictRecord& conflict : state.conflicts) {
    out.append("  - ");
    out.append(conflict.to_string());
    out.append("\n");
  }
  out.append("\nleases:\n");
  if (state.leases.empty()) {
    out.append("  (none)\n");
  }
  for (const LeaseView& lease : state.leases) {
    out.append("  - ");
    out.append(lease.id.to_string());
    out.append(" holder=");
    out.append(lease.holder.to_string());
    out.append(" [");
    out.append(fabric_federation::to_string(lease.state));
    out.append("] scopes=");
    out.append(render_grants(lease.scopes));
    out.append("\n");
  }
  if (!state.global_reasons.empty()) {
    out.append("\nfederation reasons:\n");
    for (const Reason& reason : state.global_reasons) {
      out.append("  - ");
      out.append(reason.to_string());
      out.append("\n");
    }
  }
  return out;
}

void render_state_json(const FederationState& state, JsonWriter& writer) {
  writer.begin_object();
  writer.key("federation");
  writer.string(state.federation.to_string());
  writer.key("coordinator");
  writer.string(state.coordinator.to_string());
  writer.key("coordinator_incarnation");
  writer.number(state.coordinator_incarnation.value());
  writer.key("epoch");
  writer.number(state.epoch.value());
  writer.key("reconciling");
  writer.boolean(state.reconciling);
  writer.key("policy_id");
  writer.string(state.policy_id.str());
  writer.key("policy_generation");
  writer.number(state.policy_generation.value());
  writer.key("policy_digest");
  writer.string(state.policy_digest.to_hex());
  writer.key("logical_tick");
  writer.number(state.logical_time.value());
  writer.key("state_digest");
  writer.string(state.digest_hex());
  writer.key("artifact_count");
  writer.number(static_cast<std::uint64_t>(state.artifact_count));
  writer.key("rejected_artifact_count");
  writer.number(static_cast<std::uint64_t>(state.rejected_artifact_count));
  writer.key("duplicate_artifact_count");
  writer.number(static_cast<std::uint64_t>(state.duplicate_artifact_count));
  writer.key("partition");
  writer.begin_object();
  writer.key("state");
  writer.string(fabric_federation::to_string(state.partition.state));
  writer.key("summary");
  writer.string(state.partition.summary);
  writer.key("components");
  writer.number(static_cast<std::uint64_t>(state.partition.components.size()));
  writer.end_object();
  writer.key("members");
  writer.begin_array();
  for (const MemberState& member : state.members) {
    writer.begin_object();
    writer.key("member");
    writer.string(member.member.to_string());
    writer.key("domain");
    writer.string(member.domain.to_string());
    writer.key("lifecycle");
    writer.string(fabric_federation::to_string(member.lifecycle));
    writer.key("lineage");
    writer.number(member.lineage.value());
    writer.key("bootstrap");
    writer.boolean(member.bootstrap);
    writer.key("generation");
    writer.number(member.current_identity.generation.value());
    writer.key("incarnation");
    writer.number(member.current_identity.incarnation.value());
    writer.key("constitution_digest");
    writer.string(member.current_identity.constitution.to_hex());
    writer.key("current");
    writer.boolean(member.activation_current);
    writer.key("evidence");
    writer.string(fabric_federation::to_string(member.evidence));
    writer.key("local_authority");
    writer.begin_array();
    for (const ScopeGrant& grant : member.retained_local_authority) {
      writer.string(grant.to_string());
    }
    writer.end_array();
    writer.key("federation_authority");
    writer.begin_array();
    for (const ScopeGrant& grant : member.federation_authority) {
      writer.string(grant.to_string());
    }
    writer.end_array();
    writer.key("withheld");
    writer.begin_array();
    for (const ScopeGrant& grant : member.withheld_grants) {
      writer.string(grant.to_string());
    }
    writer.end_array();
    writer.key("withheld_global_mutation");
    writer.begin_array();
    for (const ScopeGrant& grant : member.withheld_global_mutation) {
      writer.string(grant.to_string());
    }
    writer.end_array();
    writer.key("contributors");
    writer.begin_array();
    for (const Contribution& contribution : member.contributing_parties) {
      writer.begin_object();
      writer.key("member");
      writer.string(contribution.member.to_string());
      writer.key("role");
      writer.string(fabric_federation::to_string(contribution.role));
      writer.key("generation");
      writer.number(contribution.generation.value());
      writer.key("incarnation");
      writer.number(contribution.incarnation.value());
      writer.key("constitution_digest");
      writer.string(contribution.constitution.to_hex());
      writer.end_object();
    }
    writer.end_array();
    writer.end_object();
  }
  writer.end_array();
  writer.key("conflicts");
  writer.begin_array();
  for (const ConflictRecord& conflict : state.conflicts) {
    writer.begin_object();
    writer.key("grant");
    writer.string(conflict.grant.to_string());
    writer.key("kind");
    writer.string(fabric_federation::to_string(conflict.kind));
    writer.key("claimants");
    writer.begin_array();
    for (const MemberId& claimant : conflict.claimants) {
      writer.string(claimant.to_string());
    }
    writer.end_array();
    writer.key("detail");
    writer.string(conflict.detail);
    writer.end_object();
  }
  writer.end_array();
  writer.key("leases");
  writer.begin_array();
  for (const LeaseView& lease : state.leases) {
    writer.begin_object();
    writer.key("id");
    writer.string(lease.id.to_string());
    writer.key("holder");
    writer.string(lease.holder.to_string());
    writer.key("state");
    writer.string(fabric_federation::to_string(lease.state));
    writer.key("issued_epoch");
    writer.number(lease.issued_epoch.value());
    writer.key("not_after_tick");
    writer.number(lease.not_after.value());
    writer.key("revoked");
    writer.boolean(lease.revoked);
    writer.key("scopes");
    writer.begin_array();
    for (const ScopeGrant& grant : lease.scopes) {
      writer.string(grant.to_string());
    }
    writer.end_array();
    writer.end_object();
  }
  writer.end_array();
  writer.key("reasons");
  writer.begin_array();
  for (const Reason& reason : state.global_reasons) {
    writer.begin_object();
    writer.key("code");
    writer.string(fabric_federation::to_string(reason.code));
    writer.key("detail");
    writer.string(reason.detail);
    writer.end_object();
  }
  writer.end_array();
  writer.end_object();
}

}  // namespace fabric_federation
