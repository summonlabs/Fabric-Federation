// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The authority evaluator. Read this file together with docs/authority-model.md;
// the order of the checks below is the order documented there, and every branch
// records a typed reason so that a decision can always be explained.
#include "fabric_federation/authority.hpp"

#include <algorithm>

namespace fabric_federation {
namespace {

void add_actor_contribution(Explanation& explanation, const AuthorityRequest& request,
                            bool current) {
  Contribution contribution;
  contribution.member = request.actor.member;
  contribution.role = ContributionRole::Actor;
  contribution.generation = request.actor.generation;
  contribution.incarnation = request.actor.incarnation;
  contribution.constitution = request.actor.constitution;
  contribution.evidence = request.digest();
  contribution.epoch = request.epoch_seen;
  contribution.identity_current = current;
  explanation.contributions.push_back(std::move(contribution));
}

bool holds_authority(MemberLifecycleState state) {
  return lifecycle_holds_federation_authority(state);
}

}  // namespace

Status AuthorityRequest::encode(Writer& writer) const {
  Status status = writer.id16(id.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(federation.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(epoch_seen.value());
  if (!status.ok()) {
    return status;
  }
  status = actor.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = requested.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(lease.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(issued_at.value());
  if (!status.ok()) {
    return status;
  }
  return writer.identifier(constraint.str());
}

Result<AuthorityRequest> AuthorityRequest::decode(Reader& reader) {
  AuthorityRequest request;
  auto id = reader.id16();
  if (!id.has_value()) {
    return id.status();
  }
  request.id = RequestId::from_bytes(id.value());
  auto federation = reader.id16();
  if (!federation.has_value()) {
    return federation.status();
  }
  request.federation = FederationId::from_bytes(federation.value());
  auto epoch = reader.u64();
  if (!epoch.has_value()) {
    return epoch.status();
  }
  request.epoch_seen = Epoch(epoch.value());
  auto actor = MemberIdentity::decode(reader);
  if (!actor.has_value()) {
    return actor.status();
  }
  request.actor = std::move(actor.value());
  auto requested = ScopeGrant::decode(reader);
  if (!requested.has_value()) {
    return requested.status();
  }
  request.requested = std::move(requested.value());
  auto lease = reader.id16();
  if (!lease.has_value()) {
    return lease.status();
  }
  request.lease = LeaseId::from_bytes(lease.value());
  auto issued_at = reader.u64();
  if (!issued_at.has_value()) {
    return issued_at.status();
  }
  request.issued_at = Tick(issued_at.value());
  auto constraint = reader.identifier();
  if (!constraint.has_value()) {
    return constraint.status();
  }
  if (!constraint.value().empty()) {
    auto parsed = ConstraintToken::parse(constraint.value());
    if (!parsed.has_value()) {
      return Status::make(ErrorCode::InvalidArgument, "request constraint is malformed");
    }
    request.constraint = std::move(parsed.value());
  }
  return request;
}

Digest AuthorityRequest::digest() const {
  Writer writer;
  if (!encode(writer).ok()) {
    return Digest();
  }
  return writer.sha256();
}

std::string AuthorityRequest::to_string() const {
  std::string out = id.to_string();
  out.append(" actor=");
  out.append(actor.to_string());
  out.append(" grant=");
  out.append(requested.to_string());
  out.append(" epoch_seen=");
  out.append(std::to_string(epoch_seen.value()));
  if (!lease.is_nil()) {
    out.append(" lease=");
    out.append(lease.to_string());
  }
  return out;
}

Digest AuthorityDecision::digest() const {
  Writer writer;
  if (!encode(writer).ok()) {
    return Digest();
  }
  return writer.sha256();
}

Status AuthorityDecision::encode(Writer& writer) const {
  Status status = writer.id16(request.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u8(static_cast<std::uint8_t>(outcome));
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(federation.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(epoch_seen.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(epoch_current.value());
  if (!status.ok()) {
    return status;
  }
  status = requested.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = actor_declared.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = actor_current.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = writer.u8(static_cast<std::uint8_t>(lifecycle));
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, effective_authority, kMaxEffectiveGrantsPerDecision);
  if (!status.ok()) {
    return status;
  }
  status = explanation.encode(writer);
  if (!status.ok()) {
    return status;
  }
  return writer.u64(decided_at.value());
}

Result<AuthorityDecision> AuthorityDecision::decode(Reader& reader) {
  AuthorityDecision decision;
  auto request = reader.id16();
  if (!request.has_value()) {
    return request.status();
  }
  decision.request = RequestId::from_bytes(request.value());
  auto outcome = reader.u8();
  if (!outcome.has_value()) {
    return outcome.status();
  }
  if (outcome.value() > static_cast<std::uint8_t>(Outcome::Unknown)) {
    return Status::make(ErrorCode::InvalidArgument, "decision outcome is out of range");
  }
  decision.outcome = static_cast<Outcome>(outcome.value());
  auto federation = reader.id16();
  if (!federation.has_value()) {
    return federation.status();
  }
  decision.federation = FederationId::from_bytes(federation.value());
  auto epoch_seen = reader.u64();
  if (!epoch_seen.has_value()) {
    return epoch_seen.status();
  }
  decision.epoch_seen = Epoch(epoch_seen.value());
  auto epoch_current = reader.u64();
  if (!epoch_current.has_value()) {
    return epoch_current.status();
  }
  decision.epoch_current = Epoch(epoch_current.value());
  auto requested = ScopeGrant::decode(reader);
  if (!requested.has_value()) {
    return requested.status();
  }
  decision.requested = std::move(requested.value());
  auto declared = MemberIdentity::decode(reader);
  if (!declared.has_value()) {
    return declared.status();
  }
  decision.actor_declared = std::move(declared.value());
  auto current = MemberIdentity::decode(reader);
  if (!current.has_value()) {
    return current.status();
  }
  decision.actor_current = std::move(current.value());
  auto lifecycle = reader.u8();
  if (!lifecycle.has_value()) {
    return lifecycle.status();
  }
  if (lifecycle.value() > static_cast<std::uint8_t>(MemberLifecycleState::Retired)) {
    return Status::make(ErrorCode::InvalidArgument, "lifecycle state is out of range");
  }
  decision.lifecycle = static_cast<MemberLifecycleState>(lifecycle.value());
  auto effective = decode_grants(reader, kMaxEffectiveGrantsPerDecision);
  if (!effective.has_value()) {
    return effective.status();
  }
  decision.effective_authority = std::move(effective.value());
  auto explanation = Explanation::decode(reader);
  if (!explanation.has_value()) {
    return explanation.status();
  }
  decision.explanation = std::move(explanation.value());
  auto decided_at = reader.u64();
  if (!decided_at.has_value()) {
    return decided_at.status();
  }
  decision.decided_at = Tick(decided_at.value());
  return decision;
}

std::string AuthorityDecision::to_string() const {
  std::string out(fabric_federation::to_string(outcome));
  out.append(" request=");
  out.append(request.to_string());
  out.append(" grant=");
  out.append(requested.to_string());
  out.append(" lifecycle=");
  out.append(fabric_federation::to_string(lifecycle));
  out.append(" epoch=");
  out.append(std::to_string(epoch_current.value()));
  if (!effective_authority.empty()) {
    out.append(" effective=[");
    out.append(render_grants(effective_authority));
    out.append("]");
  }
  out.append(" digest=");
  out.append(digest().to_hex().substr(0, 16));
  return out;
}

ReasonCode withholding_reason(const FederationState& state, const ScopeGrant& grant) noexcept {
  (void)grant;
  if (state.reconciling) {
    return ReasonCode::PartitionReconcilingSuspendsGlobalMutation;
  }
  if (state.partition.state == PartitionState::Split) {
    return ReasonCode::PartitionSplitSuspendsGlobalMutation;
  }
  if (state.partition.state == PartitionState::Indeterminate) {
    return ReasonCode::PartitionIndeterminateSuspendsGlobalMutation;
  }
  return ReasonCode::MembershipDegradedObservationGap;
}

AuthorityDecision evaluate_local_authority(const MemberConstitution& constitution,
                                          const ScopeGrant& requested, Tick now) {
  AuthorityDecision decision;
  decision.requested = requested;
  decision.decided_at = now;
  decision.actor_current.domain = constitution.domain;
  decision.actor_current.member = constitution.member;
  decision.actor_current.generation = constitution.generation;
  decision.actor_current.constitution = constitution.digest();
  decision.lifecycle = MemberLifecycleState::Active;

  Contribution contribution;
  contribution.member = constitution.member;
  contribution.role = ContributionRole::Actor;
  contribution.generation = constitution.generation;
  contribution.constitution = constitution.digest();
  contribution.identity_current = true;
  contribution.note = "local authority";
  decision.explanation.contributions.push_back(std::move(contribution));
  decision.explanation.considered_grants.push_back(requested);

  if (grants_cover(constitution.retained, requested)) {
    decision.outcome = Outcome::Granted;
    decision.explanation.outcome = Outcome::Granted;
    decision.explanation.evidence = EvidenceState::Known;
    decision.explanation.add(ReasonCode::ScopeLocalAuthorityAlwaysGranted,
                             "the member retains " + requested.to_string() +
                                 "; the federation has no standing over local authority");
    decision.effective_authority.push_back(requested);
    decision.explanation.effective_grants.push_back(requested);
  } else {
    decision.outcome = Outcome::Refused;
    decision.explanation.outcome = Outcome::Refused;
    decision.explanation.evidence = EvidenceState::Known;
    decision.explanation.add(ReasonCode::ScopeRetainedLocalAuthority,
                             requested.to_string() +
                                 " is not part of the member's retained local authority; "
                                 "federation authority must be requested from the coordinator");
  }
  decision.explanation.summary =
      "local authority evaluation for " + requested.to_string();
  decision.explanation.canonicalize();
  return decision;
}

AuthorityDecision evaluate_authority(const AuthorityRequest& request, const FederationState& state,
                                     const FederationPolicy& policy,
                                     const ScopeCatalog& catalog) {
  AuthorityDecision decision;
  decision.request = request.id;
  decision.federation = request.federation;
  decision.epoch_seen = request.epoch_seen;
  decision.epoch_current = state.epoch;
  decision.requested = request.requested;
  decision.actor_declared = request.actor;
  decision.decided_at = state.logical_time;

  Explanation& explanation = decision.explanation;
  explanation.considered_grants.push_back(request.requested);
  add_actor_contribution(explanation, request, false);

  const auto finish = [&](Outcome outcome, EvidenceState evidence, std::string summary) {
    decision.outcome = outcome;
    explanation.outcome = outcome;
    explanation.evidence = evidence;
    explanation.summary = std::move(summary);
    explanation.canonicalize();
    return decision;
  };

  // ---- 1. the federation itself -------------------------------------------
  if (request.federation != state.federation) {
    explanation.add(ReasonCode::FederationIdentityMismatch,
                    "request names " + request.federation.to_string() + ", this coordinator serves " +
                        state.federation.to_string());
    return finish(Outcome::Refused, EvidenceState::Invalid,
                  "the request names a federation this coordinator does not serve");
  }

  // ---- 2. replay fence -----------------------------------------------------
  if (state.has_replay(request.id)) {
    explanation.add(ReasonCode::RequestReplayed,
                    "request " + request.id.to_string() +
                        " was already decided; a repeated identifier never grants fresh authority");
    return finish(Outcome::Replayed, EvidenceState::Known,
                  "the request identifier is already in the replay ledger");
  }
  explanation.add(ReasonCode::RequestFresh, "request identifier has not been decided before");

  // ---- 3. epoch ------------------------------------------------------------
  if (request.epoch_seen > state.epoch) {
    explanation.add(ReasonCode::EpochAheadOfCoordinator,
                    "request was made at epoch " + std::to_string(request.epoch_seen.value()) +
                        ", this coordinator is at epoch " + std::to_string(state.epoch.value()) +
                        "; authority is not granted on an epoch the coordinator cannot see");
    return finish(Outcome::Refused, EvidenceState::Stale,
                  "the requester has seen a later epoch than this coordinator");
  }
  if (request.epoch_seen < state.epoch) {
    explanation.add(ReasonCode::EpochStale,
                    "request was made at epoch " + std::to_string(request.epoch_seen.value()) +
                        ", current epoch is " + std::to_string(state.epoch.value()));
    return finish(Outcome::Stale, EvidenceState::Stale, "the request belongs to a previous epoch");
  }
  explanation.add(ReasonCode::EpochMatches,
                  "epoch " + std::to_string(state.epoch.value()) + " matches");

  // ---- 4. local authority is decided locally -------------------------------
  bool scope_known = false;
  const ScopeClass scope_class = catalog.classify(request.requested.scope, scope_known);
  if (scope_known && scope_class == ScopeClass::Local) {
    explanation.add(ReasonCode::ScopeLocalAuthorityAlwaysGranted,
                    request.requested.to_string() +
                        " is local authority; the federation neither grants nor removes it");
    decision.effective_authority.push_back(request.requested);
    explanation.effective_grants.push_back(request.requested);
    return finish(Outcome::Granted, EvidenceState::Known,
                  "local authority; the federation has no standing over it");
  }
  if (!scope_known) {
    explanation.add(ReasonCode::ScopeUnknownToCatalogue,
                    "scope " + request.requested.scope.str() +
                        " is not in the federation scope catalogue of this build");
    return finish(Outcome::Unsupported, EvidenceState::Unknown,
                  "the requested scope is not modelled by this build");
  }

  // ---- 5. member lookup ----------------------------------------------------
  const MemberState* member_state = state.find(request.actor.member);
  if (member_state == nullptr) {
    explanation.add(ReasonCode::IdentityMemberUnknown,
                    "no evidence about member " + request.actor.member.to_string() +
                        " exists in this federation");
    return finish(Outcome::Unknown, EvidenceState::Unknown,
                  "the federation holds no evidence about the requesting member");
  }
  decision.actor_current = member_state->current_identity;
  decision.lifecycle = member_state->lifecycle;
  decision.effective_authority = member_state->federation_authority;
  for (const Contribution& contribution : member_state->contributing_parties) {
    explanation.contributions.push_back(contribution);
  }
  for (const ConflictRecord& conflict : member_state->conflicts) {
    explanation.conflicts.push_back(conflict);
  }
  for (const Reason& reason : member_state->reasons) {
    explanation.reasons.push_back(reason);
  }
  for (Contribution& contribution : explanation.contributions) {
    contribution.identity_current =
        contribution.member == member_state->member &&
        contribution.constitution == member_state->current_identity.constitution;
  }

  EvidenceState evidence = member_state->evidence;

  // ---- 6. lifecycle --------------------------------------------------------
  switch (member_state->lifecycle) {
    case MemberLifecycleState::Absent:
      return finish(Outcome::Unknown, EvidenceState::Unknown,
                    "the member has no membership evidence at all");
    case MemberLifecycleState::Proposed:
      return finish(Outcome::Incomplete, EvidenceState::Incomplete,
                    "the member is proposed but not admitted");
    case MemberLifecycleState::Admitted:
      return finish(Outcome::Incomplete, EvidenceState::Incomplete,
                    "the member is admitted but not active at the current epoch");
    case MemberLifecycleState::Retired:
      return finish(Outcome::Refused, evidence, "the membership lineage has been retired");
    case MemberLifecycleState::Leaving:
      explanation.add(ReasonCode::MembershipLeaving,
                      "the member has left; every federation-derived grant ended and local "
                      "authority was untouched");
      return finish(Outcome::Fenced, evidence, "the member has left the federation");
    case MemberLifecycleState::Fenced:
      explanation.add(ReasonCode::MembershipFencedByOrder,
                      "a fence is in force for this member");
      return finish(Outcome::Fenced, evidence, "federation authority is fenced for this member");
    case MemberLifecycleState::Active:
    case MemberLifecycleState::Degraded:
      break;
  }

  // ---- 7. exact identity ---------------------------------------------------
  const bool authority_held = holds_authority(member_state->lifecycle);
  const IdentityMismatch mismatch =
      compare_identities(member_state->current_identity, request.actor);
  if (mismatch != IdentityMismatch::None) {
    const Outcome outcome = authority_held ? Outcome::Fenced : Outcome::Stale;
    switch (mismatch) {
      case IdentityMismatch::Member:
      case IdentityMismatch::Domain:
        explanation.add(ReasonCode::IdentityMemberUnknown,
                        "presented member/domain does not match the recorded member");
        return finish(Outcome::Refused, EvidenceState::Invalid,
                      "the presented identity names a different member");
      case IdentityMismatch::Generation:
        explanation.add(ReasonCode::IdentityGenerationStale,
                        "presented generation " +
                            std::to_string(request.actor.generation.value()) +
                            ", current generation " +
                            std::to_string(member_state->current_identity.generation.value()));
        break;
      case IdentityMismatch::Constitution:
        explanation.add(ReasonCode::IdentityConstitutionStale,
                        "presented constitution " +
                            request.actor.constitution.to_hex().substr(0, 16) +
                            ", current constitution " +
                            member_state->current_identity.constitution.to_hex().substr(0, 16));
        break;
      case IdentityMismatch::Incarnation:
        explanation.add(ReasonCode::IdentityIncarnationStale,
                        "presented incarnation " +
                            std::to_string(request.actor.incarnation.value()) +
                            ", current incarnation " +
                            std::to_string(member_state->current_identity.incarnation.value()));
        break;
      case IdentityMismatch::Node:
        explanation.add(ReasonCode::IdentityIncarnationStale,
                        "presented node " + request.actor.node.to_string() +
                            " is not the node recorded for the current incarnation");
        break;
      case IdentityMismatch::None:
        break;
    }
    return finish(outcome, EvidenceState::Stale,
                  authority_held
                      ? "the presented identity no longer matches the authority that was granted; "
                        "the authority is fenced"
                      : "the presented identity is superseded");
  }
  explanation.add(ReasonCode::IdentityMatches, "generation, incarnation and digest match");

  // ---- 8. delegation -------------------------------------------------------
  for (const ConflictRecord& conflict : member_state->conflicts) {
    if (conflict.grant.verb == request.requested.verb &&
        conflict.grant.scope.covers(request.requested.scope)) {
      explanation.add(ReasonCode::DelegationConflictContained,
                      "overlapping delegations disagree about " + conflict.grant.to_string() +
                          "; no party is granted the grant while the disagreement stands");
      return finish(Outcome::Conflicting, EvidenceState::Conflicting,
                    "overlapping delegations conflict; the grant is contained, not awarded");
    }
  }

  if (!grants_cover(member_state->federation_authority, request.requested)) {
    bool withdrawn = false;
    for (const ScopeGrant& grant : member_state->withdrawn_grants) {
      if (grant.verb == request.requested.verb && grant.scope.covers(request.requested.scope)) {
        withdrawn = true;
        break;
      }
    }
    if (withdrawn) {
      explanation.add(ReasonCode::DelegationWithdrawn,
                      "the member withdrew " + request.requested.to_string());
      return finish(Outcome::Refused, EvidenceState::Known,
                    "the member withdrew this grant; withdrawal is not restored implicitly");
    }
    if (policy.scope_delegation_forbidden(request.requested.scope)) {
      explanation.add(ReasonCode::ScopeDelegationForbiddenByPolicy,
                      "policy forbids delegating " + request.requested.scope.str());
      return finish(Outcome::Refused, EvidenceState::Known,
                    "federation policy forbids this delegation");
    }
    bool withheld_global = false;
    for (const ScopeGrant& grant : member_state->withheld_global_mutation) {
      if (grant == request.requested) {
        withheld_global = true;
        break;
      }
    }
    if (withheld_global) {
      const ReasonCode code = withholding_reason(state, request.requested);
      explanation.add(code, "global-mutation authority over " + request.requested.to_string() +
                                " is suspended");
      return finish(Outcome::Fenced, EvidenceState::Stale,
                    "global-mutation authority is suspended by the current partition state");
    }
    bool delegated_but_withheld = false;
    for (const ScopeGrant& grant : member_state->withheld_grants) {
      if (grant == request.requested) {
        delegated_but_withheld = true;
        break;
      }
    }
    if (delegated_but_withheld) {
      explanation.add(ReasonCode::MembershipDegradedObservationGap,
                      "the grant is delegated but currently withheld from this member");
      return finish(Outcome::Degraded, EvidenceState::Indeterminate,
                    "the grant is withheld while the federation is degraded");
    }
    const bool ever_delegated = [&] {
      for (const DelegationTerms& terms : member_state->delegated_terms) {
        if (terms.grant.verb == request.requested.verb &&
            terms.grant.scope.covers(request.requested.scope)) {
          return true;
        }
      }
      return false;
    }();
    if (ever_delegated) {
      explanation.add(ReasonCode::ScopeVerbNotDelegated,
                      request.requested.to_string() +
                          " is delegated for other verbs but not for this one");
      return finish(Outcome::Refused, EvidenceState::Known,
                    "the member delegated the scope but not for this verb");
    }
    explanation.add(ReasonCode::ScopeNotDelegated,
                    "the member never delegated " + request.requested.to_string() +
                        "; the authority remains local to the member");
    return finish(Outcome::Refused, EvidenceState::Known,
                  "the member never delegated this grant to the federation");
  }
  explanation.add(ReasonCode::ScopeCoveredByDelegation,
                  request.requested.to_string() + " is covered by the member's delegation");

  // ---- 9. lease ------------------------------------------------------------
  if (policy.lease_required(request.requested)) {
    explanation.add(ReasonCode::LeaseRequiredByPolicy,
                    "policy requires a lease for " + request.requested.to_string());
    if (request.lease.is_nil()) {
      explanation.add(ReasonCode::LeaseMissing, "no lease was presented");
      return finish(Outcome::Refused, EvidenceState::Incomplete,
                    "a lease is required for this grant and none was presented");
    }
    const LeaseView* view = nullptr;
    for (const LeaseView& candidate : state.leases) {
      if (candidate.id == request.lease) {
        view = &candidate;
        break;
      }
    }
    if (view == nullptr) {
      explanation.add(ReasonCode::LeaseMissing,
                      "lease " + request.lease.to_string() + " is not known to this coordinator");
      return finish(Outcome::Refused, EvidenceState::Unknown,
                    "the presented lease is unknown to this coordinator");
    }
    if (view->holder != request.actor.member ||
        view->holder_incarnation != request.actor.incarnation ||
        view->holder_generation != request.actor.generation) {
      explanation.add(ReasonCode::LeaseHolderMismatch,
                      "lease " + view->id.to_string() + " is bound to " +
                          view->holder.to_string() + " incarnation " +
                          std::to_string(view->holder_incarnation.value()) + " generation " +
                          std::to_string(view->holder_generation.value()));
      return finish(Outcome::Fenced, EvidenceState::Stale,
                    "the lease is bound to a different member identity");
    }
    if (view->state != LeaseState::Valid) {
      explanation.add(view->reason, "lease " + view->id.to_string() + " is " +
                                        std::string(fabric_federation::to_string(view->state)));
      const Outcome outcome = (view->state == LeaseState::Revoked)
                                  ? Outcome::Fenced
                                  : (view->state == LeaseState::ScopeNotCovered
                                         ? Outcome::Refused
                                         : Outcome::Stale);
      return finish(outcome, EvidenceState::Stale,
                    "the presented lease is " +
                        std::string(fabric_federation::to_string(view->state)));
    }
    if (!grants_cover(view->scopes, request.requested)) {
      explanation.add(ReasonCode::LeaseScopeNotCovered,
                      "lease " + view->id.to_string() + " does not cover " +
                          request.requested.to_string());
      return finish(Outcome::Refused, EvidenceState::Known,
                    "the lease does not cover the requested grant");
    }
    explanation.add(ReasonCode::LeaseValid, "lease " + view->id.to_string() + " is valid");
  }

  // ---- 10. partition and global mutation ----------------------------------
  if (scope_class == ScopeClass::GlobalMutation) {
    if (state.reconciling && policy.suspend_global_mutation_while_reconciling()) {
      explanation.add(ReasonCode::PartitionReconcilingSuspendsGlobalMutation,
                      "the federation is reconciling after a partition");
      return finish(Outcome::Fenced, EvidenceState::Stale,
                    "global-mutation authority is suspended while reconciling");
    }
    if (state.partition.state == PartitionState::Split &&
        policy.suspend_global_mutation_on_partition()) {
      explanation.add(ReasonCode::PartitionSplitSuspendsGlobalMutation,
                      "the active set is split into " +
                          std::to_string(state.partition.components.size()) +
                          " component(s); no side keeps global-mutation authority");
      return finish(Outcome::Fenced, EvidenceState::Stale,
                    "global-mutation authority is suspended by the observed partition");
    }
    if (state.partition.state == PartitionState::Indeterminate &&
        policy.suspend_global_mutation_on_partition()) {
      explanation.add(ReasonCode::PartitionIndeterminateSuspendsGlobalMutation,
                      "reachability evidence is incomplete: " + state.partition.summary);
      return finish(Outcome::Fenced, EvidenceState::Indeterminate,
                    "global-mutation authority is suspended because partition evidence is "
                    "incomplete");
    }
    explanation.add(ReasonCode::PartitionConnected, "the active set is mutually reachable");
  }

  // ---- 11. degraded membership --------------------------------------------
  if (member_state->lifecycle == MemberLifecycleState::Degraded &&
      (request.requested.verb == AuthorityVerb::Mutate ||
       request.requested.verb == AuthorityVerb::Administer)) {
    explanation.add(ReasonCode::MembershipDegradedObservationGap,
                    "the member is degraded; mutating authority is withheld while observation "
                    "remains permitted");
    return finish(Outcome::Degraded, EvidenceState::Indeterminate,
                  "the member is degraded: observation is permitted, mutation is withheld");
  }

  explanation.effective_grants.push_back(request.requested);
  return finish(Outcome::Granted, evidence, "authority granted for " +
                                                request.requested.to_string() + " at epoch " +
                                                std::to_string(state.epoch.value()));
}

}  // namespace fabric_federation
