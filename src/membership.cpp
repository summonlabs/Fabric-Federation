// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/membership.hpp"

#include <algorithm>
#include <map>
#include <set>

namespace fabric_federation {
namespace {

template <class T>
void sort_unique(std::vector<T>& items) {
  std::sort(items.begin(), items.end());
  items.erase(std::unique(items.begin(), items.end()), items.end());
}

bool contains(const std::vector<MemberId>& members, const MemberId& member) {
  return std::find(members.begin(), members.end(), member) != members.end();
}

// The contribution records the issuer's own revision, taken from the artefact
// envelope, not the subject's. A decision therefore names the exact revision of
// every party that contributed to it.
Contribution make_contribution(const Artifact& artifact, ContributionRole role,
                               const MemberIdentity& identity, bool current) {
  Contribution contribution;
  contribution.member = artifact.envelope.issuer.member;
  contribution.role = role;
  contribution.generation = artifact.envelope.issuer.generation;
  contribution.incarnation = artifact.envelope.issuer.incarnation;
  contribution.constitution = artifact.envelope.issuer.constitution.is_zero()
                                  ? identity.constitution
                                  : artifact.envelope.issuer.constitution;
  contribution.evidence = artifact.digest();
  contribution.epoch = artifact.envelope.issuer.epoch;
  contribution.identity_current = current;
  return contribution;
}

}  // namespace

MultiPartyAssessment assess_multi_party(const MemberId& candidate, const MemberId& proposer,
                                        bool proposer_active,
                                        const std::vector<MemberId>& endorsers,
                                        const FederationPolicy& policy, bool bootstrap) {
  MultiPartyAssessment assessment;
  assessment.bootstrap = bootstrap;
  assessment.proposer_is_candidate = proposer == candidate;

  std::vector<MemberId> parties;
  if (!proposer.is_nil()) {
    parties.push_back(proposer);
  }
  if (!candidate.is_nil()) {
    parties.push_back(candidate);
  }
  for (const MemberId& endorser : endorsers) {
    if (!endorser.is_nil()) {
      parties.push_back(endorser);
    }
  }
  sort_unique(parties);
  assessment.parties = parties;
  assessment.distinct_parties = parties.size();

  std::vector<MemberId> counted;
  for (const MemberId& endorser : endorsers) {
    if (endorser.is_nil() || endorser == candidate || endorser == proposer) {
      continue;
    }
    counted.push_back(endorser);
  }
  sort_unique(counted);
  assessment.endorsements = counted.size();
  assessment.proposer_active = proposer_active;

  if (bootstrap) {
    assessment.satisfied = true;
    Reason reason;
    reason.code = ReasonCode::MultiPartyBootstrapGenesis;
    reason.detail = "membership established by the federation genesis record; this is an "
                    "operator-provisioned single-party bootstrap, not multi-party authority";
    assessment.reasons.push_back(std::move(reason));
    return assessment;
  }

  bool satisfied = true;
  if (assessment.proposer_is_candidate) {
    satisfied = false;
    Reason reason;
    reason.code = ReasonCode::MultiPartySelfProposalRejected;
    reason.detail = "a member cannot sponsor its own admission";
    assessment.reasons.push_back(std::move(reason));
  }
  if (!proposer_active) {
    satisfied = false;
    Reason reason;
    reason.code = ReasonCode::MultiPartyProposerNotActive;
    reason.detail = "the sponsor is not an active member of this federation";
    assessment.reasons.push_back(std::move(reason));
  }
  const std::size_t required_parties = policy.required_distinct_parties();
  if (assessment.distinct_parties < required_parties) {
    satisfied = false;
    Reason reason;
    reason.code = ReasonCode::MultiPartyInsufficientDistinctParties;
    reason.detail = std::to_string(assessment.distinct_parties) +
                    " distinct part(ies) contributed, policy requires " +
                    std::to_string(required_parties);
    assessment.reasons.push_back(std::move(reason));
  }
  const std::size_t required_endorsements = policy.required_endorsements();
  if (assessment.endorsements < required_endorsements) {
    satisfied = false;
    Reason reason;
    reason.code = ReasonCode::MultiPartyInsufficientEndorsements;
    reason.detail = std::to_string(assessment.endorsements) + " endorsement(s) from third "
                    "parties, policy requires " + std::to_string(required_endorsements);
    assessment.reasons.push_back(std::move(reason));
  }
  assessment.satisfied = satisfied;
  if (satisfied) {
    Reason reason;
    reason.code = ReasonCode::MultiPartySatisfied;
    reason.detail = std::to_string(assessment.distinct_parties) + " distinct parties, " +
                    std::to_string(assessment.endorsements) + " third-party endorsement(s)";
    assessment.reasons.push_back(std::move(reason));
  }
  return assessment;
}

MembershipDerivation derive_membership(const MemberId& member,
                                       const std::vector<Artifact>& member_artifacts,
                                       const MembershipContext& context) {
  MembershipDerivation derivation;
  MembershipFacts& facts = derivation.facts;
  const FederationPolicy& policy = *context.policy;

  const bool bootstrap_member = contains(context.bootstrap_members, member);
  facts.bootstrap = bootstrap_member;
  if (bootstrap_member) {
    for (const MemberDeclaration& declaration : context.bootstrap_declarations) {
      if (declaration.constitution.member == member) {
        facts.declaration = declaration;
        facts.current_identity = declaration.identity();
        facts.admitted_identity = facts.current_identity;
        break;
      }
    }
  }

  // ---- 1. determine the current lineage -----------------------------------
  // A lineage only advances past a slot that the member itself closed with a
  // leave notice. A third party cannot bump another member's lineage.
  std::set<std::uint64_t> leave_lineages;
  std::set<std::uint64_t> present_lineages;
  for (const Artifact& artifact : member_artifacts) {
    present_lineages.insert(artifact.body.lineage.value());
    if (artifact.envelope.kind == ArtifactKind::MembershipLeave &&
        artifact.envelope.issuer.member == member) {
      leave_lineages.insert(artifact.body.lineage.value());
    }
  }
  std::uint64_t lineage = 0;
  for (std::size_t guard = 0; guard < member_artifacts.size() + 1; ++guard) {
    if (leave_lineages.count(lineage) == 0 || present_lineages.count(lineage + 1) == 0) {
      break;
    }
    ++lineage;
  }
  facts.lineage = Lineage(lineage);

  // ---- 2. collect current-lineage artefacts -------------------------------
  std::vector<const Artifact*> proposals;
  std::vector<const Artifact*> acceptances;
  std::vector<const Artifact*> endorsements;
  std::vector<const Artifact*> admissions;
  std::vector<const Artifact*> activations;
  std::vector<const Artifact*> reattestations;
  std::vector<const Artifact*> leaves;
  std::vector<const Artifact*> fences;
  std::vector<const Artifact*> retirements;
  std::vector<const Artifact*> delegations;
  std::vector<const Artifact*> withdrawals;
  std::size_t superseded = 0;

  for (const Artifact& artifact : member_artifacts) {
    if (artifact.body.lineage.value() != lineage) {
      ++superseded;
      continue;
    }
    switch (artifact.envelope.kind) {
      case ArtifactKind::MembershipProposal:
        proposals.push_back(&artifact);
        break;
      case ArtifactKind::MembershipAcceptance:
        acceptances.push_back(&artifact);
        break;
      case ArtifactKind::MembershipEndorsement:
        endorsements.push_back(&artifact);
        break;
      case ArtifactKind::MembershipAdmission:
        admissions.push_back(&artifact);
        break;
      case ArtifactKind::MembershipActivation:
        activations.push_back(&artifact);
        break;
      case ArtifactKind::MemberReattestation:
        reattestations.push_back(&artifact);
        break;
      case ArtifactKind::MembershipLeave:
        leaves.push_back(&artifact);
        break;
      case ArtifactKind::MembershipFence:
        fences.push_back(&artifact);
        break;
      case ArtifactKind::MembershipRetirement:
        retirements.push_back(&artifact);
        break;
      case ArtifactKind::DelegationDeclaration:
        delegations.push_back(&artifact);
        break;
      case ArtifactKind::DelegationWithdrawal:
        withdrawals.push_back(&artifact);
        break;
      default:
        break;
    }
  }

  if (superseded != 0) {
    Reason reason;
    reason.code = ReasonCode::ArtifactSupersededLineage;
    reason.detail = std::to_string(superseded) + " artefact(s) belong to an earlier lineage";
    facts.reasons.push_back(std::move(reason));
  }

  // has_proposal reflects the presence of any proposal for the record; the
  // operative set below excludes self-proposals.
  facts.has_proposal = !proposals.empty();
  facts.has_acceptance = !acceptances.empty();
  facts.has_admission = !admissions.empty();
  facts.has_activation = !activations.empty();
  facts.has_leave = !leaves.empty();
  facts.has_fence = !fences.empty();
  facts.has_retirement = !retirements.empty();
  facts.has_reattestation = !reattestations.empty();

  // ---- 3. declared constitution -------------------------------------------
  // The proposal names the identity the candidate is being admitted as. When
  // several proposals disagree, the disagreement is a conflict and nothing is
  // admitted; the runtime does not pick a winner by recency.
  // A member cannot sponsor its own admission, so a self-proposal can never be
  // the operative one. It is recorded as evidence and set aside, which keeps a
  // member from denying itself admission by filing one alongside a legitimate
  // sponsor's proposal.
  {
    std::vector<const Artifact*> sponsored;
    for (const Artifact* candidate : proposals) {
      if (candidate->envelope.issuer.member == member) {
        Reason reason;
        reason.code = ReasonCode::MultiPartySelfProposalRejected;
        reason.detail = "a self-proposal was recorded but cannot admit anyone";
        facts.reasons.push_back(std::move(reason));
        continue;
      }
      sponsored.push_back(candidate);
    }
    proposals = std::move(sponsored);
  }
  if (!proposals.empty()) {
    std::vector<const Artifact*> sorted_proposals = proposals;
    // The highest generation wins: a member that re-consents at a new
    // generation supersedes its earlier declaration in the same lineage. Ties
    // are broken by evidence identifier, never by arrival order.
    std::sort(sorted_proposals.begin(), sorted_proposals.end(),
              [](const Artifact* a, const Artifact* b) {
                if (a->body.declaration.constitution.generation !=
                    b->body.declaration.constitution.generation) {
                  return b->body.declaration.constitution.generation <
                         a->body.declaration.constitution.generation;
                }
                return a->envelope.evidence < b->envelope.evidence;
              });
    const Artifact* chosen = sorted_proposals.front();
    facts.declaration = chosen->body.declaration;
    for (const Artifact* other : sorted_proposals) {
      if (other->body.declaration.constitution.digest() !=
          chosen->body.declaration.constitution.digest()) {
        ConflictRecord conflict;
        conflict.grant = ScopeGrant{};
        conflict.kind = ConflictKind::ConflictingIdentity;
        conflict.claimants.push_back(chosen->envelope.issuer.member);
        conflict.claimants.push_back(other->envelope.issuer.member);
        conflict.detail = "two proposals declare different constitutions for the same member and "
                          "generation";
        facts.conflicts.push_back(std::move(conflict));
      }
    }
    facts.admitted_identity = facts.declaration.identity();
    facts.current_identity = facts.admitted_identity;
  }

  // ---- 4. consent, endorsement, activation --------------------------------
  if (!proposals.empty()) {
    const Artifact* proposal = nullptr;
    for (const Artifact* candidate : proposals) {
      if (proposal == nullptr ||
          proposal->body.declaration.constitution.generation <
              candidate->body.declaration.constitution.generation ||
          (proposal->body.declaration.constitution.generation ==
               candidate->body.declaration.constitution.generation &&
           candidate->envelope.evidence < proposal->envelope.evidence)) {
        proposal = candidate;
      }
    }
    const Digest proposed_constitution = proposal->body.declaration.constitution.digest();

    const Artifact* acceptance = nullptr;
    for (const Artifact* candidate : acceptances) {
      if (candidate->envelope.issuer.member != member) {
        continue;
      }
      if (candidate->body.declared_identity.constitution != proposed_constitution) {
        Reason reason;
        reason.code = ReasonCode::IdentityConstitutionStale;
        reason.detail = "an acceptance echoes a different constitution than the proposal";
        facts.reasons.push_back(std::move(reason));
        continue;
      }
      if (acceptance == nullptr || candidate->envelope.evidence < acceptance->envelope.evidence) {
        acceptance = candidate;
      }
    }
    if (acceptance != nullptr) {
      facts.has_acceptance = true;
      facts.acceptance_matches_declaration = true;
      facts.current_identity = acceptance->body.declaration.identity();
      facts.contributions.push_back(
          make_contribution(*acceptance, ContributionRole::Candidate, facts.current_identity,
                            true));
    } else if (!acceptances.empty()) {
      facts.has_acceptance = false;
      Reason reason;
      reason.code = ReasonCode::EvidenceIncomplete;
      reason.detail = "no acceptance matches the proposed constitution";
      facts.reasons.push_back(std::move(reason));
    }

    // Endorsements: only from other members, and only when they attest the same
    // constitution.
    std::vector<MemberId> endorsers;
    for (const Artifact* candidate : endorsements) {
      if (candidate->envelope.issuer.member == member ||
          candidate->envelope.issuer.member == proposal->envelope.issuer.member) {
        continue;
      }
      if (candidate->body.declared_identity.constitution != proposed_constitution) {
        continue;
      }
      // An endorsement only counts when the endorsing member is itself
      // established in this federation. An outsider's endorsement attests
      // nothing the federation can act on.
      if (!contains(context.established_members, candidate->envelope.issuer.member)) {
        Reason reason;
        reason.code = ReasonCode::MultiPartyEndorserNotActive;
        reason.detail = "an endorsement from " +
                        candidate->envelope.issuer.member.to_string() +
                        " was ignored because that member is not established in this federation";
        facts.reasons.push_back(std::move(reason));
        continue;
      }
      endorsers.push_back(candidate->envelope.issuer.member);
    }
    sort_unique(endorsers);
    facts.endorsers = endorsers;
    facts.endorsement_count = endorsers.size();
    for (const Artifact* candidate : endorsements) {
      if (candidate->envelope.issuer.member == member ||
          candidate->envelope.issuer.member == proposal->envelope.issuer.member) {
        continue;
      }
      if (candidate->body.declared_identity.constitution != proposed_constitution) {
        continue;
      }
      MemberIdentity identity = candidate->body.declared_identity;
      facts.contributions.push_back(make_contribution(
          *candidate, ContributionRole::Endorser, identity,
          contains(context.established_members, candidate->envelope.issuer.member)));
    }
    facts.contributions.push_back(make_contribution(
        *proposal, ContributionRole::Proposer, proposal->body.declaration.identity(),
        contains(context.established_members, proposal->envelope.issuer.member)));
  }

  // Re-attestation: the member's latest declaration of its own identity.
  if (!reattestations.empty()) {
    std::vector<const Artifact*> owned;
    for (const Artifact* candidate : reattestations) {
      if (candidate->envelope.issuer.member == member) {
        owned.push_back(candidate);
      }
    }
    if (!owned.empty()) {
      std::sort(owned.begin(), owned.end(), [](const Artifact* a, const Artifact* b) {
        if (a->envelope.issuer.epoch != b->envelope.issuer.epoch) {
          return a->envelope.issuer.epoch < b->envelope.issuer.epoch;
        }
        if (a->body.declaration.incarnation != b->body.declaration.incarnation) {
          return a->body.declaration.incarnation < b->body.declaration.incarnation;
        }
        return a->envelope.evidence < b->envelope.evidence;
      });
      const Artifact* latest = owned.back();
      facts.current_identity = latest->body.declared_identity;
      facts.declaration = latest->body.declaration;
      facts.contributions.push_back(make_contribution(*latest, ContributionRole::Candidate,
                                                     facts.current_identity, true));
    }
  }

  // ---- 5. admission -------------------------------------------------------
  bool admission_valid = false;
  if (!proposals.empty()) {
    const Artifact* proposal = nullptr;
    for (const Artifact* candidate : proposals) {
      if (proposal == nullptr ||
          proposal->body.declaration.constitution.generation <
              candidate->body.declaration.constitution.generation ||
          (proposal->body.declaration.constitution.generation ==
               candidate->body.declaration.constitution.generation &&
           candidate->envelope.evidence < proposal->envelope.evidence)) {
        proposal = candidate;
      }
    }
    const MultiPartyAssessment multi = assess_multi_party(
        member, proposal->envelope.issuer.member,
        contains(context.established_members, proposal->envelope.issuer.member), facts.endorsers,
        policy, false);
    facts.distinct_parties = multi.distinct_parties;
    for (const Reason& reason : multi.reasons) {
      facts.reasons.push_back(reason);
    }
    if (!facts.acceptance_matches_declaration) {
      Reason reason;
      reason.code = ReasonCode::EvidenceIncomplete;
      reason.detail = "the candidate has not consented to the proposed constitution";
      facts.reasons.push_back(std::move(reason));
    }

    const Artifact* admission = nullptr;
    for (const Artifact* candidate : admissions) {
      if (admission == nullptr || candidate->envelope.evidence < admission->envelope.evidence) {
        admission = candidate;
      }
    }
    // The admission digest is derived from the evidence that warrants the
    // admission, not from whichever coordinator record happens to exist, so it
    // is the same no matter when the record was issued.
    {
      Writer writer;
      Status encoded = writer.u64(facts.lineage.value());
      if (encoded.ok() && proposal != nullptr) {
        encoded = writer.digest(proposal->digest());
      }
      if (encoded.ok()) {
        encoded = writer.digest(facts.current_identity.constitution);
      }
      if (encoded.ok()) {
        encoded = writer.count(facts.endorsers.size(), kMaxMembers);
      }
      if (encoded.ok()) {
        for (const MemberId& endorser : facts.endorsers) {
          encoded = writer.id16(endorser.bytes());
          if (!encoded.ok()) {
            break;
          }
        }
      }
      facts.admission_digest = encoded.ok() ? writer.sha256() : Digest();
    }
    // Admission is derived from the evidence itself. A coordinator admission
    // record is an audit entry, not a source of authority, so the derived state
    // does not depend on whether (or when) the record was written. That is what
    // makes the canonical state permutation independent: the record set a
    // coordinator accumulates depends on arrival order, the evidence set does
    // not.
    admission_valid = multi.satisfied && facts.acceptance_matches_declaration;
    if (!admission_valid) {
      Reason reason;
      reason.code = ReasonCode::MembershipProposedInsufficientEvidence;
      reason.detail = "the evidence does not yet satisfy the multi-party rules for admission";
      facts.reasons.push_back(std::move(reason));
    }
    if (admission != nullptr) {
      if (!admission_valid) {
        facts.rejected_kinds.push_back(ArtifactKind::MembershipAdmission);
        Reason reason;
        reason.code = ReasonCode::ArtifactRejected;
        reason.detail = "admission record rejected: the evidence does not satisfy the multi-party "
                        "rules";
        facts.reasons.push_back(std::move(reason));
      } else if (admission->body.declared_identity.constitution !=
                 facts.admitted_identity.constitution) {
        // The record belongs to a superseded constitution. That is expected
        // after a re-consent at a new generation, so it is recorded as stale
        // evidence and does not overwrite the current admission.
        Reason reason;
        reason.code = ReasonCode::IdentityConstitutionStale;
        reason.detail = "an admission record names a constitution that has since been superseded";
        facts.reasons.push_back(std::move(reason));
      } else {
        facts.admitted_epoch = admission->body.epoch;
      }
    }
    // The coordinator's record is recorded as a contribution when it exists,
    // but admission itself is derived from the evidence above, so a null record
    // is not an error.
    if (admission != nullptr && admission_valid) {
      facts.contributions.push_back(make_contribution(
          *admission, ContributionRole::Coordinator, admission->body.declared_identity, true));
    }
  } else if (bootstrap_member) {
    // Bootstrap membership is established by the genesis record.
    admission_valid = true;
    facts.distinct_parties = 1;
    Reason reason;
    reason.code = ReasonCode::MultiPartyBootstrapGenesis;
    reason.detail = "membership established by the genesis record (single-party bootstrap)";
    facts.reasons.push_back(std::move(reason));
    facts.contributions.push_back(Contribution{member, ContributionRole::Candidate,
                                               facts.declaration.constitution.generation,
                                               facts.declaration.incarnation,
                                               facts.declaration.constitution.digest(), Digest(),
                                               Epoch(1), true, "genesis founder"});
  }

  // ---- 6. fence order -----------------------------------------------------
  // Fencing is permitted from the coordinator and from the member itself. A
  // fence is sticky: it is cleared only by an activation at a strictly greater
  // epoch.
  Epoch fence_epoch;
  bool fenced = false;
  for (const Artifact* candidate : fences) {
    const bool self_fence = candidate->envelope.issuer.member == member;
    if (!self_fence && candidate->envelope.issuer.member != MemberId()) {
      // A fence issued by another member is not accepted.
      continue;
    }
    if (!fenced || fence_epoch < candidate->body.epoch) {
      fenced = true;
      fence_epoch = candidate->body.epoch;
      facts.fence_reason = candidate->body.fence_reason;
    }
  }
  facts.fence_epoch = fence_epoch;

  // ---- 7. lifecycle -------------------------------------------------------
  const Artifact* activation = nullptr;
  for (const Artifact* candidate : activations) {
    if (activation == nullptr || candidate->body.epoch > activation->body.epoch ||
        (candidate->body.epoch == activation->body.epoch &&
         candidate->envelope.evidence < activation->envelope.evidence)) {
      activation = candidate;
    }
  }
  for (const Artifact* candidate : activations) {
    if (candidate->body.declared_identity.incarnation != facts.current_identity.incarnation) {
      facts.superseded_incarnations.push_back(candidate->body.declared_identity.incarnation);
    }
  }
  std::sort(facts.superseded_incarnations.begin(), facts.superseded_incarnations.end());
  facts.superseded_incarnations.erase(
      std::unique(facts.superseded_incarnations.begin(), facts.superseded_incarnations.end()),
      facts.superseded_incarnations.end());

  // Whether the member is currently activated is derived from its own evidence:
  // admission is established, and the identity it presents belongs to the
  // current epoch. A member that has re-attested at the current epoch presents
  // a current declaration; a member that has not is still presenting the
  // identity it consented with, which is current as long as the federation's
  // epoch has not moved past it.
  bool declaration_is_current = true;
  if (activation != nullptr) {
    facts.activation_epoch = activation->body.epoch;
    facts.activation_tick = activation->envelope.issuer.issued_at;
    declaration_is_current = activation->body.epoch == context.current_epoch;
  } else {
    declaration_is_current = true;
  }
  for (const Artifact* candidate : reattestations) {
    if (candidate->envelope.issuer.member != member) {
      continue;
    }
    facts.activation_epoch = candidate->body.epoch;
    facts.activation_tick = candidate->envelope.issuer.issued_at;
    declaration_is_current = candidate->body.epoch >= context.current_epoch;
  }
  // The activation matches when the member is admitted and the identity it
  // currently presents is the one it was admitted with.
  facts.activation_matches_identity =
      admission_valid &&
      facts.current_identity.constitution == facts.admitted_identity.constitution;
  facts.activation_at_current_epoch = declaration_is_current;
  facts.generation_changed_since_admission =
      !facts.admitted_identity.generation.is_zero() &&
      facts.current_identity.generation != facts.admitted_identity.generation;

  if (facts.has_retirement) {
    derivation.lifecycle = MemberLifecycleState::Retired;
    Reason reason;
    reason.code = ReasonCode::MembershipRetired;
    reason.detail = "a retirement record closed this membership lineage";
    facts.reasons.push_back(std::move(reason));
  } else if (facts.has_leave) {
    derivation.lifecycle = MemberLifecycleState::Leaving;
    Reason reason;
    reason.code = ReasonCode::MembershipLeaving;
    reason.detail = "the member has left; federation authority has ended and no local authority "
                    "was affected";
    facts.reasons.push_back(std::move(reason));
  } else if (!facts.has_proposal && !bootstrap_member) {
    derivation.lifecycle = MemberLifecycleState::Absent;
    Reason reason;
    reason.code = ReasonCode::MembershipAbsent;
    reason.detail = "no proposal exists for this member in the current lineage";
    facts.reasons.push_back(std::move(reason));
  } else if (fenced && (activation == nullptr || !(fence_epoch < activation->body.epoch))) {
    derivation.lifecycle = MemberLifecycleState::Fenced;
    Reason reason;
    reason.code = ReasonCode::MembershipFencedByOrder;
    reason.detail = "a fence is in force and no activation at a later epoch has cleared it";
    facts.reasons.push_back(std::move(reason));
  } else if (!admission_valid) {
    derivation.lifecycle = MemberLifecycleState::Proposed;
    Reason reason;
    reason.code = ReasonCode::MembershipProposedInsufficientEvidence;
    reason.detail = "the proposal has not been admitted; no federation authority is held";
    facts.reasons.push_back(std::move(reason));
  } else if (activation == nullptr) {
    derivation.lifecycle = MemberLifecycleState::Admitted;
    Reason reason;
    reason.code = ReasonCode::MembershipAdmittedPendingActivation;
    reason.detail = "admitted but not yet activated at the current epoch";
    facts.reasons.push_back(std::move(reason));
  } else if (!facts.activation_matches_identity) {
    if (facts.generation_changed_since_admission && policy.reconsent_on_generation_change()) {
      derivation.lifecycle = MemberLifecycleState::Fenced;
      Reason reason;
      reason.code = ReasonCode::GenerationChangeRequiresReconsent;
      reason.detail = "the member declared generation " +
                      std::to_string(facts.current_identity.generation.value()) +
                      " but consented at generation " +
                      std::to_string(facts.admitted_identity.generation.value()) +
                      "; fresh consent is required";
      facts.reasons.push_back(std::move(reason));
    } else {
      if (facts.generation_changed_since_admission) {
        Reason reason;
        reason.code = ReasonCode::GenerationChangeAcceptedByPolicy;
        reason.detail = "policy allows a generation change without fresh consent";
        facts.reasons.push_back(std::move(reason));
      }
      derivation.lifecycle = MemberLifecycleState::Admitted;
      Reason reason;
      reason.code = ReasonCode::MembershipRequiresReattestation;
      reason.detail = "the active activation is bound to a different identity; reactivation at the "
                      "current epoch is required";
      facts.reasons.push_back(std::move(reason));
    }
  } else if (!facts.activation_at_current_epoch) {
    derivation.lifecycle = MemberLifecycleState::Degraded;
    Reason reason;
    reason.code = ReasonCode::MembershipRequiresReattestation;
    reason.detail = "the activation belongs to epoch " +
                    std::to_string(facts.activation_epoch.value()) + ", the federation is at epoch " +
                    std::to_string(context.current_epoch.value());
    facts.reasons.push_back(std::move(reason));
  } else {
    bool degraded = false;
    if (context.reconciling && policy.suspend_global_mutation_while_reconciling()) {
      degraded = true;
      Reason reason;
      reason.code = ReasonCode::PartitionReconcilingSuspendsGlobalMutation;
      reason.detail = "the federation is reconciling after a partition";
      facts.reasons.push_back(std::move(reason));
    }
    if (context.partition.state == PartitionState::Split &&
        policy.suspend_global_mutation_on_partition()) {
      degraded = true;
      Reason reason;
      reason.code = ReasonCode::PartitionSplitSuspendsGlobalMutation;
      reason.detail = "the active set is partitioned; global-mutation authority is suspended for "
                      "every component";
      facts.reasons.push_back(std::move(reason));
    } else if (context.partition.state == PartitionState::Indeterminate &&
               policy.suspend_global_mutation_on_partition()) {
      degraded = true;
      Reason reason;
      reason.code = ReasonCode::PartitionIndeterminateSuspendsGlobalMutation;
      reason.detail = "reachability evidence is incomplete; global-mutation authority is suspended "
                      "rather than assumed";
      facts.reasons.push_back(std::move(reason));
    }
    const std::vector<CapabilityRequirement> required = policy.mandatory_capabilities();
    if (!required.empty()) {
      const CompatibilityReport report =
          evaluate_compatibility(required, facts.declaration.constitution.capabilities);
      if (report.state != CompatibilityState::Satisfied) {
        degraded = true;
        Reason reason;
        reason.code = ReasonCode::MembershipDegradedObservationGap;
        reason.detail = "mandatory capability evidence is " +
                        std::string(fabric_federation::to_string(report.state)) + ": " +
                        report.summary;
        facts.reasons.push_back(std::move(reason));
      }
    }
    if (degraded) {
      derivation.lifecycle = MemberLifecycleState::Degraded;
    } else {
      derivation.lifecycle = MemberLifecycleState::Active;
      Reason reason;
      reason.code = ReasonCode::MembershipActive;
      reason.detail = "active at epoch " + std::to_string(context.current_epoch.value());
      facts.reasons.push_back(std::move(reason));
    }
  }

  // ---- 8. evidence quality ------------------------------------------------
  if (!facts.conflicts.empty()) {
    facts.evidence = EvidenceState::Conflicting;
  } else if (derivation.lifecycle == MemberLifecycleState::Absent) {
    facts.evidence = EvidenceState::Unknown;
  } else if (derivation.lifecycle == MemberLifecycleState::Proposed) {
    facts.evidence = EvidenceState::Incomplete;
  } else if (context.partition.state == PartitionState::Indeterminate) {
    facts.evidence = EvidenceState::Indeterminate;
  } else {
    facts.evidence = EvidenceState::Known;
  }

  // ---- 9. delegation terms and withdrawals --------------------------------
  if (!delegations.empty()) {
    const Artifact* latest = nullptr;
    for (const Artifact* candidate : delegations) {
      if (candidate->envelope.issuer.member != member) {
        continue;
      }
      if (latest == nullptr || latest->envelope.issuer.epoch < candidate->envelope.issuer.epoch ||
          (latest->envelope.issuer.epoch == candidate->envelope.issuer.epoch &&
           candidate->envelope.evidence < latest->envelope.evidence)) {
        latest = candidate;
      }
    }
    if (latest != nullptr) {
      facts.delegated_terms = latest->body.delegated_terms;
    } else {
      facts.delegated_terms = facts.declaration.constitution.delegated;
    }
  } else if (!facts.declaration.constitution.delegated.empty()) {
    facts.delegated_terms = facts.declaration.constitution.delegated;
  }
  for (const Artifact* candidate : withdrawals) {
    if (candidate->envelope.issuer.member != member) {
      continue;
    }
    for (const ScopeGrant& grant : candidate->body.withdrawn_grants) {
      facts.withdrawn_grants.push_back(grant);
    }
  }
  canonicalize_grants(facts.withdrawn_grants);

  derivation.retained_local_authority = facts.declaration.constitution.retained;
  canonicalize_grants(derivation.retained_local_authority);
  return derivation;
}

}  // namespace fabric_federation
