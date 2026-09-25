// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/explanation.hpp"

#include <algorithm>
#include <sstream>

namespace fabric_federation {

std::string_view to_string(ReasonCode code) noexcept {
  switch (code) {
    case ReasonCode::MembershipActive:
      return "MEMBERSHIP_ACTIVE";
    case ReasonCode::MembershipAdmittedPendingActivation:
      return "MEMBERSHIP_ADMITTED_PENDING_ACTIVATION";
    case ReasonCode::MembershipProposedInsufficientEvidence:
      return "MEMBERSHIP_PROPOSED_INSUFFICIENT_EVIDENCE";
    case ReasonCode::MembershipAbsent:
      return "MEMBERSHIP_ABSENT";
    case ReasonCode::MembershipRetired:
      return "MEMBERSHIP_RETIRED";
    case ReasonCode::MembershipLeaving:
      return "MEMBERSHIP_LEAVING";
    case ReasonCode::MembershipFencedByOrder:
      return "MEMBERSHIP_FENCED_BY_ORDER";
    case ReasonCode::MembershipRequiresReattestation:
      return "MEMBERSHIP_REQUIRES_REATTESTATION";
    case ReasonCode::MembershipDegradedObservationGap:
      return "MEMBERSHIP_DEGRADED_OBSERVATION_GAP";
    case ReasonCode::MultiPartySatisfied:
      return "MULTIPARTY_SATISFIED";
    case ReasonCode::MultiPartyInsufficientDistinctParties:
      return "MULTIPARTY_INSUFFICIENT_DISTINCT_PARTIES";
    case ReasonCode::MultiPartyInsufficientEndorsements:
      return "MULTIPARTY_INSUFFICIENT_ENDORSEMENTS";
    case ReasonCode::MultiPartyEndorserNotActive:
      return "MULTIPARTY_ENDORSER_NOT_ACTIVE";
    case ReasonCode::MultiPartyProposerNotActive:
      return "MULTIPARTY_PROPOSER_NOT_ACTIVE";
    case ReasonCode::MultiPartySelfProposalRejected:
      return "MULTIPARTY_SELF_PROPOSAL_REJECTED";
    case ReasonCode::MultiPartyBootstrapGenesis:
      return "MULTIPARTY_BOOTSTRAP_GENESIS";
    case ReasonCode::IdentityMatches:
      return "IDENTITY_MATCHES";
    case ReasonCode::IdentityGenerationStale:
      return "IDENTITY_GENERATION_STALE";
    case ReasonCode::IdentityIncarnationStale:
      return "IDENTITY_INCARNATION_STALE";
    case ReasonCode::IdentityConstitutionStale:
      return "IDENTITY_CONSTITUTION_STALE";
    case ReasonCode::IdentityDomainMismatch:
      return "IDENTITY_DOMAIN_MISMATCH";
    case ReasonCode::IdentityMemberUnknown:
      return "IDENTITY_MEMBER_UNKNOWN";
    case ReasonCode::GenerationChangeRequiresReconsent:
      return "GENERATION_CHANGE_REQUIRES_RECONSENT";
    case ReasonCode::GenerationChangeAcceptedByPolicy:
      return "GENERATION_CHANGE_ACCEPTED_BY_POLICY";
    case ReasonCode::ScopeCoveredByDelegation:
      return "SCOPE_COVERED_BY_DELEGATION";
    case ReasonCode::ScopeNotDelegated:
      return "SCOPE_NOT_DELEGATED";
    case ReasonCode::ScopeRetainedLocalAuthority:
      return "SCOPE_RETAINED_LOCAL_AUTHORITY";
    case ReasonCode::ScopeUnknownToCatalogue:
      return "SCOPE_UNKNOWN_TO_CATALOGUE";
    case ReasonCode::ScopeDelegationForbiddenByPolicy:
      return "SCOPE_DELEGATION_FORBIDDEN_BY_POLICY";
    case ReasonCode::ScopeVerbNotDelegated:
      return "SCOPE_VERB_NOT_DELEGATED";
    case ReasonCode::ScopeLocalAuthorityAlwaysGranted:
      return "SCOPE_LOCAL_AUTHORITY_ALWAYS_GRANTED";
    case ReasonCode::DelegationWithdrawn:
      return "DELEGATION_WITHDRAWN";
    case ReasonCode::DelegationExpired:
      return "DELEGATION_EXPIRED";
    case ReasonCode::DelegationConflictContained:
      return "DELEGATION_CONFLICT_CONTAINED";
    case ReasonCode::DelegationPrecedenceConfigured:
      return "DELEGATION_PRECEDENCE_CONFIGURED";
    case ReasonCode::DelegationPrecedenceUnsatisfiable:
      return "DELEGATION_PRECEDENCE_UNSATISFIABLE";
    case ReasonCode::LeaseValid:
      return "LEASE_VALID";
    case ReasonCode::LeaseMissing:
      return "LEASE_MISSING";
    case ReasonCode::LeaseExpired:
      return "LEASE_EXPIRED";
    case ReasonCode::LeaseRevoked:
      return "LEASE_REVOKED";
    case ReasonCode::LeaseStaleIssuer:
      return "LEASE_STALE_ISSUER";
    case ReasonCode::LeaseEpochMismatch:
      return "LEASE_EPOCH_MISMATCH";
    case ReasonCode::LeaseHolderMismatch:
      return "LEASE_HOLDER_MISMATCH";
    case ReasonCode::LeaseScopeNotCovered:
      return "LEASE_SCOPE_NOT_COVERED";
    case ReasonCode::LeaseRequiredByPolicy:
      return "LEASE_REQUIRED_BY_POLICY";
    case ReasonCode::EpochMatches:
      return "EPOCH_MATCHES";
    case ReasonCode::EpochStale:
      return "EPOCH_STALE";
    case ReasonCode::EpochAheadOfCoordinator:
      return "EPOCH_AHEAD_OF_COORDINATOR";
    case ReasonCode::PartitionConnected:
      return "PARTITION_CONNECTED";
    case ReasonCode::PartitionSplitSuspendsGlobalMutation:
      return "PARTITION_SPLIT_SUSPENDS_GLOBAL_MUTATION";
    case ReasonCode::PartitionIndeterminateSuspendsGlobalMutation:
      return "PARTITION_INDETERMINATE_SUSPENDS_GLOBAL_MUTATION";
    case ReasonCode::PartitionReconcilingSuspendsGlobalMutation:
      return "PARTITION_RECONCILING_SUSPENDS_GLOBAL_MUTATION";
    case ReasonCode::PartitionObservationStale:
      return "PARTITION_OBSERVATION_STALE";
    case ReasonCode::PartitionReattestationComplete:
      return "PARTITION_REATTESTATION_COMPLETE";
    case ReasonCode::PartitionReattestationMissing:
      return "PARTITION_REATTESTATION_MISSING";
    case ReasonCode::RequestReplayed:
      return "REQUEST_REPLAYED";
    case ReasonCode::RequestFresh:
      return "REQUEST_FRESH";
    case ReasonCode::EvidenceDuplicateIdentical:
      return "EVIDENCE_DUPLICATE_IDENTICAL";
    case ReasonCode::EvidenceDuplicateConflicting:
      return "EVIDENCE_DUPLICATE_CONFLICTING";
    case ReasonCode::CapabilitySatisfied:
      return "CAPABILITY_SATISFIED";
    case ReasonCode::CapabilityMissing:
      return "CAPABILITY_MISSING";
    case ReasonCode::CapabilityIncompatible:
      return "CAPABILITY_INCOMPATIBLE";
    case ReasonCode::CapabilityUnsupported:
      return "CAPABILITY_UNSUPPORTED";
    case ReasonCode::EvidenceUnknown:
      return "EVIDENCE_UNKNOWN";
    case ReasonCode::EvidenceIncomplete:
      return "EVIDENCE_INCOMPLETE";
    case ReasonCode::EvidenceInvalid:
      return "EVIDENCE_INVALID";
    case ReasonCode::EvidenceIndeterminate:
      return "EVIDENCE_INDETERMINATE";
    case ReasonCode::EvidenceConflicting:
      return "EVIDENCE_CONFLICTING";
    case ReasonCode::ArtifactAccepted:
      return "ARTIFACT_ACCEPTED";
    case ReasonCode::ArtifactRejected:
      return "ARTIFACT_REJECTED";
    case ReasonCode::ArtifactDigestMismatch:
      return "ARTIFACT_DIGEST_MISMATCH";
    case ReasonCode::ArtifactSubjectMismatch:
      return "ARTIFACT_SUBJECT_MISMATCH";
    case ReasonCode::ArtifactEpochStale:
      return "ARTIFACT_EPOCH_STALE";
    case ReasonCode::ArtifactMalformed:
      return "ARTIFACT_MALFORMED";
    case ReasonCode::ArtifactUnknownKind:
      return "ARTIFACT_UNKNOWN_KIND";
    case ReasonCode::ArtifactSupersededLineage:
      return "ARTIFACT_SUPERSEDED_LINEAGE";
    case ReasonCode::PolicyRuleMatched:
      return "POLICY_RULE_MATCHED";
    case ReasonCode::PolicyRuleNotMatched:
      return "POLICY_RULE_NOT_MATCHED";
    case ReasonCode::PolicyRejected:
      return "POLICY_REJECTED";
    case ReasonCode::FederationUnknown:
      return "FEDERATION_UNKNOWN";
    case ReasonCode::FederationIdentityMismatch:
      return "FEDERATION_IDENTITY_MISMATCH";
    case ReasonCode::LimitExceeded:
      return "LIMIT_EXCEEDED";
  }
  return "EVIDENCE_UNKNOWN";
}

std::string Reason::to_string() const {
  std::string out(fabric_federation::to_string(code));
  if (!detail.empty()) {
    out.append(" (");
    out.append(detail);
    out.append(")");
  }
  return out;
}

std::string_view to_string(ContributionRole role) noexcept {
  switch (role) {
    case ContributionRole::Proposer:
      return "proposer";
    case ContributionRole::Candidate:
      return "candidate";
    case ContributionRole::Endorser:
      return "endorser";
    case ContributionRole::Coordinator:
      return "coordinator";
    case ContributionRole::Observer:
      return "observer";
    case ContributionRole::Actor:
      return "actor";
  }
  return "observer";
}

void Explanation::add(ReasonCode code, std::string detail) {
  if (reasons.size() >= kMaxReasonsPerDecision) {
    limit_reached = true;
    return;
  }
  for (const Reason& existing : reasons) {
    if (existing.code == code && existing.detail == detail) {
      return;
    }
  }
  Reason reason;
  reason.code = code;
  reason.detail = std::move(detail);
  reasons.push_back(std::move(reason));
}

bool Explanation::has(ReasonCode code) const noexcept {
  for (const Reason& reason : reasons) {
    if (reason.code == code) {
      return true;
    }
  }
  return false;
}

void Explanation::canonicalize() {
  std::sort(reasons.begin(), reasons.end());
  reasons.erase(std::unique(reasons.begin(), reasons.end()), reasons.end());
  std::sort(contributions.begin(), contributions.end());
  contributions.erase(std::unique(contributions.begin(), contributions.end()), contributions.end());
  canonicalize_conflicts(conflicts);
  canonicalize_grants(considered_grants);
  canonicalize_grants(effective_grants);
}

Status Explanation::encode(Writer& writer) const {
  Explanation copy = *this;
  copy.canonicalize();
  Status status = writer.u8(static_cast<std::uint8_t>(copy.outcome));
  if (!status.ok()) {
    return status;
  }
  status = writer.u8(static_cast<std::uint8_t>(copy.evidence));
  if (!status.ok()) {
    return status;
  }
  status = writer.count(copy.reasons.size(), kMaxReasonsPerDecision);
  if (!status.ok()) {
    return status;
  }
  for (const Reason& reason : copy.reasons) {
    status = writer.u16(static_cast<std::uint16_t>(reason.code));
    if (!status.ok()) {
      return status;
    }
    status = writer.text(reason.detail, kMaxShortTextLength);
    if (!status.ok()) {
      return status;
    }
  }
  status = writer.count(copy.contributions.size(), kMaxContributionsPerDecision);
  if (!status.ok()) {
    return status;
  }
  for (const Contribution& contribution : copy.contributions) {
    status = writer.id16(contribution.member.bytes());
    if (!status.ok()) {
      return status;
    }
    status = writer.u8(static_cast<std::uint8_t>(contribution.role));
    if (!status.ok()) {
      return status;
    }
    status = writer.u64(contribution.generation.value());
    if (!status.ok()) {
      return status;
    }
    status = writer.u64(contribution.incarnation.value());
    if (!status.ok()) {
      return status;
    }
    status = writer.digest(contribution.constitution);
    if (!status.ok()) {
      return status;
    }
    status = writer.digest(contribution.evidence);
    if (!status.ok()) {
      return status;
    }
    status = writer.u64(contribution.epoch.value());
    if (!status.ok()) {
      return status;
    }
    status = writer.boolean(contribution.identity_current);
    if (!status.ok()) {
      return status;
    }
    status = writer.text(contribution.note, kMaxShortTextLength);
    if (!status.ok()) {
      return status;
    }
  }
  status = encode_conflicts(writer, copy.conflicts, kMaxConflicts);
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, copy.considered_grants, kMaxEffectiveGrantsPerDecision);
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, copy.effective_grants, kMaxEffectiveGrantsPerDecision);
  if (!status.ok()) {
    return status;
  }
  status = writer.boolean(copy.limit_reached);
  if (!status.ok()) {
    return status;
  }
  return writer.text(copy.summary, kMaxExplanationTextLength);
}

Result<Explanation> Explanation::decode(Reader& reader) {
  Explanation explanation;
  auto outcome = reader.u8();
  if (!outcome.has_value()) {
    return outcome.status();
  }
  if (outcome.value() > static_cast<std::uint8_t>(Outcome::Unknown)) {
    return Status::make(ErrorCode::InvalidArgument, "outcome is out of range");
  }
  explanation.outcome = static_cast<Outcome>(outcome.value());
  auto evidence = reader.u8();
  if (!evidence.has_value()) {
    return evidence.status();
  }
  if (evidence.value() > static_cast<std::uint8_t>(EvidenceState::Invalid)) {
    return Status::make(ErrorCode::InvalidArgument, "evidence state is out of range");
  }
  explanation.evidence = static_cast<EvidenceState>(evidence.value());

  auto reason_count = reader.count(kMaxReasonsPerDecision);
  if (!reason_count.has_value()) {
    return reason_count.status();
  }
  explanation.reasons.reserve(reason_count.value());
  for (std::uint32_t i = 0; i < reason_count.value(); ++i) {
    auto code = reader.u16();
    if (!code.has_value()) {
      return code.status();
    }
    if (code.value() > static_cast<std::uint16_t>(ReasonCode::LimitExceeded)) {
      return Status::make(ErrorCode::InvalidArgument, "reason code is out of range");
    }
    auto detail = reader.text(kMaxShortTextLength);
    if (!detail.has_value()) {
      return detail.status();
    }
    Reason reason;
    reason.code = static_cast<ReasonCode>(code.value());
    reason.detail = std::move(detail.value());
    explanation.reasons.push_back(std::move(reason));
  }

  auto contribution_count = reader.count(kMaxContributionsPerDecision);
  if (!contribution_count.has_value()) {
    return contribution_count.status();
  }
  explanation.contributions.reserve(contribution_count.value());
  for (std::uint32_t i = 0; i < contribution_count.value(); ++i) {
    Contribution contribution;
    auto member = reader.id16();
    if (!member.has_value()) {
      return member.status();
    }
    contribution.member = MemberId::from_bytes(member.value());
    auto role = reader.u8();
    if (!role.has_value()) {
      return role.status();
    }
    if (role.value() > static_cast<std::uint8_t>(ContributionRole::Actor)) {
      return Status::make(ErrorCode::InvalidArgument, "contribution role is out of range");
    }
    contribution.role = static_cast<ContributionRole>(role.value());
    auto generation = reader.u64();
    if (!generation.has_value()) {
      return generation.status();
    }
    contribution.generation = Generation(generation.value());
    auto incarnation = reader.u64();
    if (!incarnation.has_value()) {
      return incarnation.status();
    }
    contribution.incarnation = Incarnation(incarnation.value());
    auto constitution = reader.digest();
    if (!constitution.has_value()) {
      return constitution.status();
    }
    contribution.constitution = constitution.value();
    auto evidence_digest = reader.digest();
    if (!evidence_digest.has_value()) {
      return evidence_digest.status();
    }
    contribution.evidence = evidence_digest.value();
    auto epoch = reader.u64();
    if (!epoch.has_value()) {
      return epoch.status();
    }
    contribution.epoch = Epoch(epoch.value());
    auto current = reader.boolean();
    if (!current.has_value()) {
      return current.status();
    }
    contribution.identity_current = current.value();
    auto note = reader.text(kMaxShortTextLength);
    if (!note.has_value()) {
      return note.status();
    }
    contribution.note = std::move(note.value());
    explanation.contributions.push_back(std::move(contribution));
  }

  auto conflicts = decode_conflicts(reader, kMaxConflicts);
  if (!conflicts.has_value()) {
    return conflicts.status();
  }
  explanation.conflicts = std::move(conflicts.value());
  auto considered = decode_grants(reader, kMaxEffectiveGrantsPerDecision);
  if (!considered.has_value()) {
    return considered.status();
  }
  explanation.considered_grants = std::move(considered.value());
  auto effective = decode_grants(reader, kMaxEffectiveGrantsPerDecision);
  if (!effective.has_value()) {
    return effective.status();
  }
  explanation.effective_grants = std::move(effective.value());
  auto limit = reader.boolean();
  if (!limit.has_value()) {
    return limit.status();
  }
  explanation.limit_reached = limit.value();
  auto summary = reader.text(kMaxExplanationTextLength);
  if (!summary.has_value()) {
    return summary.status();
  }
  explanation.summary = std::move(summary.value());
  explanation.canonicalize();
  return explanation;
}

Digest Explanation::digest() const {
  Writer writer;
  if (!encode(writer).ok()) {
    return Digest();
  }
  return writer.sha256();
}

std::string render_explanation(const Explanation& explanation) {
  Explanation copy = explanation;
  copy.canonicalize();
  std::ostringstream out;
  out << "outcome: " << to_string(copy.outcome) << "\n";
  out << "evidence: " << to_string(copy.evidence) << "\n";
  if (!copy.summary.empty()) {
    out << "summary: " << copy.summary << "\n";
  }
  out << "reasons:\n";
  if (copy.reasons.empty()) {
    out << "  (none)\n";
  }
  for (const Reason& reason : copy.reasons) {
    out << "  - " << reason.to_string() << "\n";
  }
  out << "contributing members:\n";
  if (copy.contributions.empty()) {
    out << "  (none)\n";
  }
  for (const Contribution& contribution : copy.contributions) {
    out << "  - " << contribution.member.to_string()
        << " role=" << to_string(contribution.role)
        << " gen=" << contribution.generation.value()
        << " inc=" << contribution.incarnation.value()
        << " epoch=" << contribution.epoch.value()
        << " digest=" << contribution.constitution.to_hex().substr(0, 16)
        << (contribution.identity_current ? " current" : " superseded");
    if (!contribution.note.empty()) {
      out << " note=" << contribution.note;
    }
    out << "\n";
  }
  out << "considered grants: " << render_grants(copy.considered_grants) << "\n";
  out << "effective grants: " << render_grants(copy.effective_grants) << "\n";
  out << "conflicts:\n";
  if (copy.conflicts.empty()) {
    out << "  (none)\n";
  }
  for (const ConflictRecord& conflict : copy.conflicts) {
    out << "  - " << conflict.to_string() << "\n";
  }
  return out.str();
}

std::string summarize_explanation(const Explanation& explanation) {
  Explanation copy = explanation;
  copy.canonicalize();
  std::string out(fabric_federation::to_string(copy.outcome));
  out.append(" ");
  out.append(render_grants(copy.effective_grants));
  if (!copy.reasons.empty()) {
    out.append(" [");
    for (std::size_t i = 0; i < copy.reasons.size() && i < 4; ++i) {
      if (i != 0) {
        out.append(",");
      }
      out.append(fabric_federation::to_string(copy.reasons[i].code));
    }
    if (copy.reasons.size() > 4) {
      out.append(",..");
    }
    out.append("]");
  }
  if (copy.limit_reached) {
    out.append(" (explanation truncated at the bound)");
  }
  return out;
}

}  // namespace fabric_federation
