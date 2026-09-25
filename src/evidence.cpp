// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/evidence.hpp"

#include <algorithm>

namespace fabric_federation {
namespace {

template <class T>
void sort_unique(std::vector<T>& items) {
  std::sort(items.begin(), items.end());
  items.erase(std::unique(items.begin(), items.end()), items.end());
}

Status expect_empty_ids(const std::vector<MemberId>& members, std::string_view what) {
  if (!members.empty()) {
    return Status::make(ErrorCode::InvalidArgument,
                        std::string(what) + " must not carry member identifiers");
  }
  return Status::success();
}

}  // namespace

std::string_view to_string(ArtifactKind kind) noexcept {
  switch (kind) {
    case ArtifactKind::FederationGenesis:
      return "federation-genesis";
    case ArtifactKind::PolicyUpdate:
      return "policy-update";
    case ArtifactKind::MembershipProposal:
      return "membership-proposal";
    case ArtifactKind::MembershipAcceptance:
      return "membership-acceptance";
    case ArtifactKind::MembershipEndorsement:
      return "membership-endorsement";
    case ArtifactKind::MembershipAdmission:
      return "membership-admission";
    case ArtifactKind::MembershipActivation:
      return "membership-activation";
    case ArtifactKind::DelegationDeclaration:
      return "delegation-declaration";
    case ArtifactKind::DelegationWithdrawal:
      return "delegation-withdrawal";
    case ArtifactKind::MembershipLeave:
      return "membership-leave";
    case ArtifactKind::MembershipFence:
      return "membership-fence";
    case ArtifactKind::MembershipRetirement:
      return "membership-retirement";
    case ArtifactKind::MemberReattestation:
      return "member-reattestation";
    case ArtifactKind::LeaseIssued:
      return "lease-issued";
    case ArtifactKind::LeaseRevoked:
      return "lease-revoked";
    case ArtifactKind::EpochAdvance:
      return "epoch-advance";
    case ArtifactKind::ReconciliationComplete:
      return "reconciliation-complete";
    case ArtifactKind::PartitionReport:
      return "partition-report";
    case ArtifactKind::TimeAdvance:
      return "time-advance";
  }
  return "unknown";
}

bool parse_artifact_kind(std::string_view text, ArtifactKind& out) noexcept {
  for (std::uint16_t value = 0; value <= static_cast<std::uint16_t>(ArtifactKind::TimeAdvance);
       ++value) {
    const auto kind = static_cast<ArtifactKind>(value);
    if (to_string(kind) == text) {
      out = kind;
      return true;
    }
  }
  return false;
}

bool artifact_kind_requires_coordinator(ArtifactKind kind) noexcept {
  switch (kind) {
    case ArtifactKind::FederationGenesis:
    case ArtifactKind::PolicyUpdate:
    case ArtifactKind::MembershipAdmission:
    case ArtifactKind::MembershipActivation:
    case ArtifactKind::MembershipRetirement:
    case ArtifactKind::LeaseIssued:
    case ArtifactKind::LeaseRevoked:
    case ArtifactKind::EpochAdvance:
    case ArtifactKind::ReconciliationComplete:
    case ArtifactKind::TimeAdvance:
      return true;
    default:
      return false;
  }
}

bool artifact_kind_is_coordinator_issued(ArtifactKind kind) noexcept {
  if (kind == ArtifactKind::MembershipFence) {
    // A fence may be issued by the coordinator or by the member itself. A
    // member fencing itself is always permitted: fencing only reduces
    // authority.
    return true;
  }
  return artifact_kind_requires_coordinator(kind);
}

Status Provenance::encode(Writer& writer) const {
  Status status = writer.id16(node.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(member.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(generation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(incarnation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.digest(constitution);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(epoch.value());
  if (!status.ok()) {
    return status;
  }
  return writer.u64(issued_at.value());
}

Result<Provenance> Provenance::decode(Reader& reader) {
  Provenance provenance;
  auto node = reader.id16();
  if (!node.has_value()) {
    return node.status();
  }
  provenance.node = NodeId::from_bytes(node.value());
  auto member = reader.id16();
  if (!member.has_value()) {
    return member.status();
  }
  provenance.member = MemberId::from_bytes(member.value());
  auto generation = reader.u64();
  if (!generation.has_value()) {
    return generation.status();
  }
  provenance.generation = Generation(generation.value());
  auto incarnation = reader.u64();
  if (!incarnation.has_value()) {
    return incarnation.status();
  }
  provenance.incarnation = Incarnation(incarnation.value());
  auto constitution = reader.digest();
  if (!constitution.has_value()) {
    return constitution.status();
  }
  provenance.constitution = constitution.value();
  auto epoch = reader.u64();
  if (!epoch.has_value()) {
    return epoch.status();
  }
  provenance.epoch = Epoch(epoch.value());
  auto issued_at = reader.u64();
  if (!issued_at.has_value()) {
    return issued_at.status();
  }
  provenance.issued_at = Tick(issued_at.value());
  return provenance;
}

std::string Provenance::to_string() const {
  std::string out = "node=";
  out.append(node.to_string());
  if (!member.is_nil()) {
    out.append(" member=");
    out.append(member.to_string());
    out.append(" gen=");
    out.append(std::to_string(generation.value()));
    out.append(" inc=");
    out.append(std::to_string(incarnation.value()));
    out.append(" digest=");
    out.append(constitution.to_hex().substr(0, 16));
  }
  out.append(" epoch=");
  out.append(std::to_string(epoch.value()));
  out.append(" at=");
  out.append(std::to_string(issued_at.value()));
  return out;
}

Status ArtifactEnvelope::encode(Writer& writer) const {
  Status status = writer.id16(evidence.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u16(static_cast<std::uint16_t>(kind));
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(federation.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(subject.bytes());
  if (!status.ok()) {
    return status;
  }
  status = issuer.encode(writer);
  if (!status.ok()) {
    return status;
  }
  return writer.digest(body_digest);
}

Result<ArtifactEnvelope> ArtifactEnvelope::decode(Reader& reader) {
  ArtifactEnvelope envelope;
  auto evidence = reader.id16();
  if (!evidence.has_value()) {
    return evidence.status();
  }
  envelope.evidence = EvidenceId::from_bytes(evidence.value());
  auto kind = reader.u16();
  if (!kind.has_value()) {
    return kind.status();
  }
  if (kind.value() > static_cast<std::uint16_t>(ArtifactKind::TimeAdvance)) {
    return Status::make(ErrorCode::InvalidArgument, "artefact kind is out of range");
  }
  envelope.kind = static_cast<ArtifactKind>(kind.value());
  auto federation = reader.id16();
  if (!federation.has_value()) {
    return federation.status();
  }
  envelope.federation = FederationId::from_bytes(federation.value());
  auto subject = reader.id16();
  if (!subject.has_value()) {
    return subject.status();
  }
  envelope.subject = MemberId::from_bytes(subject.value());
  auto issuer = Provenance::decode(reader);
  if (!issuer.has_value()) {
    return issuer.status();
  }
  envelope.issuer = std::move(issuer.value());
  auto body_digest = reader.digest();
  if (!body_digest.has_value()) {
    return body_digest.status();
  }
  envelope.body_digest = body_digest.value();
  return envelope;
}

std::string ArtifactEnvelope::to_string() const {
  std::string out = evidence.to_string();
  out.append(" kind=");
  out.append(fabric_federation::to_string(kind));
  out.append(" subject=");
  out.append(subject.is_nil() ? std::string("(federation)") : subject.to_string());
  out.append(" issuer{");
  out.append(issuer.to_string());
  out.append("} body=");
  out.append(body_digest.to_hex().substr(0, 16));
  return out;
}

Status FederationGenesis::encode(Writer& writer) const {
  Status status = writer.id16(federation.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(coordinator.bytes());
  if (!status.ok()) {
    return status;
  }
  status = founder.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, founder_grants, kMaxScopesPerMember);
  if (!status.ok()) {
    return status;
  }
  status = policy.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = writer.text(description, kMaxTextLength);
  if (!status.ok()) {
    return status;
  }
  return writer.u64(created_at.value());
}

Result<FederationGenesis> FederationGenesis::decode(Reader& reader) {
  FederationGenesis genesis;
  auto federation = reader.id16();
  if (!federation.has_value()) {
    return federation.status();
  }
  genesis.federation = FederationId::from_bytes(federation.value());
  auto coordinator = reader.id16();
  if (!coordinator.has_value()) {
    return coordinator.status();
  }
  genesis.coordinator = NodeId::from_bytes(coordinator.value());
  auto founder = MemberDeclaration::decode(reader);
  if (!founder.has_value()) {
    return founder.status();
  }
  genesis.founder = std::move(founder.value());
  auto grants = decode_grants(reader, kMaxScopesPerMember);
  if (!grants.has_value()) {
    return grants.status();
  }
  genesis.founder_grants = std::move(grants.value());
  auto policy = FederationPolicy::decode(reader);
  if (!policy.has_value()) {
    return policy.status();
  }
  genesis.policy = std::move(policy.value());
  auto description = reader.text(kMaxTextLength);
  if (!description.has_value()) {
    return description.status();
  }
  genesis.description = std::move(description.value());
  auto created_at = reader.u64();
  if (!created_at.has_value()) {
    return created_at.status();
  }
  genesis.created_at = Tick(created_at.value());
  return genesis;
}

std::string FederationGenesis::to_string() const {
  std::string out = "federation=";
  out.append(federation.to_string());
  out.append(" coordinator=");
  out.append(coordinator.to_string());
  out.append(" founder=");
  out.append(founder.constitution.member.to_string());
  out.append(" bootstrap_grants=[");
  out.append(render_grants(founder_grants));
  out.append("]");
  return out;
}

void canonicalize_body(ArtifactBody& body) {
  body.declaration.constitution.canonicalize();
  body.policy.canonicalize();
  body.genesis.founder.constitution.canonicalize();
  canonicalize_grants(body.genesis.founder_grants);
  canonicalize_terms(body.delegated_terms);
  canonicalize_grants(body.withdrawn_grants);
  canonicalize_grants(body.lease_scopes);
  sort_unique(body.parties);
  sort_unique(body.unreachable_members);
  std::sort(body.observations.begin(), body.observations.end());
  body.observations.erase(std::unique(body.observations.begin(), body.observations.end()),
                          body.observations.end());
}

Status ArtifactBody::encode(Writer& writer) const {
  ArtifactBody copy = *this;
  canonicalize_body(copy);
  Status status = copy.declaration.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = copy.declared_identity.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = copy.genesis.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = copy.policy.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(copy.epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(copy.policy_generation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.digest(copy.policy_digest);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(copy.lineage.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.count(copy.parties.size(), kMaxMembers);
  if (!status.ok()) {
    return status;
  }
  for (const MemberId& party : copy.parties) {
    status = writer.id16(party.bytes());
    if (!status.ok()) {
      return status;
    }
  }
  status = writer.u32(static_cast<std::uint32_t>(copy.required_endorsements));
  if (!status.ok()) {
    return status;
  }
  status = writer.u32(static_cast<std::uint32_t>(copy.required_distinct_parties));
  if (!status.ok()) {
    return status;
  }
  status = encode_terms(writer, copy.delegated_terms, kMaxDelegationTermsPerMember);
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, copy.withdrawn_grants, kMaxScopesPerMember);
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(copy.lease.bytes());
  if (!status.ok()) {
    return status;
  }
  status = copy.lease_holder.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, copy.lease_scopes, kMaxScopesPerLease);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(copy.lease_issued_epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(copy.lease_not_after_epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(copy.lease_not_after.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(copy.lease_issuer_incarnation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.count(copy.observations.size(), kMaxMembersPerObservation);
  if (!status.ok()) {
    return status;
  }
  for (const PeerObservation& observation : copy.observations) {
    status = observation.encode(writer);
    if (!status.ok()) {
      return status;
    }
  }
  status = writer.count(copy.unreachable_members.size(), kMaxMembers);
  if (!status.ok()) {
    return status;
  }
  for (const MemberId& member : copy.unreachable_members) {
    status = writer.id16(member.bytes());
    if (!status.ok()) {
      return status;
    }
  }
  status = writer.u8(static_cast<std::uint8_t>(copy.outcome));
  if (!status.ok()) {
    return status;
  }
  status = writer.u16(static_cast<std::uint16_t>(copy.reason_code));
  if (!status.ok()) {
    return status;
  }
  status = writer.u16(static_cast<std::uint16_t>(copy.fence_reason));
  if (!status.ok()) {
    return status;
  }
  status = writer.text(copy.reason_text, kMaxTextLength);
  if (!status.ok()) {
    return status;
  }
  return writer.u64(copy.logical_time.value());
}

Result<ArtifactBody> ArtifactBody::decode(Reader& reader) {
  ArtifactBody body;
  auto declaration = MemberDeclaration::decode(reader);
  if (!declaration.has_value()) {
    return declaration.status();
  }
  body.declaration = std::move(declaration.value());
  auto identity = MemberIdentity::decode(reader);
  if (!identity.has_value()) {
    return identity.status();
  }
  body.declared_identity = std::move(identity.value());
  auto genesis = FederationGenesis::decode(reader);
  if (!genesis.has_value()) {
    return genesis.status();
  }
  body.genesis = std::move(genesis.value());
  auto policy = FederationPolicy::decode(reader);
  if (!policy.has_value()) {
    return policy.status();
  }
  body.policy = std::move(policy.value());
  auto epoch = reader.u64();
  if (!epoch.has_value()) {
    return epoch.status();
  }
  body.epoch = Epoch(epoch.value());
  auto policy_generation = reader.u64();
  if (!policy_generation.has_value()) {
    return policy_generation.status();
  }
  body.policy_generation = Generation(policy_generation.value());
  auto policy_digest = reader.digest();
  if (!policy_digest.has_value()) {
    return policy_digest.status();
  }
  body.policy_digest = policy_digest.value();
  auto lineage = reader.u64();
  if (!lineage.has_value()) {
    return lineage.status();
  }
  body.lineage = Lineage(lineage.value());
  auto party_count = reader.count(kMaxMembers);
  if (!party_count.has_value()) {
    return party_count.status();
  }
  body.parties.reserve(party_count.value());
  for (std::uint32_t i = 0; i < party_count.value(); ++i) {
    auto party = reader.id16();
    if (!party.has_value()) {
      return party.status();
    }
    body.parties.push_back(MemberId::from_bytes(party.value()));
  }
  auto required_endorsements = reader.u32();
  if (!required_endorsements.has_value()) {
    return required_endorsements.status();
  }
  body.required_endorsements = required_endorsements.value();
  auto required_parties = reader.u32();
  if (!required_parties.has_value()) {
    return required_parties.status();
  }
  body.required_distinct_parties = required_parties.value();
  auto terms = decode_terms(reader, kMaxDelegationTermsPerMember);
  if (!terms.has_value()) {
    return terms.status();
  }
  body.delegated_terms = std::move(terms.value());
  auto withdrawn = decode_grants(reader, kMaxScopesPerMember);
  if (!withdrawn.has_value()) {
    return withdrawn.status();
  }
  body.withdrawn_grants = std::move(withdrawn.value());
  auto lease = reader.id16();
  if (!lease.has_value()) {
    return lease.status();
  }
  body.lease = LeaseId::from_bytes(lease.value());
  auto lease_holder = MemberIdentity::decode(reader);
  if (!lease_holder.has_value()) {
    return lease_holder.status();
  }
  body.lease_holder = std::move(lease_holder.value());
  auto lease_scopes = decode_grants(reader, kMaxScopesPerLease);
  if (!lease_scopes.has_value()) {
    return lease_scopes.status();
  }
  body.lease_scopes = std::move(lease_scopes.value());
  auto lease_issued_epoch = reader.u64();
  if (!lease_issued_epoch.has_value()) {
    return lease_issued_epoch.status();
  }
  body.lease_issued_epoch = Epoch(lease_issued_epoch.value());
  auto lease_not_after_epoch = reader.u64();
  if (!lease_not_after_epoch.has_value()) {
    return lease_not_after_epoch.status();
  }
  body.lease_not_after_epoch = Epoch(lease_not_after_epoch.value());
  auto lease_not_after = reader.u64();
  if (!lease_not_after.has_value()) {
    return lease_not_after.status();
  }
  body.lease_not_after = Tick(lease_not_after.value());
  auto lease_issuer_incarnation = reader.u64();
  if (!lease_issuer_incarnation.has_value()) {
    return lease_issuer_incarnation.status();
  }
  body.lease_issuer_incarnation = Incarnation(lease_issuer_incarnation.value());
  auto observation_count = reader.count(kMaxMembersPerObservation);
  if (!observation_count.has_value()) {
    return observation_count.status();
  }
  body.observations.reserve(observation_count.value());
  for (std::uint32_t i = 0; i < observation_count.value(); ++i) {
    auto observation = PeerObservation::decode(reader);
    if (!observation.has_value()) {
      return observation.status();
    }
    body.observations.push_back(std::move(observation.value()));
  }
  auto unreachable_count = reader.count(kMaxMembers);
  if (!unreachable_count.has_value()) {
    return unreachable_count.status();
  }
  body.unreachable_members.reserve(unreachable_count.value());
  for (std::uint32_t i = 0; i < unreachable_count.value(); ++i) {
    auto member = reader.id16();
    if (!member.has_value()) {
      return member.status();
    }
    body.unreachable_members.push_back(MemberId::from_bytes(member.value()));
  }
  auto outcome = reader.u8();
  if (!outcome.has_value()) {
    return outcome.status();
  }
  if (outcome.value() > static_cast<std::uint8_t>(Outcome::Unknown)) {
    return Status::make(ErrorCode::InvalidArgument, "artefact outcome is out of range");
  }
  body.outcome = static_cast<Outcome>(outcome.value());
  auto reason = reader.u16();
  if (!reason.has_value()) {
    return reason.status();
  }
  if (reason.value() > static_cast<std::uint16_t>(ReasonCode::LimitExceeded)) {
    return Status::make(ErrorCode::InvalidArgument, "artefact reason code is out of range");
  }
  body.reason_code = static_cast<ReasonCode>(reason.value());
  auto fence_reason = reader.u16();
  if (!fence_reason.has_value()) {
    return fence_reason.status();
  }
  if (fence_reason.value() > static_cast<std::uint16_t>(ReasonCode::LimitExceeded)) {
    return Status::make(ErrorCode::InvalidArgument, "artefact fence reason is out of range");
  }
  body.fence_reason = static_cast<ReasonCode>(fence_reason.value());
  auto reason_text = reader.text(kMaxTextLength);
  if (!reason_text.has_value()) {
    return reason_text.status();
  }
  body.reason_text = std::move(reason_text.value());
  auto logical_time = reader.u64();
  if (!logical_time.has_value()) {
    return logical_time.status();
  }
  body.logical_time = Tick(logical_time.value());
  canonicalize_body(body);
  return body;
}

Digest ArtifactBody::digest() const {
  Writer writer;
  if (!encode(writer).ok()) {
    return Digest();
  }
  return writer.sha256();
}

std::string ArtifactBody::to_string() const {
  std::string out = "declaration{";
  out.append(declaration.to_string());
  out.append("}");
  return out;
}

Digest Artifact::digest() const {
  Writer writer;
  if (!encode(writer).ok()) {
    return Digest();
  }
  return writer.sha256();
}

Status Artifact::verify_digest() const {
  const Digest computed = body.digest();
  if (computed.is_zero()) {
    return Status::make(ErrorCode::Internal, "artefact body could not be encoded");
  }
  if (computed != envelope.body_digest) {
    return Status::make(ErrorCode::ChecksumMismatch,
                        "artefact body digest does not match the envelope");
  }
  return Status::success();
}

Status Artifact::validate(const ScopeCatalog& catalog) const {
  Status status = verify_digest();
  if (!status.ok()) {
    return status;
  }
  if (envelope.evidence.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument, "artefact has no evidence identifier");
  }
  if (envelope.federation.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument, "artefact has no federation identity");
  }
  if (envelope.issuer.node.is_nil() && envelope.issuer.member.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument, "artefact has no issuer");
  }
  if (envelope.issuer.member.is_nil() && !artifact_kind_is_coordinator_issued(envelope.kind)) {
    return Status::make(ErrorCode::InvalidArgument,
                        "artefact kind " +
                            std::string(fabric_federation::to_string(envelope.kind)) +
                            " must be issued by a member");
  }

  const ArtifactBody& declaration = this->body;
  switch (envelope.kind) {
    case ArtifactKind::FederationGenesis: {
      if (declaration.genesis.federation != envelope.federation) {
        return Status::make(ErrorCode::InvalidArgument,
                            "genesis record names a different federation");
      }
      if (declaration.genesis.founder.constitution.member != envelope.subject) {
        return Status::make(ErrorCode::InvalidArgument,
                            "genesis founder does not match the artefact subject");
      }
      status = validate_constitution(declaration.genesis.founder.constitution, catalog);
      if (!status.ok()) {
        return status;
      }
      status = validate_policy(declaration.genesis.policy);
      if (!status.ok()) {
        return status;
      }
      for (const ScopeGrant& grant : declaration.genesis.founder_grants) {
        bool known = false;
        const ScopeClass scope_class = catalog.classify(grant.scope, known);
        if (!known) {
          return Status::make(ErrorCode::InvalidArgument,
                              "bootstrap grant names an unknown scope");
        }
        (void)scope_class;
      }
      break;
    }
    case ArtifactKind::PolicyUpdate: {
      status = validate_policy(declaration.policy);
      if (!status.ok()) {
        return status;
      }
      if (declaration.policy.generation != declaration.policy_generation) {
        return Status::make(ErrorCode::InvalidArgument,
                            "policy update generation does not match its body");
      }
      break;
    }
    case ArtifactKind::MembershipProposal: {
      status = validate_constitution(declaration.declaration.constitution, catalog);
      if (!status.ok()) {
        return status;
      }
      if (declaration.declaration.constitution.member != envelope.subject) {
        return Status::make(ErrorCode::InvalidArgument,
                            "proposal subject does not match the declared constitution");
      }
      break;
    }
    case ArtifactKind::MembershipAcceptance:
    case ArtifactKind::MembershipEndorsement:
    case ArtifactKind::MemberReattestation: {
      status = validate_constitution(declaration.declaration.constitution, catalog);
      if (!status.ok()) {
        return status;
      }
      if (declaration.declaration.constitution.member != envelope.subject) {
        return Status::make(ErrorCode::InvalidArgument,
                            "declaration subject does not match the declared constitution");
      }
      const MemberIdentity derived = declaration.declaration.identity();
      if (derived.incarnation != declaration.declared_identity.incarnation ||
          derived.constitution != declaration.declared_identity.constitution) {
        return Status::make(ErrorCode::InvalidArgument,
                            "declared identity does not match the accompanying declaration");
      }
      break;
    }
    case ArtifactKind::MembershipAdmission: {
      if (declaration.declared_identity.member != envelope.subject) {
        return Status::make(ErrorCode::InvalidArgument,
                            "admission identity does not match the artefact subject");
      }
      if (declaration.parties.size() < 2 && declaration.parties.size() != 1) {
        return Status::make(ErrorCode::InvalidArgument,
                            "admission record must name the parties it relies on");
      }
      break;
    }
    case ArtifactKind::MembershipActivation: {
      if (declaration.declared_identity.member != envelope.subject) {
        return Status::make(ErrorCode::InvalidArgument,
                            "activation identity does not match the artefact subject");
      }
      break;
    }
    case ArtifactKind::DelegationDeclaration: {
      status = validate_constitution(declaration.declaration.constitution, catalog);
      if (!status.ok()) {
        return status;
      }
      if (declaration.declared_identity.member != envelope.subject) {
        return Status::make(ErrorCode::InvalidArgument,
                            "delegation declaration identity does not match the subject");
      }
      break;
    }
    case ArtifactKind::DelegationWithdrawal: {
      if (declaration.withdrawn_grants.empty()) {
        return Status::make(ErrorCode::InvalidArgument,
                            "a delegation withdrawal must name the grants it withdraws");
      }
      break;
    }
    case ArtifactKind::MembershipLeave:
    case ArtifactKind::MembershipFence:
    case ArtifactKind::MembershipRetirement: {
      if (envelope.subject.is_nil()) {
        return Status::make(ErrorCode::InvalidArgument, "lifecycle record has no subject");
      }
      break;
    }
    case ArtifactKind::LeaseIssued: {
      if (declaration.lease.is_nil()) {
        return Status::make(ErrorCode::InvalidArgument, "lease record has no lease identifier");
      }
      if (declaration.lease_holder.member != envelope.subject) {
        return Status::make(ErrorCode::InvalidArgument,
                            "lease holder does not match the artefact subject");
      }
      if (declaration.lease_scopes.empty()) {
        return Status::make(ErrorCode::InvalidArgument, "lease grants no scopes");
      }
      break;
    }
    case ArtifactKind::LeaseRevoked: {
      if (declaration.lease.is_nil()) {
        return Status::make(ErrorCode::InvalidArgument, "lease revocation has no lease identifier");
      }
      break;
    }
    case ArtifactKind::EpochAdvance: {
      if (declaration.epoch.is_zero()) {
        return Status::make(ErrorCode::InvalidArgument, "epoch advance must name the new epoch");
      }
      break;
    }
    case ArtifactKind::ReconciliationComplete: {
      if (declaration.epoch.is_zero()) {
        return Status::make(ErrorCode::InvalidArgument,
                            "reconciliation record must name the epoch it closes");
      }
      status = expect_empty_ids(declaration.parties, "reconciliation record");
      if (!status.ok()) {
        return status;
      }
      break;
    }
    case ArtifactKind::PartitionReport: {
      for (const PeerObservation& observation : declaration.observations) {
        if (observation.peer.is_nil()) {
          return Status::make(ErrorCode::InvalidArgument,
                              "partition report contains a peer with no identity");
        }
      }
      break;
    }
    case ArtifactKind::TimeAdvance: {
      if (declaration.logical_time.is_zero()) {
        return Status::make(ErrorCode::InvalidArgument, "time advance must name the new tick");
      }
      break;
    }
  }
  return Status::success();
}

Status Artifact::encode(Writer& writer) const {
  Status status = envelope.encode(writer);
  if (!status.ok()) {
    return status;
  }
  return body.encode(writer);
}

Result<Artifact> Artifact::decode(Reader& reader) {
  auto envelope = ArtifactEnvelope::decode(reader);
  if (!envelope.has_value()) {
    return envelope.status();
  }
  auto body = ArtifactBody::decode(reader);
  if (!body.has_value()) {
    return body.status();
  }
  Artifact artifact;
  artifact.envelope = std::move(envelope.value());
  artifact.body = std::move(body.value());
  return artifact;
}

Artifact Artifact::make(ArtifactEnvelope envelope, ArtifactBody body) {
  canonicalize_body(body);
  Artifact artifact;
  artifact.body = std::move(body);
  envelope.body_digest = artifact.body.digest();
  artifact.envelope = std::move(envelope);
  return artifact;
}

std::string Artifact::to_string() const {
  std::string out = envelope.to_string();
  out.append(" digest=");
  out.append(digest().to_hex().substr(0, 16));
  if (!body.reason_text.empty()) {
    out.append(" reason=\"");
    out.append(body.reason_text);
    out.append("\"");
  }
  return out;
}

}  // namespace fabric_federation