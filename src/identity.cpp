// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/identity.hpp"

#include <algorithm>

namespace fabric_federation {
namespace {

template <class T>
void sort_unique(std::vector<T>& items) {
  std::sort(items.begin(), items.end());
  items.erase(std::unique(items.begin(), items.end()), items.end());
}

}  // namespace

std::string_view to_string(MemberLifecycleState state) noexcept {
  switch (state) {
    case MemberLifecycleState::Absent:
      return "ABSENT";
    case MemberLifecycleState::Proposed:
      return "PROPOSED";
    case MemberLifecycleState::Admitted:
      return "ADMITTED";
    case MemberLifecycleState::Active:
      return "ACTIVE";
    case MemberLifecycleState::Degraded:
      return "DEGRADED";
    case MemberLifecycleState::Fenced:
      return "FENCED";
    case MemberLifecycleState::Leaving:
      return "LEAVING";
    case MemberLifecycleState::Retired:
      return "RETIRED";
  }
  return "ABSENT";
}

bool lifecycle_holds_federation_authority(MemberLifecycleState state) noexcept {
  return state == MemberLifecycleState::Active || state == MemberLifecycleState::Degraded;
}

bool lifecycle_is_terminal(MemberLifecycleState state) noexcept {
  return state == MemberLifecycleState::Retired;
}

void MemberConstitution::canonicalize() {
  canonicalize_statements(capabilities);
  canonicalize_requirements(requirements);
  canonicalize_grants(retained);
  canonicalize_terms(delegated);
}

Status MemberConstitution::encode(Writer& writer) const {
  Status status = writer.id16(domain.bytes());
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
  status = writer.u32(software_major);
  if (!status.ok()) {
    return status;
  }
  status = writer.u32(software_minor);
  if (!status.ok()) {
    return status;
  }
  status = writer.u32(software_patch);
  if (!status.ok()) {
    return status;
  }
  status = encode_statements(writer, capabilities, kMaxCapabilitiesPerMember);
  if (!status.ok()) {
    return status;
  }
  status = encode_requirements(writer, requirements, kMaxCapabilitiesPerMember);
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, retained, kMaxScopesPerMember);
  if (!status.ok()) {
    return status;
  }
  status = encode_terms(writer, delegated, kMaxDelegationTermsPerMember);
  if (!status.ok()) {
    return status;
  }
  return writer.text(description, kMaxTextLength);
}

Result<MemberConstitution> MemberConstitution::decode(Reader& reader) {
  MemberConstitution constitution;
  auto domain = reader.id16();
  if (!domain.has_value()) {
    return domain.status();
  }
  constitution.domain = FabricDomainId::from_bytes(domain.value());
  auto member = reader.id16();
  if (!member.has_value()) {
    return member.status();
  }
  constitution.member = MemberId::from_bytes(member.value());
  auto generation = reader.u64();
  if (!generation.has_value()) {
    return generation.status();
  }
  constitution.generation = Generation(generation.value());
  auto major = reader.u32();
  if (!major.has_value()) {
    return major.status();
  }
  constitution.software_major = major.value();
  auto minor = reader.u32();
  if (!minor.has_value()) {
    return minor.status();
  }
  constitution.software_minor = minor.value();
  auto patch = reader.u32();
  if (!patch.has_value()) {
    return patch.status();
  }
  constitution.software_patch = patch.value();

  auto capabilities = decode_statements(reader, kMaxCapabilitiesPerMember);
  if (!capabilities.has_value()) {
    return capabilities.status();
  }
  constitution.capabilities = std::move(capabilities.value());
  auto requirements = decode_requirements(reader, kMaxCapabilitiesPerMember);
  if (!requirements.has_value()) {
    return requirements.status();
  }
  constitution.requirements = std::move(requirements.value());
  auto retained = decode_grants(reader, kMaxScopesPerMember);
  if (!retained.has_value()) {
    return retained.status();
  }
  constitution.retained = std::move(retained.value());
  auto delegated = decode_terms(reader, kMaxDelegationTermsPerMember);
  if (!delegated.has_value()) {
    return delegated.status();
  }
  constitution.delegated = std::move(delegated.value());
  auto description = reader.text(kMaxTextLength);
  if (!description.has_value()) {
    return description.status();
  }
  constitution.description = std::move(description.value());
  constitution.canonicalize();
  return constitution;
}

Digest MemberConstitution::digest() const {
  MemberConstitution copy = *this;
  copy.canonicalize();
  Writer writer;
  if (!copy.encode(writer).ok()) {
    return Digest();
  }
  return writer.sha256();
}

std::string MemberConstitution::to_string() const {
  std::string out = "domain=";
  out.append(domain.to_string());
  out.append(" member=");
  out.append(member.to_string());
  out.append(" generation=");
  out.append(std::to_string(generation.value()));
  out.append(" software=");
  out.append(std::to_string(software_major));
  out.append(".");
  out.append(std::to_string(software_minor));
  out.append(".");
  out.append(std::to_string(software_patch));
  out.append(" retained=[");
  out.append(render_grants(retained));
  out.append("] delegated=[");
  for (std::size_t i = 0; i < delegated.size(); ++i) {
    if (i != 0) {
      out.append(", ");
    }
    out.append(delegated[i].to_string());
  }
  if (delegated.empty()) {
    out.append("(none)");
  }
  out.append("] capabilities=[");
  for (std::size_t i = 0; i < capabilities.size(); ++i) {
    if (i != 0) {
      out.append(", ");
    }
    out.append(capabilities[i].to_string());
  }
  if (capabilities.empty()) {
    out.append("(none)");
  }
  out.append("] digest=");
  out.append(digest_hex());
  return out;
}

Status validate_constitution(const MemberConstitution& constitution, const ScopeCatalog& catalog) {
  if (constitution.domain.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument, "constitution has no domain identity");
  }
  if (constitution.member.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument, "constitution has no member identity");
  }
  if (constitution.capabilities.size() > kMaxCapabilitiesPerMember) {
    return Status::make(ErrorCode::BoundsExceeded, "too many capability statements");
  }
  if (constitution.requirements.size() > kMaxCapabilitiesPerMember) {
    return Status::make(ErrorCode::BoundsExceeded, "too many capability requirements");
  }
  if (constitution.retained.size() > kMaxScopesPerMember) {
    return Status::make(ErrorCode::BoundsExceeded, "too many retained grants");
  }
  if (constitution.delegated.size() > kMaxDelegationTermsPerMember) {
    return Status::make(ErrorCode::BoundsExceeded, "too many delegation terms");
  }
  if (constitution.description.size() > kMaxTextLength) {
    return Status::make(ErrorCode::BoundsExceeded, "constitution description is too long");
  }

  // A member may not both keep and hand over the same authority.
  std::vector<ScopeGrant> delegated_grants;
  delegated_grants.reserve(constitution.delegated.size());
  for (const DelegationTerms& terms : constitution.delegated) {
    if (terms.grant.scope.is_wildcard() && terms.grant.scope.str() == "*") {
      return Status::make(ErrorCode::InvalidArgument,
                          "a member may not delegate every scope at once");
    }
    bool known = false;
    const ScopeClass scope_class = catalog.classify(terms.grant.scope, known);
    if (!known) {
      return Status::make(ErrorCode::InvalidArgument,
                          "delegated scope " + terms.grant.scope.str() +
                              " is not in the scope catalogue");
    }
    if (scope_class == ScopeClass::Local) {
      return Status::make(ErrorCode::InvalidArgument,
                          "scope " + terms.grant.scope.str() +
                              " is local authority and cannot be delegated");
    }
    // The member's own domain namespace is never delegable, whatever the
    // catalogue says.
    const std::string& text = terms.grant.scope.str();
    if (text.size() >= 7 && text.compare(0, 7, "domain.") == 0) {
      return Status::make(ErrorCode::InvalidArgument,
                          "a member may not delegate authority inside its own domain");
    }
    delegated_grants.push_back(terms.grant);
  }

  for (const ScopeGrant& retained : constitution.retained) {
    bool known = false;
    const ScopeClass scope_class = catalog.classify(retained.scope, known);
    if (!known) {
      return Status::make(ErrorCode::InvalidArgument,
                          "retained scope " + retained.scope.str() +
                              " is not in the scope catalogue");
    }
    if (scope_class != ScopeClass::Local) {
      return Status::make(ErrorCode::InvalidArgument,
                          "scope " + retained.scope.str() +
                              " is federation authority and cannot be listed as retained local "
                              "authority");
    }
    for (const ScopeGrant& delegated : delegated_grants) {
      if (retained.verb != delegated.verb) {
        continue;
      }
      if (delegated.scope.covers(retained.scope) || retained.scope.covers(delegated.scope)) {
        return Status::make(
            ErrorCode::InvalidArgument,
            "grant " + retained.to_string() +
                " is declared both as retained local authority and as delegated authority");
      }
    }
  }
  return Status::success();
}

Status MemberIdentity::encode(Writer& writer) const {
  Status status = writer.id16(domain.bytes());
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
  status = writer.id16(node.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(started_at.value());
  if (!status.ok()) {
    return status;
  }
  return writer.boolean(reincarnated);
}

Result<MemberIdentity> MemberIdentity::decode(Reader& reader) {
  MemberIdentity identity;
  auto domain = reader.id16();
  if (!domain.has_value()) {
    return domain.status();
  }
  identity.domain = FabricDomainId::from_bytes(domain.value());
  auto member = reader.id16();
  if (!member.has_value()) {
    return member.status();
  }
  identity.member = MemberId::from_bytes(member.value());
  auto generation = reader.u64();
  if (!generation.has_value()) {
    return generation.status();
  }
  identity.generation = Generation(generation.value());
  auto incarnation = reader.u64();
  if (!incarnation.has_value()) {
    return incarnation.status();
  }
  identity.incarnation = Incarnation(incarnation.value());
  auto constitution = reader.digest();
  if (!constitution.has_value()) {
    return constitution.status();
  }
  identity.constitution = constitution.value();
  auto node = reader.id16();
  if (!node.has_value()) {
    return node.status();
  }
  identity.node = NodeId::from_bytes(node.value());
  auto started_at = reader.u64();
  if (!started_at.has_value()) {
    return started_at.status();
  }
  identity.started_at = Tick(started_at.value());
  auto reincarnated = reader.boolean();
  if (!reincarnated.has_value()) {
    return reincarnated.status();
  }
  identity.reincarnated = reincarnated.value();
  return identity;
}

std::string MemberIdentity::to_string() const {
  std::string out = member.to_string();
  out.append(" gen=");
  out.append(std::to_string(generation.value()));
  out.append(" inc=");
  out.append(std::to_string(incarnation.value()));
  out.append(" node=");
  out.append(node.to_string());
  out.append(" digest=");
  out.append(constitution.to_hex().substr(0, 16));
  return out;
}

Digest MemberIdentity::digest() const {
  Writer writer;
  if (!encode(writer).ok()) {
    return Digest();
  }
  return writer.sha256();
}

std::string_view to_string(IdentityMismatch mismatch) noexcept {
  switch (mismatch) {
    case IdentityMismatch::None:
      return "none";
    case IdentityMismatch::Member:
      return "member";
    case IdentityMismatch::Domain:
      return "domain";
    case IdentityMismatch::Generation:
      return "generation";
    case IdentityMismatch::Incarnation:
      return "incarnation";
    case IdentityMismatch::Constitution:
      return "constitution";
    case IdentityMismatch::Node:
      return "node";
  }
  return "none";
}

IdentityMismatch compare_identities(const MemberIdentity& expected,
                                    const MemberIdentity& presented) noexcept {
  if (expected.member != presented.member) {
    return IdentityMismatch::Member;
  }
  if (expected.domain != presented.domain) {
    return IdentityMismatch::Domain;
  }
  if (expected.generation != presented.generation) {
    return IdentityMismatch::Generation;
  }
  if (expected.constitution != presented.constitution) {
    return IdentityMismatch::Constitution;
  }
  if (expected.incarnation != presented.incarnation) {
    return IdentityMismatch::Incarnation;
  }
  if (expected.node != presented.node) {
    return IdentityMismatch::Node;
  }
  return IdentityMismatch::None;
}

MemberIdentity MemberDeclaration::identity() const {
  MemberIdentity identity;
  identity.domain = constitution.domain;
  identity.member = constitution.member;
  identity.generation = constitution.generation;
  identity.incarnation = incarnation;
  identity.constitution = constitution.digest();
  identity.node = node;
  identity.started_at = declared_at;
  identity.reincarnated = !incarnation.is_zero() && incarnation.value() > 1;
  return identity;
}

Status MemberDeclaration::encode(Writer& writer) const {
  Status status = constitution.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(incarnation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(node.bytes());
  if (!status.ok()) {
    return status;
  }
  return writer.u64(declared_at.value());
}

Result<MemberDeclaration> MemberDeclaration::decode(Reader& reader) {
  MemberDeclaration declaration;
  auto constitution = MemberConstitution::decode(reader);
  if (!constitution.has_value()) {
    return constitution.status();
  }
  declaration.constitution = std::move(constitution.value());
  auto incarnation = reader.u64();
  if (!incarnation.has_value()) {
    return incarnation.status();
  }
  declaration.incarnation = Incarnation(incarnation.value());
  auto node = reader.id16();
  if (!node.has_value()) {
    return node.status();
  }
  declaration.node = NodeId::from_bytes(node.value());
  auto declared_at = reader.u64();
  if (!declared_at.has_value()) {
    return declared_at.status();
  }
  declaration.declared_at = Tick(declared_at.value());
  return declaration;
}

std::string MemberDeclaration::to_string() const {
  std::string out = constitution.to_string();
  out.append(" incarnation=");
  out.append(std::to_string(incarnation.value()));
  out.append(" node=");
  out.append(node.to_string());
  return out;
}

MembershipSlot MembershipSlot::make(const MemberId& member, Lineage lineage) {
  MembershipSlot slot;
  slot.member = member;
  slot.lineage = lineage;
  slot.lineage_id = LineageId::derive(member.to_string(), lineage.value());
  return slot;
}

}  // namespace fabric_federation
