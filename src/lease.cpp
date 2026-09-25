// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/lease.hpp"

namespace fabric_federation {
namespace {

LeaseEvaluation evaluate_common(const AuthorityLease& lease, Epoch current_epoch,
                                Incarnation coordinator_incarnation, Tick now) {
  LeaseEvaluation result;
  if (lease.revoked) {
    result.state = LeaseState::Revoked;
    result.reason = ReasonCode::LeaseRevoked;
    result.detail = "revoked at tick " + std::to_string(lease.revoked_at.value());
    return result;
  }
  if (lease.issuer_incarnation != coordinator_incarnation) {
    result.state = LeaseState::StaleIssuer;
    result.reason = ReasonCode::LeaseStaleIssuer;
    result.detail = "issued by coordinator incarnation " +
                    std::to_string(lease.issuer_incarnation.value()) + ", current is " +
                    std::to_string(coordinator_incarnation.value());
    return result;
  }
  const std::uint64_t lowest = lease.issued_epoch.value();
  const std::uint64_t highest = lease.not_after_epoch.value() > lease.issued_epoch.value()
                                    ? lease.not_after_epoch.value()
                                    : lease.issued_epoch.value();
  if (current_epoch.value() > highest) {
    result.state = LeaseState::EpochMismatch;
    result.reason = ReasonCode::LeaseEpochMismatch;
    result.detail = "lease is valid through epoch " + std::to_string(highest) + ", current epoch " +
                    std::to_string(current_epoch.value());
    return result;
  }
  if (current_epoch.value() < lowest) {
    result.state = LeaseState::EpochMismatch;
    result.reason = ReasonCode::LeaseEpochMismatch;
    result.detail = "lease starts at epoch " + std::to_string(lowest) + ", current epoch " +
                    std::to_string(current_epoch.value());
    return result;
  }
  if (now.value() > lease.not_after.value()) {
    result.state = LeaseState::Expired;
    result.reason = ReasonCode::LeaseExpired;
    result.detail = "lease expired at tick " + std::to_string(lease.not_after.value()) +
                    ", now " + std::to_string(now.value());
    return result;
  }
  result.state = LeaseState::Valid;
  result.reason = ReasonCode::LeaseValid;
  return result;
}

}  // namespace

std::string_view to_string(LeaseState state) noexcept {
  switch (state) {
    case LeaseState::Valid:
      return "VALID";
    case LeaseState::Unknown:
      return "UNKNOWN";
    case LeaseState::Expired:
      return "EXPIRED";
    case LeaseState::Revoked:
      return "REVOKED";
    case LeaseState::StaleIssuer:
      return "STALE_ISSUER";
    case LeaseState::EpochMismatch:
      return "EPOCH_MISMATCH";
    case LeaseState::HolderMismatch:
      return "HOLDER_MISMATCH";
    case LeaseState::ScopeNotCovered:
      return "SCOPE_NOT_COVERED";
  }
  return "UNKNOWN";
}

bool operator==(const AuthorityLease& a, const AuthorityLease& b) noexcept {
  return a.id == b.id && a.federation == b.federation && a.holder == b.holder &&
         a.scopes == b.scopes && a.issued_epoch == b.issued_epoch &&
         a.not_after_epoch == b.not_after_epoch && a.issued_at == b.issued_at &&
         a.not_after == b.not_after && a.issuer_node == b.issuer_node &&
         a.issuer_incarnation == b.issuer_incarnation && a.revoked == b.revoked &&
         a.revoked_at == b.revoked_at && a.revoke_reason == b.revoke_reason &&
         a.revoke_detail == b.revoke_detail;
}

Status AuthorityLease::encode(Writer& writer) const {
  Status status = writer.id16(id.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(federation.bytes());
  if (!status.ok()) {
    return status;
  }
  status = holder.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, scopes, kMaxScopesPerLease);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(issued_epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(not_after_epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(issued_at.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(not_after.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(issuer_node.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(issuer_incarnation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.boolean(revoked);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(revoked_at.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u16(static_cast<std::uint16_t>(revoke_reason));
  if (!status.ok()) {
    return status;
  }
  return writer.text(revoke_detail, kMaxShortTextLength);
}

Result<AuthorityLease> AuthorityLease::decode(Reader& reader) {
  AuthorityLease lease;
  auto id = reader.id16();
  if (!id.has_value()) {
    return id.status();
  }
  lease.id = LeaseId::from_bytes(id.value());
  auto federation = reader.id16();
  if (!federation.has_value()) {
    return federation.status();
  }
  lease.federation = FederationId::from_bytes(federation.value());
  auto holder = MemberIdentity::decode(reader);
  if (!holder.has_value()) {
    return holder.status();
  }
  lease.holder = std::move(holder.value());
  auto scopes = decode_grants(reader, kMaxScopesPerLease);
  if (!scopes.has_value()) {
    return scopes.status();
  }
  lease.scopes = std::move(scopes.value());
  auto issued_epoch = reader.u64();
  if (!issued_epoch.has_value()) {
    return issued_epoch.status();
  }
  lease.issued_epoch = Epoch(issued_epoch.value());
  auto not_after_epoch = reader.u64();
  if (!not_after_epoch.has_value()) {
    return not_after_epoch.status();
  }
  lease.not_after_epoch = Epoch(not_after_epoch.value());
  auto issued_at = reader.u64();
  if (!issued_at.has_value()) {
    return issued_at.status();
  }
  lease.issued_at = Tick(issued_at.value());
  auto not_after = reader.u64();
  if (!not_after.has_value()) {
    return not_after.status();
  }
  lease.not_after = Tick(not_after.value());
  auto issuer_node = reader.id16();
  if (!issuer_node.has_value()) {
    return issuer_node.status();
  }
  lease.issuer_node = NodeId::from_bytes(issuer_node.value());
  auto issuer_incarnation = reader.u64();
  if (!issuer_incarnation.has_value()) {
    return issuer_incarnation.status();
  }
  lease.issuer_incarnation = Incarnation(issuer_incarnation.value());
  auto revoked = reader.boolean();
  if (!revoked.has_value()) {
    return revoked.status();
  }
  lease.revoked = revoked.value();
  auto revoked_at = reader.u64();
  if (!revoked_at.has_value()) {
    return revoked_at.status();
  }
  lease.revoked_at = Tick(revoked_at.value());
  auto reason = reader.u16();
  if (!reason.has_value()) {
    return reason.status();
  }
  lease.revoke_reason = static_cast<ReasonCode>(reason.value());
  auto detail = reader.text(kMaxShortTextLength);
  if (!detail.has_value()) {
    return detail.status();
  }
  lease.revoke_detail = std::move(detail.value());
  return lease;
}

Digest AuthorityLease::digest() const {
  Writer writer;
  if (!encode(writer).ok()) {
    return Digest();
  }
  return writer.sha256();
}

std::string AuthorityLease::to_string() const {
  std::string out = id.to_string();
  out.append(" holder=");
  out.append(holder.to_string());
  out.append(" scopes=[");
  out.append(render_grants(scopes));
  out.append("] issued_epoch=");
  out.append(std::to_string(issued_epoch.value()));
  if (!not_after_epoch.is_zero()) {
    out.append(" not_after_epoch=");
    out.append(std::to_string(not_after_epoch.value()));
  }
  out.append(" not_after_tick=");
  out.append(std::to_string(not_after.value()));
  out.append(" issuer_incarnation=");
  out.append(std::to_string(issuer_incarnation.value()));
  if (revoked) {
    out.append(" REVOKED");
  }
  return out;
}

LeaseEvaluation evaluate_lease(const AuthorityLease& lease, Epoch current_epoch,
                               Incarnation coordinator_incarnation, Tick now) {
  return evaluate_common(lease, current_epoch, coordinator_incarnation, now);
}

LeaseEvaluation evaluate_lease(const AuthorityLease& lease, const ScopeGrant& requested,
                               Epoch current_epoch, Incarnation coordinator_incarnation, Tick now) {
  LeaseEvaluation result = evaluate_common(lease, current_epoch, coordinator_incarnation, now);
  if (result.state != LeaseState::Valid) {
    return result;
  }
  if (!grants_cover(lease.scopes, requested)) {
    result.state = LeaseState::ScopeNotCovered;
    result.reason = ReasonCode::LeaseScopeNotCovered;
    result.detail = "lease does not cover " + requested.to_string();
    return result;
  }
  return result;
}

}  // namespace fabric_federation
