// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/protocol.hpp"

#include <cstring>

namespace fabric_federation {

std::string_view to_string(MessageType type) noexcept {
  switch (type) {
    case MessageType::Hello:
      return "hello";
    case MessageType::Welcome:
      return "welcome";
    case MessageType::ErrorMessage:
      return "error";
    case MessageType::Ping:
      return "ping";
    case MessageType::Pong:
      return "pong";
    case MessageType::Goodbye:
      return "goodbye";
    case MessageType::SubmitArtifact:
      return "submit-artifact";
    case MessageType::SubmitArtifactResult:
      return "submit-artifact-result";
    case MessageType::QueryDigest:
      return "query-digest";
    case MessageType::DigestValue:
      return "digest-value";
    case MessageType::QueryState:
      return "query-state";
    case MessageType::StateValue:
      return "state-value";
    case MessageType::AuthorityQuery:
      return "authority-query";
    case MessageType::AuthorityResult:
      return "authority-result";
    case MessageType::IssueLease:
      return "issue-lease";
    case MessageType::LeaseResult:
      return "lease-result";
    case MessageType::RevokeLease:
      return "revoke-lease";
    case MessageType::ReportObservation:
      return "report-observation";
    case MessageType::AdvanceTime:
      return "advance-time";
    case MessageType::FenceMember:
      return "fence-member";
    case MessageType::AdvanceEpoch:
      return "advance-epoch";
    case MessageType::CompleteReconciliation:
      return "complete-reconciliation";
    case MessageType::QueryArtifacts:
      return "query-artifacts";
    case MessageType::ArtifactListValue:
      return "artifact-list-value";
    case MessageType::QueryLeases:
      return "query-leases";
    case MessageType::LeaseListValue:
      return "lease-list-value";
    case MessageType::StatsQuery:
      return "stats-query";
    case MessageType::StatsValue:
      return "stats-value";
    case MessageType::SimpleResult:
      return "simple-result";
    case MessageType::ProbeRequest:
      return "probe-request";
    case MessageType::ProbeResult:
      return "probe-result";
  }
  return "unknown";
}

bool parse_message_type(std::string_view text, MessageType& out) noexcept {
  for (std::uint16_t value = static_cast<std::uint16_t>(MessageType::Hello);
       value <= kMaxMessageType; ++value) {
    const auto type = static_cast<MessageType>(value);
    if (to_string(type) == text) {
      out = type;
      return true;
    }
  }
  return false;
}

Status write_message(Socket& socket, MessageType type, std::span<const std::byte> payload) {
  if (payload.size() > kMaxFramePayloadBytes) {
    return Status::make(ErrorCode::BoundsExceeded, "outgoing payload exceeds the frame bound");
  }
  const std::size_t frame_length = 12 + payload.size() + kFrameTrailerBytes;
  std::vector<std::byte> frame(4 + frame_length);
  store_u32_le(frame.data(), static_cast<std::uint32_t>(frame_length));
  store_u32_le(frame.data() + 4, kFrameMagic);
  std::uint16_t version = kWireProtocolVersion;
  std::memcpy(frame.data() + 8, &version, 2);
  std::uint16_t type_value = static_cast<std::uint16_t>(type);
  std::memcpy(frame.data() + 10, &type_value, 2);
  store_u32_le(frame.data() + 12, static_cast<std::uint32_t>(payload.size()));
  if (!payload.empty()) {
    std::memcpy(frame.data() + kFrameHeaderBytes, payload.data(), payload.size());
  }
  const std::size_t digest_offset = kFrameHeaderBytes + payload.size();
  const Digest digest =
      Sha256::hash(std::span<const std::byte>(frame.data() + 4, 12 + payload.size()));
  std::memcpy(frame.data() + digest_offset, digest.data(), Digest::kSize);
  return socket.send_all(std::span<const std::byte>(frame.data(), frame.size()));
}

Result<Message> read_message(Socket& socket, const FrameLimits& limits) {
  std::byte length_bytes[4];
  Status status = socket.recv_exact(std::span<std::byte>(length_bytes, sizeof(length_bytes)));
  if (!status.ok()) {
    return status;
  }
  const std::uint32_t frame_length = load_u32_le(length_bytes);
  if (frame_length < 12 + kFrameTrailerBytes) {
    return Status::make(ErrorCode::ProtocolViolation, "frame length is smaller than the header");
  }
  if (frame_length > limits.max_payload_bytes + 12 + kFrameTrailerBytes) {
    // Validated before allocating anything.
    return Status::make(ErrorCode::BoundsExceeded, "frame length exceeds the configured bound");
  }
  std::vector<std::byte> frame(frame_length);
  status = socket.recv_exact(std::span<std::byte>(frame.data(), frame.size()));
  if (!status.ok()) {
    return status;
  }
  if (load_u32_le(frame.data()) != kFrameMagic) {
    return Status::make(ErrorCode::ProtocolViolation, "frame magic does not match");
  }
  std::uint16_t version = 0;
  std::memcpy(&version, frame.data() + 4, 2);
  if (version != kWireProtocolVersion) {
    return Status::make(ErrorCode::UnsupportedVersion,
                        "frame declares protocol version " + std::to_string(version));
  }
  std::uint16_t type_value = 0;
  std::memcpy(&type_value, frame.data() + 6, 2);
  const std::uint32_t payload_length = load_u32_le(frame.data() + 8);
  if (static_cast<std::size_t>(payload_length) + 12 + kFrameTrailerBytes != frame_length) {
    return Status::make(ErrorCode::ProtocolViolation,
                        "declared payload length does not match the frame length");
  }
  const Digest stored = Digest::from_bytes(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(frame.data()) + 12 + payload_length, Digest::kSize));
  const Digest computed =
      Sha256::hash(std::span<const std::byte>(frame.data(), 12 + payload_length));
  if (stored != computed) {
    return Status::make(ErrorCode::ChecksumMismatch, "frame digest does not match its content");
  }
  if (type_value < static_cast<std::uint16_t>(MessageType::Hello) || type_value > kMaxMessageType) {
    return Status::make(ErrorCode::ProtocolViolation,
                        "frame declares message type " + std::to_string(type_value) +
                            " which this build does not implement");
  }
  Message message;
  message.type = static_cast<MessageType>(type_value);
  message.payload.assign(frame.begin() + 12, frame.begin() + 12 + payload_length);
  return message;
}

// ---------------------------------------------------------------------------
// Payload codecs
// ---------------------------------------------------------------------------

Status HelloRequest::encode(Writer& writer) const {
  Status status = writer.id16(federation.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(node.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(incarnation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u16(protocol_version);
  if (!status.ok()) {
    return status;
  }
  return writer.text(product, kMaxShortTextLength);
}

Result<HelloRequest> HelloRequest::decode(Reader& reader) {
  HelloRequest request;
  auto federation = reader.id16();
  if (!federation.has_value()) {
    return federation.status();
  }
  request.federation = FederationId::from_bytes(federation.value());
  auto node = reader.id16();
  if (!node.has_value()) {
    return node.status();
  }
  request.node = NodeId::from_bytes(node.value());
  auto incarnation = reader.u64();
  if (!incarnation.has_value()) {
    return incarnation.status();
  }
  request.incarnation = Incarnation(incarnation.value());
  auto version = reader.u16();
  if (!version.has_value()) {
    return version.status();
  }
  request.protocol_version = version.value();
  auto product = reader.text(kMaxShortTextLength);
  if (!product.has_value()) {
    return product.status();
  }
  request.product = std::move(product.value());
  return request;
}

Status WelcomeResponse::encode(Writer& writer) const {
  Status status = writer.id16(federation.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(coordinator.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(coordinator_incarnation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(logical_time.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.digest(state_digest);
  if (!status.ok()) {
    return status;
  }
  status = writer.identifier(policy_id.str());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(policy_generation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u16(protocol_version);
  if (!status.ok()) {
    return status;
  }
  return writer.text(detail, kMaxTextLength);
}

Result<WelcomeResponse> WelcomeResponse::decode(Reader& reader) {
  WelcomeResponse response;
  auto federation = reader.id16();
  if (!federation.has_value()) {
    return federation.status();
  }
  response.federation = FederationId::from_bytes(federation.value());
  auto coordinator = reader.id16();
  if (!coordinator.has_value()) {
    return coordinator.status();
  }
  response.coordinator = NodeId::from_bytes(coordinator.value());
  auto incarnation = reader.u64();
  if (!incarnation.has_value()) {
    return incarnation.status();
  }
  response.coordinator_incarnation = Incarnation(incarnation.value());
  auto epoch = reader.u64();
  if (!epoch.has_value()) {
    return epoch.status();
  }
  response.epoch = Epoch(epoch.value());
  auto logical_time = reader.u64();
  if (!logical_time.has_value()) {
    return logical_time.status();
  }
  response.logical_time = Tick(logical_time.value());
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.status();
  }
  response.state_digest = digest.value();
  auto policy_id = reader.identifier();
  if (!policy_id.has_value()) {
    return policy_id.status();
  }
  auto parsed_policy = PolicyId::parse(policy_id.value());
  if (parsed_policy.has_value()) {
    response.policy_id = std::move(parsed_policy.value());
  }
  auto policy_generation = reader.u64();
  if (!policy_generation.has_value()) {
    return policy_generation.status();
  }
  response.policy_generation = Generation(policy_generation.value());
  auto version = reader.u16();
  if (!version.has_value()) {
    return version.status();
  }
  response.protocol_version = version.value();
  auto detail = reader.text(kMaxTextLength);
  if (!detail.has_value()) {
    return detail.status();
  }
  response.detail = std::move(detail.value());
  return response;
}

Status ErrorResponse::encode(Writer& writer) const {
  Status status = writer.u16(static_cast<std::uint16_t>(code));
  if (!status.ok()) {
    return status;
  }
  return writer.text(message, kMaxTextLength);
}

Result<ErrorResponse> ErrorResponse::decode(Reader& reader) {
  ErrorResponse response;
  auto code = reader.u16();
  if (!code.has_value()) {
    return code.status();
  }
  if (code.value() > static_cast<std::uint16_t>(ErrorCode::Internal)) {
    return Status::make(ErrorCode::ProtocolViolation, "error code is out of range");
  }
  response.code = static_cast<ErrorCode>(code.value());
  auto message = reader.text(kMaxTextLength);
  if (!message.has_value()) {
    return message.status();
  }
  response.message = std::move(message.value());
  return response;
}

Status DigestResponse::encode(Writer& writer) const {
  Status status = writer.digest(state_digest);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(logical_time.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(artifact_count);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(member_count);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(active_member_count);
  if (!status.ok()) {
    return status;
  }
  return writer.boolean(reconciling);
}

Result<DigestResponse> DigestResponse::decode(Reader& reader) {
  DigestResponse response;
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.status();
  }
  response.state_digest = digest.value();
  auto epoch = reader.u64();
  if (!epoch.has_value()) {
    return epoch.status();
  }
  response.epoch = Epoch(epoch.value());
  auto logical_time = reader.u64();
  if (!logical_time.has_value()) {
    return logical_time.status();
  }
  response.logical_time = Tick(logical_time.value());
  auto artifacts = reader.u64();
  if (!artifacts.has_value()) {
    return artifacts.status();
  }
  response.artifact_count = artifacts.value();
  auto members = reader.u64();
  if (!members.has_value()) {
    return members.status();
  }
  response.member_count = members.value();
  auto active = reader.u64();
  if (!active.has_value()) {
    return active.status();
  }
  response.active_member_count = active.value();
  auto reconciling = reader.boolean();
  if (!reconciling.has_value()) {
    return reconciling.status();
  }
  response.reconciling = reconciling.value();
  return response;
}

Status StateResponse::encode(Writer& writer) const {
  Status status = writer.digest(state_digest);
  if (!status.ok()) {
    return status;
  }
  return writer.text(json, kMaxSnapshotChunkBytes);
}

Result<StateResponse> StateResponse::decode(Reader& reader) {
  StateResponse response;
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.status();
  }
  response.state_digest = digest.value();
  auto json = reader.text(kMaxSnapshotChunkBytes);
  if (!json.has_value()) {
    return json.status();
  }
  response.json = std::move(json.value());
  return response;
}

Status AuthorityResponse::encode(Writer& writer) const { return decision.encode(writer); }

Result<AuthorityResponse> AuthorityResponse::decode(Reader& reader) {
  AuthorityResponse response;
  auto decision = AuthorityDecision::decode(reader);
  if (!decision.has_value()) {
    return decision.status();
  }
  response.decision = std::move(decision.value());
  return response;
}

Status ArtifactResponse::encode(Writer& writer) const {
  Status status = writer.u16(static_cast<std::uint16_t>(code));
  if (!status.ok()) {
    return status;
  }
  status = writer.text(detail, kMaxTextLength);
  if (!status.ok()) {
    return status;
  }
  status = writer.digest(artifact_digest);
  if (!status.ok()) {
    return status;
  }
  status = writer.digest(state_digest);
  if (!status.ok()) {
    return status;
  }
  status = writer.u8(static_cast<std::uint8_t>(outcome));
  if (!status.ok()) {
    return status;
  }
  status = writer.boolean(already_present);
  if (!status.ok()) {
    return status;
  }
  status = writer.boolean(rejected);
  if (!status.ok()) {
    return status;
  }
  return writer.u64(artifact_count);
}

Result<ArtifactResponse> ArtifactResponse::decode(Reader& reader) {
  ArtifactResponse response;
  auto code = reader.u16();
  if (!code.has_value()) {
    return code.status();
  }
  if (code.value() > static_cast<std::uint16_t>(ErrorCode::Internal)) {
    return Status::make(ErrorCode::ProtocolViolation, "error code is out of range");
  }
  response.code = static_cast<ErrorCode>(code.value());
  auto detail = reader.text(kMaxTextLength);
  if (!detail.has_value()) {
    return detail.status();
  }
  response.detail = std::move(detail.value());
  auto artifact_digest = reader.digest();
  if (!artifact_digest.has_value()) {
    return artifact_digest.status();
  }
  response.artifact_digest = artifact_digest.value();
  auto state_digest = reader.digest();
  if (!state_digest.has_value()) {
    return state_digest.status();
  }
  response.state_digest = state_digest.value();
  auto outcome = reader.u8();
  if (!outcome.has_value()) {
    return outcome.status();
  }
  if (outcome.value() > static_cast<std::uint8_t>(Outcome::Unknown)) {
    return Status::make(ErrorCode::ProtocolViolation, "outcome is out of range");
  }
  response.outcome = static_cast<Outcome>(outcome.value());
  auto already = reader.boolean();
  if (!already.has_value()) {
    return already.status();
  }
  response.already_present = already.value();
  auto rejected = reader.boolean();
  if (!rejected.has_value()) {
    return rejected.status();
  }
  response.rejected = rejected.value();
  auto count = reader.u64();
  if (!count.has_value()) {
    return count.status();
  }
  response.artifact_count = count.value();
  return response;
}

Status LeaseIssueRequest::encode(Writer& writer) const {
  Status status = writer.id16(holder.bytes());
  if (!status.ok()) {
    return status;
  }
  status = encode_grants(writer, scopes, kMaxScopesPerLease);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(not_after_epoch.value());
  if (!status.ok()) {
    return status;
  }
  return writer.u64(lifetime_ticks.value());
}

Result<LeaseIssueRequest> LeaseIssueRequest::decode(Reader& reader) {
  LeaseIssueRequest request;
  auto holder = reader.id16();
  if (!holder.has_value()) {
    return holder.status();
  }
  request.holder = MemberId::from_bytes(holder.value());
  auto scopes = decode_grants(reader, kMaxScopesPerLease);
  if (!scopes.has_value()) {
    return scopes.status();
  }
  request.scopes = std::move(scopes.value());
  auto not_after_epoch = reader.u64();
  if (!not_after_epoch.has_value()) {
    return not_after_epoch.status();
  }
  request.not_after_epoch = Epoch(not_after_epoch.value());
  auto lifetime = reader.u64();
  if (!lifetime.has_value()) {
    return lifetime.status();
  }
  request.lifetime_ticks = Tick(lifetime.value());
  return request;
}

Status LeaseResponse::encode(Writer& writer) const {
  Status status = writer.u16(static_cast<std::uint16_t>(code));
  if (!status.ok()) {
    return status;
  }
  status = writer.text(detail, kMaxTextLength);
  if (!status.ok()) {
    return status;
  }
  return lease.encode(writer);
}

Result<LeaseResponse> LeaseResponse::decode(Reader& reader) {
  LeaseResponse response;
  auto code = reader.u16();
  if (!code.has_value()) {
    return code.status();
  }
  response.code = static_cast<ErrorCode>(code.value());
  auto detail = reader.text(kMaxTextLength);
  if (!detail.has_value()) {
    return detail.status();
  }
  response.detail = std::move(detail.value());
  auto lease = AuthorityLease::decode(reader);
  if (!lease.has_value()) {
    return lease.status();
  }
  response.lease = std::move(lease.value());
  return response;
}

Status LeaseRevokeRequest::encode(Writer& writer) const {
  Status status = writer.id16(lease.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u16(static_cast<std::uint16_t>(reason));
  if (!status.ok()) {
    return status;
  }
  return writer.text(detail, kMaxTextLength);
}

Result<LeaseRevokeRequest> LeaseRevokeRequest::decode(Reader& reader) {
  LeaseRevokeRequest request;
  auto lease = reader.id16();
  if (!lease.has_value()) {
    return lease.status();
  }
  request.lease = LeaseId::from_bytes(lease.value());
  auto reason = reader.u16();
  if (!reason.has_value()) {
    return reason.status();
  }
  request.reason = static_cast<ReasonCode>(reason.value());
  auto detail = reader.text(kMaxTextLength);
  if (!detail.has_value()) {
    return detail.status();
  }
  request.detail = std::move(detail.value());
  return request;
}

Status ObservationRequest::encode(Writer& writer) const { return observation.encode(writer); }

Result<ObservationRequest> ObservationRequest::decode(Reader& reader) {
  ObservationRequest request;
  auto observation = MemberObservation::decode(reader);
  if (!observation.has_value()) {
    return observation.status();
  }
  request.observation = std::move(observation.value());
  return request;
}

Status TimeAdvanceRequest::encode(Writer& writer) const { return writer.u64(to.value()); }

Result<TimeAdvanceRequest> TimeAdvanceRequest::decode(Reader& reader) {
  TimeAdvanceRequest request;
  auto to = reader.u64();
  if (!to.has_value()) {
    return to.status();
  }
  request.to = Tick(to.value());
  return request;
}

Status MemberActionRequest::encode(Writer& writer) const {
  Status status = writer.id16(subject.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(lineage.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u16(static_cast<std::uint16_t>(reason));
  if (!status.ok()) {
    return status;
  }
  return writer.text(detail, kMaxTextLength);
}

Result<MemberActionRequest> MemberActionRequest::decode(Reader& reader) {
  MemberActionRequest request;
  auto subject = reader.id16();
  if (!subject.has_value()) {
    return subject.status();
  }
  request.subject = MemberId::from_bytes(subject.value());
  auto lineage = reader.u64();
  if (!lineage.has_value()) {
    return lineage.status();
  }
  request.lineage = Lineage(lineage.value());
  auto epoch = reader.u64();
  if (!epoch.has_value()) {
    return epoch.status();
  }
  request.epoch = Epoch(epoch.value());
  auto reason = reader.u16();
  if (!reason.has_value()) {
    return reason.status();
  }
  request.reason = static_cast<ReasonCode>(reason.value());
  auto detail = reader.text(kMaxTextLength);
  if (!detail.has_value()) {
    return detail.status();
  }
  request.detail = std::move(detail.value());
  return request;
}

Status SimpleResponse::encode(Writer& writer) const {
  Status status = writer.u16(static_cast<std::uint16_t>(code));
  if (!status.ok()) {
    return status;
  }
  status = writer.text(detail, kMaxTextLength);
  if (!status.ok()) {
    return status;
  }
  return writer.digest(state_digest);
}

Result<SimpleResponse> SimpleResponse::decode(Reader& reader) {
  SimpleResponse response;
  auto code = reader.u16();
  if (!code.has_value()) {
    return code.status();
  }
  response.code = static_cast<ErrorCode>(code.value());
  auto detail = reader.text(kMaxTextLength);
  if (!detail.has_value()) {
    return detail.status();
  }
  response.detail = std::move(detail.value());
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.status();
  }
  response.state_digest = digest.value();
  return response;
}

Status ArtifactListResponse::encode(Writer& writer) const {
  Status status = writer.count(artifacts.size(), kMaxArtifacts);
  if (!status.ok()) {
    return status;
  }
  for (const Artifact& artifact : artifacts) {
    status = artifact.encode(writer);
    if (!status.ok()) {
      return status;
    }
  }
  return writer.digest(state_digest);
}

Result<ArtifactListResponse> ArtifactListResponse::decode(Reader& reader) {
  ArtifactListResponse response;
  auto count = reader.count(kMaxArtifacts);
  if (!count.has_value()) {
    return count.status();
  }
  response.artifacts.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto artifact = Artifact::decode(reader);
    if (!artifact.has_value()) {
      return artifact.status();
    }
    response.artifacts.push_back(std::move(artifact.value()));
  }
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.status();
  }
  response.state_digest = digest.value();
  return response;
}

Status LeaseListResponse::encode(Writer& writer) const {
  Status status = writer.count(leases.size(), kMaxLeases);
  if (!status.ok()) {
    return status;
  }
  for (const AuthorityLease& lease : leases) {
    status = lease.encode(writer);
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

Result<LeaseListResponse> LeaseListResponse::decode(Reader& reader) {
  LeaseListResponse response;
  auto count = reader.count(kMaxLeases);
  if (!count.has_value()) {
    return count.status();
  }
  response.leases.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto lease = AuthorityLease::decode(reader);
    if (!lease.has_value()) {
      return lease.status();
    }
    response.leases.push_back(std::move(lease.value()));
  }
  return response;
}

Status ProbeResponse::encode(Writer& writer) const {
  Status status = writer.id16(federation.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.id16(member.bytes());
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
  status = writer.u64(epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(logical_time.value());
  if (!status.ok()) {
    return status;
  }
  return writer.digest(constitution);
}

Result<ProbeResponse> ProbeResponse::decode(Reader& reader) {
  ProbeResponse response;
  auto federation = reader.id16();
  if (!federation.has_value()) {
    return federation.status();
  }
  response.federation = FederationId::from_bytes(federation.value());
  auto member = reader.id16();
  if (!member.has_value()) {
    return member.status();
  }
  response.member = MemberId::from_bytes(member.value());
  auto incarnation = reader.u64();
  if (!incarnation.has_value()) {
    return incarnation.status();
  }
  response.incarnation = Incarnation(incarnation.value());
  auto node = reader.id16();
  if (!node.has_value()) {
    return node.status();
  }
  response.node = NodeId::from_bytes(node.value());
  auto epoch = reader.u64();
  if (!epoch.has_value()) {
    return epoch.status();
  }
  response.epoch = Epoch(epoch.value());
  auto logical_time = reader.u64();
  if (!logical_time.has_value()) {
    return logical_time.status();
  }
  response.logical_time = Tick(logical_time.value());
  auto constitution = reader.digest();
  if (!constitution.has_value()) {
    return constitution.status();
  }
  response.constitution = constitution.value();
  return response;
}

Status StatsResponse::encode(Writer& writer) const {
  Status status = writer.digest(state_digest);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(logical_time.value());
  if (!status.ok()) {
    return status;
  }
  for (const std::uint64_t value :
       {artifacts, rejected_artifacts, duplicate_artifacts, members, active_members, leases,
        replay_entries, connections_accepted, protocol_errors, journal_records, journal_bytes}) {
    status = writer.u64(value);
    if (!status.ok()) {
      return status;
    }
  }
  status = writer.boolean(reconciling);
  if (!status.ok()) {
    return status;
  }
  status = writer.text(partition_state, kMaxShortTextLength);
  if (!status.ok()) {
    return status;
  }
  return writer.text(transport, kMaxTextLength);
}

Result<StatsResponse> StatsResponse::decode(Reader& reader) {
  StatsResponse response;
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.status();
  }
  response.state_digest = digest.value();
  auto epoch = reader.u64();
  if (!epoch.has_value()) {
    return epoch.status();
  }
  response.epoch = Epoch(epoch.value());
  auto logical_time = reader.u64();
  if (!logical_time.has_value()) {
    return logical_time.status();
  }
  response.logical_time = Tick(logical_time.value());
  std::uint64_t* targets[] = {&response.artifacts,        &response.rejected_artifacts,
                              &response.duplicate_artifacts, &response.members,
                              &response.active_members,   &response.leases,
                              &response.replay_entries,   &response.connections_accepted,
                              &response.protocol_errors,  &response.journal_records,
                              &response.journal_bytes};
  for (std::uint64_t* target : targets) {
    auto value = reader.u64();
    if (!value.has_value()) {
      return value.status();
    }
    *target = value.value();
  }
  auto reconciling = reader.boolean();
  if (!reconciling.has_value()) {
    return reconciling.status();
  }
  response.reconciling = reconciling.value();
  auto partition = reader.text(kMaxShortTextLength);
  if (!partition.has_value()) {
    return partition.status();
  }
  response.partition_state = std::move(partition.value());
  auto transport = reader.text(kMaxTextLength);
  if (!transport.has_value()) {
    return transport.status();
  }
  response.transport = std::move(transport.value());
  return response;
}

}  // namespace fabric_federation
