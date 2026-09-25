// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Wire protocol.
//
// Framing
//   u32 frame_length   (bytes that follow this field)
//   u32 magic          ('FDEF')
//   u16 protocol_version
//   u16 message_type
//   u32 payload_length
//   payload bytes
//   32-byte sha256 over magic..payload
//
// frame_length must equal 44 + payload_length exactly. The payload length is
// validated against a bound before anything is allocated, so a hostile frame
// cannot make the receiver allocate an arbitrary amount of memory.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/authority.hpp"
#include "fabric_federation/version.hpp"
#include "fabric_federation/codec.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/evidence.hpp"
#include "fabric_federation/export.hpp"
#include "fabric_federation/ids.hpp"
#include "fabric_federation/lease.hpp"
#include "fabric_federation/net.hpp"
#include "fabric_federation/partition.hpp"

namespace fabric_federation {

inline constexpr std::uint32_t kFrameMagic = 0x46454446u;  // 'FDEF'
inline constexpr std::size_t kFrameHeaderBytes = 16;
inline constexpr std::size_t kFrameTrailerBytes = Digest::kSize;
inline constexpr std::size_t kFrameOverheadBytes = kFrameHeaderBytes + kFrameTrailerBytes;

enum class MessageType : std::uint16_t {
  Hello = 1,
  Welcome = 2,
  ErrorMessage = 3,
  Ping = 4,
  Pong = 5,
  Goodbye = 6,

  SubmitArtifact = 10,
  SubmitArtifactResult = 11,
  QueryDigest = 12,
  DigestValue = 13,
  QueryState = 14,
  StateValue = 15,
  AuthorityQuery = 16,
  AuthorityResult = 17,
  IssueLease = 18,
  LeaseResult = 19,
  RevokeLease = 20,
  ReportObservation = 21,
  AdvanceTime = 22,
  FenceMember = 23,
  AdvanceEpoch = 24,
  CompleteReconciliation = 25,
  QueryArtifacts = 26,
  ArtifactListValue = 27,
  QueryLeases = 28,
  LeaseListValue = 29,
  StatsQuery = 30,
  StatsValue = 31,
  SimpleResult = 32,
  // Peer reachability probe. A member answers this on its own listener so that
  // other members can record real, mutually confirmed reachability evidence.
  ProbeRequest = 33,
  ProbeResult = 34,
};

// Highest message type this build implements. Frames above it are rejected.
inline constexpr std::uint16_t kMaxMessageType = static_cast<std::uint16_t>(MessageType::ProbeResult);

[[nodiscard]] FFED_API std::string_view to_string(MessageType type) noexcept;
[[nodiscard]] FFED_API bool parse_message_type(std::string_view text, MessageType& out) noexcept;

struct FrameLimits {
  std::uint32_t max_payload_bytes = kMaxFramePayloadBytes;
};

struct Message {
  MessageType type = MessageType::ErrorMessage;
  std::vector<std::byte> payload;

  [[nodiscard]] std::span<const std::byte> span() const {
    return std::span<const std::byte>(payload.data(), payload.size());
  }
};

FFED_API Status write_message(Socket& socket, MessageType type,
                              std::span<const std::byte> payload);
[[nodiscard]] FFED_API Result<Message> read_message(Socket& socket,
                                                    const FrameLimits& limits = FrameLimits{});

// ---- payloads -------------------------------------------------------------

struct HelloRequest {
  FederationId federation;
  NodeId node;
  Incarnation incarnation;
  std::uint16_t protocol_version = kWireProtocolVersion;
  std::string product;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<HelloRequest> decode(Reader& reader);
};

struct WelcomeResponse {
  FederationId federation;
  NodeId coordinator;
  Incarnation coordinator_incarnation;
  Epoch epoch;
  Tick logical_time;
  Digest state_digest;
  PolicyId policy_id;
  Generation policy_generation;
  std::uint16_t protocol_version = kWireProtocolVersion;
  std::string detail;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<WelcomeResponse> decode(Reader& reader);
};

struct ErrorResponse {
  ErrorCode code = ErrorCode::Internal;
  std::string message;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<ErrorResponse> decode(Reader& reader);
};

struct DigestResponse {
  Digest state_digest;
  Epoch epoch;
  Tick logical_time;
  std::uint64_t artifact_count = 0;
  std::uint64_t member_count = 0;
  std::uint64_t active_member_count = 0;
  bool reconciling = false;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<DigestResponse> decode(Reader& reader);
};

struct StateResponse {
  Digest state_digest;
  std::string json;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<StateResponse> decode(Reader& reader);
};

struct AuthorityResponse {
  AuthorityDecision decision;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<AuthorityResponse> decode(Reader& reader);
};

struct ArtifactResponse {
  ErrorCode code = ErrorCode::Ok;
  std::string detail;
  Digest artifact_digest;
  Digest state_digest;
  Outcome outcome = Outcome::Unknown;
  bool already_present = false;
  bool rejected = false;
  std::uint64_t artifact_count = 0;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<ArtifactResponse> decode(Reader& reader);
};

struct LeaseIssueRequest {
  MemberId holder;
  std::vector<ScopeGrant> scopes;
  Epoch not_after_epoch;
  Tick lifetime_ticks;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<LeaseIssueRequest> decode(Reader& reader);
};

struct LeaseResponse {
  ErrorCode code = ErrorCode::Ok;
  std::string detail;
  AuthorityLease lease;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<LeaseResponse> decode(Reader& reader);
};

struct LeaseRevokeRequest {
  LeaseId lease;
  ReasonCode reason = ReasonCode::LeaseRevoked;
  std::string detail;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<LeaseRevokeRequest> decode(Reader& reader);
};

struct ObservationRequest {
  MemberObservation observation;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<ObservationRequest> decode(Reader& reader);
};

struct TimeAdvanceRequest {
  Tick to;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<TimeAdvanceRequest> decode(Reader& reader);
};

struct MemberActionRequest {
  MemberId subject;
  Lineage lineage;
  Epoch epoch;
  ReasonCode reason = ReasonCode::EvidenceUnknown;
  std::string detail;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<MemberActionRequest> decode(Reader& reader);
};

struct SimpleResponse {
  ErrorCode code = ErrorCode::Ok;
  std::string detail;
  Digest state_digest;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<SimpleResponse> decode(Reader& reader);
};

struct ArtifactListResponse {
  std::vector<Artifact> artifacts;
  Digest state_digest;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<ArtifactListResponse> decode(Reader& reader);
};

struct LeaseListResponse {
  std::vector<AuthorityLease> leases;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<LeaseListResponse> decode(Reader& reader);
};

struct ProbeResponse {
  FederationId federation;
  MemberId member;
  Incarnation incarnation;
  NodeId node;
  Epoch epoch;
  Tick logical_time;
  Digest constitution;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<ProbeResponse> decode(Reader& reader);
};

struct StatsResponse {
  Digest state_digest;
  Epoch epoch;
  Tick logical_time;
  std::uint64_t artifacts = 0;
  std::uint64_t rejected_artifacts = 0;
  std::uint64_t duplicate_artifacts = 0;
  std::uint64_t members = 0;
  std::uint64_t active_members = 0;
  std::uint64_t leases = 0;
  std::uint64_t replay_entries = 0;
  std::uint64_t connections_accepted = 0;
  std::uint64_t protocol_errors = 0;
  std::uint64_t journal_records = 0;
  std::uint64_t journal_bytes = 0;
  bool reconciling = false;
  std::string partition_state;
  std::string transport;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<StatsResponse> decode(Reader& reader);
};

// Serialises a payload struct into a writer. Every payload type implements
// encode(); this helper keeps the call sites uniform.
template <class T>
[[nodiscard]] Status encode_payload(const T& payload, Writer& writer) {
  return payload.encode(writer);
}

template <class T>
[[nodiscard]] Result<T> decode_payload(std::span<const std::byte> bytes) {
  Reader reader(bytes);
  auto value = T::decode(reader);
  if (!value.has_value()) {
    return value.status();
  }
  const Status end = reader.expect_end();
  if (!end.ok()) {
    return end;
  }
  return value;
}

}  // namespace fabric_federation
