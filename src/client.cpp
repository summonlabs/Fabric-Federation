// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/client.hpp"

namespace fabric_federation {
namespace {

template <class T>
Result<T> decode_expected(const Message& message, MessageType expected) {
  if (message.type == MessageType::ErrorMessage) {
    auto error = decode_payload<ErrorResponse>(message.span());
    if (error.has_value()) {
      return Status::make(error.value().code, error.value().message);
    }
    return Status::make(ErrorCode::ProtocolViolation, "the coordinator reported an error");
  }
  if (message.type != expected) {
    return Status::make(ErrorCode::ProtocolViolation,
                        "expected " + std::string(to_string(expected)) + ", received " +
                            std::string(to_string(message.type)));
  }
  return decode_payload<T>(message.span());
}

}  // namespace

CoordinatorClient::CoordinatorClient(CoordinatorClient&& other) noexcept
    : socket_(std::move(other.socket_)), welcome_(std::move(other.welcome_)) {}

CoordinatorClient& CoordinatorClient::operator=(CoordinatorClient&& other) noexcept {
  if (this != &other) {
    socket_ = std::move(other.socket_);
    welcome_ = std::move(other.welcome_);
  }
  return *this;
}

CoordinatorClient::~CoordinatorClient() {
  const Status status = close();
  (void)status;
}

Result<CoordinatorClient> CoordinatorClient::connect(const Endpoint& endpoint,
                                                     const FederationId& federation,
                                                     const NodeId& node,
                                                     Incarnation incarnation) {
  auto socket = Socket::connect(endpoint);
  if (!socket.has_value()) {
    return socket.status();
  }
  CoordinatorClient client;
  client.socket_ = std::move(socket.value());

  HelloRequest hello;
  hello.federation = federation;
  hello.node = node;
  hello.incarnation = incarnation;
  hello.protocol_version = kWireProtocolVersion;
  hello.product = std::string(kProductName) + " " + std::string(kVersionString);
  Writer writer;
  Status status = hello.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = write_message(client.socket_, MessageType::Hello, writer.span());
  if (!status.ok()) {
    return status;
  }
  auto response = read_message(client.socket_);
  if (!response.has_value()) {
    return response.status();
  }
  auto welcome = decode_expected<WelcomeResponse>(response.value(), MessageType::Welcome);
  if (!welcome.has_value()) {
    return welcome.status();
  }
  if (welcome.value().federation != federation) {
    return Status::make(ErrorCode::Refused,
                        "the coordinator serves a different federation: " +
                            welcome.value().federation.to_string());
  }
  client.welcome_ = std::move(welcome.value());
  return client;
}

Result<Message> CoordinatorClient::exchange(MessageType request_type, const Writer& payload) {
  std::lock_guard<std::mutex> lock(mutex_);
  const Status status = write_message(socket_, request_type, payload.span());
  if (!status.ok()) {
    return status;
  }
  return read_message(socket_);
}

Result<DigestResponse> CoordinatorClient::query_digest() {
  Writer writer;
  auto response = exchange(MessageType::QueryDigest, writer);
  if (!response.has_value()) {
    return response.status();
  }
  auto decoded = decode_expected<DigestResponse>(response.value(), MessageType::DigestValue);
  if (decoded.has_value()) {
    std::lock_guard<std::mutex> lock(mutex_);
    welcome_.logical_time = decoded.value().logical_time;
    welcome_.epoch = decoded.value().epoch;
    welcome_.state_digest = decoded.value().state_digest;
  }
  return decoded;
}

Result<StateResponse> CoordinatorClient::query_state() {
  Writer writer;
  auto response = exchange(MessageType::QueryState, writer);
  if (!response.has_value()) {
    return response.status();
  }
  return decode_expected<StateResponse>(response.value(), MessageType::StateValue);
}

Result<StatsResponse> CoordinatorClient::query_stats() {
  Writer writer;
  auto response = exchange(MessageType::StatsQuery, writer);
  if (!response.has_value()) {
    return response.status();
  }
  return decode_expected<StatsResponse>(response.value(), MessageType::StatsValue);
}

Result<AuthorityDecision> CoordinatorClient::query_authority(const AuthorityRequest& request) {
  Writer writer;
  Status status = request.encode(writer);
  if (!status.ok()) {
    return status;
  }
  auto response = exchange(MessageType::AuthorityQuery, writer);
  if (!response.has_value()) {
    return response.status();
  }
  auto decoded = decode_expected<AuthorityResponse>(response.value(), MessageType::AuthorityResult);
  if (!decoded.has_value()) {
    return decoded.status();
  }
  return decoded.value().decision;
}

Result<ArtifactResponse> CoordinatorClient::submit(const Artifact& artifact) {
  Writer writer;
  Status status = artifact.encode(writer);
  if (!status.ok()) {
    return status;
  }
  auto response = exchange(MessageType::SubmitArtifact, writer);
  if (!response.has_value()) {
    return response.status();
  }
  return decode_expected<ArtifactResponse>(response.value(), MessageType::SubmitArtifactResult);
}

Result<AuthorityLease> CoordinatorClient::issue_lease(const LeaseIssueRequest& request) {
  Writer writer;
  Status status = request.encode(writer);
  if (!status.ok()) {
    return status;
  }
  auto response = exchange(MessageType::IssueLease, writer);
  if (!response.has_value()) {
    return response.status();
  }
  auto decoded = decode_expected<LeaseResponse>(response.value(), MessageType::LeaseResult);
  if (!decoded.has_value()) {
    return decoded.status();
  }
  if (decoded.value().code != ErrorCode::Ok) {
    return Status::make(decoded.value().code, decoded.value().detail);
  }
  return decoded.value().lease;
}

Result<SimpleResponse> CoordinatorClient::revoke_lease(const LeaseId& lease, ReasonCode reason,
                                                       std::string_view detail) {
  LeaseRevokeRequest request;
  request.lease = lease;
  request.reason = reason;
  request.detail = std::string(detail);
  Writer writer;
  Status status = request.encode(writer);
  if (!status.ok()) {
    return status;
  }
  auto response = exchange(MessageType::RevokeLease, writer);
  if (!response.has_value()) {
    return response.status();
  }
  return decode_expected<SimpleResponse>(response.value(), MessageType::SimpleResult);
}

Result<SimpleResponse> CoordinatorClient::report_observation(
    const MemberObservation& observation) {
  ObservationRequest request;
  request.observation = observation;
  Writer writer;
  Status status = request.encode(writer);
  if (!status.ok()) {
    return status;
  }
  auto response = exchange(MessageType::ReportObservation, writer);
  if (!response.has_value()) {
    return response.status();
  }
  return decode_expected<SimpleResponse>(response.value(), MessageType::SimpleResult);
}

Result<SimpleResponse> CoordinatorClient::advance_time(Tick to) {
  TimeAdvanceRequest request;
  request.to = to;
  Writer writer;
  Status status = request.encode(writer);
  if (!status.ok()) {
    return status;
  }
  auto response = exchange(MessageType::AdvanceTime, writer);
  if (!response.has_value()) {
    return response.status();
  }
  return decode_expected<SimpleResponse>(response.value(), MessageType::SimpleResult);
}

Result<SimpleResponse> CoordinatorClient::fence_member(const MemberId& member, Lineage lineage,
                                                       ReasonCode reason,
                                                       std::string_view detail) {
  MemberActionRequest request;
  request.subject = member;
  request.lineage = lineage;
  request.reason = reason;
  request.detail = std::string(detail);
  Writer writer;
  Status status = request.encode(writer);
  if (!status.ok()) {
    return status;
  }
  auto response = exchange(MessageType::FenceMember, writer);
  if (!response.has_value()) {
    return response.status();
  }
  return decode_expected<SimpleResponse>(response.value(), MessageType::SimpleResult);
}

Result<SimpleResponse> CoordinatorClient::advance_epoch(Epoch epoch, ReasonCode reason,
                                                        std::string_view detail) {
  MemberActionRequest request;
  request.epoch = epoch;
  request.reason = reason;
  request.detail = std::string(detail);
  Writer writer;
  Status status = request.encode(writer);
  if (!status.ok()) {
    return status;
  }
  auto response = exchange(MessageType::AdvanceEpoch, writer);
  if (!response.has_value()) {
    return response.status();
  }
  return decode_expected<SimpleResponse>(response.value(), MessageType::SimpleResult);
}

Result<SimpleResponse> CoordinatorClient::complete_reconciliation(Epoch epoch) {
  MemberActionRequest request;
  request.epoch = epoch;
  request.reason = ReasonCode::PartitionReattestationComplete;
  Writer writer;
  Status status = request.encode(writer);
  if (!status.ok()) {
    return status;
  }
  auto response = exchange(MessageType::CompleteReconciliation, writer);
  if (!response.has_value()) {
    return response.status();
  }
  return decode_expected<SimpleResponse>(response.value(), MessageType::SimpleResult);
}

Result<ArtifactListResponse> CoordinatorClient::query_artifacts() {
  Writer writer;
  auto response = exchange(MessageType::QueryArtifacts, writer);
  if (!response.has_value()) {
    return response.status();
  }
  return decode_expected<ArtifactListResponse>(response.value(), MessageType::ArtifactListValue);
}

Result<LeaseListResponse> CoordinatorClient::query_leases() {
  Writer writer;
  auto response = exchange(MessageType::QueryLeases, writer);
  if (!response.has_value()) {
    return response.status();
  }
  return decode_expected<LeaseListResponse>(response.value(), MessageType::LeaseListValue);
}

Status CoordinatorClient::ping() {
  Writer writer;
  auto response = exchange(MessageType::Ping, writer);
  if (!response.has_value()) {
    return response.status();
  }
  if (response.value().type != MessageType::Pong) {
    return Status::make(ErrorCode::ProtocolViolation, "the coordinator did not answer a ping");
  }
  return Status::success();
}

Status CoordinatorClient::close() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!socket_.valid()) {
    return Status::success();
  }
  Writer writer;
  const Status status = write_message(socket_, MessageType::Goodbye, writer.span());
  (void)status;
  return socket_.close();
}

}  // namespace fabric_federation
