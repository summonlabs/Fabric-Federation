// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Client for the federation coordinator. One connection, one request at a
// time, guarded by a mutex so a caller may share it between threads.
#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "fabric_federation/evidence.hpp"
#include "fabric_federation/net.hpp"
#include "fabric_federation/protocol.hpp"

namespace fabric_federation {

class FFED_API CoordinatorClient {
 public:
  CoordinatorClient() = default;
  CoordinatorClient(CoordinatorClient&& other) noexcept;
  CoordinatorClient& operator=(CoordinatorClient&& other) noexcept;
  CoordinatorClient(const CoordinatorClient&) = delete;
  CoordinatorClient& operator=(const CoordinatorClient&) = delete;
  ~CoordinatorClient();

  // Connects and performs the hello handshake. The federation identity is
  // checked by the coordinator; a client that names the wrong federation is
  // refused.
  [[nodiscard]] static Result<CoordinatorClient> connect(const Endpoint& endpoint,
                                                         const FederationId& federation,
                                                         const NodeId& node,
                                                         Incarnation incarnation);

  [[nodiscard]] const WelcomeResponse& welcome() const noexcept { return welcome_; }
  [[nodiscard]] bool connected() const noexcept { return socket_.valid(); }

  [[nodiscard]] Result<DigestResponse> query_digest();
  [[nodiscard]] Result<StateResponse> query_state();
  [[nodiscard]] Result<StatsResponse> query_stats();
  [[nodiscard]] Result<AuthorityDecision> query_authority(const AuthorityRequest& request);
  [[nodiscard]] Result<ArtifactResponse> submit(const Artifact& artifact);
  [[nodiscard]] Result<AuthorityLease> issue_lease(const LeaseIssueRequest& request);
  [[nodiscard]] Result<SimpleResponse> revoke_lease(const LeaseId& lease, ReasonCode reason,
                                                    std::string_view detail);
  [[nodiscard]] Result<SimpleResponse> report_observation(const MemberObservation& observation);
  [[nodiscard]] Result<SimpleResponse> advance_time(Tick to);
  [[nodiscard]] Result<SimpleResponse> fence_member(const MemberId& member, Lineage lineage,
                                                    ReasonCode reason, std::string_view detail);
  [[nodiscard]] Result<SimpleResponse> advance_epoch(Epoch epoch, ReasonCode reason,
                                                     std::string_view detail);
  [[nodiscard]] Result<SimpleResponse> complete_reconciliation(Epoch epoch);
  [[nodiscard]] Result<ArtifactListResponse> query_artifacts();
  [[nodiscard]] Result<LeaseListResponse> query_leases();
  [[nodiscard]] Status ping();
  [[nodiscard]] Status close();

 private:
  [[nodiscard]] Result<Message> exchange(MessageType request_type, const Writer& payload);

  Socket socket_;
  WelcomeResponse welcome_;
  std::mutex mutex_;
};

}  // namespace fabric_federation
