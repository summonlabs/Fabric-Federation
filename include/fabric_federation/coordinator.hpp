// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// The federation coordinator.
//
// The coordinator is the single logical authority that holds the accepted
// evidence set, derives federation state from it, issues the decision records
// that follow from policy, and answers authority questions. It is NOT a
// consensus implementation: it does not run a agreement protocol, it does not
// have quorum, and it makes no Byzantine-fault claim. Its job is to be the one
// place where the rules in docs/authority-model.md are applied, so that the
// answer is reproducible and explainable.
//
// Ownership and locking
//   * one state mutex guards the evidence set, the derived inputs and the
//     journal. No callback, no socket write and no thread join ever happens
//     while it is held,
//   * the connection registry has its own mutex. It is never taken while the
//     state mutex is held, and the state mutex is never taken while the
//     connection registry mutex is held,
//   * shutdown closes the listener, shuts down the sockets owned by worker
//     threads, then joins them; it never joins a thread while holding either
//     lock. See docs/concurrency.md for the full audit.
#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "fabric_federation/authority.hpp"
#include "fabric_federation/evidence.hpp"
#include "fabric_federation/ids.hpp"
#include "fabric_federation/journal.hpp"
#include "fabric_federation/lease.hpp"
#include "fabric_federation/policy.hpp"
#include "fabric_federation/scope.hpp"
#include "fabric_federation/state.hpp"

namespace fabric_federation {

class Socket;
struct Message;

struct CoordinatorConfig {
  FederationId federation;
  NodeId node;
  std::string description;
  FederationPolicy policy;
  // Empty means the coordinator keeps no durable state. Every claim about
  // restart behaviour in the documentation refers to a configuration with a
  // journal path.
  std::filesystem::path journal_path;
  std::uint16_t listen_port = 0;
  bool listen = false;
  std::size_t max_connections = 64;
  std::size_t worker_threads = 4;
  std::size_t max_pending_connections = 128;
  Tick initial_tick = Tick(1);
  // Bootstrap: when true, a genesis record is created on first start. It
  // establishes a single founder and is explicitly single-party.
  bool bootstrap = false;
  MemberDeclaration founder;
  std::vector<ScopeGrant> founder_grants;
};

enum class SubmissionDisposition : std::uint8_t {
  Applied = 0,
  // The identical artefact was already present. Applying it again changes
  // nothing; it is not an error and it is not counted twice.
  Duplicate,
  // The artefact was recorded but refused: it is malformed, it belongs to
  // another federation, or its content conflicts with evidence already held.
  Rejected,
  Invalid,
};

[[nodiscard]] FFED_API std::string_view to_string(SubmissionDisposition disposition) noexcept;

struct SubmissionOutcome {
  SubmissionDisposition disposition = SubmissionDisposition::Invalid;
  ReasonCode reason = ReasonCode::EvidenceUnknown;
  std::string detail;
  Digest artifact_digest;
  Digest state_digest;
  std::uint64_t artifact_count = 0;
  // Decision records the coordinator issued as a consequence of this
  // submission (admission, activation).
  std::vector<Artifact> issued;
};

struct LeaseRequest {
  MemberId holder;
  std::vector<ScopeGrant> scopes;
  Epoch not_after_epoch;
  Tick lifetime_ticks;
};

struct CoordinatorStats {
  Digest state_digest;
  Epoch epoch;
  Tick logical_time;
  Incarnation coordinator_incarnation;
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
  bool durable = false;
  bool reconciling = false;
  std::string partition_state;
  std::string transport;
  std::string recovery;
};

class FFED_API FederationCoordinator {
 public:
  ~FederationCoordinator();
  FederationCoordinator(const FederationCoordinator&) = delete;
  FederationCoordinator& operator=(const FederationCoordinator&) = delete;

  // Creates the coordinator and recovers any durable state. This does not open
  // a listening socket; call start() for that.
  [[nodiscard]] static Result<std::unique_ptr<FederationCoordinator>> create(
      const CoordinatorConfig& config);

  // Opens the listener (when configured) and starts the worker pool.
  [[nodiscard]] Status start();
  // Stops the listener, shuts down the connections owned by the workers, joins
  // every thread, then flushes and closes the journal.
  [[nodiscard]] Status stop();
  [[nodiscard]] bool running() const noexcept;

  // ---- evidence -----------------------------------------------------------
  [[nodiscard]] Result<SubmissionOutcome> submit_artifact(const Artifact& artifact);

  // ---- authority ----------------------------------------------------------
  [[nodiscard]] Result<AuthorityDecision> evaluate(const AuthorityRequest& request);

  // ---- leases -------------------------------------------------------------
  [[nodiscard]] Result<AuthorityLease> issue_lease(const LeaseRequest& request);
  [[nodiscard]] Status revoke_lease(const LeaseId& lease, ReasonCode reason,
                                    std::string_view detail);

  // ---- membership and partition lifecycle ---------------------------------
  [[nodiscard]] Status report_observation(const MemberObservation& observation);
  [[nodiscard]] Status advance_time(Tick to);
  // Fencing always succeeds: it only ever removes authority.
  [[nodiscard]] Status fence_member(const MemberId& member, Lineage lineage, ReasonCode reason,
                                    std::string_view detail);
  [[nodiscard]] Status retire_member(const MemberId& member, Lineage lineage, ReasonCode reason,
                                     std::string_view detail);
  [[nodiscard]] Status advance_epoch(Epoch epoch, ReasonCode reason, std::string_view detail);
  [[nodiscard]] Status complete_reconciliation(Epoch epoch);

  // ---- inspection ---------------------------------------------------------
  [[nodiscard]] Result<FederationState> state() const;
  [[nodiscard]] Result<std::vector<Artifact>> artifacts() const;
  [[nodiscard]] Result<std::vector<AuthorityLease>> leases() const;
  [[nodiscard]] Result<std::vector<MemberObservation>> observations() const;
  [[nodiscard]] Digest state_digest() const;
  [[nodiscard]] CoordinatorStats stats() const;
  [[nodiscard]] const FederationPolicy& policy() const;
  [[nodiscard]] const ScopeCatalog& catalog() const;
  [[nodiscard]] Epoch epoch() const;
  [[nodiscard]] Tick logical_time() const;
  [[nodiscard]] Incarnation incarnation() const;
  [[nodiscard]] std::uint16_t listen_port() const;
  [[nodiscard]] std::string describe() const;

 private:
  FederationCoordinator();

  // Connection handling. Declared here so the worker threads can reach the
  // public operations without a second copy of the locking rules.
  void serve(const std::shared_ptr<Socket>& socket);
  [[nodiscard]] Status handle_message(const Message& message, Socket& socket);
  void shutdown_connections();
  void accept_loop();
  void worker_loop();

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace fabric_federation
