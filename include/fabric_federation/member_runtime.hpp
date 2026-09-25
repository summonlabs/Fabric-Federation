// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Member fabric runtime.
//
// One instance represents one independently governed fabric domain in a
// federation. It owns its own identity, generation, incarnation, declared
// capabilities, retained local authority and the exact set of grants it offers
// to the federation. It builds the artefacts it is entitled to issue, submits
// them, and answers authority questions about its own local authority without
// consulting the federation at all.
#pragma once

#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "fabric_federation/client.hpp"
#include "fabric_federation/evidence.hpp"
#include "fabric_federation/net.hpp"

namespace fabric_federation {

struct MemberConfig {
  FederationId federation;
  MemberConstitution constitution;
  NodeId node;
  Incarnation incarnation;
  Endpoint coordinator;
  // When non-zero the member listens for peer reachability probes on this
  // loopback port. Port 0 selects an ephemeral port, which probe_port()
  // reports.
  std::uint16_t probe_port = 0;
  bool listen_for_probes = false;
  Tick initial_tick = Tick(1);
};

struct MemberStatus {
  MemberLifecycleState lifecycle = MemberLifecycleState::Absent;
  MemberIdentity identity;
  Epoch epoch;
  Tick logical_time;
  Digest federation_state_digest;
  std::vector<ScopeGrant> local_authority;
  std::vector<ScopeGrant> federation_authority;
  std::vector<ScopeGrant> withheld;
  std::size_t contributing_parties = 0;
};

class FFED_API MemberFabricRuntime {
 public:
  ~MemberFabricRuntime();
  MemberFabricRuntime(const MemberFabricRuntime&) = delete;
  MemberFabricRuntime& operator=(const MemberFabricRuntime&) = delete;

  [[nodiscard]] static Result<std::unique_ptr<MemberFabricRuntime>> create(
      const MemberConfig& config);

  // Connects to the coordinator and performs the hello handshake.
  [[nodiscard]] Status attach();
  [[nodiscard]] Status detach();
  [[nodiscard]] bool attached() const noexcept;
  [[nodiscard]] const MemberConstitution& constitution() const noexcept;
  [[nodiscard]] MemberIdentity identity() const;
  [[nodiscard]] const Endpoint& coordinator_endpoint() const noexcept;
  [[nodiscard]] std::uint16_t probe_port() const noexcept;
  [[nodiscard]] Incarnation incarnation() const noexcept;

  // ---- membership artefacts (issued by this member) -----------------------
  [[nodiscard]] Result<Artifact> build_proposal(const MemberDeclaration& candidate,
                                                Lineage lineage) const;
  [[nodiscard]] Result<Artifact> build_acceptance(Lineage lineage) const;
  [[nodiscard]] Result<Artifact> build_endorsement(const MemberDeclaration& candidate,
                                                   Lineage lineage) const;
  [[nodiscard]] Result<Artifact> build_reattestation() const;
  [[nodiscard]] Result<Artifact> build_delegation_declaration(
      const std::vector<DelegationTerms>& terms) const;
  [[nodiscard]] Result<Artifact> build_withdrawal(const std::vector<ScopeGrant>& grants,
                                                  Lineage lineage) const;
  [[nodiscard]] Result<Artifact> build_leave(Lineage lineage, ReasonCode reason,
                                             std::string_view detail) const;
  [[nodiscard]] Result<Artifact> build_self_fence(Lineage lineage, ReasonCode reason,
                                                  std::string_view detail) const;

  // Builds and submits in one step.
  [[nodiscard]] Result<ArtifactResponse> propose(const MemberDeclaration& candidate,
                                                 Lineage lineage);
  [[nodiscard]] Result<ArtifactResponse> accept(Lineage lineage);
  [[nodiscard]] Result<ArtifactResponse> endorse(const MemberDeclaration& candidate,
                                                 Lineage lineage);
  [[nodiscard]] Result<ArtifactResponse> reattest();
  [[nodiscard]] Result<ArtifactResponse> declare_delegation(
      const std::vector<DelegationTerms>& terms);
  [[nodiscard]] Result<ArtifactResponse> withdraw(const std::vector<ScopeGrant>& grants,
                                                  Lineage lineage);
  [[nodiscard]] Result<ArtifactResponse> leave(Lineage lineage);
  [[nodiscard]] Result<ArtifactResponse> self_fence(Lineage lineage, ReasonCode reason,
                                                    std::string_view detail);
  [[nodiscard]] Result<ArtifactResponse> submit(const Artifact& artifact);
  // Re-declares the current constitution at a fresh incarnation. This is what a
  // restarted member does: the generation and digest are unchanged, so consent
  // still stands, but the incarnation is new and the old activation no longer
  // applies.
  [[nodiscard]] Result<ArtifactResponse> restart_with_new_incarnation(
      Incarnation new_incarnation);

  // ---- authority ----------------------------------------------------------
  // Local authority never depends on the federation.
  [[nodiscard]] AuthorityDecision evaluate_local(const ScopeGrant& grant) const;
  [[nodiscard]] Result<AuthorityDecision> request_authority(const ScopeGrant& grant,
                                                            LeaseId lease);
  [[nodiscard]] Result<MemberStatus> status();
  [[nodiscard]] Result<DigestResponse> coordinator_digest();
  [[nodiscard]] Result<AuthorityLease> request_lease(const std::vector<ScopeGrant>& scopes,
                                                     Epoch not_after_epoch,
                                                     Tick lifetime_ticks);

  // ---- reachability evidence ---------------------------------------------
  struct PeerTarget {
    MemberId member;
    Endpoint endpoint;
  };
  // Probes each peer directly over loopback TCP and returns what was actually
  // observed. A probe that cannot connect is recorded as UNREACHABLE with the
  // transport error as its detail; it is never reported as reachable.
  [[nodiscard]] MemberObservation probe_peers(const std::vector<PeerTarget>& peers);
  [[nodiscard]] Result<SimpleResponse> report_observation(const MemberObservation& observation);

  // Starts and stops the probe listener. Closing it is how a partition is
  // produced for real in the tests: peers genuinely stop being able to connect.
  [[nodiscard]] Status start_probe_listener();
  [[nodiscard]] Status stop_probe_listener();
  // Serves probe requests until the listener is closed. Runs on a dedicated
  // thread when the runtime is created with listen_for_probes.
  [[nodiscard]] Status serve_probes_once();
  void stop_probe_thread();

  [[nodiscard]] std::string describe() const;

 private:
  MemberFabricRuntime();

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace fabric_federation
