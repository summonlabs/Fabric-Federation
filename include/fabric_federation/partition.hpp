// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Reachability evidence and partition assessment.
//
// Members probe each other directly over the framed transport and report what
// they observed. The coordinator does not perform consensus and does not
// perform failure detection on behalf of the members: it evaluates the
// observation set it holds, and when that set is incomplete the result is
// INDETERMINATE, which is treated at least as conservatively as a partition.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/codec.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/export.hpp"
#include "fabric_federation/ids.hpp"

namespace fabric_federation {

enum class ReachabilityState : std::uint8_t {
  // A connection attempt succeeded and a protocol response was received.
  Reachable = 0,
  // A connection attempt failed, or the peer closed the connection.
  Unreachable = 1,
  // No attempt has been made, or the attempt produced no usable answer.
  Unknown = 2,
};

[[nodiscard]] FFED_API std::string_view to_string(ReachabilityState state) noexcept;

struct PeerObservation {
  MemberId peer;
  // The peer incarnation the observer believes it reached. Zero means unknown.
  Incarnation peer_incarnation;
  ReachabilityState state = ReachabilityState::Unknown;
  // Tick at which the observation was made, on the coordinator's logical clock.
  Tick observed_at;
  // Bounded diagnostic text (for example the transport error).
  std::string detail;

  friend bool operator==(const PeerObservation& a, const PeerObservation& b) noexcept {
    return a.peer == b.peer && a.peer_incarnation == b.peer_incarnation && a.state == b.state &&
           a.observed_at == b.observed_at && a.detail == b.detail;
  }
  friend bool operator<(const PeerObservation& a, const PeerObservation& b) noexcept {
    if (a.peer != b.peer) {
      return a.peer < b.peer;
    }
    if (a.peer_incarnation != b.peer_incarnation) {
      return a.peer_incarnation < b.peer_incarnation;
    }
    if (a.state != b.state) {
      return static_cast<std::uint8_t>(a.state) < static_cast<std::uint8_t>(b.state);
    }
    if (a.observed_at != b.observed_at) {
      return a.observed_at < b.observed_at;
    }
    return a.detail < b.detail;
  }

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<PeerObservation> decode(Reader& reader);
};

// One member's view of its peers, as recorded by the coordinator.
struct MemberObservation {
  MemberId observer;
  Incarnation observer_incarnation;
  Epoch epoch;
  Tick recorded_at;
  std::vector<PeerObservation> peers;

  friend bool operator<(const MemberObservation& a, const MemberObservation& b) noexcept {
    if (a.observer != b.observer) {
      return a.observer < b.observer;
    }
    return a.observer_incarnation < b.observer_incarnation;
  }

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<MemberObservation> decode(Reader& reader);
};

enum class PartitionState : std::uint8_t {
  // Every known active member is mutually reachable.
  Connected = 0,
  // Two or more components were observed. No component may exercise
  // global-mutation authority.
  Split = 1,
  // The observation set is incomplete or stale. Treated at least as
  // conservatively as a split.
  Indeterminate = 2,
  // No active members at all.
  Empty = 3,
};

[[nodiscard]] FFED_API std::string_view to_string(PartitionState state) noexcept;

struct PartitionComponent {
  std::vector<MemberId> members;

  friend bool operator<(const PartitionComponent& a, const PartitionComponent& b) noexcept {
    return a.members < b.members;
  }
};

struct PartitionAssessment {
  PartitionState state = PartitionState::Empty;
  std::vector<PartitionComponent> components;
  std::vector<MemberId> mutually_reachable;
  std::vector<MemberId> unreachable;
  std::vector<MemberId> unobserved;
  std::vector<MemberId> stale_observations;
  EvidenceState evidence = EvidenceState::Unknown;
  std::string summary;

  [[nodiscard]] bool allows_global_mutation() const noexcept {
    return state == PartitionState::Connected;
  }
};

// Deterministic assessment. Inputs are canonicalised first, so the result does
// not depend on the order in which observations arrived.
//
//   * an edge exists only when BOTH endpoints observed each other as reachable
//     and the observed incarnation matches the member's current incarnation
//     (this is the mutual-reachability rule; it is a conservative reading of
//     one-directional evidence, not a failure detector),
//   * an observation from a previous epoch, or older than the configured
//     freshness bound, does not count,
//   * an active member with no usable observation at all makes the whole
//     assessment INDETERMINATE.
[[nodiscard]] FFED_API PartitionAssessment assess_partition(
    const std::vector<MemberId>& active_members,
    const std::vector<Incarnation>& active_incarnations,
    const std::vector<MemberObservation>& observations, Epoch current_epoch, Tick now,
    std::uint64_t freshness_ticks);

}  // namespace fabric_federation
