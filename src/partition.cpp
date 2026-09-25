// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/partition.hpp"

#include <algorithm>
#include <map>

namespace fabric_federation {
namespace {

struct PairKey {
  MemberId observer;
  MemberId peer;
  friend bool operator<(const PairKey& a, const PairKey& b) noexcept {
    if (a.observer != b.observer) {
      return a.observer < b.observer;
    }
    return a.peer < b.peer;
  }
};

class DisjointSet {
 public:
  explicit DisjointSet(std::size_t size) : parent_(size), rank_(size, 0) {
    for (std::size_t i = 0; i < size; ++i) {
      parent_[i] = i;
    }
  }

  std::size_t find(std::size_t index) {
    while (parent_[index] != index) {
      parent_[index] = parent_[parent_[index]];
      index = parent_[index];
    }
    return index;
  }

  void unite(std::size_t a, std::size_t b) {
    a = find(a);
    b = find(b);
    if (a == b) {
      return;
    }
    if (rank_[a] < rank_[b]) {
      std::swap(a, b);
    }
    parent_[b] = a;
    if (rank_[a] == rank_[b]) {
      ++rank_[a];
    }
  }

 private:
  std::vector<std::size_t> parent_;
  std::vector<int> rank_;
};

}  // namespace

std::string_view to_string(ReachabilityState state) noexcept {
  switch (state) {
    case ReachabilityState::Reachable:
      return "REACHABLE";
    case ReachabilityState::Unreachable:
      return "UNREACHABLE";
    case ReachabilityState::Unknown:
      return "UNKNOWN";
  }
  return "UNKNOWN";
}

std::string_view to_string(PartitionState state) noexcept {
  switch (state) {
    case PartitionState::Connected:
      return "CONNECTED";
    case PartitionState::Split:
      return "SPLIT";
    case PartitionState::Indeterminate:
      return "INDETERMINATE";
    case PartitionState::Empty:
      return "EMPTY";
  }
  return "INDETERMINATE";
}

Status PeerObservation::encode(Writer& writer) const {
  Status status = writer.id16(peer.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(peer_incarnation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u8(static_cast<std::uint8_t>(state));
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(observed_at.value());
  if (!status.ok()) {
    return status;
  }
  return writer.text(detail, kMaxShortTextLength);
}

Result<PeerObservation> PeerObservation::decode(Reader& reader) {
  PeerObservation observation;
  auto peer = reader.id16();
  if (!peer.has_value()) {
    return peer.status();
  }
  observation.peer = MemberId::from_bytes(peer.value());
  auto incarnation = reader.u64();
  if (!incarnation.has_value()) {
    return incarnation.status();
  }
  observation.peer_incarnation = Incarnation(incarnation.value());
  auto state = reader.u8();
  if (!state.has_value()) {
    return state.status();
  }
  if (state.value() > static_cast<std::uint8_t>(ReachabilityState::Unknown)) {
    return Status::make(ErrorCode::InvalidArgument, "reachability state is out of range");
  }
  observation.state = static_cast<ReachabilityState>(state.value());
  auto observed_at = reader.u64();
  if (!observed_at.has_value()) {
    return observed_at.status();
  }
  observation.observed_at = Tick(observed_at.value());
  auto detail = reader.text(kMaxShortTextLength);
  if (!detail.has_value()) {
    return detail.status();
  }
  observation.detail = std::move(detail.value());
  return observation;
}

Status MemberObservation::encode(Writer& writer) const {
  Status status = writer.id16(observer.bytes());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(observer_incarnation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(epoch.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(recorded_at.value());
  if (!status.ok()) {
    return status;
  }
  std::vector<PeerObservation> sorted = peers;
  std::sort(sorted.begin(), sorted.end());
  sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());
  status = writer.count(sorted.size(), kMaxMembersPerObservation);
  if (!status.ok()) {
    return status;
  }
  for (const PeerObservation& peer : sorted) {
    status = peer.encode(writer);
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

Result<MemberObservation> MemberObservation::decode(Reader& reader) {
  MemberObservation observation;
  auto observer = reader.id16();
  if (!observer.has_value()) {
    return observer.status();
  }
  observation.observer = MemberId::from_bytes(observer.value());
  auto incarnation = reader.u64();
  if (!incarnation.has_value()) {
    return incarnation.status();
  }
  observation.observer_incarnation = Incarnation(incarnation.value());
  auto epoch = reader.u64();
  if (!epoch.has_value()) {
    return epoch.status();
  }
  observation.epoch = Epoch(epoch.value());
  auto recorded_at = reader.u64();
  if (!recorded_at.has_value()) {
    return recorded_at.status();
  }
  observation.recorded_at = Tick(recorded_at.value());
  auto count = reader.count(kMaxMembersPerObservation);
  if (!count.has_value()) {
    return count.status();
  }
  observation.peers.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto peer = PeerObservation::decode(reader);
    if (!peer.has_value()) {
      return peer.status();
    }
    observation.peers.push_back(std::move(peer.value()));
  }
  return observation;
}

PartitionAssessment assess_partition(const std::vector<MemberId>& active_members,
                                     const std::vector<Incarnation>& active_incarnations,
                                     const std::vector<MemberObservation>& observations,
                                     Epoch current_epoch, Tick now, std::uint64_t freshness_ticks) {
  PartitionAssessment assessment;

  std::vector<MemberId> members = active_members;
  std::sort(members.begin(), members.end());
  members.erase(std::unique(members.begin(), members.end()), members.end());
  if (members.size() != active_incarnations.size()) {
    // A caller that supplies mismatched vectors gets the conservative answer.
    assessment.state = PartitionState::Indeterminate;
    assessment.evidence = EvidenceState::Invalid;
    assessment.summary = "active member and incarnation lists disagree";
    return assessment;
  }
  if (members.empty()) {
    assessment.state = PartitionState::Empty;
    assessment.evidence = EvidenceState::Unknown;
    assessment.summary = "no active members";
    return assessment;
  }
  if (members.size() == 1) {
    // A graph with one node has no edges to be missing. There is nothing to
    // partition a single active member from, so no reachability evidence is
    // required and none is invented.
    PartitionComponent component;
    component.members = members;
    assessment.components.push_back(std::move(component));
    assessment.mutually_reachable = members;
    assessment.state = PartitionState::Connected;
    assessment.evidence = EvidenceState::Known;
    assessment.summary = "a single active member cannot be partitioned from itself";
    return assessment;
  }

  std::map<MemberId, Incarnation> current_incarnation;
  std::map<MemberId, std::size_t> index_of;
  for (std::size_t i = 0; i < members.size(); ++i) {
    current_incarnation[members[i]] = active_incarnations[i];
    index_of[members[i]] = i;
  }

  // Latest usable observation per (observer, peer).
  std::map<PairKey, PeerObservation> latest;
  std::vector<MemberId> stale;
  for (const MemberObservation& observation : observations) {
    if (observation.observer.is_nil() || index_of.find(observation.observer) == index_of.end()) {
      continue;
    }
    if (observation.epoch != current_epoch) {
      stale.push_back(observation.observer);
      continue;
    }
    if (freshness_ticks != 0 && observation.recorded_at.value() > now.value()) {
      stale.push_back(observation.observer);
      continue;
    }
    for (const PeerObservation& peer : observation.peers) {
      if (peer.peer.is_nil() || peer.peer == observation.observer) {
        continue;
      }
      if (index_of.find(peer.peer) == index_of.end()) {
        // An observation about a member the federation does not consider active
        // is not evidence about the current active set.
        continue;
      }
      if (freshness_ticks != 0) {
        if (peer.observed_at.value() > now.value() ||
            now.value() - peer.observed_at.value() > freshness_ticks) {
          stale.push_back(peer.peer);
          continue;
        }
      }
      const PairKey key{observation.observer, peer.peer};
      auto existing = latest.find(key);
      if (existing == latest.end() || existing->second.observed_at < peer.observed_at) {
        latest[key] = peer;
      }
    }
  }
  std::sort(stale.begin(), stale.end());
  stale.erase(std::unique(stale.begin(), stale.end()), stale.end());
  assessment.stale_observations = stale;

  // An edge exists only when both endpoints confirm each other at the
  // incarnation the federation currently believes is running.
  DisjointSet components(members.size());
  std::vector<bool> has_confirmed_edge(members.size(), false);
  std::vector<bool> referenced(members.size(), false);
  std::vector<bool> seen_unreachable(members.size(), false);
  std::vector<std::pair<std::size_t, std::size_t>> candidate_pairs;
  for (const auto& entry : latest) {
    const std::size_t observer_index = index_of[entry.first.observer];
    const std::size_t peer_index = index_of[entry.first.peer];
    referenced[observer_index] = true;
    referenced[peer_index] = true;
    if (entry.second.state == ReachabilityState::Unreachable) {
      seen_unreachable[peer_index] = true;
      continue;
    }
    if (entry.second.state != ReachabilityState::Reachable) {
      continue;
    }
    if (entry.second.peer_incarnation.is_zero() ||
        entry.second.peer_incarnation != current_incarnation[entry.first.peer]) {
      // Reached something, but not the incarnation the federation believes is
      // running. Not usable as evidence about the current member.
      continue;
    }
    if (observer_index < peer_index) {
      candidate_pairs.emplace_back(observer_index, peer_index);
    }
  }
  for (const auto& pair : candidate_pairs) {
    const MemberId& a = members[pair.first];
    const MemberId& b = members[pair.second];
    const auto forward = latest.find(PairKey{a, b});
    const auto backward = latest.find(PairKey{b, a});
    if (forward == latest.end() || backward == latest.end()) {
      continue;
    }
    if (forward->second.state != ReachabilityState::Reachable ||
        backward->second.state != ReachabilityState::Reachable) {
      continue;
    }
    if (forward->second.peer_incarnation != current_incarnation[b] ||
        backward->second.peer_incarnation != current_incarnation[a]) {
      continue;
    }
    components.unite(pair.first, pair.second);
    has_confirmed_edge[pair.first] = true;
    has_confirmed_edge[pair.second] = true;
  }

  for (std::size_t i = 0; i < members.size(); ++i) {
    if (has_confirmed_edge[i]) {
      assessment.mutually_reachable.push_back(members[i]);
    }
    if (seen_unreachable[i] && !has_confirmed_edge[i]) {
      assessment.unreachable.push_back(members[i]);
    }
    if (!referenced[i]) {
      assessment.unobserved.push_back(members[i]);
    }
  }

  std::map<std::size_t, std::vector<MemberId>> grouped;
  for (std::size_t i = 0; i < members.size(); ++i) {
    grouped[components.find(i)].push_back(members[i]);
  }
  for (auto& entry : grouped) {
    PartitionComponent component;
    component.members = entry.second;
    std::sort(component.members.begin(), component.members.end());
    assessment.components.push_back(std::move(component));
  }
  std::sort(assessment.components.begin(), assessment.components.end());

  if (!assessment.unobserved.empty()) {
    assessment.state = PartitionState::Indeterminate;
    assessment.evidence = EvidenceState::Indeterminate;
    assessment.summary = "no usable reachability observation covers " +
                         std::to_string(assessment.unobserved.size()) + " active member(s)";
  } else if (assessment.components.size() == 1) {
    assessment.state = PartitionState::Connected;
    assessment.evidence = EvidenceState::Known;
    assessment.summary = "all active members are mutually reachable";
  } else {
    assessment.state = PartitionState::Split;
    assessment.evidence = EvidenceState::Known;
    assessment.summary = "the active set is split into " +
                         std::to_string(assessment.components.size()) + " component(s)";
  }
  return assessment;
}

}  // namespace fabric_federation
