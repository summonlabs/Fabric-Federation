// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Every externally influenced size is bounded before it is used, and every
// arithmetic step on externally influenced integers is checked. These constants
// are the single source of truth for those bounds.
#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

#include "fabric_federation/errors.hpp"

namespace fabric_federation {

// ---- identifiers and text -------------------------------------------------
inline constexpr std::size_t kMaxIdentifierLength = 96;
inline constexpr std::size_t kMaxShortTextLength = 256;
inline constexpr std::size_t kMaxTextLength = 4096;
inline constexpr std::size_t kMaxExplanationTextLength = 8192;

// ---- membership and authority --------------------------------------------
inline constexpr std::size_t kMaxMembers = 1024;
inline constexpr std::size_t kMaxScopesPerMember = 512;
inline constexpr std::size_t kMaxCapabilitiesPerMember = 512;
inline constexpr std::size_t kMaxDelegationTermsPerMember = 512;
inline constexpr std::size_t kMaxRequiredEndorsements = 32;
inline constexpr std::size_t kMaxArtifacts = 65536;
inline constexpr std::size_t kMaxArtifactsPerMember = 4096;
inline constexpr std::size_t kMaxLeases = 8192;
inline constexpr std::size_t kMaxLeasesPerMember = 256;
inline constexpr std::size_t kMaxReplayEntries = 65536;
inline constexpr std::size_t kMaxReplayEntriesPerMember = 4096;
inline constexpr std::size_t kMaxScopesPerLease = 256;
inline constexpr std::size_t kMaxConflicts = 4096;
inline constexpr std::size_t kMaxPolicyRules = 1024;
inline constexpr std::size_t kMaxPrecedenceEntries = 256;

// ---- decision explanations ------------------------------------------------
inline constexpr std::size_t kMaxReasonsPerDecision = 64;
inline constexpr std::size_t kMaxContributionsPerDecision = 1024;
inline constexpr std::size_t kMaxEffectiveGrantsPerDecision = 512;

// ---- transport ------------------------------------------------------------
inline constexpr std::size_t kMaxConnections = 128;
inline constexpr std::size_t kMaxPendingRequests = 1024;
inline constexpr std::uint32_t kMaxFramePayloadBytes = 1u << 20;   // 1 MiB
inline constexpr std::uint32_t kMaxFrameBytes = kMaxFramePayloadBytes + 64u;
inline constexpr std::size_t kMaxMembersPerObservation = 1024;
inline constexpr std::uint32_t kMaxSnapshotChunkBytes = 1u << 20;

// ---- persistence ----------------------------------------------------------
inline constexpr std::uint64_t kMaxJournalRecordBytes = 1ull << 20;    // 1 MiB
inline constexpr std::uint64_t kMaxJournalBytes = 1ull << 31;          // 2 GiB
inline constexpr std::uint64_t kMaxSnapshotBytes = 1ull << 30;         // 1 GiB
inline constexpr std::size_t kMaxRecoveredArtifacts = kMaxArtifacts;
inline constexpr std::size_t kMaxRecoveryDiagnostics = 256;

// ---- checked arithmetic ---------------------------------------------------
[[nodiscard]] inline bool checked_add_u64(std::uint64_t a, std::uint64_t b, std::uint64_t& out) {
  if (b > std::numeric_limits<std::uint64_t>::max() - a) {
    return false;
  }
  out = a + b;
  return true;
}

[[nodiscard]] inline bool checked_mul_u64(std::uint64_t a, std::uint64_t b, std::uint64_t& out) {
  if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) {
    return false;
  }
  out = a * b;
  return true;
}

[[nodiscard]] inline bool checked_inc_u64(std::uint64_t& value) {
  if (value == std::numeric_limits<std::uint64_t>::max()) {
    return false;
  }
  ++value;
  return true;
}

// Narrows a size_t into a std::uint32_t only when the value actually fits.
[[nodiscard]] inline bool narrow_u32(std::size_t value, std::uint32_t& out) {
  if (value > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
    return false;
  }
  out = static_cast<std::uint32_t>(value);
  return true;
}

}  // namespace fabric_federation
