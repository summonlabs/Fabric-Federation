// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Version and format-identity constants for Fabric Federation.
#pragma once

#include <cstdint>
#include <string_view>

namespace fabric_federation {

inline constexpr int kVersionMajor = 1;
inline constexpr int kVersionMinor = 0;
inline constexpr int kVersionPatch = 0;
inline constexpr std::string_view kVersionString = "1.0.0";
inline constexpr std::string_view kProductName = "Fabric Federation";
inline constexpr std::string_view kOrganization = "Summon Software Labs";

// Wire, journal and canonical-state formats are versioned independently of the
// library version so that a future incompatible change is detectable rather
// than silently misinterpreted. Every reader rejects a format version it does
// not implement; it never guesses.
inline constexpr std::uint16_t kWireProtocolVersion = 1;
inline constexpr std::uint32_t kJournalFormatVersion = 1;
inline constexpr std::uint32_t kSnapshotFormatVersion = 1;
inline constexpr std::uint32_t kCanonicalStateVersion = 1;

// Provenance label for behaviour that is implemented in this repository and
// exercised by the test suite on this machine.
inline constexpr std::string_view kEvidenceReal = "REAL";
// Provenance label for generated fixture data that is explicitly not a
// measurement of physical hardware or a real network.
inline constexpr std::string_view kEvidenceSynthetic = "SYNTHETIC";
// Provenance label for behaviour this runtime deliberately does not provide.
inline constexpr std::string_view kEvidenceUnsupported = "UNSUPPORTED";

}  // namespace fabric_federation
