// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Capability statements and compatibility evaluation.
//
// A declaration is what a member says about itself; a requirement is what a
// member (or the federation policy) needs from another member. Evaluation
// produces one of five distinct answers. "We have no evidence" is UNKNOWN and
// is never folded into SATISFIED.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/codec.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/export.hpp"
#include "fabric_federation/names.hpp"

namespace fabric_federation {

enum class CompatibilityState : std::uint8_t {
  Satisfied = 0,
  // A declared capability does not satisfy a requirement's version range.
  Incompatible = 1,
  // The requirement asks for something this runtime has no model for.
  Unsupported = 2,
  // No declaration covers the requirement. Missing evidence, not success.
  Unknown = 3,
  // Two declarations for one capability disagree.
  Conflicting = 4,
};

[[nodiscard]] FFED_API std::string_view to_string(CompatibilityState state) noexcept;

struct CapabilityRequirement {
  CapabilityId capability;
  std::uint32_t min_version = 0;
  // Inclusive upper bound. 0 means "no upper bound".
  std::uint32_t max_version = 0;
  bool mandatory = true;

  friend bool operator==(const CapabilityRequirement& a, const CapabilityRequirement& b) noexcept {
    return a.capability == b.capability && a.min_version == b.min_version &&
           a.max_version == b.max_version && a.mandatory == b.mandatory;
  }
  friend bool operator<(const CapabilityRequirement& a, const CapabilityRequirement& b) noexcept {
    if (a.capability != b.capability) {
      return a.capability < b.capability;
    }
    if (a.min_version != b.min_version) {
      return a.min_version < b.min_version;
    }
    if (a.max_version != b.max_version) {
      return a.max_version < b.max_version;
    }
    return a.mandatory < b.mandatory;
  }

  [[nodiscard]] bool version_in_range(std::uint32_t version) const noexcept {
    if (version < min_version) {
      return false;
    }
    return max_version == 0 || version <= max_version;
  }
  [[nodiscard]] std::string to_string() const;
  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<CapabilityRequirement> decode(Reader& reader);
};

struct CapabilityStatement {
  CapabilityId capability;
  std::uint32_t version = 0;
  // Known means the member produced evidence this runtime can point at (a
  // declaration artefact with a matching digest). Unknown means the statement
  // is asserted without evidence.
  EvidenceState evidence = EvidenceState::Unknown;
  // Digest of the evidence backing the statement; zero when there is none.
  Digest evidence_digest;

  friend bool operator==(const CapabilityStatement& a, const CapabilityStatement& b) noexcept {
    return a.capability == b.capability && a.version == b.version && a.evidence == b.evidence &&
           a.evidence_digest == b.evidence_digest;
  }
  friend bool operator<(const CapabilityStatement& a, const CapabilityStatement& b) noexcept {
    if (a.capability != b.capability) {
      return a.capability < b.capability;
    }
    if (a.version != b.version) {
      return a.version < b.version;
    }
    if (a.evidence != b.evidence) {
      return static_cast<std::uint8_t>(a.evidence) < static_cast<std::uint8_t>(b.evidence);
    }
    return a.evidence_digest < b.evidence_digest;
  }

  [[nodiscard]] std::string to_string() const;
  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<CapabilityStatement> decode(Reader& reader);
};

FFED_API void canonicalize_statements(std::vector<CapabilityStatement>& statements);
FFED_API void canonicalize_requirements(std::vector<CapabilityRequirement>& requirements);

[[nodiscard]] FFED_API Status encode_statements(Writer& writer,
                                                const std::vector<CapabilityStatement>& statements,
                                                std::size_t max_count);
[[nodiscard]] FFED_API Result<std::vector<CapabilityStatement>> decode_statements(
    Reader& reader, std::size_t max_count);
[[nodiscard]] FFED_API Status encode_requirements(
    Writer& writer, const std::vector<CapabilityRequirement>& requirements, std::size_t max_count);
[[nodiscard]] FFED_API Result<std::vector<CapabilityRequirement>> decode_requirements(
    Reader& reader, std::size_t max_count);

[[nodiscard]] FFED_API Digest digest_statements(
    const std::vector<CapabilityStatement>& statements);

struct CapabilityMatch {
  CapabilityId capability;
  bool mandatory = true;
  bool declared = false;
  std::uint32_t declared_version = 0;
  CapabilityRequirement requirement;
  CompatibilityState state = CompatibilityState::Unknown;
  std::string detail;
};

struct CompatibilityReport {
  CompatibilityState state = CompatibilityState::Unknown;
  std::vector<CapabilityMatch> matches;
  std::string summary;

  [[nodiscard]] bool satisfied() const noexcept {
    return state == CompatibilityState::Satisfied;
  }
};

// Capabilities this build models. A requirement that names anything else is
// reported as UNSUPPORTED: the runtime does not pretend to evaluate a
// capability it has no model for.
[[nodiscard]] FFED_API bool capability_is_modelled(const CapabilityId& capability);
[[nodiscard]] FFED_API const std::vector<CapabilityId>& modelled_capabilities();

// Deterministic evaluation. The order of requirements and statements does not
// affect the result: both are canonicalised first.
[[nodiscard]] FFED_API CompatibilityReport evaluate_compatibility(
    const std::vector<CapabilityRequirement>& requirements,
    const std::vector<CapabilityStatement>& statements);

}  // namespace fabric_federation
