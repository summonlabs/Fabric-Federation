// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Shared command-line helpers for the Fabric Federation tools.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/authority.hpp"
#include "fabric_federation/coordinator.hpp"
#include "fabric_federation/evidence.hpp"
#include "fabric_federation/ids.hpp"
#include "fabric_federation/scope.hpp"
#include "fabric_federation/state.hpp"

namespace ffed::app {

struct Arguments {
  std::vector<std::string> raw;

  [[nodiscard]] bool has(std::string_view name) const;
  [[nodiscard]] std::string get(std::string_view name, std::string_view fallback = {}) const;
  [[nodiscard]] std::uint64_t get_u64(std::string_view name, std::uint64_t fallback) const;
  [[nodiscard]] std::vector<std::string> get_all(std::string_view name) const;
};

// Parses "--name value" and "--flag" forms. A "--" terminator stops parsing.
[[nodiscard]] Arguments parse_arguments(int argc, char* argv[], int first = 1);

// Parses "scope:verb" or just "scope" (verb defaults to observe).
[[nodiscard]] fabric_federation::Result<std::vector<fabric_federation::ScopeGrant>> parse_grants(
    std::string_view text, fabric_federation::AuthorityVerb default_verb);

// Parses "scope:verb:mode[:weight[:not_after]]".
[[nodiscard]] fabric_federation::Result<std::vector<fabric_federation::DelegationTerms>>
parse_terms(std::string_view text);

// Parses "capability:version[:known|:unknown]".
[[nodiscard]] fabric_federation::Result<std::vector<fabric_federation::CapabilityStatement>>
parse_capabilities(std::string_view text);

// Parses the compact constitution description used by the tools:
//   "gen=1;caps=...;retained=...;delegated=...;desc=free text"
// Member and domain identities are supplied separately.
[[nodiscard]] fabric_federation::Result<fabric_federation::MemberConstitution> parse_constitution(
    std::string_view spec, const fabric_federation::MemberId& member,
    const fabric_federation::FabricDomainId& domain);

// Renders a decision for humans or as JSON.
[[nodiscard]] std::string render_decision(const fabric_federation::AuthorityDecision& decision,
                                          bool json);

}  // namespace ffed::app
