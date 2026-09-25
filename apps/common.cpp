// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "common.hpp"

#include <sstream>

#include "fabric_federation/json.hpp"
#include "fabric_federation/text.hpp"
#include "fabric_federation/version.hpp"

namespace ffed::app {
namespace {

std::vector<std::string> split(std::string_view text, char separator) {
  std::vector<std::string> parts;
  std::size_t start = 0;
  for (std::size_t i = 0; i <= text.size(); ++i) {
    if (i == text.size() || text[i] == separator) {
      parts.emplace_back(text.substr(start, i - start));
      start = i + 1;
    }
  }
  return parts;
}

std::string trim(std::string_view text) {
  std::size_t start = 0;
  std::size_t end = text.size();
  while (start < end && (text[start] == ' ' || text[start] == '\t')) {
    ++start;
  }
  while (end > start && (text[end - 1] == ' ' || text[end - 1] == '\t')) {
    --end;
  }
  return std::string(text.substr(start, end - start));
}

}  // namespace

bool Arguments::has(std::string_view name) const {
  for (const std::string& item : raw) {
    if (item == name) {
      return true;
    }
  }
  return false;
}

std::string Arguments::get(std::string_view name, std::string_view fallback) const {
  for (std::size_t i = 0; i + 1 < raw.size(); ++i) {
    if (raw[i] == name) {
      return raw[i + 1];
    }
  }
  return std::string(fallback);
}

std::vector<std::string> Arguments::get_all(std::string_view name) const {
  std::vector<std::string> out;
  for (std::size_t i = 0; i + 1 < raw.size(); ++i) {
    if (raw[i] == name) {
      out.push_back(raw[i + 1]);
    }
  }
  return out;
}

std::uint64_t Arguments::get_u64(std::string_view name, std::uint64_t fallback) const {
  const std::string text = get(name);
  if (text.empty()) {
    return fallback;
  }
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return fallback;
    }
    if (value > (0xffffffffffffffffull - static_cast<std::uint64_t>(c - '0')) / 10ull) {
      return fallback;
    }
    value = value * 10ull + static_cast<std::uint64_t>(c - '0');
  }
  return value;
}

Arguments parse_arguments(int argc, char* argv[], int first) {
  Arguments arguments;
  for (int i = first; i < argc; ++i) {
    arguments.raw.emplace_back(argv[i]);
  }
  return arguments;
}

fabric_federation::Result<std::vector<fabric_federation::ScopeGrant>> parse_grants(
    std::string_view text, fabric_federation::AuthorityVerb default_verb) {
  using namespace fabric_federation;
  std::vector<ScopeGrant> grants;
  if (text.empty()) {
    return grants;
  }
  for (const std::string& item : split(text, ',')) {
    const std::string trimmed = trim(item);
    if (trimmed.empty()) {
      continue;
    }
    const std::vector<std::string> parts = split(trimmed, ':');
    if (parts.size() > 2) {
      return Status::make(ErrorCode::InvalidArgument, "a grant is written scope[:verb]");
    }
    auto scope = ScopeId::parse(parts[0]);
    if (!scope.has_value()) {
      return scope.status();
    }
    ScopeGrant grant;
    grant.scope = std::move(scope.value());
    grant.verb = default_verb;
    if (parts.size() == 2) {
      if (!parse_verb(parts[1], grant.verb)) {
        return Status::make(ErrorCode::InvalidArgument, "unknown authority verb: " + parts[1]);
      }
    }
    grants.push_back(std::move(grant));
  }
  canonicalize_grants(grants);
  return grants;
}

fabric_federation::Result<std::vector<fabric_federation::DelegationTerms>> parse_terms(
    std::string_view text) {
  using namespace fabric_federation;
  std::vector<DelegationTerms> terms;
  if (text.empty()) {
    return terms;
  }
  for (const std::string& item : split(text, ',')) {
    const std::string trimmed = trim(item);
    if (trimmed.empty()) {
      continue;
    }
    const std::vector<std::string> parts = split(trimmed, ':');
    if (parts.size() < 3) {
      return Status::make(ErrorCode::InvalidArgument,
                          "delegation terms are written scope:verb:mode[:weight[:not_after]]");
    }
    auto scope = ScopeId::parse(parts[0]);
    if (!scope.has_value()) {
      return scope.status();
    }
    DelegationTerms term;
    term.grant.scope = std::move(scope.value());
    if (!parse_verb(parts[1], term.grant.verb)) {
      return Status::make(ErrorCode::InvalidArgument, "unknown authority verb: " + parts[1]);
    }
    if (parts[2] == "shared") {
      term.mode = DelegationMode::Shared;
    } else if (parts[2] == "exclusive") {
      term.mode = DelegationMode::Exclusive;
    } else {
      return Status::make(ErrorCode::InvalidArgument, "unknown delegation mode: " + parts[2]);
    }
    if (parts.size() > 3 && !parts[3].empty()) {
      std::uint64_t weight = 0;
      for (const char c : parts[3]) {
        if (c < '0' || c > '9') {
          return Status::make(ErrorCode::InvalidArgument, "delegation weight must be numeric");
        }
        weight = weight * 10ull + static_cast<std::uint64_t>(c - '0');
        if (weight > 0xffffffffull) {
          return Status::make(ErrorCode::OutOfRange, "delegation weight is out of range");
        }
      }
      term.weight = static_cast<std::uint32_t>(weight);
    }
    if (parts.size() > 4 && !parts[4].empty()) {
      std::uint64_t ticks = 0;
      for (const char c : parts[4]) {
        if (c < '0' || c > '9') {
          return Status::make(ErrorCode::InvalidArgument, "not_after must be a tick count");
        }
        ticks = ticks * 10ull + static_cast<std::uint64_t>(c - '0');
      }
      term.not_after = Tick(ticks);
    }
    terms.push_back(std::move(term));
  }
  canonicalize_terms(terms);
  return terms;
}

fabric_federation::Result<std::vector<fabric_federation::CapabilityStatement>> parse_capabilities(
    std::string_view text) {
  using namespace fabric_federation;
  std::vector<CapabilityStatement> statements;
  if (text.empty()) {
    return statements;
  }
  for (const std::string& item : split(text, ',')) {
    const std::string trimmed = trim(item);
    if (trimmed.empty()) {
      continue;
    }
    const std::vector<std::string> parts = split(trimmed, ':');
    if (parts.size() < 2) {
      return Status::make(ErrorCode::InvalidArgument,
                          "a capability is written capability:version[:known]");
    }
    auto capability = CapabilityId::parse(parts[0]);
    if (!capability.has_value()) {
      return capability.status();
    }
    CapabilityStatement statement;
    statement.capability = std::move(capability.value());
    std::uint64_t version = 0;
    for (const char c : parts[1]) {
      if (c < '0' || c > '9') {
        return Status::make(ErrorCode::InvalidArgument, "capability version must be numeric");
      }
      version = version * 10ull + static_cast<std::uint64_t>(c - '0');
      if (version > 0xffffffffull) {
        return Status::make(ErrorCode::OutOfRange, "capability version is out of range");
      }
    }
    statement.version = static_cast<std::uint32_t>(version);
    statement.evidence = EvidenceState::Unknown;
    if (parts.size() > 2 && parts[2] == "known") {
      statement.evidence = EvidenceState::Known;
      statement.evidence_digest = Digest::of(trimmed);
    }
    statements.push_back(std::move(statement));
  }
  canonicalize_statements(statements);
  return statements;
}

fabric_federation::Result<fabric_federation::MemberConstitution> parse_constitution(
    std::string_view spec, const fabric_federation::MemberId& member,
    const fabric_federation::FabricDomainId& domain) {
  using namespace fabric_federation;
  MemberConstitution constitution;
  constitution.member = member;
  constitution.domain = domain;
  constitution.generation = Generation(1);
  constitution.software_major = static_cast<std::uint32_t>(kVersionMajor);
  constitution.software_minor = static_cast<std::uint32_t>(kVersionMinor);
  constitution.software_patch = static_cast<std::uint32_t>(kVersionPatch);
  constitution.description = "member fabric domain";

  for (const std::string& item : split(spec, ';')) {
    const std::string trimmed = trim(item);
    if (trimmed.empty()) {
      continue;
    }
    const std::size_t equals = trimmed.find('=');
    if (equals == std::string::npos) {
      return Status::make(ErrorCode::InvalidArgument,
                          "constitution fields are written name=value");
    }
    const std::string name = trim(trimmed.substr(0, equals));
    const std::string value = trim(trimmed.substr(equals + 1));
    if (name == "gen") {
      std::uint64_t generation = 0;
      for (const char c : value) {
        if (c < '0' || c > '9') {
          return Status::make(ErrorCode::InvalidArgument, "generation must be numeric");
        }
        generation = generation * 10ull + static_cast<std::uint64_t>(c - '0');
      }
      constitution.generation = Generation(generation);
    } else if (name == "caps") {
      auto capabilities = parse_capabilities(value);
      if (!capabilities.has_value()) {
        return capabilities.status();
      }
      constitution.capabilities = std::move(capabilities.value());
    } else if (name == "retained") {
      auto grants = parse_grants(value, AuthorityVerb::Administer);
      if (!grants.has_value()) {
        return grants.status();
      }
      constitution.retained = std::move(grants.value());
    } else if (name == "delegated") {
      auto terms = parse_terms(value);
      if (!terms.has_value()) {
        return terms.status();
      }
      constitution.delegated = std::move(terms.value());
    } else if (name == "desc") {
      constitution.description = value;
    } else {
      return Status::make(ErrorCode::InvalidArgument, "unknown constitution field: " + name);
    }
  }
  if (constitution.capabilities.empty()) {
    // The default declaration satisfies the shipped policy's mandatory
    // capability. A member that declares nothing would be degraded, which is
    // correct but inconvenient as an implicit default.
    auto capabilities = parse_capabilities("federation.protocol.v1:1:known");
    if (capabilities.has_value()) {
      constitution.capabilities = std::move(capabilities.value());
    }
  }
  if (constitution.description.size() > kMaxTextLength) {
    return Status::make(ErrorCode::BoundsExceeded, "the description is too long");
  }
  constitution.canonicalize();
  return constitution;
}

std::string render_decision(const fabric_federation::AuthorityDecision& decision, bool json) {
  using namespace fabric_federation;
  if (json) {
    JsonWriter writer(true);
    writer.begin_object();
    writer.key("outcome");
    writer.string(to_string(decision.outcome));
    writer.key("request");
    writer.string(decision.request.to_string());
    writer.key("grant");
    writer.string(decision.requested.to_string());
    writer.key("lifecycle");
    writer.string(to_string(decision.lifecycle));
    writer.key("epoch_seen");
    writer.number(decision.epoch_seen.value());
    writer.key("epoch_current");
    writer.number(decision.epoch_current.value());
    writer.key("decided_at");
    writer.number(decision.decided_at.value());
    writer.key("actor_generation");
    writer.number(decision.actor_declared.generation.value());
    writer.key("actor_incarnation");
    writer.number(decision.actor_declared.incarnation.value());
    writer.key("actor_digest");
    writer.string(decision.actor_declared.constitution.to_hex());
    writer.key("current_generation");
    writer.number(decision.actor_current.generation.value());
    writer.key("current_incarnation");
    writer.number(decision.actor_current.incarnation.value());
    writer.key("current_digest");
    writer.string(decision.actor_current.constitution.to_hex());
    writer.key("effective_authority");
    writer.begin_array();
    for (const ScopeGrant& grant : decision.effective_authority) {
      writer.string(grant.to_string());
    }
    writer.end_array();
    writer.key("explanation");
    writer.begin_object();
    writer.key("evidence");
    writer.string(to_string(decision.explanation.evidence));
    writer.key("summary");
    writer.string(decision.explanation.summary);
    writer.key("reasons");
    writer.begin_array();
    for (const Reason& reason : decision.explanation.reasons) {
      writer.begin_object();
      writer.key("code");
      writer.string(to_string(reason.code));
      writer.key("detail");
      writer.string(reason.detail);
      writer.end_object();
    }
    writer.end_array();
    writer.key("contributors");
    writer.begin_array();
    for (const Contribution& contribution : decision.explanation.contributions) {
      writer.begin_object();
      writer.key("member");
      writer.string(contribution.member.to_string());
      writer.key("role");
      writer.string(to_string(contribution.role));
      writer.key("generation");
      writer.number(contribution.generation.value());
      writer.key("incarnation");
      writer.number(contribution.incarnation.value());
      writer.key("constitution_digest");
      writer.string(contribution.constitution.to_hex());
      writer.key("current");
      writer.boolean(contribution.identity_current);
      writer.end_object();
    }
    writer.end_array();
    writer.key("conflicts");
    writer.begin_array();
    for (const ConflictRecord& conflict : decision.explanation.conflicts) {
      writer.begin_object();
      writer.key("grant");
      writer.string(conflict.grant.to_string());
      writer.key("kind");
      writer.string(to_string(conflict.kind));
      writer.key("detail");
      writer.string(conflict.detail);
      writer.end_object();
    }
    writer.end_array();
    writer.end_object();
    writer.key("decision_digest");
    writer.string(decision.digest().to_hex());
    writer.end_object();
    return writer.str();
  }
  return render_explanation(decision.explanation);
}

}  // namespace ffed::app
