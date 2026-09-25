// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/capability.hpp"

#include <algorithm>

namespace fabric_federation {
namespace {

template <class T>
void sort_unique(std::vector<T>& items) {
  std::sort(items.begin(), items.end());
  items.erase(std::unique(items.begin(), items.end()), items.end());
}

}  // namespace

std::string_view to_string(CompatibilityState state) noexcept {
  switch (state) {
    case CompatibilityState::Satisfied:
      return "SATISFIED";
    case CompatibilityState::Incompatible:
      return "INCOMPATIBLE";
    case CompatibilityState::Unsupported:
      return "UNSUPPORTED";
    case CompatibilityState::Unknown:
      return "UNKNOWN";
    case CompatibilityState::Conflicting:
      return "CONFLICTING";
  }
  return "UNKNOWN";
}

bool capability_is_modelled(const CapabilityId& capability) {
  const std::vector<CapabilityId>& modelled = modelled_capabilities();
  return std::find(modelled.begin(), modelled.end(), capability) != modelled.end();
}

const std::vector<CapabilityId>& modelled_capabilities() {
  static const std::vector<CapabilityId> modelled = [] {
    std::vector<CapabilityId> out;
    for (const char* name : {"federation.protocol.v1", "federation.transport.framed-tcp",
                             "federation.authority.lease", "federation.partition.observation",
                             "federation.canonical-state.v1", "federation.membership.multiparty"}) {
      auto parsed = CapabilityId::parse(name);
      if (parsed.has_value()) {
        out.push_back(std::move(parsed.value()));
      }
    }
    std::sort(out.begin(), out.end());
    return out;
  }();
  return modelled;
}

std::string CapabilityRequirement::to_string() const {
  std::string out = capability.str();
  out.append(" >= ");
  out.append(std::to_string(min_version));
  if (max_version != 0) {
    out.append(" <= ");
    out.append(std::to_string(max_version));
  }
  out.append(mandatory ? " (mandatory)" : " (optional)");
  return out;
}

Status CapabilityRequirement::encode(Writer& writer) const {
  Status status = writer.identifier(capability.str());
  if (!status.ok()) {
    return status;
  }
  status = writer.u32(min_version);
  if (!status.ok()) {
    return status;
  }
  status = writer.u32(max_version);
  if (!status.ok()) {
    return status;
  }
  return writer.boolean(mandatory);
}

Result<CapabilityRequirement> CapabilityRequirement::decode(Reader& reader) {
  auto capability = reader.identifier();
  if (!capability.has_value()) {
    return capability.status();
  }
  // An empty identifier means "this requirement names no capability", which is
  // how an unused optional field is encoded. It is not an error.
  CapabilityId parsed;
  if (!capability.value().empty()) {
    auto candidate = CapabilityId::parse(capability.value());
    if (!candidate.has_value()) {
      return Status::make(ErrorCode::InvalidArgument, "capability identifier is malformed");
    }
    parsed = std::move(candidate.value());
  }
  auto min_version = reader.u32();
  if (!min_version.has_value()) {
    return min_version.status();
  }
  auto max_version = reader.u32();
  if (!max_version.has_value()) {
    return max_version.status();
  }
  auto mandatory = reader.boolean();
  if (!mandatory.has_value()) {
    return mandatory.status();
  }
  if (max_version.value() != 0 && max_version.value() < min_version.value()) {
    return Status::make(ErrorCode::InvalidArgument, "capability version range is inverted");
  }
  CapabilityRequirement requirement;
  requirement.capability = std::move(parsed);
  requirement.min_version = min_version.value();
  requirement.max_version = max_version.value();
  requirement.mandatory = mandatory.value();
  return requirement;
}

std::string CapabilityStatement::to_string() const {
  std::string out = capability.str();
  out.append(" = ");
  out.append(std::to_string(version));
  out.append(" evidence=");
  out.append(fabric_federation::to_string(evidence));
  return out;
}

Status CapabilityStatement::encode(Writer& writer) const {
  Status status = writer.identifier(capability.str());
  if (!status.ok()) {
    return status;
  }
  status = writer.u32(version);
  if (!status.ok()) {
    return status;
  }
  status = writer.u8(static_cast<std::uint8_t>(evidence));
  if (!status.ok()) {
    return status;
  }
  return writer.digest(evidence_digest);
}

Result<CapabilityStatement> CapabilityStatement::decode(Reader& reader) {
  auto capability = reader.identifier();
  if (!capability.has_value()) {
    return capability.status();
  }
  auto parsed = CapabilityId::parse(capability.value());
  if (!parsed.has_value()) {
    return Status::make(ErrorCode::InvalidArgument, "capability identifier is malformed");
  }
  auto version = reader.u32();
  if (!version.has_value()) {
    return version.status();
  }
  auto evidence = reader.u8();
  if (!evidence.has_value()) {
    return evidence.status();
  }
  if (evidence.value() > static_cast<std::uint8_t>(EvidenceState::Invalid)) {
    return Status::make(ErrorCode::InvalidArgument, "evidence state is out of range");
  }
  auto digest = reader.digest();
  if (!digest.has_value()) {
    return digest.status();
  }
  CapabilityStatement statement;
  statement.capability = std::move(parsed.value());
  statement.version = version.value();
  statement.evidence = static_cast<EvidenceState>(evidence.value());
  statement.evidence_digest = digest.value();
  return statement;
}

void canonicalize_statements(std::vector<CapabilityStatement>& statements) { sort_unique(statements); }
void canonicalize_requirements(std::vector<CapabilityRequirement>& requirements) {
  sort_unique(requirements);
}

Status encode_statements(Writer& writer, const std::vector<CapabilityStatement>& statements,
                         std::size_t max_count) {
  Status status = writer.count(statements.size(), max_count);
  if (!status.ok()) {
    return status;
  }
  for (const CapabilityStatement& statement : statements) {
    status = statement.encode(writer);
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

Result<std::vector<CapabilityStatement>> decode_statements(Reader& reader, std::size_t max_count) {
  auto count = reader.count(max_count);
  if (!count.has_value()) {
    return count.status();
  }
  std::vector<CapabilityStatement> statements;
  statements.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto statement = CapabilityStatement::decode(reader);
    if (!statement.has_value()) {
      return statement.status();
    }
    statements.push_back(std::move(statement.value()));
  }
  return statements;
}

Status encode_requirements(Writer& writer, const std::vector<CapabilityRequirement>& requirements,
                           std::size_t max_count) {
  Status status = writer.count(requirements.size(), max_count);
  if (!status.ok()) {
    return status;
  }
  for (const CapabilityRequirement& requirement : requirements) {
    status = requirement.encode(writer);
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

Result<std::vector<CapabilityRequirement>> decode_requirements(Reader& reader,
                                                               std::size_t max_count) {
  auto count = reader.count(max_count);
  if (!count.has_value()) {
    return count.status();
  }
  std::vector<CapabilityRequirement> requirements;
  requirements.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto requirement = CapabilityRequirement::decode(reader);
    if (!requirement.has_value()) {
      return requirement.status();
    }
    requirements.push_back(std::move(requirement.value()));
  }
  return requirements;
}

Digest digest_statements(const std::vector<CapabilityStatement>& statements) {
  Writer writer;
  std::vector<CapabilityStatement> copy = statements;
  canonicalize_statements(copy);
  if (!encode_statements(writer, copy, kMaxCapabilitiesPerMember).ok()) {
    return Digest();
  }
  return writer.sha256();
}

CompatibilityReport evaluate_compatibility(const std::vector<CapabilityRequirement>& requirements,
                                           const std::vector<CapabilityStatement>& statements) {
  std::vector<CapabilityRequirement> sorted_requirements = requirements;
  std::vector<CapabilityStatement> sorted_statements = statements;
  canonicalize_requirements(sorted_requirements);
  canonicalize_statements(sorted_statements);

  CompatibilityReport report;
  bool any_incompatible = false;
  bool any_conflicting = false;
  bool any_unsupported = false;
  bool any_unknown_mandatory = false;
  bool any_unknown_optional = false;

  for (const CapabilityRequirement& requirement : sorted_requirements) {
    CapabilityMatch match;
    match.capability = requirement.capability;
    match.mandatory = requirement.mandatory;
    match.requirement = requirement;

    std::vector<std::uint32_t> versions;
    for (const CapabilityStatement& statement : sorted_statements) {
      if (statement.capability == requirement.capability) {
        versions.push_back(statement.version);
      }
    }
    std::sort(versions.begin(), versions.end());
    versions.erase(std::unique(versions.begin(), versions.end()), versions.end());

    if (!capability_is_modelled(requirement.capability)) {
      match.state = CompatibilityState::Unsupported;
      match.detail = "this build has no model for the capability";
      any_unsupported = true;
    } else if (versions.empty()) {
      match.declared = false;
      match.state = CompatibilityState::Unknown;
      match.detail = "no declaration covers the requirement";
      if (requirement.mandatory) {
        any_unknown_mandatory = true;
      } else {
        any_unknown_optional = true;
      }
    } else if (versions.size() > 1) {
      match.declared = true;
      match.state = CompatibilityState::Conflicting;
      match.detail = "two declarations for one capability disagree on version";
      any_conflicting = true;
    } else {
      match.declared = true;
      match.declared_version = versions.front();
      if (!requirement.version_in_range(versions.front())) {
        match.state = CompatibilityState::Incompatible;
        match.detail = "declared version is outside the required range";
        any_incompatible = true;
      } else {
        // A version in range is not the same as evidence that it works. An
        // asserted-but-unwitnessed statement stays UNKNOWN.
        bool evidence_known = false;
        for (const CapabilityStatement& statement : sorted_statements) {
          if (statement.capability == requirement.capability &&
              statement.evidence == EvidenceState::Known) {
            evidence_known = true;
            break;
          }
        }
        if (evidence_known) {
          match.state = CompatibilityState::Satisfied;
          match.detail = "version in range with evidence";
        } else {
          match.state = CompatibilityState::Unknown;
          match.detail = "version in range but the statement carries no evidence";
          if (requirement.mandatory) {
            any_unknown_mandatory = true;
          } else {
            any_unknown_optional = true;
          }
        }
      }
    }
    report.matches.push_back(std::move(match));
  }

  if (any_incompatible) {
    report.state = CompatibilityState::Incompatible;
    report.summary = "an incompatible declaration was found";
  } else if (any_conflicting) {
    report.state = CompatibilityState::Conflicting;
    report.summary = "declarations for one capability disagree";
  } else if (any_unsupported && (any_unknown_mandatory || report.matches.size() == 1)) {
    report.state = CompatibilityState::Unsupported;
    report.summary = "a requirement names a capability this build does not model";
  } else if (any_unknown_mandatory) {
    report.state = CompatibilityState::Unknown;
    report.summary = "a mandatory requirement has no usable evidence";
  } else if (any_unsupported) {
    report.state = CompatibilityState::Unsupported;
    report.summary = "a requirement names a capability this build does not model";
  } else if (any_unknown_optional) {
    report.state = CompatibilityState::Unknown;
    report.summary = "only optional requirements are unevidenced";
  } else if (report.matches.empty()) {
    report.state = CompatibilityState::Satisfied;
    report.summary = "no requirements were stated";
  } else {
    report.state = CompatibilityState::Satisfied;
    report.summary = "every requirement is satisfied with evidence";
  }
  return report;
}

}  // namespace fabric_federation
