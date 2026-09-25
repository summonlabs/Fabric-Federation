// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/scope.hpp"

#include <algorithm>

namespace fabric_federation {
namespace {

// Every collection of grants is stored sorted and duplicate-free so that the
// canonical encoding of a set does not depend on insertion order.
template <class T>
void sort_unique(std::vector<T>& items) {
  std::sort(items.begin(), items.end());
  items.erase(std::unique(items.begin(), items.end()), items.end());
}

}  // namespace

std::string_view to_string(AuthorityVerb verb) noexcept {
  switch (verb) {
    case AuthorityVerb::Observe:
      return "observe";
    case AuthorityVerb::Write:
      return "write";
    case AuthorityVerb::Mutate:
      return "mutate";
    case AuthorityVerb::Administer:
      return "administer";
  }
  return "invalid";
}

bool parse_verb(std::string_view text, AuthorityVerb& out) noexcept {
  if (text == "observe") {
    out = AuthorityVerb::Observe;
    return true;
  }
  if (text == "write") {
    out = AuthorityVerb::Write;
    return true;
  }
  if (text == "mutate") {
    out = AuthorityVerb::Mutate;
    return true;
  }
  if (text == "administer") {
    out = AuthorityVerb::Administer;
    return true;
  }
  return false;
}

Result<AuthorityVerb> verb_from_wire(std::uint8_t value) {
  if (value > static_cast<std::uint8_t>(AuthorityVerb::Administer)) {
    return Status::make(ErrorCode::InvalidArgument, "authority verb is out of range");
  }
  return static_cast<AuthorityVerb>(value);
}

std::string_view to_string(ScopeClass scope_class) noexcept {
  switch (scope_class) {
    case ScopeClass::Local:
      return "local";
    case ScopeClass::Federation:
      return "federation";
    case ScopeClass::GlobalMutation:
      return "global-mutation";
  }
  return "invalid";
}

std::string_view to_string(DelegationMode mode) noexcept {
  switch (mode) {
    case DelegationMode::Shared:
      return "shared";
    case DelegationMode::Exclusive:
      return "exclusive";
  }
  return "invalid";
}

std::string_view to_string(ConflictKind kind) noexcept {
  switch (kind) {
    case ConflictKind::OverlappingExclusive:
      return "overlapping-exclusive";
    case ConflictKind::AmbiguousPrecedence:
      return "ambiguous-precedence";
    case ConflictKind::ModeMismatch:
      return "mode-mismatch";
    case ConflictKind::DuplicateEvidence:
      return "duplicate-evidence";
    case ConflictKind::ConflictingIdentity:
      return "conflicting-identity";
    case ConflictKind::PrecedenceUnsatisfiable:
      return "precedence-unsatisfiable";
  }
  return "invalid";
}

std::string ScopeGrant::to_string() const {
  return scope.str() + ":" + std::string(fabric_federation::to_string(verb));
}

Status ScopeGrant::encode(Writer& writer) const {
  Status status = writer.identifier(scope.str());
  if (!status.ok()) {
    return status;
  }
  return writer.u8(static_cast<std::uint8_t>(verb));
}

Result<ScopeGrant> ScopeGrant::decode(Reader& reader) {
  auto scope = reader.identifier();
  if (!scope.has_value()) {
    return scope.status();
  }
  // An empty scope encodes "no scope". It occurs in conflict records that are
  // not about a particular grant, and it is a legal value.
  ScopeId parsed_scope;
  if (!scope.value().empty()) {
    auto candidate = ScopeId::parse(scope.value());
    if (!candidate.has_value()) {
      return Status::make(ErrorCode::InvalidArgument, "scope identifier is malformed");
    }
    parsed_scope = std::move(candidate.value());
  }
  auto verb = reader.u8();
  if (!verb.has_value()) {
    return verb.status();
  }
  auto parsed_verb = verb_from_wire(verb.value());
  if (!parsed_verb.has_value()) {
    return parsed_verb.status();
  }
  ScopeGrant grant;
  grant.scope = std::move(parsed_scope);
  grant.verb = parsed_verb.value();
  return grant;
}

void canonicalize_grants(std::vector<ScopeGrant>& grants) { sort_unique(grants); }

bool grants_cover(const std::vector<ScopeGrant>& grants, const ScopeGrant& query) {
  for (const ScopeGrant& candidate : grants) {
    if (candidate.verb != query.verb) {
      continue;
    }
    if (candidate.scope.covers(query.scope)) {
      return true;
    }
  }
  return false;
}

std::vector<ScopeGrant> intersect_grants(const std::vector<ScopeGrant>& left,
                                         const std::vector<ScopeGrant>& right) {
  std::vector<ScopeGrant> out;
  for (const ScopeGrant& candidate : left) {
    for (const ScopeGrant& filter : right) {
      if (candidate.verb != filter.verb) {
        continue;
      }
      if (!filter.scope.covers(candidate.scope)) {
        continue;
      }
      // The concrete side wins so that the result names real scopes even when
      // the filter is a pattern.
      ScopeGrant grant;
      if (candidate.scope.is_wildcard() && !filter.scope.is_wildcard()) {
        grant.scope = filter.scope;
      } else {
        grant.scope = candidate.scope;
      }
      grant.verb = candidate.verb;
      out.push_back(grant);
      break;
    }
  }
  canonicalize_grants(out);
  return out;
}

Status encode_grants(Writer& writer, const std::vector<ScopeGrant>& grants, std::size_t max_count) {
  Status status = writer.count(grants.size(), max_count);
  if (!status.ok()) {
    return status;
  }
  for (const ScopeGrant& grant : grants) {
    status = grant.encode(writer);
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

Result<std::vector<ScopeGrant>> decode_grants(Reader& reader, std::size_t max_count) {
  auto count = reader.count(max_count);
  if (!count.has_value()) {
    return count.status();
  }
  std::vector<ScopeGrant> grants;
  grants.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto grant = ScopeGrant::decode(reader);
    if (!grant.has_value()) {
      return grant.status();
    }
    grants.push_back(std::move(grant.value()));
  }
  return grants;
}

std::string render_grants(const std::vector<ScopeGrant>& grants) {
  std::string out;
  for (std::size_t i = 0; i < grants.size(); ++i) {
    if (i != 0) {
      out.append(", ");
    }
    out.append(grants[i].to_string());
  }
  if (out.empty()) {
    out = "(none)";
  }
  return out;
}

Digest digest_grants(const std::vector<ScopeGrant>& grants) {
  Writer writer;
  std::vector<ScopeGrant> copy = grants;
  canonicalize_grants(copy);
  if (!encode_grants(writer, copy, kMaxScopesPerMember).ok()) {
    return Digest();
  }
  return writer.sha256();
}

Status DelegationTerms::encode(Writer& writer) const {
  Status status = grant.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = writer.u8(static_cast<std::uint8_t>(mode));
  if (!status.ok()) {
    return status;
  }
  status = writer.u32(weight);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(not_after.value());
  if (!status.ok()) {
    return status;
  }
  return writer.identifier(constraint.str());
}

Result<DelegationTerms> DelegationTerms::decode(Reader& reader) {
  auto grant = ScopeGrant::decode(reader);
  if (!grant.has_value()) {
    return grant.status();
  }
  auto mode = reader.u8();
  if (!mode.has_value()) {
    return mode.status();
  }
  if (mode.value() > static_cast<std::uint8_t>(DelegationMode::Exclusive)) {
    return Status::make(ErrorCode::InvalidArgument, "delegation mode is out of range");
  }
  auto weight = reader.u32();
  if (!weight.has_value()) {
    return weight.status();
  }
  auto not_after = reader.u64();
  if (!not_after.has_value()) {
    return not_after.status();
  }
  auto constraint = reader.identifier();
  if (!constraint.has_value()) {
    return constraint.status();
  }
  DelegationTerms terms;
  terms.grant = std::move(grant.value());
  terms.mode = static_cast<DelegationMode>(mode.value());
  terms.weight = weight.value();
  terms.not_after = Tick(not_after.value());
  if (!constraint.value().empty()) {
    auto parsed = ConstraintToken::parse(constraint.value());
    if (!parsed.has_value()) {
      return Status::make(ErrorCode::InvalidArgument, "constraint token is malformed");
    }
    terms.constraint = std::move(parsed.value());
  }
  return terms;
}

std::string DelegationTerms::to_string() const {
  std::string out = grant.to_string();
  out.append(" ");
  out.append(fabric_federation::to_string(mode));
  out.append(" weight=");
  out.append(std::to_string(weight));
  if (!not_after.is_zero()) {
    out.append(" not_after=");
    out.append(std::to_string(not_after.value()));
  }
  if (!constraint.empty()) {
    out.append(" constraint=");
    out.append(constraint.str());
  }
  return out;
}

void canonicalize_terms(std::vector<DelegationTerms>& terms) { sort_unique(terms); }

Status encode_terms(Writer& writer, const std::vector<DelegationTerms>& terms,
                    std::size_t max_count) {
  Status status = writer.count(terms.size(), max_count);
  if (!status.ok()) {
    return status;
  }
  for (const DelegationTerms& term : terms) {
    status = term.encode(writer);
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

Result<std::vector<DelegationTerms>> decode_terms(Reader& reader, std::size_t max_count) {
  auto count = reader.count(max_count);
  if (!count.has_value()) {
    return count.status();
  }
  std::vector<DelegationTerms> terms;
  terms.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto term = DelegationTerms::decode(reader);
    if (!term.has_value()) {
      return term.status();
    }
    terms.push_back(std::move(term.value()));
  }
  return terms;
}

Digest digest_terms(const std::vector<DelegationTerms>& terms) {
  Writer writer;
  std::vector<DelegationTerms> copy = terms;
  canonicalize_terms(copy);
  if (!encode_terms(writer, copy, kMaxDelegationTermsPerMember).ok()) {
    return Digest();
  }
  return writer.sha256();
}

std::string ConflictRecord::to_string() const {
  std::string out = std::string(fabric_federation::to_string(kind));
  out.append(" on ");
  out.append(grant.to_string());
  out.append(" claimants=[");
  for (std::size_t i = 0; i < claimants.size(); ++i) {
    if (i != 0) {
      out.append(",");
    }
    out.append(claimants[i].to_string());
  }
  out.append("]");
  if (!detail.empty()) {
    out.append(" ");
    out.append(detail);
  }
  return out;
}

void canonicalize_conflicts(std::vector<ConflictRecord>& conflicts) {
  for (ConflictRecord& conflict : conflicts) {
    std::sort(conflict.claimants.begin(), conflict.claimants.end());
    conflict.claimants.erase(std::unique(conflict.claimants.begin(), conflict.claimants.end()),
                             conflict.claimants.end());
  }
  sort_unique(conflicts);
}

Status encode_conflicts(Writer& writer, const std::vector<ConflictRecord>& conflicts,
                        std::size_t max_count) {
  Status status = writer.count(conflicts.size(), max_count);
  if (!status.ok()) {
    return status;
  }
  for (const ConflictRecord& conflict : conflicts) {
    status = conflict.grant.encode(writer);
    if (!status.ok()) {
      return status;
    }
    status = writer.u8(static_cast<std::uint8_t>(conflict.kind));
    if (!status.ok()) {
      return status;
    }
    status = writer.count(conflict.claimants.size(), kMaxMembers);
    if (!status.ok()) {
      return status;
    }
    for (const MemberId& member : conflict.claimants) {
      status = writer.id16(member.bytes());
      if (!status.ok()) {
        return status;
      }
    }
    status = writer.text(conflict.detail, kMaxTextLength);
    if (!status.ok()) {
      return status;
    }
  }
  return Status::success();
}

Result<std::vector<ConflictRecord>> decode_conflicts(Reader& reader, std::size_t max_count) {
  auto count = reader.count(max_count);
  if (!count.has_value()) {
    return count.status();
  }
  std::vector<ConflictRecord> conflicts;
  conflicts.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto grant = ScopeGrant::decode(reader);
    if (!grant.has_value()) {
      return grant.status();
    }
    auto kind = reader.u8();
    if (!kind.has_value()) {
      return kind.status();
    }
    if (kind.value() > static_cast<std::uint8_t>(ConflictKind::PrecedenceUnsatisfiable)) {
      return Status::make(ErrorCode::InvalidArgument, "conflict kind is out of range");
    }
    auto claimants = reader.count(kMaxMembers);
    if (!claimants.has_value()) {
      return claimants.status();
    }
    ConflictRecord conflict;
    conflict.grant = std::move(grant.value());
    conflict.kind = static_cast<ConflictKind>(kind.value());
    conflict.claimants.reserve(claimants.value());
    for (std::uint32_t k = 0; k < claimants.value(); ++k) {
      auto id = reader.id16();
      if (!id.has_value()) {
        return id.status();
      }
      conflict.claimants.push_back(MemberId::from_bytes(id.value()));
    }
    auto detail = reader.text(kMaxTextLength);
    if (!detail.has_value()) {
      return detail.status();
    }
    conflict.detail = std::move(detail.value());
    conflicts.push_back(std::move(conflict));
  }
  return conflicts;
}

Digest digest_conflicts(const std::vector<ConflictRecord>& conflicts) {
  Writer writer;
  std::vector<ConflictRecord> copy = conflicts;
  canonicalize_conflicts(copy);
  if (!encode_conflicts(writer, copy, kMaxConflicts).ok()) {
    return Digest();
  }
  return writer.sha256();
}

// ---------------------------------------------------------------------------
// ScopeCatalog
// ---------------------------------------------------------------------------

ScopeCatalog::ScopeCatalog() = default;

void ScopeCatalog::add(ScopeDescriptor descriptor) {
  for (ScopeDescriptor& existing : entries_) {
    if (existing.scope == descriptor.scope) {
      existing = std::move(descriptor);
      std::sort(entries_.begin(), entries_.end());
      return;
    }
  }
  entries_.push_back(std::move(descriptor));
  std::sort(entries_.begin(), entries_.end());
}

const ScopeDescriptor* ScopeCatalog::find(const ScopeId& scope) const {
  for (const ScopeDescriptor& descriptor : entries_) {
    if (descriptor.scope == scope) {
      return &descriptor;
    }
  }
  return nullptr;
}

ScopeClass ScopeCatalog::classify(const ScopeId& scope, bool& known) const {
  if (scope.is_wildcard()) {
    known = false;
    return ScopeClass::Federation;
  }
  if (const ScopeDescriptor* descriptor = find(scope)) {
    known = true;
    return descriptor->scope_class;
  }
  // Everything under the member's own domain namespace is local authority. This
  // is a structural rule, not a name heuristic: the federation never has a
  // catalogue entry under this prefix.
  if (scope.str().size() > 7 && scope.str().compare(0, 7, "domain.") == 0) {
    known = true;
    return ScopeClass::Local;
  }
  known = false;
  return ScopeClass::Federation;
}

Digest ScopeCatalog::digest() const {
  Writer writer;
  std::vector<ScopeDescriptor> sorted = entries_;
  std::sort(sorted.begin(), sorted.end());
  if (!writer.count(sorted.size(), kMaxPolicyRules).ok()) {
    return Digest();
  }
  for (const ScopeDescriptor& descriptor : sorted) {
    if (!writer.identifier(descriptor.scope.str()).ok()) {
      return Digest();
    }
    if (!writer.u8(static_cast<std::uint8_t>(descriptor.scope_class)).ok()) {
      return Digest();
    }
    if (!writer.text(descriptor.description, kMaxShortTextLength).ok()) {
      return Digest();
    }
  }
  return writer.sha256();
}

const ScopeCatalog& ScopeCatalog::builtin() {
  static const ScopeCatalog catalog = [] {
    ScopeCatalog built;
    const auto add = [&built](const char* name, ScopeClass scope_class, const char* description) {
      auto scope = ScopeId::parse(name);
      if (!scope.has_value()) {
        return;
      }
      ScopeDescriptor descriptor;
      descriptor.scope = std::move(scope.value());
      descriptor.scope_class = scope_class;
      descriptor.description = description;
      built.add(std::move(descriptor));
    };
    add("federation.membership.observe", ScopeClass::Federation,
        "read membership records for the federation");
    add("federation.membership.propose", ScopeClass::Federation,
        "sponsor a candidate member");
    add("federation.membership.admit", ScopeClass::GlobalMutation,
        "change the membership set of the federation");
    add("federation.delegation.observe", ScopeClass::Federation,
        "read delegation terms held across the federation");
    add("federation.delegation.grant", ScopeClass::GlobalMutation,
        "change the delegation terms held across the federation");
    add("federation.policy.observe", ScopeClass::Federation, "read the federation policy");
    add("federation.policy.endorse", ScopeClass::Federation,
        "endorse a policy revision without adopting it");
    add("federation.policy.adopt", ScopeClass::GlobalMutation,
        "adopt a policy revision for the federation");
    add("federation.epoch.observe", ScopeClass::Federation, "read the federation epoch");
    add("federation.epoch.advance", ScopeClass::GlobalMutation,
        "advance the federation epoch");
    add("federation.route.advertise", ScopeClass::GlobalMutation,
        "publish reachability advertisements consumed federation-wide");
    add("federation.route.observe", ScopeClass::Federation, "read federation-wide advertisements");
    add("federation.capacity.publish", ScopeClass::Federation,
        "publish capacity statements for the federation");
    add("federation.health.report", ScopeClass::Federation, "publish health statements");
    add("federation.evidence.attest", ScopeClass::Federation,
        "attest another member's declared identity");
    add("federation.lease.observe", ScopeClass::Federation, "read federation leases");
    return built;
  }();
  return catalog;
}

}  // namespace fabric_federation
