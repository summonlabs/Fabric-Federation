// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Scopes, authority verbs, delegation terms and the scope catalogue.
//
// A grant is a (scope, verb) pair. Membership never transfers "everything": a
// member declares exactly which grants it retains locally and exactly which it
// delegates, and the two sets must be disjoint. The catalogue classifies each
// federation scope, and classifies everything the catalogue does not know as
// unknown, which the authority evaluator reports as UNSUPPORTED rather than
// quietly ignoring.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/codec.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/export.hpp"
#include "fabric_federation/ids.hpp"
#include "fabric_federation/names.hpp"

namespace fabric_federation {

enum class AuthorityVerb : std::uint8_t {
  Observe = 0,
  Write = 1,
  Mutate = 2,
  Administer = 3,
};

[[nodiscard]] FFED_API std::string_view to_string(AuthorityVerb verb) noexcept;
[[nodiscard]] FFED_API bool parse_verb(std::string_view text, AuthorityVerb& out) noexcept;
[[nodiscard]] FFED_API Result<AuthorityVerb> verb_from_wire(std::uint8_t value);

enum class ScopeClass : std::uint8_t {
  // Authority that never leaves the member. The federation cannot grant it and
  // cannot take it away.
  Local = 0,
  // Authority a member may delegate to the federation for observation or
  // bounded writes.
  Federation = 1,
  // Authority that changes federation-wide state. Suspended for every member
  // while a partition is observed or while the federation is reconciling.
  GlobalMutation = 2,
};

[[nodiscard]] FFED_API std::string_view to_string(ScopeClass scope_class) noexcept;

struct ScopeDescriptor {
  ScopeId scope;
  ScopeClass scope_class = ScopeClass::Local;
  std::string description;

  friend bool operator==(const ScopeDescriptor& a, const ScopeDescriptor& b) noexcept {
    return a.scope == b.scope && a.scope_class == b.scope_class && a.description == b.description;
  }
  friend bool operator<(const ScopeDescriptor& a, const ScopeDescriptor& b) noexcept {
    return a.scope < b.scope;
  }
};

// A single unit of authority: a scope and a verb over it.
struct ScopeGrant {
  ScopeId scope;
  AuthorityVerb verb = AuthorityVerb::Observe;

  friend bool operator==(const ScopeGrant& a, const ScopeGrant& b) noexcept {
    return a.scope == b.scope && a.verb == b.verb;
  }
  friend bool operator!=(const ScopeGrant& a, const ScopeGrant& b) noexcept { return !(a == b); }
  friend bool operator<(const ScopeGrant& a, const ScopeGrant& b) noexcept {
    if (a.scope != b.scope) {
      return a.scope < b.scope;
    }
    return static_cast<std::uint8_t>(a.verb) < static_cast<std::uint8_t>(b.verb);
  }

  [[nodiscard]] std::string to_string() const;
  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<ScopeGrant> decode(Reader& reader);
};

// Sort and remove duplicates. Every collection of grants stored in the model is
// canonicalised so that two processes holding the same set encode identically.
FFED_API void canonicalize_grants(std::vector<ScopeGrant>& grants);
// Pattern-aware containment: true when some grant in the set covers the query.
[[nodiscard]] FFED_API bool grants_cover(const std::vector<ScopeGrant>& grants,
                                         const ScopeGrant& query);
// Set intersection, keeping concrete entries from the left side only when the
// right side covers them. The result is canonicalised.
[[nodiscard]] FFED_API std::vector<ScopeGrant> intersect_grants(
    const std::vector<ScopeGrant>& left, const std::vector<ScopeGrant>& right);

[[nodiscard]] FFED_API Status encode_grants(Writer& writer, const std::vector<ScopeGrant>& grants,
                                            std::size_t max_count);
[[nodiscard]] FFED_API Result<std::vector<ScopeGrant>> decode_grants(Reader& reader,
                                                                    std::size_t max_count);
[[nodiscard]] FFED_API std::string render_grants(const std::vector<ScopeGrant>& grants);
[[nodiscard]] FFED_API Digest digest_grants(const std::vector<ScopeGrant>& grants);

enum class DelegationMode : std::uint8_t {
  // Several members may hold the same grant at the same time with identical
  // terms. Shared holders do not outrank each other.
  Shared = 0,
  // Exactly one member may hold the grant. A second exclusive claim is a
  // conflict, never a replacement.
  Exclusive = 1,
};

[[nodiscard]] FFED_API std::string_view to_string(DelegationMode mode) noexcept;

// The exact terms a member offers to the federation for one grant.
struct DelegationTerms {
  ScopeGrant grant;
  DelegationMode mode = DelegationMode::Shared;
  // Weight is meaningful only for Shared holdings. Two shared holdings of the
  // same grant with different weights are ambiguous and conflict; the runtime
  // never breaks the tie by recency.
  std::uint32_t weight = 1;
  // 0 means the terms do not expire.
  Tick not_after;
  ConstraintToken constraint;

  friend bool operator==(const DelegationTerms& a, const DelegationTerms& b) noexcept {
    return a.grant == b.grant && a.mode == b.mode && a.weight == b.weight &&
           a.not_after == b.not_after && a.constraint == b.constraint;
  }
  friend bool operator<(const DelegationTerms& a, const DelegationTerms& b) noexcept {
    if (a.grant != b.grant) {
      return a.grant < b.grant;
    }
    if (a.mode != b.mode) {
      return static_cast<std::uint8_t>(a.mode) < static_cast<std::uint8_t>(b.mode);
    }
    if (a.weight != b.weight) {
      return a.weight < b.weight;
    }
    if (a.not_after != b.not_after) {
      return a.not_after < b.not_after;
    }
    return a.constraint < b.constraint;
  }

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<DelegationTerms> decode(Reader& reader);
  [[nodiscard]] std::string to_string() const;
};

FFED_API void canonicalize_terms(std::vector<DelegationTerms>& terms);
[[nodiscard]] FFED_API Status encode_terms(Writer& writer, const std::vector<DelegationTerms>& terms,
                                           std::size_t max_count);
[[nodiscard]] FFED_API Result<std::vector<DelegationTerms>> decode_terms(Reader& reader,
                                                                        std::size_t max_count);
[[nodiscard]] FFED_API Digest digest_terms(const std::vector<DelegationTerms>& terms);

enum class ConflictKind : std::uint8_t {
  // Two or more members hold overlapping exclusive authority over one grant.
  OverlappingExclusive = 0,
  // Shared holdings of the same grant disagree on weight, so no holder can be
  // ordered ahead of another without inventing a rule.
  AmbiguousPrecedence = 1,
  // Shared and exclusive holdings of the same grant coexist.
  ModeMismatch = 2,
  // The same evidence identifier arrived twice with different content.
  DuplicateEvidence = 3,
  // Two different declarations claim the same member identity.
  ConflictingIdentity = 4,
  // A configured precedence rule names a member that cannot take precedence.
  PrecedenceUnsatisfiable = 5,
};

[[nodiscard]] FFED_API std::string_view to_string(ConflictKind kind) noexcept;

struct ConflictRecord {
  ScopeGrant grant;
  ConflictKind kind = ConflictKind::OverlappingExclusive;
  std::vector<MemberId> claimants;
  std::string detail;

  friend bool operator==(const ConflictRecord& a, const ConflictRecord& b) noexcept {
    return a.grant == b.grant && a.kind == b.kind && a.claimants == b.claimants &&
           a.detail == b.detail;
  }
  friend bool operator<(const ConflictRecord& a, const ConflictRecord& b) noexcept {
    if (a.grant != b.grant) {
      return a.grant < b.grant;
    }
    if (a.kind != b.kind) {
      return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
    }
    if (a.claimants != b.claimants) {
      return a.claimants < b.claimants;
    }
    return a.detail < b.detail;
  }

  [[nodiscard]] std::string to_string() const;
};

FFED_API void canonicalize_conflicts(std::vector<ConflictRecord>& conflicts);
[[nodiscard]] FFED_API Status encode_conflicts(Writer& writer,
                                               const std::vector<ConflictRecord>& conflicts,
                                               std::size_t max_count);
[[nodiscard]] FFED_API Result<std::vector<ConflictRecord>> decode_conflicts(Reader& reader,
                                                                           std::size_t max_count);
[[nodiscard]] FFED_API Digest digest_conflicts(const std::vector<ConflictRecord>& conflicts);

// The catalogue of scopes this runtime understands.
class FFED_API ScopeCatalog {
 public:
  ScopeCatalog();

  void add(ScopeDescriptor descriptor);
  [[nodiscard]] const ScopeDescriptor* find(const ScopeId& scope) const;
  // Classification for a concrete (non-wildcard) scope. Sets known=false when
  // the catalogue has no entry for it.
  [[nodiscard]] ScopeClass classify(const ScopeId& scope, bool& known) const;
  [[nodiscard]] const std::vector<ScopeDescriptor>& entries() const noexcept { return entries_; }
  [[nodiscard]] Digest digest() const;

  // The catalogue shipped with this version. It is deliberately small and
  // explicit; nothing is inferred from a scope's name.
  [[nodiscard]] static const ScopeCatalog& builtin();

 private:
  std::vector<ScopeDescriptor> entries_;
};

}  // namespace fabric_federation
