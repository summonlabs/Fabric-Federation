// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Member identity and constitution.
//
// A member's authority is always bound to an exact (generation, incarnation,
// digest) triple:
//   * generation  - the revision of the constitution below,
//   * incarnation - one run of the member's controller process,
//   * digest      - the canonical digest of the constitution bytes.
// Any change to any of the three invalidates authority that was granted against
// an earlier triple. That is the mechanism that fences reincarnation and
// re-generation; it is not an optimisation.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/capability.hpp"
#include "fabric_federation/codec.hpp"
#include "fabric_federation/digest.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/export.hpp"
#include "fabric_federation/ids.hpp"
#include "fabric_federation/scope.hpp"

namespace fabric_federation {

// Membership lifecycle. Fenced is the isolated/fenced state: the member keeps
// every bit of its local authority and loses all federation-derived authority.
enum class MemberLifecycleState : std::uint8_t {
  Absent = 0,
  Proposed = 1,
  Admitted = 2,
  Active = 3,
  Degraded = 4,
  Fenced = 5,
  Leaving = 6,
  Retired = 7,
};

[[nodiscard]] FFED_API std::string_view to_string(MemberLifecycleState state) noexcept;
[[nodiscard]] FFED_API bool lifecycle_holds_federation_authority(
    MemberLifecycleState state) noexcept;
[[nodiscard]] FFED_API bool lifecycle_is_terminal(MemberLifecycleState state) noexcept;

// A member's full, canonical self-description. The digest of this structure is
// the "digest" half of the identity triple.
struct MemberConstitution {
  FabricDomainId domain;
  MemberId member;
  Generation generation;
  std::uint32_t software_major = 0;
  std::uint32_t software_minor = 0;
  std::uint32_t software_patch = 0;
  std::vector<CapabilityStatement> capabilities;
  std::vector<CapabilityRequirement> requirements;
  // Authority the member keeps. Never derived from the federation, and never
  // changed by joining or leaving.
  std::vector<ScopeGrant> retained;
  // Authority the member offers. Must be disjoint from the retained set and
  // must not touch the member's own domain namespace.
  std::vector<DelegationTerms> delegated;
  std::string description;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<MemberConstitution> decode(Reader& reader);
  [[nodiscard]] Digest digest() const;
  [[nodiscard]] std::string digest_hex() const { return digest().to_hex(); }
  void canonicalize();
  [[nodiscard]] std::string to_string() const;
};

// Structural validation. This is what makes "joining never transfers everything"
// checkable rather than aspirational:
//   * retained and delegated authority must be disjoint,
//   * a member may not delegate anything inside its own domain namespace,
//   * a delegated scope must exist in the catalogue and must not be Local,
//   * every collection is bounded and canonical.
[[nodiscard]] FFED_API Status validate_constitution(const MemberConstitution& constitution,
                                                    const ScopeCatalog& catalog);

// The runtime identity a controller presents right now.
struct MemberIdentity {
  FabricDomainId domain;
  MemberId member;
  Generation generation;
  Incarnation incarnation;
  Digest constitution;
  NodeId node;
  Tick started_at;
  // Set when the identity is known to be a previous run of the same member.
  bool reincarnated = false;

  friend bool operator==(const MemberIdentity& a, const MemberIdentity& b) noexcept {
    return a.domain == b.domain && a.member == b.member && a.generation == b.generation &&
           a.incarnation == b.incarnation && a.constitution == b.constitution && a.node == b.node &&
           a.started_at == b.started_at && a.reincarnated == b.reincarnated;
  }
  friend bool operator!=(const MemberIdentity& a, const MemberIdentity& b) noexcept {
    return !(a == b);
  }
  friend bool operator<(const MemberIdentity& a, const MemberIdentity& b) noexcept {
    if (a.member != b.member) {
      return a.member < b.member;
    }
    if (a.generation != b.generation) {
      return a.generation < b.generation;
    }
    if (a.incarnation != b.incarnation) {
      return a.incarnation < b.incarnation;
    }
    if (a.constitution != b.constitution) {
      return a.constitution < b.constitution;
    }
    if (a.node != b.node) {
      return a.node < b.node;
    }
    if (a.domain != b.domain) {
      return a.domain < b.domain;
    }
    if (a.started_at != b.started_at) {
      return a.started_at < b.started_at;
    }
    return a.reincarnated < b.reincarnated;
  }

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<MemberIdentity> decode(Reader& reader);
  [[nodiscard]] std::string to_string() const;
  [[nodiscard]] Digest digest() const;

  // True when both identities name the same member in the same domain. The
  // generation and incarnation may still differ.
  [[nodiscard]] bool same_lineage(const MemberIdentity& other) const noexcept {
    return member == other.member && domain == other.domain;
  }
};

// Detailed identity comparison used by the authority evaluator and by the
// explanation it produces.
enum class IdentityMismatch : std::uint8_t {
  None = 0,
  Member,
  Domain,
  Generation,
  Incarnation,
  Constitution,
  Node,
};

[[nodiscard]] FFED_API std::string_view to_string(IdentityMismatch mismatch) noexcept;
[[nodiscard]] FFED_API IdentityMismatch compare_identities(const MemberIdentity& expected,
                                                           const MemberIdentity& presented) noexcept;

struct MemberDeclaration {
  MemberConstitution constitution;
  Incarnation incarnation;
  NodeId node;
  Tick declared_at;

  [[nodiscard]] MemberIdentity identity() const;
  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<MemberDeclaration> decode(Reader& reader);
  [[nodiscard]] std::string to_string() const;
};

// Membership slot accounting. A slot is (member, lineage): leaving ends a
// lineage, and rejoining starts the next one, so a rejoin can never reuse an
// earlier admission record.
struct MembershipSlot {
  MemberId member;
  Lineage lineage;
  // Hard identity of the lineage: derived from (member, lineage).
  LineageId lineage_id;

  [[nodiscard]] static MembershipSlot make(const MemberId& member, Lineage lineage);
  friend bool operator==(const MembershipSlot& a, const MembershipSlot& b) noexcept {
    return a.member == b.member && a.lineage == b.lineage && a.lineage_id == b.lineage_id;
  }
  friend bool operator<(const MembershipSlot& a, const MembershipSlot& b) noexcept {
    if (a.member != b.member) {
      return a.member < b.member;
    }
    return a.lineage < b.lineage;
  }
};

}  // namespace fabric_federation
