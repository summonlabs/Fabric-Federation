// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Accepted evidence: the artefact model.
//
// Federation state is a pure function of a set of artefacts. It is not a
// sequence of mutations: applying the same artefact set in any arrival order
// produces the same derived state and the same canonical digest. That property
// is what makes "equivalent accepted evidence yields deterministic logical
// state" testable rather than aspirational.
//
// An artefact is an envelope (who issued it, about whom, in which epoch) plus a
// typed body. The envelope carries the canonical digest of the body, so a
// tampered or truncated body is detected before it can influence state.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/capability.hpp"
#include "fabric_federation/codec.hpp"
#include "fabric_federation/digest.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/explanation.hpp"
#include "fabric_federation/export.hpp"
#include "fabric_federation/ids.hpp"
#include "fabric_federation/identity.hpp"
#include "fabric_federation/partition.hpp"
#include "fabric_federation/policy.hpp"
#include "fabric_federation/scope.hpp"

namespace fabric_federation {

enum class ArtifactKind : std::uint16_t {
  // Bootstrap. Recorded by the coordinator operator. Explicitly single-party:
  // it establishes a founder and nothing else, and it can only appear as the
  // first artefact of a federation.
  FederationGenesis = 0,
  // A new policy revision.
  PolicyUpdate = 1,
  // A member asks to join. Issued by an already-active member (the sponsor) or,
  // for the founder, by the bootstrap path.
  MembershipProposal = 2,
  // The candidate consents, echoing the exact identity it was proposed with.
  MembershipAcceptance = 3,
  // A third party attests the candidate's identity. Never issued by the
  // candidate or by the sponsor.
  MembershipEndorsement = 4,
  // Coordinator decision record: policy was satisfied for an exact identity.
  MembershipAdmission = 5,
  // Coordinator decision record: the member is active at a given epoch.
  MembershipActivation = 6,
  // A member (re)declares the terms it offers.
  DelegationDeclaration = 7,
  // A member withdraws delegated authority. Takes effect immediately and fences
  // every lease and activation bound to those grants.
  DelegationWithdrawal = 8,
  // A member leaves. Local authority is untouched; federation authority ends.
  MembershipLeave = 9,
  // Coordinator or self-initiated fence. Always permitted: fencing reduces
  // authority and therefore never needs multi-party agreement.
  MembershipFence = 10,
  // Coordinator record ending a lineage.
  MembershipRetirement = 11,
  // A member re-declares its identity after reincarnation or after a partition.
  MemberReattestation = 12,
  // Lease lifecycle records.
  LeaseIssued = 13,
  LeaseRevoked = 14,
  // Coordinator record advancing the federation epoch.
  EpochAdvance = 15,
  // Coordinator record that reconciliation finished for an epoch.
  ReconciliationComplete = 16,
  // A member reports what it could reach.
  PartitionReport = 17,
  // Logical clock advance. Recorded so that replaying the same artefact set
  // reproduces the same tick values.
  TimeAdvance = 18,
};

[[nodiscard]] FFED_API std::string_view to_string(ArtifactKind kind) noexcept;
[[nodiscard]] FFED_API bool parse_artifact_kind(std::string_view text, ArtifactKind& out) noexcept;

struct Provenance {
  NodeId node;
  // Nil for coordinator-issued artefacts.
  MemberId member;
  Generation generation;
  Incarnation incarnation;
  // The issuer's constitution digest at the moment it issued the artefact. A
  // decision can therefore name the exact revision of every party that
  // contributed to it, rather than only the revision it happens to hold now.
  Digest constitution;
  Epoch epoch;
  Tick issued_at;

  friend bool operator==(const Provenance& a, const Provenance& b) noexcept {
    return a.node == b.node && a.member == b.member && a.generation == b.generation &&
           a.incarnation == b.incarnation && a.constitution == b.constitution &&
           a.epoch == b.epoch && a.issued_at == b.issued_at;
  }
  friend bool operator<(const Provenance& a, const Provenance& b) noexcept {
    if (a.member != b.member) {
      return a.member < b.member;
    }
    if (a.node != b.node) {
      return a.node < b.node;
    }
    if (a.epoch != b.epoch) {
      return a.epoch < b.epoch;
    }
    if (a.incarnation != b.incarnation) {
      return a.incarnation < b.incarnation;
    }
    if (a.generation != b.generation) {
      return a.generation < b.generation;
    }
    return a.issued_at < b.issued_at;
  }

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<Provenance> decode(Reader& reader);
  [[nodiscard]] std::string to_string() const;
};

struct ArtifactEnvelope {
  EvidenceId evidence;
  ArtifactKind kind = ArtifactKind::FederationGenesis;
  FederationId federation;
  // The member this artefact is about. Nil for federation-level artefacts.
  MemberId subject;
  Provenance issuer;
  // Canonical digest of the body. Verified on decode and on submit.
  Digest body_digest;

  friend bool operator==(const ArtifactEnvelope& a, const ArtifactEnvelope& b) noexcept {
    return a.evidence == b.evidence && a.kind == b.kind && a.federation == b.federation &&
           a.subject == b.subject && a.issuer == b.issuer && a.body_digest == b.body_digest;
  }

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<ArtifactEnvelope> decode(Reader& reader);
  [[nodiscard]] std::string to_string() const;
};

struct FederationGenesis {
  FederationId federation;
  NodeId coordinator;
  MemberDeclaration founder;
  // Authority granted to the founder by the bootstrap record. Bounded by
  // policy: the bootstrap path may not grant more than the catalogue allows.
  std::vector<ScopeGrant> founder_grants;
  FederationPolicy policy;
  std::string description;
  Tick created_at;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<FederationGenesis> decode(Reader& reader);
  [[nodiscard]] std::string to_string() const;
};

// The body of an artefact. One structure carries every field any artefact kind
// can use; validate_artifact_body() rejects an artefact that sets a field its
// kind does not define, so the encoding stays canonical and an out-of-place
// field cannot be smuggled through.
struct ArtifactBody {
  // ---- declarations -------------------------------------------------------
  MemberDeclaration declaration;
  MemberIdentity declared_identity;
  FederationGenesis genesis;
  FederationPolicy policy;

  // ---- federation context -------------------------------------------------
  Epoch epoch;
  Generation policy_generation;
  Digest policy_digest;

  // ---- membership bookkeeping --------------------------------------------
  Lineage lineage;
  std::vector<MemberId> parties;
  std::size_t required_endorsements = 0;
  std::size_t required_distinct_parties = 0;

  // ---- delegation ---------------------------------------------------------
  std::vector<DelegationTerms> delegated_terms;
  std::vector<ScopeGrant> withdrawn_grants;

  // ---- lease --------------------------------------------------------------
  LeaseId lease;
  MemberIdentity lease_holder;
  std::vector<ScopeGrant> lease_scopes;
  Epoch lease_issued_epoch;
  Epoch lease_not_after_epoch;
  Tick lease_not_after;
  Incarnation lease_issuer_incarnation;

  // ---- partition ----------------------------------------------------------
  std::vector<PeerObservation> observations;
  std::vector<MemberId> unreachable_members;

  // ---- decision record ----------------------------------------------------
  Outcome outcome = Outcome::Unknown;
  ReasonCode reason_code = ReasonCode::EvidenceUnknown;
  ReasonCode fence_reason = ReasonCode::EvidenceUnknown;
  std::string reason_text;

  // ---- logical clock ------------------------------------------------------
  Tick logical_time;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<ArtifactBody> decode(Reader& reader);
  [[nodiscard]] Digest digest() const;
  [[nodiscard]] std::string to_string() const;
};

struct Artifact {
  ArtifactEnvelope envelope;
  ArtifactBody body;

  [[nodiscard]] Digest digest() const;
  // Recomputes the body digest and compares it with the envelope.
  [[nodiscard]] Status verify_digest() const;
  // Structural validation of the body against its kind, plus bounds.
  [[nodiscard]] Status validate(const ScopeCatalog& catalog) const;
  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<Artifact> decode(Reader& reader);
  // Builds an artefact, computing the body digest.
  [[nodiscard]] static Artifact make(ArtifactEnvelope envelope, ArtifactBody body);
  [[nodiscard]] std::string to_string() const;
};

FFED_API void canonicalize_body(ArtifactBody& body);

// True for kinds the coordinator may issue on its own authority. Every other
// kind must be issued by a member.
[[nodiscard]] FFED_API bool artifact_kind_is_coordinator_issued(ArtifactKind kind) noexcept;
// True for kinds the coordinator will never accept from a member connection.
[[nodiscard]] FFED_API bool artifact_kind_requires_coordinator(ArtifactKind kind) noexcept;

}  // namespace fabric_federation
