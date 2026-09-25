// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Provenance of a decision.
//
// Every outcome this runtime produces carries the reason list, the contributing
// members with their exact generations, incarnations and digests, the scopes
// that were considered, the conflicts that were found and the quality of the
// evidence that was available. A decision without provenance is not produced:
// the explanation is part of the decision digest.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/codec.hpp"
#include "fabric_federation/digest.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/export.hpp"
#include "fabric_federation/ids.hpp"
#include "fabric_federation/scope.hpp"

namespace fabric_federation {

enum class ReasonCode : std::uint16_t {
  // ---- membership ---------------------------------------------------------
  MembershipActive = 0,
  MembershipAdmittedPendingActivation,
  MembershipProposedInsufficientEvidence,
  MembershipAbsent,
  MembershipRetired,
  MembershipLeaving,
  MembershipFencedByOrder,
  MembershipRequiresReattestation,
  MembershipDegradedObservationGap,
  // ---- multi-party requirement -------------------------------------------
  MultiPartySatisfied,
  MultiPartyInsufficientDistinctParties,
  MultiPartyInsufficientEndorsements,
  MultiPartyEndorserNotActive,
  MultiPartyProposerNotActive,
  MultiPartySelfProposalRejected,
  MultiPartyBootstrapGenesis,
  // ---- identity -----------------------------------------------------------
  IdentityMatches,
  IdentityGenerationStale,
  IdentityIncarnationStale,
  IdentityConstitutionStale,
  IdentityDomainMismatch,
  IdentityMemberUnknown,
  // ---- generation change and consent -------------------------------------
  GenerationChangeRequiresReconsent,
  GenerationChangeAcceptedByPolicy,
  // ---- scopes and delegation ---------------------------------------------
  ScopeCoveredByDelegation,
  ScopeNotDelegated,
  ScopeRetainedLocalAuthority,
  ScopeUnknownToCatalogue,
  ScopeDelegationForbiddenByPolicy,
  ScopeVerbNotDelegated,
  ScopeLocalAuthorityAlwaysGranted,
  DelegationWithdrawn,
  DelegationExpired,
  DelegationConflictContained,
  DelegationPrecedenceConfigured,
  DelegationPrecedenceUnsatisfiable,
  // ---- leases -------------------------------------------------------------
  LeaseValid,
  LeaseMissing,
  LeaseExpired,
  LeaseRevoked,
  LeaseStaleIssuer,
  LeaseEpochMismatch,
  LeaseHolderMismatch,
  LeaseScopeNotCovered,
  LeaseRequiredByPolicy,
  // ---- epoch --------------------------------------------------------------
  EpochMatches,
  EpochStale,
  EpochAheadOfCoordinator,
  // ---- partition ----------------------------------------------------------
  PartitionConnected,
  PartitionSplitSuspendsGlobalMutation,
  PartitionIndeterminateSuspendsGlobalMutation,
  PartitionReconcilingSuspendsGlobalMutation,
  PartitionObservationStale,
  PartitionReattestationComplete,
  PartitionReattestationMissing,
  // ---- replay -------------------------------------------------------------
  RequestReplayed,
  RequestFresh,
  EvidenceDuplicateIdentical,
  EvidenceDuplicateConflicting,
  // ---- capability ---------------------------------------------------------
  CapabilitySatisfied,
  CapabilityMissing,
  CapabilityIncompatible,
  CapabilityUnsupported,
  // ---- evidence quality ---------------------------------------------------
  EvidenceUnknown,
  EvidenceIncomplete,
  EvidenceInvalid,
  EvidenceIndeterminate,
  EvidenceConflicting,
  // ---- artefact handling --------------------------------------------------
  ArtifactAccepted,
  ArtifactRejected,
  ArtifactDigestMismatch,
  ArtifactSubjectMismatch,
  ArtifactEpochStale,
  ArtifactMalformed,
  ArtifactUnknownKind,
  ArtifactSupersededLineage,
  // ---- policy -------------------------------------------------------------
  PolicyRuleMatched,
  PolicyRuleNotMatched,
  PolicyRejected,
  // ---- federation ---------------------------------------------------------
  FederationUnknown,
  FederationIdentityMismatch,
  // ---- limits -------------------------------------------------------------
  LimitExceeded,
  // Highest valid reason code. Used by decoders to reject out-of-range values.
  MaxReasonCode = LimitExceeded,
};

[[nodiscard]] FFED_API std::string_view to_string(ReasonCode code) noexcept;

struct Reason {
  ReasonCode code = ReasonCode::EvidenceUnknown;
  std::string detail;

  friend bool operator==(const Reason& a, const Reason& b) noexcept {
    return a.code == b.code && a.detail == b.detail;
  }
  friend bool operator<(const Reason& a, const Reason& b) noexcept {
    if (a.code != b.code) {
      return static_cast<std::uint16_t>(a.code) < static_cast<std::uint16_t>(b.code);
    }
    return a.detail < b.detail;
  }
  [[nodiscard]] std::string to_string() const;
};

enum class ContributionRole : std::uint8_t {
  Proposer = 0,
  Candidate = 1,
  Endorser = 2,
  Coordinator = 3,
  Observer = 4,
  Actor = 5,
};

[[nodiscard]] FFED_API std::string_view to_string(ContributionRole role) noexcept;

// One party that contributed to a decision, with the exact revision of its
// identity that the contribution is bound to.
struct Contribution {
  MemberId member;
  ContributionRole role = ContributionRole::Observer;
  Generation generation;
  Incarnation incarnation;
  Digest constitution;
  Digest evidence;
  Epoch epoch;
  bool identity_current = false;
  std::string note;

  friend bool operator<(const Contribution& a, const Contribution& b) noexcept {
    if (a.member != b.member) {
      return a.member < b.member;
    }
    if (a.role != b.role) {
      return static_cast<std::uint8_t>(a.role) < static_cast<std::uint8_t>(b.role);
    }
    if (a.incarnation != b.incarnation) {
      return a.incarnation < b.incarnation;
    }
    if (a.generation != b.generation) {
      return a.generation < b.generation;
    }
    if (a.constitution != b.constitution) {
      return a.constitution < b.constitution;
    }
    return a.evidence < b.evidence;
  }
  friend bool operator==(const Contribution& a, const Contribution& b) noexcept {
    return a.member == b.member && a.role == b.role && a.generation == b.generation &&
           a.incarnation == b.incarnation && a.constitution == b.constitution &&
           a.evidence == b.evidence && a.epoch == b.epoch &&
           a.identity_current == b.identity_current && a.note == b.note;
  }
};

struct Explanation {
  Outcome outcome = Outcome::Unknown;
  EvidenceState evidence = EvidenceState::Unknown;
  std::vector<Reason> reasons;
  std::vector<Contribution> contributions;
  std::vector<ConflictRecord> conflicts;
  std::vector<ScopeGrant> considered_grants;
  std::vector<ScopeGrant> effective_grants;
  bool limit_reached = false;
  std::string summary;

  void add(ReasonCode code, std::string detail);
  // Sorts and de-duplicates every collection so that two processes that reached
  // the same conclusion encode it identically.
  void canonicalize();
  [[nodiscard]] bool has(ReasonCode code) const noexcept;
  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<Explanation> decode(Reader& reader);
  [[nodiscard]] Digest digest() const;
};

// Multi-line human-readable rendering, stable across runs.
[[nodiscard]] FFED_API std::string render_explanation(const Explanation& explanation);
// Single-line rendering used by the CLI's default output.
[[nodiscard]] FFED_API std::string summarize_explanation(const Explanation& explanation);

}  // namespace fabric_federation
