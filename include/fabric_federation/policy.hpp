// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Federation policy.
//
// Policy is provisioned out of band (by whoever operates the coordinator) and
// recorded as a versioned, digest-addressed object. Every rule is explicit:
// nothing is inferred from a name, and a rule kind this version does not
// implement is rejected rather than ignored.
//
// Policy is NOT consensus. Rules such as "require N endorsements" or
// "require M distinct parties" are deterministic evidence-counting rules
// evaluated by one coordinator over the evidence it holds. They do not
// constitute agreement, quorum or fault tolerance, and the runtime never
// claims otherwise.
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

enum class PolicyRuleKind : std::uint8_t {
  // value = number of endorsements required from members other than the
  // proposer and the candidate.
  RequireEndorsements = 0,
  // value = minimum number of distinct member identities that must appear
  // across the admission evidence. Never below 2 for a non-bootstrap member.
  RequireDistinctParties = 1,
  // capability = the requirement every member must satisfy at admission.
  RequireCapability = 2,
  // scope = a scope pattern that may not be delegated at all.
  ForbidScopeDelegation = 3,
  // scope = a scope pattern whose authority requires a federation lease.
  RequireLease = 4,
  // value = 1 to suspend global-mutation authority while a partition is
  // observed. Disabling this rule is possible but is recorded as a policy
  // decision and is reported by the inspection tools.
  SuspendGlobalMutationOnPartition = 5,
  // value = 1 to suspend global-mutation authority while the federation is
  // reconciling after a partition.
  SuspendGlobalMutationWhileReconciling = 6,
  // value = 1 to require mutually confirmed reachability before an edge counts
  // as present in the partition graph.
  RequireMutualReachability = 7,
  // value = maximum lease lifetime in ticks.
  MaxLeaseLifetimeTicks = 8,
  // value = 1 to require fresh consent when a member's generation changes.
  RequireReconsentOnGenerationChange = 9,
  // scope + members = configured precedence for one grant. This is an explicit,
  // pre-agreed ordering, not a recency rule.
  PrecedenceForGrant = 10,
  // value = 1 to require re-attestation from every member after a partition
  // before global-mutation authority resumes.
  RequireReattestationAfterPartition = 11,
  // value = maximum age in ticks of a peer observation before it stops counting
  // as evidence. 0 means observations never expire.
  ObservationFreshnessTicks = 12,
  // value = 1 to allow a member to keep its admission across a generation
  // change (the new generation still requires an activation artefact).
  AllowGenerationChangeWithoutReconsent = 13,
};

[[nodiscard]] FFED_API std::string_view to_string(PolicyRuleKind kind) noexcept;

struct PolicyRule {
  RuleId id;
  PolicyRuleKind kind = PolicyRuleKind::RequireEndorsements;
  bool enabled = true;
  std::uint64_t value = 0;
  ScopeId scope;
  CapabilityRequirement capability;
  std::vector<MemberId> members;
  std::string description;

  friend bool operator==(const PolicyRule& a, const PolicyRule& b) noexcept;
  friend bool operator<(const PolicyRule& a, const PolicyRule& b) noexcept {
    if (a.id != b.id) {
      return a.id < b.id;
    }
    return static_cast<std::uint8_t>(a.kind) < static_cast<std::uint8_t>(b.kind);
  }

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<PolicyRule> decode(Reader& reader);
  [[nodiscard]] std::string to_string() const;
};

struct FederationPolicy {
  PolicyId id;
  Generation generation;
  std::vector<PolicyRule> rules;
  std::string description;

  [[nodiscard]] Status encode(Writer& writer) const;
  [[nodiscard]] static Result<FederationPolicy> decode(Reader& reader);
  [[nodiscard]] Digest digest() const;
  [[nodiscard]] std::string digest_hex() const { return digest().to_hex(); }
  void canonicalize();
  [[nodiscard]] std::string to_string() const;

  // ---- effective parameters, each with a documented default ----------------
  [[nodiscard]] std::size_t required_endorsements() const;
  [[nodiscard]] std::size_t required_distinct_parties() const;
  [[nodiscard]] bool scope_delegation_forbidden(const ScopeId& scope) const;
  [[nodiscard]] bool lease_required(const ScopeGrant& grant) const;
  [[nodiscard]] std::uint64_t max_lease_lifetime_ticks() const;
  [[nodiscard]] bool reconsent_on_generation_change() const;
  [[nodiscard]] bool suspend_global_mutation_on_partition() const;
  [[nodiscard]] bool suspend_global_mutation_while_reconciling() const;
  [[nodiscard]] bool require_mutual_reachability() const;
  [[nodiscard]] bool require_reattestation_after_partition() const;
  [[nodiscard]] std::uint64_t observation_freshness_ticks() const;
  // Returns the configured precedence order for a grant, or nullptr when the
  // policy declares none. A null result means an overlapping exclusive claim is
  // a conflict that the runtime preserves rather than resolves.
  [[nodiscard]] const std::vector<MemberId>* precedence_for(const ScopeGrant& grant) const;
  [[nodiscard]] std::vector<CapabilityRequirement> mandatory_capabilities() const;
  [[nodiscard]] const PolicyRule* find_rule(const RuleId& id) const;
};

// Structural validation: duplicate rule identifiers with different bodies,
// out-of-range values, malformed patterns and unbounded collections are all
// rejected here.
[[nodiscard]] FFED_API Status validate_policy(const FederationPolicy& policy);

// The policy shipped with this version. Conservative defaults: two distinct
// parties, one endorsement, leases required for global-mutation grants,
// re-consent on generation change, global-mutation suspension on partition.
[[nodiscard]] FFED_API FederationPolicy default_policy();

}  // namespace fabric_federation
