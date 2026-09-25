// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/policy.hpp"

#include <algorithm>
#include <set>

namespace fabric_federation {
namespace {

template <class T>
void sort_unique(std::vector<T>& items) {
  std::sort(items.begin(), items.end());
  items.erase(std::unique(items.begin(), items.end()), items.end());
}

constexpr std::uint64_t kDefaultMaxLeaseLifetimeTicks = 100000;
constexpr std::uint64_t kDefaultObservationFreshnessTicks = 100000;

}  // namespace

std::string_view to_string(PolicyRuleKind kind) noexcept {
  switch (kind) {
    case PolicyRuleKind::RequireEndorsements:
      return "require-endorsements";
    case PolicyRuleKind::RequireDistinctParties:
      return "require-distinct-parties";
    case PolicyRuleKind::RequireCapability:
      return "require-capability";
    case PolicyRuleKind::ForbidScopeDelegation:
      return "forbid-scope-delegation";
    case PolicyRuleKind::RequireLease:
      return "require-lease";
    case PolicyRuleKind::SuspendGlobalMutationOnPartition:
      return "suspend-global-mutation-on-partition";
    case PolicyRuleKind::SuspendGlobalMutationWhileReconciling:
      return "suspend-global-mutation-while-reconciling";
    case PolicyRuleKind::RequireMutualReachability:
      return "require-mutual-reachability";
    case PolicyRuleKind::MaxLeaseLifetimeTicks:
      return "max-lease-lifetime-ticks";
    case PolicyRuleKind::RequireReconsentOnGenerationChange:
      return "require-reconsent-on-generation-change";
    case PolicyRuleKind::PrecedenceForGrant:
      return "precedence-for-grant";
    case PolicyRuleKind::RequireReattestationAfterPartition:
      return "require-reattestation-after-partition";
    case PolicyRuleKind::ObservationFreshnessTicks:
      return "observation-freshness-ticks";
    case PolicyRuleKind::AllowGenerationChangeWithoutReconsent:
      return "allow-generation-change-without-reconsent";
  }
  return "invalid";
}

bool operator==(const PolicyRule& a, const PolicyRule& b) noexcept {
  return a.id == b.id && a.kind == b.kind && a.enabled == b.enabled && a.value == b.value &&
         a.scope == b.scope && a.capability == b.capability && a.members == b.members &&
         a.description == b.description;
}

std::string PolicyRule::to_string() const {
  std::string out = id.str();
  out.append(" kind=");
  out.append(fabric_federation::to_string(kind));
  out.append(enabled ? " enabled" : " disabled");
  out.append(" value=");
  out.append(std::to_string(value));
  if (!scope.empty()) {
    out.append(" scope=");
    out.append(scope.str());
  }
  if (!capability.capability.empty()) {
    out.append(" capability=");
    out.append(capability.to_string());
  }
  if (!members.empty()) {
    out.append(" members=[");
    for (std::size_t i = 0; i < members.size(); ++i) {
      if (i != 0) {
        out.append(",");
      }
      out.append(members[i].to_string());
    }
    out.append("]");
  }
  return out;
}

Status PolicyRule::encode(Writer& writer) const {
  Status status = writer.identifier(id.str());
  if (!status.ok()) {
    return status;
  }
  status = writer.u8(static_cast<std::uint8_t>(kind));
  if (!status.ok()) {
    return status;
  }
  status = writer.boolean(enabled);
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(value);
  if (!status.ok()) {
    return status;
  }
  status = writer.identifier(scope.str());
  if (!status.ok()) {
    return status;
  }
  status = capability.encode(writer);
  if (!status.ok()) {
    return status;
  }
  status = writer.count(members.size(), kMaxMembers);
  if (!status.ok()) {
    return status;
  }
  for (const MemberId& member : members) {
    status = writer.id16(member.bytes());
    if (!status.ok()) {
      return status;
    }
  }
  return writer.text(description, kMaxShortTextLength);
}

Result<PolicyRule> PolicyRule::decode(Reader& reader) {
  PolicyRule rule;
  auto id = reader.identifier();
  if (!id.has_value()) {
    return id.status();
  }
  if (!id.value().empty()) {
    auto parsed_id = RuleId::parse(id.value());
    if (!parsed_id.has_value()) {
      return Status::make(ErrorCode::InvalidArgument, "policy rule identifier is malformed");
    }
    rule.id = std::move(parsed_id.value());
  }
  auto kind = reader.u8();
  if (!kind.has_value()) {
    return kind.status();
  }
  if (kind.value() > static_cast<std::uint8_t>(PolicyRuleKind::AllowGenerationChangeWithoutReconsent)) {
    return Status::make(ErrorCode::InvalidArgument, "policy rule kind is out of range");
  }
  rule.kind = static_cast<PolicyRuleKind>(kind.value());
  auto enabled = reader.boolean();
  if (!enabled.has_value()) {
    return enabled.status();
  }
  rule.enabled = enabled.value();
  auto value = reader.u64();
  if (!value.has_value()) {
    return value.status();
  }
  rule.value = value.value();
  auto scope = reader.identifier();
  if (!scope.has_value()) {
    return scope.status();
  }
  if (!scope.value().empty()) {
    auto parsed_scope = ScopeId::parse(scope.value());
    if (!parsed_scope.has_value()) {
      return Status::make(ErrorCode::InvalidArgument, "policy rule scope is malformed");
    }
    rule.scope = std::move(parsed_scope.value());
  }
  auto capability = CapabilityRequirement::decode(reader);
  if (!capability.has_value()) {
    return capability.status();
  }
  rule.capability = std::move(capability.value());
  auto count = reader.count(kMaxMembers);
  if (!count.has_value()) {
    return count.status();
  }
  rule.members.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto member = reader.id16();
    if (!member.has_value()) {
      return member.status();
    }
    rule.members.push_back(MemberId::from_bytes(member.value()));
  }
  auto description = reader.text(kMaxShortTextLength);
  if (!description.has_value()) {
    return description.status();
  }
  rule.description = std::move(description.value());
  return rule;
}

void FederationPolicy::canonicalize() {
  for (PolicyRule& rule : rules) {
    std::sort(rule.members.begin(), rule.members.end());
    rule.members.erase(std::unique(rule.members.begin(), rule.members.end()), rule.members.end());
  }
  std::sort(rules.begin(), rules.end(),
            [](const PolicyRule& a, const PolicyRule& b) { return a.id < b.id; });
}

Status FederationPolicy::encode(Writer& writer) const {
  FederationPolicy copy = *this;
  copy.canonicalize();
  Status status = writer.identifier(copy.id.str());
  if (!status.ok()) {
    return status;
  }
  status = writer.u64(copy.generation.value());
  if (!status.ok()) {
    return status;
  }
  status = writer.count(copy.rules.size(), kMaxPolicyRules);
  if (!status.ok()) {
    return status;
  }
  for (const PolicyRule& rule : copy.rules) {
    status = rule.encode(writer);
    if (!status.ok()) {
      return status;
    }
  }
  return writer.text(copy.description, kMaxTextLength);
}

Result<FederationPolicy> FederationPolicy::decode(Reader& reader) {
  FederationPolicy policy;
  auto id = reader.identifier();
  if (!id.has_value()) {
    return id.status();
  }
  if (!id.value().empty()) {
    auto parsed_id = PolicyId::parse(id.value());
    if (!parsed_id.has_value()) {
      return Status::make(ErrorCode::InvalidArgument, "policy identifier is malformed");
    }
    policy.id = std::move(parsed_id.value());
  }
  auto generation = reader.u64();
  if (!generation.has_value()) {
    return generation.status();
  }
  policy.generation = Generation(generation.value());
  auto count = reader.count(kMaxPolicyRules);
  if (!count.has_value()) {
    return count.status();
  }
  policy.rules.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto rule = PolicyRule::decode(reader);
    if (!rule.has_value()) {
      return rule.status();
    }
    policy.rules.push_back(std::move(rule.value()));
  }
  auto description = reader.text(kMaxTextLength);
  if (!description.has_value()) {
    return description.status();
  }
  policy.description = std::move(description.value());
  policy.canonicalize();
  return policy;
}

Digest FederationPolicy::digest() const {
  Writer writer;
  if (!encode(writer).ok()) {
    return Digest();
  }
  return writer.sha256();
}

std::string FederationPolicy::to_string() const {
  std::string out = id.str();
  out.append(" generation=");
  out.append(std::to_string(generation.value()));
  out.append(" rules=");
  out.append(std::to_string(rules.size()));
  out.append(" digest=");
  out.append(digest_hex().substr(0, 16));
  return out;
}

const PolicyRule* FederationPolicy::find_rule(const RuleId& rule_id) const {
  for (const PolicyRule& rule : rules) {
    if (rule.id == rule_id) {
      return &rule;
    }
  }
  return nullptr;
}

std::size_t FederationPolicy::required_endorsements() const {
  std::size_t value = 1;
  for (const PolicyRule& rule : rules) {
    if (rule.enabled && rule.kind == PolicyRuleKind::RequireEndorsements) {
      value = static_cast<std::size_t>(rule.value);
    }
  }
  return value > kMaxRequiredEndorsements ? kMaxRequiredEndorsements : value;
}

std::size_t FederationPolicy::required_distinct_parties() const {
  std::size_t value = 2;
  for (const PolicyRule& rule : rules) {
    if (rule.enabled && rule.kind == PolicyRuleKind::RequireDistinctParties) {
      value = static_cast<std::size_t>(rule.value);
    }
  }
  if (value < 2) {
    value = 2;
  }
  return value > kMaxMembers ? kMaxMembers : value;
}

bool FederationPolicy::scope_delegation_forbidden(const ScopeId& scope) const {
  for (const PolicyRule& rule : rules) {
    if (rule.enabled && rule.kind == PolicyRuleKind::ForbidScopeDelegation && !rule.scope.empty() &&
        rule.scope.covers(scope)) {
      return true;
    }
  }
  return false;
}

bool FederationPolicy::lease_required(const ScopeGrant& grant) const {
  if (grant.verb != AuthorityVerb::Mutate && grant.verb != AuthorityVerb::Administer) {
    return false;
  }
  for (const PolicyRule& rule : rules) {
    if (rule.enabled && rule.kind == PolicyRuleKind::RequireLease && !rule.scope.empty() &&
        rule.scope.covers(grant.scope)) {
      return true;
    }
  }
  return false;
}

std::uint64_t FederationPolicy::max_lease_lifetime_ticks() const {
  std::uint64_t value = kDefaultMaxLeaseLifetimeTicks;
  for (const PolicyRule& rule : rules) {
    if (rule.enabled && rule.kind == PolicyRuleKind::MaxLeaseLifetimeTicks) {
      value = rule.value;
    }
  }
  return value;
}

bool FederationPolicy::reconsent_on_generation_change() const {
  bool reconsent = true;
  for (const PolicyRule& rule : rules) {
    if (!rule.enabled) {
      continue;
    }
    if (rule.kind == PolicyRuleKind::RequireReconsentOnGenerationChange) {
      reconsent = rule.value != 0;
    } else if (rule.kind == PolicyRuleKind::AllowGenerationChangeWithoutReconsent) {
      reconsent = rule.value == 0;
    }
  }
  return reconsent;
}

bool FederationPolicy::suspend_global_mutation_on_partition() const {
  for (const PolicyRule& rule : rules) {
    if (rule.enabled && rule.kind == PolicyRuleKind::SuspendGlobalMutationOnPartition) {
      return rule.value != 0;
    }
  }
  return true;
}

bool FederationPolicy::suspend_global_mutation_while_reconciling() const {
  for (const PolicyRule& rule : rules) {
    if (rule.enabled && rule.kind == PolicyRuleKind::SuspendGlobalMutationWhileReconciling) {
      return rule.value != 0;
    }
  }
  return true;
}

bool FederationPolicy::require_mutual_reachability() const {
  for (const PolicyRule& rule : rules) {
    if (rule.enabled && rule.kind == PolicyRuleKind::RequireMutualReachability) {
      return rule.value != 0;
    }
  }
  return true;
}

bool FederationPolicy::require_reattestation_after_partition() const {
  for (const PolicyRule& rule : rules) {
    if (rule.enabled && rule.kind == PolicyRuleKind::RequireReattestationAfterPartition) {
      return rule.value != 0;
    }
  }
  return true;
}

std::uint64_t FederationPolicy::observation_freshness_ticks() const {
  std::uint64_t value = kDefaultObservationFreshnessTicks;
  for (const PolicyRule& rule : rules) {
    if (rule.enabled && rule.kind == PolicyRuleKind::ObservationFreshnessTicks) {
      value = rule.value;
    }
  }
  return value;
}

const std::vector<MemberId>* FederationPolicy::precedence_for(const ScopeGrant& grant) const {
  const std::vector<MemberId>* best = nullptr;
  for (const PolicyRule& rule : rules) {
    if (!rule.enabled || rule.kind != PolicyRuleKind::PrecedenceForGrant) {
      continue;
    }
    if (rule.scope.empty() || !rule.scope.covers(grant.scope)) {
      continue;
    }
    // A verb-specific rule is expressed by leaving scope empty and naming the
    // grant scope exactly; the first matching rule in canonical order wins so
    // the result does not depend on declaration order.
    if (best == nullptr) {
      best = &rule.members;
    }
  }
  return best;
}

std::vector<CapabilityRequirement> FederationPolicy::mandatory_capabilities() const {
  std::vector<CapabilityRequirement> out;
  for (const PolicyRule& rule : rules) {
    if (rule.enabled && rule.kind == PolicyRuleKind::RequireCapability &&
        !rule.capability.capability.empty()) {
      out.push_back(rule.capability);
    }
  }
  sort_unique(out);
  return out;
}

Status validate_policy(const FederationPolicy& policy) {
  if (policy.id.empty()) {
    return Status::make(ErrorCode::InvalidArgument, "policy has no identifier");
  }
  if (policy.rules.size() > kMaxPolicyRules) {
    return Status::make(ErrorCode::BoundsExceeded, "policy has too many rules");
  }
  // Duplicate detection runs on the policy as supplied: canonicalisation
  // removes duplicates, so checking afterwards would hide exactly the mistake
  // this rule exists to catch.
  for (const PolicyRule& rule : policy.rules) {
    if (rule.kind != PolicyRuleKind::PrecedenceForGrant) {
      continue;
    }
    std::vector<MemberId> members = rule.members;
    sort_unique(members);
    if (members.size() != rule.members.size()) {
      return Status::make(ErrorCode::Conflict,
                          "a precedence list names the same member more than once");
    }
  }
  FederationPolicy canonical = policy;
  canonical.canonicalize();
  for (std::size_t i = 1; i < canonical.rules.size(); ++i) {
    if (canonical.rules[i].id == canonical.rules[i - 1].id) {
      return Status::make(ErrorCode::Conflict,
                          "policy declares rule " + canonical.rules[i].id.str() + " twice");
    }
  }
  for (const PolicyRule& rule : canonical.rules) {
    if (rule.description.size() > kMaxShortTextLength) {
      return Status::make(ErrorCode::BoundsExceeded, "policy rule description is too long");
    }
    if (rule.kind == PolicyRuleKind::RequireEndorsements &&
        rule.value > kMaxRequiredEndorsements) {
      return Status::make(ErrorCode::OutOfRange, "required endorsement count is out of range");
    }
    if (rule.kind == PolicyRuleKind::RequireDistinctParties && rule.value < 2) {
      return Status::make(ErrorCode::InvalidArgument,
                          "a non-bootstrap admission requires at least two distinct parties");
    }
    if (rule.kind == PolicyRuleKind::PrecedenceForGrant) {
      if (rule.members.size() > kMaxPrecedenceEntries) {
        return Status::make(ErrorCode::BoundsExceeded, "precedence list is too long");
      }
      if (rule.scope.empty()) {
        return Status::make(ErrorCode::InvalidArgument,
                            "a precedence rule must name the scope it applies to");
      }
      std::vector<MemberId> members = rule.members;
      sort_unique(members);
      if (members.size() != rule.members.size()) {
        return Status::make(ErrorCode::Conflict,
                            "a precedence list names the same member more than once");
      }
    }
  }
  return Status::success();
}

FederationPolicy default_policy() {
  FederationPolicy policy;
  auto policy_id = PolicyId::parse("fabric-federation.default.v1");
  if (policy_id.has_value()) {
    policy.id = std::move(policy_id.value());
  } else {
    policy.id = PolicyId::parse("fallback").value_or(PolicyId());
  }
  policy.generation = Generation(1);
  policy.description =
      "conservative defaults: two distinct parties, no third-party endorsement required, leases "
      "for mutating federation grants, re-consent on generation change, global-mutation "
      "suspension on partition or while reconciling";

  const auto rule = [](const char* id, PolicyRuleKind kind, std::uint64_t value, const char* text) {
    PolicyRule out;
    auto parsed = RuleId::parse(id);
    if (parsed.has_value()) {
      out.id = std::move(parsed.value());
    }
    out.kind = kind;
    out.enabled = true;
    out.value = value;
    out.description = text;
    return out;
  };

  // The shipped default requires two distinct parties (the sponsor and the
  // candidate) and no third-party endorsement, because requiring an endorsement
  // raises the minimum viable federation to three members. Raising this value
  // is a deliberate policy decision, and the derivation enforces it.
  PolicyRule endorsements = rule("fed.rule.endorsements", PolicyRuleKind::RequireEndorsements, 0,
                                 "third-party endorsements required beyond the sponsor and the "
                                 "candidate; zero means the sponsor and the candidate are enough");
  PolicyRule parties = rule("fed.rule.distinct-parties", PolicyRuleKind::RequireDistinctParties, 2,
                            "at least two distinct member identities across the admission "
                            "evidence");
  PolicyRule lease = rule("fed.rule.lease-required", PolicyRuleKind::RequireLease, 1,
                          "mutating and administering federation grants require a lease");
  if (auto scope = ScopeId::parse("federation.*"); scope.has_value()) {
    lease.scope = std::move(scope.value());
  }
  PolicyRule partition_suspend =
      rule("fed.rule.partition-suspend", PolicyRuleKind::SuspendGlobalMutationOnPartition, 1,
           "a split or indeterminate partition suspends global-mutation authority");
  PolicyRule reconcile_suspend =
      rule("fed.rule.reconcile-suspend", PolicyRuleKind::SuspendGlobalMutationWhileReconciling, 1,
           "global-mutation authority stays suspended until reconciliation completes");
  PolicyRule mutual = rule("fed.rule.mutual-reachability", PolicyRuleKind::RequireMutualReachability,
                           1, "an edge requires both endpoints to confirm each other");
  PolicyRule lease_lifetime = rule("fed.rule.max-lease-lifetime",
                                   PolicyRuleKind::MaxLeaseLifetimeTicks, 100000,
                                   "leases expire after this many logical ticks");
  PolicyRule reconsent =
      rule("fed.rule.reconsent-on-generation-change",
           PolicyRuleKind::RequireReconsentOnGenerationChange, 1,
           "a generation change fences authority until the member consents again");
  PolicyRule reattest =
      rule("fed.rule.reattestation-after-partition",
           PolicyRuleKind::RequireReattestationAfterPartition, 1,
           "every active member must re-attest after a partition before global mutation resumes");
  PolicyRule freshness = rule("fed.rule.observation-freshness",
                              PolicyRuleKind::ObservationFreshnessTicks, 100000,
                              "reachability observations older than this many ticks stop counting");
  PolicyRule capability = rule("fed.rule.require-protocol", PolicyRuleKind::RequireCapability, 1,
                               "every member must declare the framed transport capability");
  if (auto id = CapabilityId::parse("federation.protocol.v1"); id.has_value()) {
    capability.capability.capability = std::move(id.value());
    capability.capability.min_version = 1;
    capability.capability.max_version = 1;
    capability.capability.mandatory = true;
  }

  policy.rules = {endorsements,        parties,        lease,        partition_suspend,
                  reconcile_suspend,  mutual,         lease_lifetime, reconsent,
                  reattest,           freshness,      capability};
  policy.canonicalize();
  return policy;
}

}  // namespace fabric_federation
