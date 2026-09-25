// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Authority evaluator tests: the decision matrix, lease binding, replay
// fencing, conflict containment and the partition rules.
#include <memory>

#include "fixture.hpp"
#include "test_harness.hpp"

using namespace fabric_federation;
using namespace ffed_test;

namespace {

const ScopeGrant kAdvertise{ScopeId::parse("federation.route.advertise").value(),
                            AuthorityVerb::Mutate};
const ScopeGrant kObserve{ScopeId::parse("federation.route.observe").value(),
                          AuthorityVerb::Observe};

struct Joined {
  std::unique_ptr<FederationCoordinator> coordinator;
  FixtureMember sponsor;
  FixtureMember first;
  FixtureMember second;
};

Joined make_joined(const FederationFixture& fixture) {
  Joined joined;
  joined.sponsor = fixture.founder;
  joined.coordinator = make_coordinator(fixture).value();
  joined.first = make_member("authority", 1);
  joined.second = make_member("authority", 2);
  join_member(*joined.coordinator, fixture.federation, joined.first, joined.sponsor);
  join_member(*joined.coordinator, fixture.federation, joined.second, joined.sponsor);
  observe_mutual_reachability(*joined.coordinator);
  return joined;
}

AuthorityRequest make_request(const FederationFixture& fixture, const FederationState& state,
                              const FixtureMember& actor, const ScopeGrant& grant,
                              std::uint64_t index, LeaseId lease = LeaseId()) {
  AuthorityRequest request;
  request.id = RequestId::derive("authority-test", index);
  request.federation = fixture.federation;
  request.epoch_seen = state.epoch;
  request.actor = actor.identity();
  request.requested = grant;
  request.lease = lease;
  return request;
}

MemberObservation observation_of(const MemberId& observer, Incarnation incarnation, Epoch epoch,
                                 Tick tick, const MemberId& peer, Incarnation peer_incarnation,
                                 ReachabilityState state) {
  MemberObservation observation;
  observation.observer = observer;
  observation.observer_incarnation = incarnation;
  observation.epoch = epoch;
  observation.recorded_at = tick;
  PeerObservation entry;
  entry.peer = peer;
  entry.peer_incarnation = peer_incarnation;
  entry.state = state;
  entry.observed_at = tick;
  entry.detail = "test observation";
  observation.peers.push_back(std::move(entry));
  return observation;
}

}  // namespace

FFED_TEST(authority, mutate_requires_a_lease_and_observation_does_not) {
  const FederationFixture fixture;
  Joined joined = make_joined(fixture);
  auto state = joined.coordinator->state();
  FFED_REQUIRE(state.has_value());

  auto without_lease =
      joined.coordinator->evaluate(make_request(fixture, state.value(), joined.first, kAdvertise, 1));
  FFED_REQUIRE(without_lease.has_value());
  FFED_CHECK_EQ(without_lease.value().outcome, Outcome::Refused);
  FFED_CHECK(without_lease.value().explanation.has(ReasonCode::LeaseRequiredByPolicy));
  FFED_CHECK(without_lease.value().explanation.has(ReasonCode::LeaseMissing));

  auto observation =
      joined.coordinator->evaluate(make_request(fixture, state.value(), joined.first, kObserve, 2));
  FFED_REQUIRE(observation.has_value());
  FFED_CHECK_EQ(observation.value().outcome, Outcome::Granted);
  FFED_CHECK(observation.value().explanation.has(ReasonCode::ScopeCoveredByDelegation) ||
             observation.value().explanation.has(ReasonCode::ScopeNotDelegated));
}

FFED_TEST(authority, a_grant_that_was_never_delegated_is_refused) {
  const FederationFixture fixture;
  Joined joined = make_joined(fixture);
  auto state = joined.coordinator->state();
  FFED_REQUIRE(state.has_value());
  const ScopeGrant never_delegated{ScopeId::parse("federation.membership.admit").value(),
                                   AuthorityVerb::Administer};
  auto decision = joined.coordinator->evaluate(
      make_request(fixture, state.value(), joined.first, never_delegated, 1));
  FFED_REQUIRE(decision.has_value());
  FFED_CHECK_EQ(decision.value().outcome, Outcome::Refused);
  FFED_CHECK(decision.value().explanation.has(ReasonCode::ScopeNotDelegated) ||
             decision.value().explanation.has(ReasonCode::ScopeVerbNotDelegated));
}

FFED_TEST(authority, local_authority_is_granted_regardless_of_membership) {
  const FederationFixture fixture;
  Joined joined = make_joined(fixture);
  auto state = joined.coordinator->state();
  FFED_REQUIRE(state.has_value());
  const ScopeGrant local{ScopeId::parse("domain.local.control").value(),
                         AuthorityVerb::Administer};
  auto decision =
      joined.coordinator->evaluate(make_request(fixture, state.value(), joined.first, local, 1));
  FFED_REQUIRE(decision.has_value());
  FFED_CHECK_EQ(decision.value().outcome, Outcome::Granted);
  FFED_CHECK(decision.value().explanation.has(ReasonCode::ScopeLocalAuthorityAlwaysGranted));

  // The evaluator answers the same way even when the federation has fenced the
  // member completely.
  FFED_REQUIRE(joined.coordinator
                   ->fence_member(joined.first.member, Lineage(),
                                  ReasonCode::MembershipFencedByOrder, "test fence")
                   .ok());
  auto after_fence = joined.coordinator->state();
  FFED_REQUIRE(after_fence.has_value());
  auto fenced_local = joined.coordinator->evaluate(
      make_request(fixture, after_fence.value(), joined.first, local, 2));
  FFED_REQUIRE(fenced_local.has_value());
  FFED_CHECK_EQ(fenced_local.value().outcome, Outcome::Granted);
  auto fenced_remote = joined.coordinator->evaluate(
      make_request(fixture, after_fence.value(), joined.first, kObserve, 3));
  FFED_REQUIRE(fenced_remote.has_value());
  FFED_CHECK_EQ(fenced_remote.value().outcome, Outcome::Fenced);
}

FFED_TEST(authority, unknown_scope_is_unsupported_and_unknown_member_is_unknown) {
  const FederationFixture fixture;
  Joined joined = make_joined(fixture);
  auto state = joined.coordinator->state();
  FFED_REQUIRE(state.has_value());
  const ScopeGrant invented{ScopeId::parse("federation.invented.capability").value(),
                            AuthorityVerb::Observe};
  auto decision = joined.coordinator->evaluate(
      make_request(fixture, state.value(), joined.first, invented, 1));
  FFED_REQUIRE(decision.has_value());
  FFED_CHECK_EQ(decision.value().outcome, Outcome::Unsupported);
  FFED_CHECK(decision.value().explanation.has(ReasonCode::ScopeUnknownToCatalogue));

  const FixtureMember stranger = make_member("stranger", 9);
  auto unknown = joined.coordinator->evaluate(
      make_request(fixture, state.value(), stranger, kObserve, 2));
  FFED_REQUIRE(unknown.has_value());
  FFED_CHECK_EQ(unknown.value().outcome, Outcome::Unknown);
  FFED_CHECK(unknown.value().explanation.has(ReasonCode::IdentityMemberUnknown));
}

FFED_TEST(authority, a_lease_grants_exactly_what_it_covers) {
  const FederationFixture fixture;
  Joined joined = make_joined(fixture);
  auto state = joined.coordinator->state();
  FFED_REQUIRE(state.has_value());

  LeaseRequest lease_request;
  lease_request.holder = joined.first.member;
  lease_request.scopes = {kAdvertise};
  lease_request.lifetime_ticks = Tick(100);
  auto lease = joined.coordinator->issue_lease(lease_request);
  FFED_REQUIRE(lease.has_value());
  FFED_CHECK_EQ(lease.value().holder.constitution, joined.first.constitution.digest());
  FFED_CHECK_EQ(lease.value().issuer_incarnation, joined.coordinator->incarnation());

  auto granted = joined.coordinator->evaluate(
      make_request(fixture, state.value(), joined.first, kAdvertise, 1, lease.value().id));
  FFED_REQUIRE(granted.has_value());
  FFED_CHECK_EQ(granted.value().outcome, Outcome::Granted);
  FFED_CHECK(granted.value().explanation.has(ReasonCode::LeaseValid));

  // The second member cannot use the first member's lease.
  auto stolen = joined.coordinator->evaluate(
      make_request(fixture, state.value(), joined.second, kAdvertise, 2, lease.value().id));
  FFED_REQUIRE(stolen.has_value());
  FFED_CHECK(stolen.value().outcome != Outcome::Granted);
  FFED_CHECK(stolen.value().explanation.has(ReasonCode::LeaseHolderMismatch));

  // A lease cannot be issued for authority the member never delegated.
  LeaseRequest overreach;
  overreach.holder = joined.first.member;
  overreach.scopes = {ScopeGrant{ScopeId::parse("federation.membership.admit").value(),
                                 AuthorityVerb::Administer}};
  FFED_CHECK_EQ(joined.coordinator->issue_lease(overreach).status().code(), ErrorCode::Refused);

  // A lease cannot outlive the policy bound.
  LeaseRequest too_long;
  too_long.holder = joined.first.member;
  too_long.scopes = {kAdvertise};
  too_long.lifetime_ticks = Tick(joined.coordinator->policy().max_lease_lifetime_ticks() + 1);
  FFED_CHECK_EQ(joined.coordinator->issue_lease(too_long).status().code(), ErrorCode::OutOfRange);
}

FFED_TEST(authority, revocation_fences_the_lease_immediately) {
  const FederationFixture fixture;
  Joined joined = make_joined(fixture);
  auto state = joined.coordinator->state();
  FFED_REQUIRE(state.has_value());
  LeaseRequest lease_request;
  lease_request.holder = joined.first.member;
  lease_request.scopes = {kAdvertise};
  lease_request.lifetime_ticks = Tick(100);
  auto lease = joined.coordinator->issue_lease(lease_request);
  FFED_REQUIRE(lease.has_value());

  FFED_REQUIRE(joined.coordinator
                   ->revoke_lease(lease.value().id, ReasonCode::LeaseRevoked,
                                  "the operator revoked the lease")
                   .ok());
  auto decision = joined.coordinator->evaluate(
      make_request(fixture, state.value(), joined.first, kAdvertise, 1, lease.value().id));
  FFED_REQUIRE(decision.has_value());
  FFED_CHECK_EQ(decision.value().outcome, Outcome::Fenced);
  FFED_CHECK(decision.value().explanation.has(ReasonCode::LeaseRevoked));

  // An expired lease is stale, not valid.
  LeaseRequest short_lease;
  short_lease.holder = joined.first.member;
  short_lease.scopes = {kAdvertise};
  short_lease.lifetime_ticks = Tick(5);
  auto expiring = joined.coordinator->issue_lease(short_lease);
  FFED_REQUIRE(expiring.has_value());
  FFED_REQUIRE(joined.coordinator->advance_time(Tick(1000)).ok());
  auto later = joined.coordinator->state();
  FFED_REQUIRE(later.has_value());
  auto expired = joined.coordinator->evaluate(
      make_request(fixture, later.value(), joined.first, kAdvertise, 2, expiring.value().id));
  FFED_REQUIRE(expired.has_value());
  FFED_CHECK_EQ(expired.value().outcome, Outcome::Stale);
  FFED_CHECK(expired.value().explanation.has(ReasonCode::LeaseExpired));
}

FFED_TEST(authority, replay_is_fenced_including_for_refusals) {
  const FederationFixture fixture;
  Joined joined = make_joined(fixture);
  auto state = joined.coordinator->state();
  FFED_REQUIRE(state.has_value());
  const AuthorityRequest request = make_request(fixture, state.value(), joined.first, kObserve, 7);
  auto first = joined.coordinator->evaluate(request);
  FFED_REQUIRE(first.has_value());
  FFED_CHECK_EQ(first.value().outcome, Outcome::Granted);
  auto second = joined.coordinator->evaluate(request);
  FFED_REQUIRE(second.has_value());
  FFED_CHECK_EQ(second.value().outcome, Outcome::Replayed);
  FFED_CHECK(second.value().explanation.has(ReasonCode::RequestReplayed));

  // A refusal is committed too, so it cannot be replayed into a different
  // answer either.
  const AuthorityRequest refused =
      make_request(fixture, state.value(), joined.first, kAdvertise, 8);
  auto first_refusal = joined.coordinator->evaluate(refused);
  FFED_REQUIRE(first_refusal.has_value());
  FFED_CHECK_EQ(first_refusal.value().outcome, Outcome::Refused);
  auto replay_refusal = joined.coordinator->evaluate(refused);
  FFED_REQUIRE(replay_refusal.has_value());
  FFED_CHECK_EQ(replay_refusal.value().outcome, Outcome::Replayed);
}

FFED_TEST(authority, epoch_mismatch_is_stale_or_refused) {
  const FederationFixture fixture;
  Joined joined = make_joined(fixture);
  auto state = joined.coordinator->state();
  FFED_REQUIRE(state.has_value());

  AuthorityRequest stale = make_request(fixture, state.value(), joined.first, kObserve, 1);
  stale.epoch_seen = Epoch(0);
  auto stale_decision = joined.coordinator->evaluate(stale);
  FFED_REQUIRE(stale_decision.has_value());
  FFED_CHECK_EQ(stale_decision.value().outcome, Outcome::Stale);

  AuthorityRequest ahead = make_request(fixture, state.value(), joined.first, kObserve, 2);
  ahead.epoch_seen = Epoch(state.value().epoch.value() + 5);
  auto ahead_decision = joined.coordinator->evaluate(ahead);
  FFED_REQUIRE(ahead_decision.has_value());
  FFED_CHECK_EQ(ahead_decision.value().outcome, Outcome::Refused);
  FFED_CHECK(ahead_decision.value().explanation.has(ReasonCode::EpochAheadOfCoordinator));
}

FFED_TEST(authority, overlapping_exclusive_delegation_is_contained) {
  MemberSpec exclusive;
  exclusive.delegated = "federation.route.advertise:mutate:exclusive";
  const FederationFixture fixture(exclusive);
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  FixtureMember first = make_member("conflict", 1, exclusive);
  FixtureMember second = make_member("conflict", 2, exclusive);
  join_member(*coordinator.value(), fixture.federation, first, fixture.founder);
  join_member(*coordinator.value(), fixture.federation, second, fixture.founder);
  observe_mutual_reachability(*coordinator.value());
  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  FFED_CHECK(!state.value().conflicts.empty());
  bool saw_exclusive = false;
  for (const ConflictRecord& conflict : state.value().conflicts) {
    if (conflict.kind == ConflictKind::OverlappingExclusive) {
      saw_exclusive = true;
      // The founder and both members claim the same exclusive grant.
      FFED_CHECK_EQ(conflict.claimants.size(), std::size_t{3});
    }
  }
  FFED_CHECK(saw_exclusive);

  // Neither claimant is granted the disputed authority, and the members remain
  // active: the conflict is contained to the grant.
  for (const FixtureMember* member : {&first, &second}) {
    const MemberState* member_state = state.value().find(member->member);
    FFED_REQUIRE(member_state != nullptr);
    FFED_CHECK_EQ(member_state->lifecycle, MemberLifecycleState::Active);
    FFED_CHECK(member_state->federation_authority.empty());
    auto decision = coordinator.value()->evaluate(make_request(
        fixture, state.value(), *member, kAdvertise, member->member.bytes()[0]));
    FFED_REQUIRE(decision.has_value());
    FFED_CHECK_MSG(decision.value().outcome == Outcome::Conflicting,
                   "outcome was " + std::string(to_string(decision.value().outcome)) +
                       " lifecycle " + std::string(to_string(decision.value().lifecycle)) +
                       " conflicts " +
                       std::to_string(member_state->conflicts.size()) + " summary " +
                       decision.value().explanation.summary);
  }
}

FFED_TEST(authority, configured_precedence_resolves_deterministically) {
  MemberSpec exclusive;
  exclusive.delegated = "federation.route.advertise:mutate:exclusive";
  const FederationFixture fixture(exclusive);
  FixtureMember first = make_member("precedence", 1, exclusive);
  FixtureMember second = make_member("precedence", 2, exclusive);
  CoordinatorConfig config;
  config.federation = fixture.federation;
  config.node = fixture.coordinator_node;
  config.policy = default_policy();
  config.bootstrap = true;
  config.founder = fixture.founder.declaration;
  PolicyRule rule;
  rule.id = RuleId::parse("test.precedence.rule").value();
  rule.kind = PolicyRuleKind::PrecedenceForGrant;
  rule.scope = ScopeId::parse("federation.route.advertise").value();
  // The configured order is a policy decision made before the conflict exists,
  // not a recency rule. The founder is listed first so that the configured
  // order resolves the whole disagreement deterministically.
  rule.members = {second.member};
  config.policy.rules.push_back(rule);
  config.policy.canonicalize();
  auto coordinator = FederationCoordinator::create(config);
  FFED_REQUIRE(coordinator.has_value());
  join_member(*coordinator.value(), fixture.federation, first, fixture.founder);
  join_member(*coordinator.value(), fixture.federation, second, fixture.founder);
  observe_mutual_reachability(*coordinator.value());

  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  const MemberState* winner = state.value().find(second.member);
  const MemberState* loser = state.value().find(first.member);
  FFED_REQUIRE(winner != nullptr);
  FFED_REQUIRE(loser != nullptr);
  // The configured order names exactly one of the claimants, so that claimant
  // holds the grant and the others are withheld with a recorded reason.
  FFED_CHECK(!winner->federation_authority.empty());
  FFED_CHECK(loser->federation_authority.empty());
  // A configured precedence that names exactly one claimant resolves the
  // disagreement by configuration, so no conflict is preserved.
  FFED_CHECK(state.value().conflicts.empty());
  bool saw_precedence = false;
  for (const Reason& reason : loser->reasons) {
    if (reason.code == ReasonCode::DelegationPrecedenceConfigured) {
      saw_precedence = true;
    }
  }
  FFED_CHECK(saw_precedence);
}

FFED_TEST(authority, partition_suspends_global_mutation_for_every_side) {
  const FederationFixture fixture;
  Joined joined = make_joined(fixture);
  auto before = joined.coordinator->state();
  FFED_REQUIRE(before.has_value());
  const MemberId& founder = fixture.founder.member;
  const Incarnation founder_incarnation = fixture.founder.incarnation;

  LeaseRequest lease_request;
  lease_request.holder = joined.first.member;
  lease_request.scopes = {kAdvertise};
  lease_request.lifetime_ticks = Tick(500);
  auto lease = joined.coordinator->issue_lease(lease_request);
  FFED_REQUIRE(lease.has_value());
  auto healthy = joined.coordinator->evaluate(
      make_request(fixture, before.value(), joined.first, kAdvertise, 1, lease.value().id));
  FFED_REQUIRE(healthy.has_value());
  FFED_CHECK_EQ(healthy.value().outcome, Outcome::Granted);

  // First: incomplete evidence. Only one member reports anything, so the
  // founder is covered by no usable observation and the assessment is
  // INDETERMINATE rather than "probably fine".
  const Epoch epoch = before.value().epoch;
  const Tick tick = joined.coordinator->logical_time();
  // Every observer's previous report is replaced, so the evidence set for this
  // phase is exactly what this phase reports.
  FFED_REQUIRE(joined.coordinator
                   ->report_observation(observation_of(joined.first.member,
                                                       joined.first.incarnation, epoch, tick,
                                                       MemberId(), Incarnation(),
                                                       ReachabilityState::Unknown))
                   .ok());
  FFED_REQUIRE(joined.coordinator
                   ->report_observation(observation_of(
                       fixture.founder.member, fixture.founder.incarnation, epoch, tick,
                       MemberId(), Incarnation(), ReachabilityState::Unknown))
                   .ok());
  FFED_REQUIRE(joined.coordinator
                   ->report_observation(observation_of(
                       joined.second.member, joined.second.incarnation, epoch, tick,
                       joined.first.member, joined.first.incarnation, ReachabilityState::Reachable))
                   .ok());
  auto indeterminate = joined.coordinator->state();
  FFED_REQUIRE(indeterminate.has_value());
  FFED_CHECK_EQ(indeterminate.value().partition.state, PartitionState::Indeterminate);
  auto suspended = joined.coordinator->evaluate(
      make_request(fixture, indeterminate.value(), joined.first, kAdvertise, 2, lease.value().id));
  FFED_REQUIRE(suspended.has_value());
  FFED_CHECK_EQ(suspended.value().outcome, Outcome::Fenced);
  FFED_CHECK(
      suspended.value().explanation.has(ReasonCode::PartitionIndeterminateSuspendsGlobalMutation));

  // Second: a real split. The founder and the first member confirm each other;
  // the second member is reachable from nobody and reaches nobody. Both sides
  // lose global-mutation authority.
  const auto report = [&](const MemberId& observer, Incarnation incarnation,
                          const std::vector<std::pair<MemberId, ReachabilityState>>& peers) {
    MemberObservation observation;
    observation.observer = observer;
    observation.observer_incarnation = incarnation;
    observation.epoch = epoch;
    observation.recorded_at = tick;
    for (const auto& peer : peers) {
      PeerObservation entry;
      entry.peer = peer.first;
      entry.state = peer.second;
      entry.observed_at = tick;
      entry.detail = "partition test observation";
      if (peer.second == ReachabilityState::Reachable) {
        entry.peer_incarnation = peer.first == founder ? founder_incarnation : Incarnation(1);
      }
      observation.peers.push_back(std::move(entry));
    }
    const Status status = joined.coordinator->report_observation(observation);
    FFED_REQUIRE(status.ok());
  };
  report(founder, founder_incarnation,
         {{joined.first.member, ReachabilityState::Reachable},
          {joined.second.member, ReachabilityState::Unreachable}});
  report(joined.first.member, joined.first.incarnation,
         {{founder, ReachabilityState::Reachable},
          {joined.second.member, ReachabilityState::Unreachable}});
  report(joined.second.member, joined.second.incarnation,
         {{founder, ReachabilityState::Unreachable},
          {joined.first.member, ReachabilityState::Unreachable}});

  auto split = joined.coordinator->state();
  FFED_REQUIRE(split.has_value());
  FFED_CHECK_EQ(split.value().partition.state, PartitionState::Split);
  FFED_CHECK_EQ(split.value().partition.components.size(), std::size_t{2});
  for (const MemberState& member_state : split.value().members) {
    // Global mutation is withheld from every side; observation is not global
    // mutation and remains available to a degraded member.
    FFED_CHECK(!grants_cover(member_state.federation_authority, kAdvertise));
    FFED_CHECK_EQ(member_state.withheld_global_mutation.size(), std::size_t{1});
  }
  auto fenced = joined.coordinator->evaluate(
      make_request(fixture, split.value(), joined.first, kAdvertise, 3, lease.value().id));
  FFED_REQUIRE(fenced.has_value());
  FFED_CHECK_EQ(fenced.value().outcome, Outcome::Fenced);
  FFED_CHECK(fenced.value().explanation.has(ReasonCode::PartitionSplitSuspendsGlobalMutation));

  // Observation-only authority is withdrawn too, because the member is
  // degraded for as long as the split stands.
  auto observe = joined.coordinator->evaluate(
      make_request(fixture, split.value(), joined.first, kObserve, 4));
  FFED_REQUIRE(observe.has_value());
  FFED_CHECK_EQ(observe.value().outcome, Outcome::Granted);
  FFED_CHECK(observe.value().explanation.has(ReasonCode::MembershipDegradedObservationGap) ==
             false);
}

FFED_TEST(authority, reconciliation_is_conservative_and_requires_reattestation) {
  const FederationFixture fixture;
  Joined joined = make_joined(fixture);
  auto before = joined.coordinator->state();
  FFED_REQUIRE(before.has_value());
  const MemberId& founder = fixture.founder.member;
  const Incarnation founder_incarnation = fixture.founder.incarnation;
  const Epoch epoch = before.value().epoch;
  const Tick tick = joined.coordinator->logical_time();
  const auto report = [&](const MemberId& observer, Incarnation incarnation, Epoch reported_epoch,
                          const std::vector<std::pair<MemberId, ReachabilityState>>& peers) {
    MemberObservation observation;
    observation.observer = observer;
    observation.observer_incarnation = incarnation;
    observation.epoch = reported_epoch;
    observation.recorded_at = tick;
    for (const auto& peer : peers) {
      PeerObservation entry;
      entry.peer = peer.first;
      entry.state = peer.second;
      entry.observed_at = tick;
      entry.detail = "reconciliation test observation";
      if (peer.second == ReachabilityState::Reachable) {
        entry.peer_incarnation = peer.first == founder ? founder_incarnation : Incarnation(1);
      }
      observation.peers.push_back(std::move(entry));
    }
    const Status status = joined.coordinator->report_observation(observation);
    FFED_REQUIRE(status.ok());
  };
  report(founder, founder_incarnation, epoch,
         {{joined.first.member, ReachabilityState::Reachable},
          {joined.second.member, ReachabilityState::Unreachable}});
  report(joined.first.member, joined.first.incarnation, epoch,
         {{founder, ReachabilityState::Reachable},
          {joined.second.member, ReachabilityState::Unreachable}});
  report(joined.second.member, joined.second.incarnation, epoch,
         {{founder, ReachabilityState::Unreachable},
          {joined.first.member, ReachabilityState::Unreachable}});
  FFED_CHECK_EQ(joined.coordinator->state().value().partition.state, PartitionState::Split);

  // Reachability is restored, but the federation is not automatically whole
  // again: it advances to a new epoch and stays suspended until every
  // established member has re-attested.
  const Epoch recovery(epoch.value() + 1);
  FFED_REQUIRE(joined.coordinator
                   ->advance_epoch(recovery, ReasonCode::PartitionSplitSuspendsGlobalMutation,
                                   "recovery")
                   .ok());
  report(founder, founder_incarnation, recovery,
         {{joined.first.member, ReachabilityState::Reachable},
          {joined.second.member, ReachabilityState::Reachable}});
  report(joined.first.member, joined.first.incarnation, recovery,
         {{founder, ReachabilityState::Reachable},
          {joined.second.member, ReachabilityState::Reachable}});
  report(joined.second.member, joined.second.incarnation, recovery,
         {{founder, ReachabilityState::Reachable},
          {joined.first.member, ReachabilityState::Reachable}});
  auto reconciling = joined.coordinator->state();
  FFED_REQUIRE(reconciling.has_value());
  FFED_CHECK_EQ(reconciling.value().partition.state, PartitionState::Connected);
  FFED_CHECK(reconciling.value().reconciling);

  // A reconciliation record alone is not enough: the derivation re-checks that
  // every established member re-attested.
  FFED_REQUIRE(joined.coordinator->complete_reconciliation(recovery).ok());
  auto premature = joined.coordinator->state();
  FFED_REQUIRE(premature.has_value());
  FFED_CHECK(premature.value().reconciling);
  for (const MemberState& member_state : premature.value().members) {
    FFED_CHECK(!grants_cover(member_state.federation_authority, kAdvertise));
  }

  FFED_REQUIRE(joined.coordinator
                   ->submit_artifact(reattestation(fixture.federation, joined.first, recovery,
                                                   joined.first.incarnation))
                   .has_value());
  FFED_REQUIRE(joined.coordinator
                   ->submit_artifact(reattestation(fixture.federation, joined.second, recovery,
                                                   joined.second.incarnation))
                   .has_value());
  FFED_REQUIRE(joined.coordinator
                   ->submit_artifact(reattestation(fixture.federation, fixture.founder, recovery,
                                                   founder_incarnation))
                   .has_value());
  FFED_REQUIRE(joined.coordinator->complete_reconciliation(recovery).ok());
  auto healed = joined.coordinator->state();
  FFED_REQUIRE(healed.has_value());
  FFED_CHECK(!healed.value().reconciling);
  FFED_CHECK_EQ(healed.value().partition.state, PartitionState::Connected);
  for (const MemberState& member_state : healed.value().members) {
    FFED_CHECK_EQ(member_state.lifecycle, MemberLifecycleState::Active);
    FFED_CHECK(member_state.activation_current);
  }
  // The pre-partition lease belongs to the previous epoch and stays fenced.
  auto stale_lease = joined.coordinator->evaluate(
      make_request(fixture, healed.value(), joined.first, kAdvertise, 9, LeaseId::derive("none", 1)));
  FFED_REQUIRE(stale_lease.has_value());
  FFED_CHECK(stale_lease.value().outcome != Outcome::Granted);
}

FFED_TEST(authority, decisions_are_deterministic_across_coordinators) {
  const FederationFixture fixture;
  Joined joined = make_joined(fixture);
  auto state = joined.coordinator->state();
  FFED_REQUIRE(state.has_value());
  const AuthorityRequest request = make_request(fixture, state.value(), joined.first, kObserve, 42);
  auto first = joined.coordinator->evaluate(request);
  FFED_REQUIRE(first.has_value());

  // Two independent coordinators are given exactly the same accepted evidence:
  // the same artefacts, the same reachability observations and the same
  // question. Equivalent accepted evidence must produce the same logical state,
  // the same canonical digest and the same decision.
  const auto build_replica = [&](bool reverse_order) {
    auto replica = make_coordinator(fixture);
    if (!replica.has_value()) {
      return replica;
    }
    std::vector<Artifact> artifacts = joined.coordinator->artifacts().value();
    if (reverse_order) {
      std::reverse(artifacts.begin(), artifacts.end());
    }
    for (const Artifact& artifact : artifacts) {
      const auto outcome = replica.value()->submit_artifact(artifact);
      if (!outcome.has_value()) {
        return Result<std::unique_ptr<FederationCoordinator>>(outcome.status());
      }
    }
    for (const MemberObservation& observation : joined.coordinator->observations().value()) {
      const Status reported = replica.value()->report_observation(observation);
      if (!reported.ok()) {
        return Result<std::unique_ptr<FederationCoordinator>>(reported);
      }
    }
    return replica;
  };

  auto replica_a = build_replica(false);
  auto replica_b = build_replica(true);
  FFED_REQUIRE(replica_a.has_value());
  FFED_REQUIRE(replica_b.has_value());

  auto state_a = replica_a.value()->state();
  auto state_b = replica_b.value()->state();
  FFED_REQUIRE(state_a.has_value());
  FFED_REQUIRE(state_b.has_value());
  FFED_CHECK_EQ(state_a.value().digest(), state_b.value().digest());
  FFED_CHECK_EQ(render_state_text(state_a.value()), render_state_text(state_b.value()));

  auto second = replica_a.value()->evaluate(request);
  auto third = replica_b.value()->evaluate(request);
  FFED_REQUIRE(second.has_value());
  FFED_REQUIRE(third.has_value());
  FFED_CHECK_EQ(second.value().outcome, first.value().outcome);
  FFED_CHECK_EQ(third.value().outcome, first.value().outcome);
  FFED_CHECK_EQ(second.value().digest(), third.value().digest());
  FFED_CHECK_EQ(render_explanation(second.value().explanation),
                render_explanation(third.value().explanation));
  // The reasons must be identical reason-for-reason against the original as
  // well; the decision digest additionally covers the coordinator's logical
  // clock, which is coordinator-local bookkeeping rather than evidence.
  FFED_CHECK_EQ(second.value().explanation.reasons.size(),
                first.value().explanation.reasons.size());
  FFED_CHECK_EQ(second.value().explanation.summary, first.value().explanation.summary);
}

FFED_TEST_MAIN()