// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Membership lifecycle tests: explicit multi-party admission, retained local
// authority, reincarnation and generation fencing, withdrawal, leave/rejoin
// lineage and retirement.
#include "fixture.hpp"
#include "test_harness.hpp"

using namespace fabric_federation;
using namespace ffed_test;

namespace {

const MemberState* find(const FederationState& state, const MemberId& member) {
  return state.find(member);
}

}  // namespace

FFED_TEST(lifecycle, bootstrap_founder_is_explicitly_single_party) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  const MemberState* founder = find(state.value(), fixture.founder.member);
  FFED_REQUIRE(founder != nullptr);
  FFED_CHECK_EQ(founder->lifecycle, MemberLifecycleState::Active);
  FFED_CHECK(founder->bootstrap);
  FFED_CHECK_EQ(founder->lineage.value(), std::uint64_t{0});
  bool saw_bootstrap_reason = false;
  for (const Reason& reason : founder->reasons) {
    if (reason.code == ReasonCode::MultiPartyBootstrapGenesis) {
      saw_bootstrap_reason = true;
    }
  }
  FFED_CHECK(saw_bootstrap_reason);
  // The founder keeps its retained local authority and holds exactly what it
  // delegated.
  FFED_CHECK(!founder->retained_local_authority.empty());
  FFED_CHECK(!founder->federation_authority.empty());
  FFED_CHECK(!founder->federation_authority.front().scope.is_wildcard());
}

FFED_TEST(lifecycle, proposal_alone_grants_nothing) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("proposal-only", 1);
  auto outcome = coordinator.value()->submit_artifact(
      proposal(fixture.federation, candidate, fixture.founder));
  FFED_REQUIRE(outcome.has_value());
  FFED_CHECK_EQ(outcome.value().disposition, SubmissionDisposition::Applied);
  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  const MemberState* member = find(state.value(), candidate.member);
  FFED_REQUIRE(member != nullptr);
  FFED_CHECK_EQ(member->lifecycle, MemberLifecycleState::Proposed);
  FFED_CHECK(member->federation_authority.empty());
  FFED_CHECK(!member->activation_current);
}

FFED_TEST(lifecycle, a_policy_that_demands_an_endorsement_is_enforced) {
  // The shipped default needs two distinct parties. A federation may raise the
  // bar and demand a third-party endorsement; the derivation enforces that
  // rather than trusting the admission record.
  const FederationFixture fixture;
  CoordinatorConfig config;
  config.federation = fixture.federation;
  config.node = fixture.coordinator_node;
  config.policy = default_policy();
  for (PolicyRule& rule : config.policy.rules) {
    if (rule.kind == PolicyRuleKind::RequireEndorsements) {
      rule.value = 1;
    }
  }
  config.policy.canonicalize();
  config.bootstrap = true;
  config.founder = fixture.founder.declaration;
  auto coordinator = FederationCoordinator::create(config);
  FFED_REQUIRE(coordinator.has_value());

  const FixtureMember candidate = make_member("endorsement", 1);
  const FixtureMember third = make_member("endorsement", 2);
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(proposal(fixture.federation, candidate, fixture.founder))
                   .has_value());
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(acceptance(fixture.federation, candidate))
                   .has_value());
  auto withheld = coordinator.value()->state();
  FFED_REQUIRE(withheld.has_value());
  const MemberState* blocked = find(withheld.value(), candidate.member);
  FFED_REQUIRE(blocked != nullptr);
  FFED_CHECK_EQ(blocked->lifecycle, MemberLifecycleState::Proposed);
  bool saw_endorsement_shortfall = false;
  for (const Reason& reason : blocked->reasons) {
    if (reason.code == ReasonCode::MultiPartyInsufficientEndorsements) {
      saw_endorsement_shortfall = true;
    }
  }
  FFED_CHECK(saw_endorsement_shortfall);

  // The third party must itself be a member before its endorsement counts, so
  // the federation grows one member at a time and the endorsement that admits
  // the candidate can only come from an already-admitted member.
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(endorsement(fixture.federation, candidate, third))
                   .has_value());
  auto still = coordinator.value()->state();
  FFED_REQUIRE(still.has_value());
  FFED_CHECK_EQ(find(still.value(), candidate.member)->lifecycle,
                MemberLifecycleState::Proposed);
}

FFED_TEST(lifecycle, one_member_cannot_create_multiparty_authority_alone) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("self-dealing", 1);

  // The candidate sponsors itself, consents to itself and endorses itself.
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(proposal(fixture.federation, candidate, candidate))
                   .has_value());
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(acceptance(fixture.federation, candidate))
                   .has_value());
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(endorsement(fixture.federation, candidate, candidate))
                   .has_value());

  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  const MemberState* member = find(state.value(), candidate.member);
  FFED_REQUIRE(member != nullptr);
  FFED_CHECK_EQ(member->lifecycle, MemberLifecycleState::Proposed);
  FFED_CHECK(member->federation_authority.empty());
  bool saw_self_proposal = false;
  bool saw_insufficient_evidence = false;
  for (const Reason& reason : member->reasons) {
    if (reason.code == ReasonCode::MultiPartySelfProposalRejected) {
      saw_self_proposal = true;
    }
    if (reason.code == ReasonCode::MembershipProposedInsufficientEvidence) {
      saw_insufficient_evidence = true;
    }
  }
  // A self-proposal is recorded and set aside: it can never be the operative
  // proposal, so the member has no valid path to admission on its own word.
  FFED_CHECK(saw_self_proposal);
  FFED_CHECK(saw_insufficient_evidence);

  // Asking the federation for authority anyway is refused.
  AuthorityRequest request;
  request.id = RequestId::derive("self-dealing", 1);
  request.federation = fixture.federation;
  request.epoch_seen = state.value().epoch;
  request.actor = candidate.identity();
  request.requested = ScopeGrant{ScopeId::parse("federation.route.advertise").value(),
                                 AuthorityVerb::Mutate};
  auto decision = coordinator.value()->evaluate(request);
  FFED_REQUIRE(decision.has_value());
  FFED_CHECK(decision.value().outcome != Outcome::Granted);
}

FFED_TEST(lifecycle, full_join_produces_active_member_with_exact_authority) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("full-join", 1);
  join_and_observe(*coordinator.value(), fixture.federation, candidate, fixture.founder);

  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  const MemberState* member = find(state.value(), candidate.member);
  FFED_REQUIRE(member != nullptr);
  FFED_CHECK_EQ(member->lifecycle, MemberLifecycleState::Active);
  FFED_CHECK(member->activation_current);
  FFED_CHECK(!member->federation_authority.empty());
  FFED_CHECK_EQ(member->retained_local_authority.size(), std::size_t{1});
  FFED_CHECK_EQ(member->current_identity.constitution, candidate.constitution.digest());
  FFED_CHECK_EQ(member->current_identity.incarnation, candidate.incarnation);

  // The provenance names the sponsor and the candidate with their exact
  // revisions.
  bool saw_sponsor = false;
  bool saw_candidate = false;
  for (const Contribution& contribution : member->contributing_parties) {
    if (contribution.role == ContributionRole::Proposer &&
        contribution.member == fixture.founder.member) {
      saw_sponsor = true;
      FFED_CHECK_EQ(contribution.constitution, fixture.founder.constitution.digest());
    }
    if (contribution.role == ContributionRole::Candidate &&
        contribution.member == candidate.member) {
      saw_candidate = true;
      FFED_CHECK_EQ(contribution.constitution, candidate.constitution.digest());
    }
  }
  FFED_CHECK(saw_sponsor);
  FFED_CHECK(saw_candidate);
}

FFED_TEST(lifecycle, reincarnation_fences_the_previous_incarnation) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("reincarnation", 1);
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(proposal(fixture.federation, candidate, fixture.founder))
                   .has_value());
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(acceptance(fixture.federation, candidate))
                   .has_value());
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(
                       endorsement(fixture.federation, candidate, fixture.founder))
                   .has_value());
  observe_mutual_reachability(*coordinator.value());
  observe_mutual_reachability(*coordinator.value());
  auto active = coordinator.value()->state();
  FFED_REQUIRE(active.has_value());
  FFED_CHECK_EQ(find(active.value(), candidate.member)->lifecycle, MemberLifecycleState::Active);

  // The member restarts with a fresh incarnation and re-attests. Same
  // generation, same constitution digest, new incarnation.
  const Artifact restarted =
      reattestation(fixture.federation, candidate, active.value().epoch, Incarnation(2));
  FFED_REQUIRE(coordinator.value()->submit_artifact(restarted).has_value());
  // The other members must observe the new incarnation for the edge to hold.
  observe_mutual_reachability(*coordinator.value());

  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  const MemberState* member = find(state.value(), candidate.member);
  FFED_REQUIRE(member != nullptr);
  FFED_CHECK_EQ(member->current_identity.incarnation, Incarnation(2));
  // The old activation is bound to incarnation 1, so the member is no longer
  // active and the previous incarnation is recorded as fenced.
  FFED_CHECK(member->lifecycle == MemberLifecycleState::Admitted ||
             member->lifecycle == MemberLifecycleState::Active);
  bool fenced_first_incarnation = false;
  for (const Incarnation& incarnation : member->fenced_incarnations) {
    if (incarnation == Incarnation(1)) {
      fenced_first_incarnation = true;
    }
  }
  FFED_CHECK(fenced_first_incarnation);

  // A request that presents the old incarnation must not be granted.
  AuthorityRequest request;
  request.id = RequestId::derive("reincarnation", 1);
  request.federation = fixture.federation;
  request.epoch_seen = state.value().epoch;
  request.actor = candidate.identity();
  request.requested = ScopeGrant{ScopeId::parse("federation.route.observe").value(),
                                 AuthorityVerb::Observe};
  auto decision = coordinator.value()->evaluate(request);
  FFED_REQUIRE(decision.has_value());
  FFED_CHECK(decision.value().outcome == Outcome::Fenced ||
             decision.value().outcome == Outcome::Stale);
  FFED_CHECK(!decision.value().explanation.has(ReasonCode::IdentityMatches) ||
             decision.value().outcome != Outcome::Granted);
}

FFED_TEST(lifecycle, generation_change_requires_fresh_consent) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  FixtureMember candidate = make_member("generation", 1);
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(proposal(fixture.federation, candidate, fixture.founder))
                   .has_value());
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(acceptance(fixture.federation, candidate))
                   .has_value());
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(
                       endorsement(fixture.federation, candidate, fixture.founder))
                   .has_value());
  observe_mutual_reachability(*coordinator.value());
  observe_mutual_reachability(*coordinator.value());
  auto active = coordinator.value()->state();
  FFED_REQUIRE(active.has_value());
  FFED_CHECK_EQ(find(active.value(), candidate.member)->lifecycle, MemberLifecycleState::Active);

  // The member changes its constitution generation without re-consenting.
  MemberSpec next_spec;
  next_spec.generation = Generation(2);
  FixtureMember regenerated = make_member("generation", 1, next_spec);
  const Artifact restated = reattestation(fixture.federation, regenerated, active.value().epoch,
                                          Incarnation(1));
  FFED_REQUIRE(coordinator.value()->submit_artifact(restated).has_value());
  observe_mutual_reachability(*coordinator.value());

  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  const MemberState* member = find(state.value(), candidate.member);
  FFED_REQUIRE(member != nullptr);
  FFED_CHECK_EQ(member->lifecycle, MemberLifecycleState::Fenced);
  bool saw_reconsent = false;
  for (const Reason& reason : member->reasons) {
    if (reason.code == ReasonCode::GenerationChangeRequiresReconsent) {
      saw_reconsent = true;
    }
  }
  FFED_CHECK(saw_reconsent);
  FFED_CHECK(member->federation_authority.empty());

  // Fresh consent restores it: the same lineage is re-consented, admitted and
  // activated against the new generation.
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(proposal(fixture.federation, regenerated, fixture.founder))
                   .has_value());
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(acceptance(fixture.federation, regenerated))
                   .has_value());
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(
                       endorsement(fixture.federation, regenerated, fixture.founder))
                   .has_value());
  observe_mutual_reachability(*coordinator.value());
  observe_mutual_reachability(*coordinator.value());
  auto recovered = coordinator.value()->state();
  FFED_REQUIRE(recovered.has_value());
  // Fresh consent restores the member's standing and its authority at the new
  // generation.
  FFED_CHECK_MSG(lifecycle_holds_federation_authority(
                     find(recovered.value(), candidate.member)->lifecycle),
                 "lifecycle " +
                     std::string(to_string(find(recovered.value(), candidate.member)->lifecycle)) +
                     (find(recovered.value(), candidate.member)->reasons.empty()
                          ? std::string()
                          : (" first " + std::string(to_string(find(recovered.value(), candidate.member)
                                                                  ->reasons.front()
                                                                  .code)) +
                             " " + find(recovered.value(), candidate.member)->reasons.front().detail)));
  FFED_CHECK_EQ(find(recovered.value(), candidate.member)->current_identity.generation,
                Generation(2));
  FFED_CHECK(!find(recovered.value(), candidate.member)->federation_authority.empty());
}

FFED_TEST(lifecycle, withdrawal_removes_authority_and_is_not_restored) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("withdrawal", 1);
  join_and_observe(*coordinator.value(), fixture.federation, candidate, fixture.founder);
  FFED_REQUIRE(find(coordinator.value()->state().value(), candidate.member) != nullptr);
  const ScopeGrant grant{ScopeId::parse("federation.route.advertise").value(),
                         AuthorityVerb::Mutate};
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(withdrawal(fixture.federation, candidate, {grant}))
                   .has_value());
  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  const MemberState* member = find(state.value(), candidate.member);
  FFED_REQUIRE(member != nullptr);
  // The withdrawn grant is gone; the member's other delegated grants remain.
  FFED_CHECK(!grants_cover(member->federation_authority, grant));
  FFED_CHECK_EQ(member->withdrawn_grants.size(), std::size_t{1});

  AuthorityRequest request;
  request.id = RequestId::derive("withdrawal", 1);
  request.federation = fixture.federation;
  request.epoch_seen = state.value().epoch;
  request.actor = candidate.identity();
  request.requested = grant;
  auto decision = coordinator.value()->evaluate(request);
  FFED_REQUIRE(decision.has_value());
  FFED_CHECK_EQ(decision.value().outcome, Outcome::Refused);
  FFED_CHECK(decision.value().explanation.has(ReasonCode::DelegationWithdrawn));
}

FFED_TEST(lifecycle, leave_ends_federation_authority_and_keeps_local_authority) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("leave", 1);
  join_and_observe(*coordinator.value(), fixture.federation, candidate, fixture.founder);
  FFED_REQUIRE(find(coordinator.value()->state().value(), candidate.member) != nullptr);
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(leave_notice(fixture.federation, candidate))
                   .has_value());
  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  const MemberState* member = find(state.value(), candidate.member);
  FFED_REQUIRE(member != nullptr);
  FFED_CHECK_EQ(member->lifecycle, MemberLifecycleState::Leaving);
  FFED_CHECK(member->federation_authority.empty());
  FFED_CHECK_EQ(member->retained_local_authority.size(), std::size_t{1});

  // Local authority is decided by the member and is untouched.
  const AuthorityDecision local = evaluate_local_authority(
      candidate.constitution,
      ScopeGrant{ScopeId::parse("domain.local.control").value(), AuthorityVerb::Administer},
      Tick(1));
  FFED_CHECK_EQ(local.outcome, Outcome::Granted);
  FFED_CHECK(local.explanation.has(ReasonCode::ScopeLocalAuthorityAlwaysGranted));
}

FFED_TEST(lifecycle, rejoin_creates_a_fresh_lineage) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("rejoin", 1);
  join_and_observe(*coordinator.value(), fixture.federation, candidate, fixture.founder);
  FFED_REQUIRE(find(coordinator.value()->state().value(), candidate.member) != nullptr);
  const Digest first_join_digest = coordinator.value()->state_digest();

  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(leave_notice(fixture.federation, candidate))
                   .has_value());
  const Digest after_leave_digest = coordinator.value()->state_digest();
  FFED_CHECK(after_leave_digest != first_join_digest);

  // The rejoin uses lineage 1. Artefacts from lineage 0 are superseded.
  FFED_REQUIRE(coordinator.value()->submit_artifact(
                   proposal(fixture.federation, candidate, fixture.founder, Lineage(1)))
                   .has_value());
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(acceptance(fixture.federation, candidate, Lineage(1)))
                   .has_value());
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(endorsement(fixture.federation, candidate, fixture.founder,
                                                 Lineage(1)))
                   .has_value());
  observe_mutual_reachability(*coordinator.value());
  observe_mutual_reachability(*coordinator.value());
  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  const MemberState* member = find(state.value(), candidate.member);
  FFED_REQUIRE(member != nullptr);
  // The rejoin restored standing and authority on a fresh lineage, and the
  // federation is at epoch 1 with no fence outstanding.
  FFED_CHECK_MSG(lifecycle_holds_federation_authority(member->lifecycle),
                 "lifecycle " + std::string(to_string(member->lifecycle)) + " reasons " +
                     std::to_string(member->reasons.size()) +
                     (member->reasons.empty()
                          ? std::string()
                          : (" first " + std::string(to_string(member->reasons.front().code)) +
                             " " + member->reasons.front().detail)));
  FFED_CHECK_EQ(member->lineage.value(), std::uint64_t{1});
  FFED_CHECK(member->admission_digest != Digest());
  // The rejoined membership is a different lineage, so the canonical state can
  // never be mistaken for the original.
  FFED_CHECK(coordinator.value()->state_digest() != first_join_digest);
  FFED_CHECK(member->lineage_id == MembershipSlot::make(candidate.member, Lineage(1)).lineage_id);
}

FFED_TEST(lifecycle, retirement_is_terminal_and_requires_leave_or_fence) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("retire", 1);
  join_and_observe(*coordinator.value(), fixture.federation, candidate, fixture.founder);
  FFED_REQUIRE(find(coordinator.value()->state().value(), candidate.member) != nullptr);
  // An active member cannot simply be retired.
  FFED_CHECK_EQ(coordinator.value()->retire_member(candidate.member, Lineage(),
                                                   ReasonCode::MembershipRetired, "test")
                    .code(),
                ErrorCode::Refused);
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(leave_notice(fixture.federation, candidate))
                   .has_value());
  FFED_REQUIRE(coordinator.value()
                   ->retire_member(candidate.member, Lineage(), ReasonCode::MembershipRetired,
                                   "the operator retired the lineage")
                   .ok());
  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  const MemberState* member = find(state.value(), candidate.member);
  FFED_REQUIRE(member != nullptr);
  FFED_CHECK_EQ(member->lifecycle, MemberLifecycleState::Retired);
  FFED_CHECK(lifecycle_is_terminal(member->lifecycle));

  // A retired member cannot be revived by a later artefact in the same lineage.
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(acceptance(fixture.federation, candidate))
                   .has_value());
  auto after = coordinator.value()->state();
  FFED_REQUIRE(after.has_value());
  FFED_CHECK_EQ(find(after.value(), candidate.member)->lifecycle,
                MemberLifecycleState::Retired);
}

FFED_TEST(lifecycle, coordinator_fence_is_sticky_until_a_later_activation) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("fence", 1);
  join_and_observe(*coordinator.value(), fixture.federation, candidate, fixture.founder);
  FFED_REQUIRE(find(coordinator.value()->state().value(), candidate.member) != nullptr);
  FFED_REQUIRE(coordinator.value()
                   ->fence_member(candidate.member, Lineage(), ReasonCode::MembershipFencedByOrder,
                                  "fenced by the operator")
                   .ok());
  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  const MemberState* member = find(state.value(), candidate.member);
  FFED_REQUIRE(member != nullptr);
  FFED_CHECK_EQ(member->lifecycle, MemberLifecycleState::Fenced);
  FFED_CHECK(member->federation_authority.empty());

  AuthorityRequest request;
  request.id = RequestId::derive("fence", 1);
  request.federation = fixture.federation;
  request.epoch_seen = state.value().epoch;
  request.actor = candidate.identity();
  request.requested = ScopeGrant{ScopeId::parse("federation.route.observe").value(),
                                 AuthorityVerb::Observe};
  auto decision = coordinator.value()->evaluate(request);
  FFED_REQUIRE(decision.has_value());
  FFED_CHECK_EQ(decision.value().outcome, Outcome::Fenced);

  // A fence is not cleared by re-attesting at the same epoch.
  FFED_REQUIRE(coordinator.value()
                   ->submit_artifact(
                       reattestation(fixture.federation, candidate, state.value().epoch,
                                     Incarnation(1)))
                   .has_value());
  auto still = coordinator.value()->state();
  FFED_REQUIRE(still.has_value());
  FFED_CHECK_EQ(find(still.value(), candidate.member)->lifecycle, MemberLifecycleState::Fenced);
}

FFED_TEST_MAIN()
