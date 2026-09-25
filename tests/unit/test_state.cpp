// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Derived-state tests: permutation independence, idempotence, equivocation
// handling, an independent reference model, and encoding determinism.
#include <algorithm>
#include <memory>
#include <set>

#include "fabric_federation/random.hpp"
#include "fixture.hpp"
#include "test_harness.hpp"

using namespace fabric_federation;
using namespace ffed_test;

namespace {

std::vector<Artifact> scenario_artifacts(const FederationId& federation,
                                         const std::vector<FixtureMember>& members,
                                         const FixtureMember& sponsor) {
  // The bootstrap founder sponsors and endorses every candidate. It is the one
  // member that is established from the first record, which keeps the
  // independent reference model below genuinely independent rather than a
  // re-implementation of the standing fixpoint.
  std::vector<Artifact> artifacts;
  for (const FixtureMember& candidate : members) {
    artifacts.push_back(proposal(federation, candidate, sponsor));
    artifacts.push_back(acceptance(federation, candidate));
    artifacts.push_back(endorsement(federation, candidate, sponsor));
  }
  return artifacts;
}

// Independent reference model: given only the artefact set, which members does
// a reader with no access to the runtime expect to be active?
std::set<std::string> reference_active_members(const std::vector<Artifact>& artifacts,
                                               const std::string& bootstrap_founder) {
  std::set<std::string> with_proposal;
  std::set<std::string> with_acceptance;
  std::set<std::string> with_endorsement;
  std::set<std::string> left;
  std::set<std::string> fenced;
  for (const Artifact& artifact : artifacts) {
    const std::string subject = artifact.envelope.subject.to_string();
    switch (artifact.envelope.kind) {
      case ArtifactKind::MembershipProposal:
        with_proposal.insert(subject);
        break;
      case ArtifactKind::MembershipAcceptance:
        with_acceptance.insert(subject);
        break;
      case ArtifactKind::MembershipEndorsement:
        with_endorsement.insert(subject);
        break;
      case ArtifactKind::MembershipLeave:
        left.insert(subject);
        break;
      case ArtifactKind::MembershipFence:
        fenced.insert(subject);
        break;
      default:
        break;
    }
  }
  std::set<std::string> active;
  // The bootstrap founder is established by the genesis record and never needs
  // a proposal.
  if (!bootstrap_founder.empty()) {
    active.insert(bootstrap_founder);
  }
  for (const std::string& member : with_proposal) {
    if (with_acceptance.count(member) == 0 || with_endorsement.count(member) == 0) {
      continue;
    }
    if (left.count(member) != 0 || fenced.count(member) != 0) {
      continue;
    }
    active.insert(member);
  }
  return active;
}

}  // namespace

FFED_TEST(state, canonical_digest_is_permutation_independent) {
  const FederationFixture fixture;
  const FixtureMember sponsor = fixture.founder;
  std::vector<FixtureMember> members;
  for (std::uint64_t i = 0; i < 6; ++i) {
    members.push_back(make_member("permutation", i + 1));
  }
  std::vector<Artifact> artifacts = scenario_artifacts(fixture.federation, members, sponsor);
  // Add evidence that changes authority rather than only membership.
  artifacts.push_back(withdrawal(fixture.federation, members[0],
                                 {ScopeGrant{ScopeId::parse("federation.route.advertise").value(),
                                             AuthorityVerb::Mutate}}));
  artifacts.push_back(leave_notice(fixture.federation, members[5]));

  DeterministicRng rng(ffed_test::property_seed());
  Digest reference;
  constexpr int kRounds = 40;
  for (int round = 0; round < kRounds; ++round) {
    std::vector<Artifact> shuffled = artifacts;
    rng.shuffle(shuffled);
    auto coordinator = make_coordinator(fixture);
    FFED_REQUIRE(coordinator.has_value());
    for (const Artifact& artifact : shuffled) {
      auto outcome = coordinator.value()->submit_artifact(artifact);
      FFED_REQUIRE(outcome.has_value());
    }
    const Digest digest = coordinator.value()->state_digest();
    FFED_REQUIRE(!digest.is_zero());
    if (round == 0) {
      reference = digest;
    } else {
      FFED_CHECK_MSG(digest == reference,
                     "round " + std::to_string(round) + " produced " + digest.to_hex() +
                         " expected " + reference.to_hex() + " (seed " +
                         std::to_string(ffed_test::property_seed()) + ")");
    }
    const Status stopped = coordinator.value()->stop();
    FFED_REQUIRE(stopped.ok());
    if (!(digest == reference)) {
      break;
    }
  }
}

FFED_TEST(state, identical_evidence_is_idempotent) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("idempotent", 1);
  for (const Artifact& artifact : scenario_artifacts(fixture.federation, {candidate},
                                                     fixture.founder)) {
    auto first = coordinator.value()->submit_artifact(artifact);
    FFED_REQUIRE(first.has_value());
    FFED_CHECK_EQ(first.value().disposition, SubmissionDisposition::Applied);
    const Digest after_first = coordinator.value()->state_digest();
    auto second = coordinator.value()->submit_artifact(artifact);
    FFED_REQUIRE(second.has_value());
    FFED_CHECK_EQ(second.value().disposition, SubmissionDisposition::Duplicate);
    FFED_CHECK_EQ(coordinator.value()->state_digest(), after_first);
  }
}

FFED_TEST(state, the_same_identifier_with_different_content_is_quarantined) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("equivocation", 1);
  Artifact honest = proposal(fixture.federation, candidate, fixture.founder);
  FFED_REQUIRE(coordinator.value()->submit_artifact(honest).has_value());
  const Digest after_honest = coordinator.value()->state_digest();

  // The same evidence identifier now carries a different body.
  Artifact forged = honest;
  forged.body.lineage = Lineage(7);
  canonicalize_body(forged.body);
  forged.envelope.body_digest = forged.body.digest();
  auto outcome = coordinator.value()->submit_artifact(forged);
  FFED_REQUIRE(outcome.has_value());
  FFED_CHECK_EQ(outcome.value().disposition, SubmissionDisposition::Rejected);
  FFED_CHECK_EQ(outcome.value().reason, ReasonCode::EvidenceDuplicateConflicting);

  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  bool saw_conflict = false;
  for (const ConflictRecord& conflict : state.value().conflicts) {
    if (conflict.kind == ConflictKind::DuplicateEvidence) {
      saw_conflict = true;
    }
  }
  FFED_CHECK(saw_conflict);
  // Both copies are quarantined, so the honest artefact stops counting.
  // Both copies are quarantined, so the member has no valid evidence left and
  // is not even a tracked member.
  const MemberState* member = state.value().find(candidate.member);
  if (member != nullptr) {
    FFED_CHECK_EQ(member->lifecycle, MemberLifecycleState::Absent);
  }
  FFED_CHECK(coordinator.value()->state_digest() != after_honest);
}

FFED_TEST(state, derivation_matches_an_independent_reference_model) {
  const FederationFixture fixture;
  DeterministicRng rng(ffed_test::property_seed() ^ 0x1234u);
  for (int iteration = 0; iteration < 12; ++iteration) {
    const std::uint64_t count = rng.range(1, 5);
    std::vector<FixtureMember> members;
    for (std::uint64_t i = 0; i < count; ++i) {
      members.push_back(make_member("reference", i + 1));
    }
    std::vector<Artifact> artifacts = scenario_artifacts(fixture.federation, members,
                                                         fixture.founder);
    std::vector<bool> leavers(members.size(), false);
    for (std::size_t i = 0; i < members.size(); ++i) {
      if (rng.below(3) == 0) {
        artifacts.push_back(leave_notice(fixture.federation, members[i]));
        leavers[i] = true;
      }
    }
    auto coordinator = make_coordinator(fixture);
    FFED_REQUIRE(coordinator.has_value());
    for (const Artifact& artifact : artifacts) {
      FFED_REQUIRE(coordinator.value()->submit_artifact(artifact).has_value());
    }
    // Reachability is evidence like any other: without it the federation is
    // INDETERMINATE and its members are degraded rather than active.
    observe_mutual_reachability(*coordinator.value());
    auto state = coordinator.value()->state();
    FFED_REQUIRE(state.has_value());

    std::set<std::string> expected =
        reference_active_members(artifacts, fixture.founder.member.to_string());
    std::set<std::string> observed;
    for (const MemberState& member : state.value().members) {
      // Established membership: admitted, active or degraded. Whether a member
      // is currently activated depends on reachability evidence, which this
      // scenario does not provide.
      if (member.lifecycle == MemberLifecycleState::Active) {
        observed.insert(member.member.to_string());
      }
    }
    std::set<std::string> difference;
    std::set_symmetric_difference(expected.begin(), expected.end(), observed.begin(),
                                  observed.end(),
                                  std::inserter(difference, difference.begin()));
    FFED_CHECK_MSG(difference.empty(), "iteration " + std::to_string(iteration) +
                                           " seed " + std::to_string(ffed_test::property_seed()) +
                                           " reference and derived active sets differ");
    for (std::size_t i = 0; i < members.size(); ++i) {
      const MemberState* member = state.value().find(members[i].member);
      FFED_REQUIRE(member != nullptr);
      if (leavers[i]) {
        FFED_CHECK(member->lifecycle != MemberLifecycleState::Active);
      }
    }
    const Status stopped = coordinator.value()->stop();
    FFED_REQUIRE(stopped.ok());
  }
}

FFED_TEST(state, every_membership_change_moves_the_canonical_digest) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  Digest previous = coordinator.value()->state_digest();
  for (std::uint64_t i = 0; i < 5; ++i) {
    const FixtureMember candidate = make_member("growth", i + 1);
    for (const Artifact& artifact : scenario_artifacts(fixture.federation, {candidate},
                                                       fixture.founder)) {
      FFED_REQUIRE(coordinator.value()->submit_artifact(artifact).has_value());
    }
    const Digest digest = coordinator.value()->state_digest();
    // Each new member changes the derived state, so the canonical digest must
    // move. Evidence that does not change the derived state (for example an
    // endorsement the policy does not require) legitimately leaves the digest
    // where it was: the digest identifies the logical state, not the byte count
    // of the evidence.
    FFED_CHECK_MSG(digest != previous, "member " + std::to_string(i) +
                                           " left the canonical digest unchanged");
    previous = digest;
  }
}

FFED_TEST(state, state_encoding_is_deterministic_and_rejects_tampering) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("encoding", 1);
  join_member(*coordinator.value(), fixture.federation, candidate, fixture.founder);
  auto first = coordinator.value()->state();
  auto second = coordinator.value()->state();
  FFED_REQUIRE(first.has_value());
  FFED_REQUIRE(second.has_value());
  FFED_CHECK_EQ(first.value().digest(), second.value().digest());
  FFED_CHECK_EQ(render_state_text(first.value()), render_state_text(second.value()));

  auto artifacts = coordinator.value()->artifacts();
  FFED_REQUIRE(artifacts.has_value());
  auto replica = make_coordinator(fixture);
  FFED_REQUIRE(replica.has_value());
  for (const Artifact& artifact : artifacts.value()) {
    FFED_REQUIRE(replica.value()->submit_artifact(artifact).has_value());
  }
  FFED_CHECK_EQ(replica.value()->state_digest(), coordinator.value()->state_digest());
}

FFED_TEST(state, malformed_and_foreign_evidence_is_rejected_without_effect) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const Digest baseline = coordinator.value()->state_digest();

  const FixtureMember candidate = make_member("rejected", 1);
  Artifact tampered = proposal(fixture.federation, candidate, fixture.founder);
  tampered.body.lineage = Lineage(3);  // digest no longer matches the envelope
  auto outcome = coordinator.value()->submit_artifact(tampered);
  FFED_REQUIRE(outcome.has_value());
  FFED_CHECK_EQ(outcome.value().disposition, SubmissionDisposition::Invalid);
  FFED_CHECK_EQ(coordinator.value()->state_digest(), baseline);

  Artifact foreign = proposal(FederationId::derive("elsewhere", 1), candidate, fixture.founder);
  foreign.envelope.federation = FederationId::derive("elsewhere", 1);
  foreign.envelope.body_digest = foreign.body.digest();
  auto foreign_outcome = coordinator.value()->submit_artifact(foreign);
  FFED_REQUIRE(foreign_outcome.has_value());
  FFED_CHECK_EQ(foreign_outcome.value().disposition, SubmissionDisposition::Rejected);
  FFED_CHECK_EQ(foreign_outcome.value().reason, ReasonCode::FederationIdentityMismatch);
  FFED_CHECK_EQ(coordinator.value()->state_digest(), baseline);
}

FFED_TEST_MAIN()