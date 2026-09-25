// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Shared test fixture: builds constitutions, members and artefacts so that the
// test suites describe intent rather than encoding layout.
#pragma once

#include <string>
#include <vector>

#include "fabric_federation/coordinator.hpp"
#include "fabric_federation/evidence.hpp"
#include "fabric_federation/member_runtime.hpp"
#include "fabric_federation/version.hpp"

namespace ffed_test {

using namespace fabric_federation;

struct MemberSpec {
  std::string seed;
  Generation generation = Generation(1);
  Incarnation incarnation = Incarnation(1);
  // Shared by default so that a fixture with several members does not
  // accidentally create an exclusive-delegation conflict. Tests that are about
  // conflicts ask for exclusive delegation explicitly.
  std::string delegated =
      "federation.route.advertise:mutate:shared,federation.route.observe:observe:shared";
  std::string retained = "domain.local.control:administer";
  bool declare_protocol_capability = true;
  std::string description = "test member";
};

inline MemberConstitution make_constitution(const MemberId& member, const FabricDomainId& domain,
                                            const MemberSpec& spec) {
  MemberConstitution constitution;
  constitution.member = member;
  constitution.domain = domain;
  constitution.generation = spec.generation;
  constitution.software_major = static_cast<std::uint32_t>(kVersionMajor);
  constitution.software_minor = static_cast<std::uint32_t>(kVersionMinor);
  constitution.software_patch = static_cast<std::uint32_t>(kVersionPatch);
  constitution.description = spec.description;
  if (spec.declare_protocol_capability) {
    CapabilityStatement capability;
    auto id = CapabilityId::parse("federation.protocol.v1");
    if (id.has_value()) {
      capability.capability = std::move(id.value());
    }
    capability.version = 1;
    capability.evidence = EvidenceState::Known;
    capability.evidence_digest = Digest::of("fixture");
    constitution.capabilities.push_back(std::move(capability));
  }
  if (!spec.retained.empty()) {
    std::size_t start = 0;
    while (start <= spec.retained.size()) {
      const std::size_t comma = spec.retained.find(',', start);
      const std::string item = spec.retained.substr(
          start, comma == std::string::npos ? std::string::npos : comma - start);
      if (!item.empty()) {
        const std::size_t colon = item.find(':');
        const std::string scope_text = colon == std::string::npos ? item : item.substr(0, colon);
        auto scope = ScopeId::parse(scope_text);
        if (scope.has_value()) {
          ScopeGrant grant;
          grant.scope = std::move(scope.value());
          grant.verb = AuthorityVerb::Administer;
          if (colon != std::string::npos) {
            // The text form is validated by the caller's expectations; an
            // unknown verb keeps the default so the fixture stays total.
            AuthorityVerb parsed = grant.verb;
            if (parse_verb(item.substr(colon + 1), parsed)) {
              grant.verb = parsed;
            }
          }
          constitution.retained.push_back(std::move(grant));
        }
      }
      if (comma == std::string::npos) {
        break;
      }
      start = comma + 1;
    }
  }
  if (!spec.delegated.empty()) {
    std::size_t start = 0;
    while (start <= spec.delegated.size()) {
      const std::size_t comma = spec.delegated.find(',', start);
      const std::string item = spec.delegated.substr(
          start, comma == std::string::npos ? std::string::npos : comma - start);
      if (!item.empty()) {
        const std::vector<std::string> parts = [&item] {
          std::vector<std::string> out;
          std::size_t begin = 0;
          for (std::size_t i = 0; i <= item.size(); ++i) {
            if (i == item.size() || item[i] == ':') {
              out.push_back(item.substr(begin, i - begin));
              begin = i + 1;
            }
          }
          return out;
        }();
        if (parts.size() >= 2) {
          auto scope = ScopeId::parse(parts[0]);
          if (scope.has_value()) {
            DelegationTerms terms;
            terms.grant.scope = std::move(scope.value());
            AuthorityVerb parsed = terms.grant.verb;
            if (parse_verb(parts[1], parsed)) {
              terms.grant.verb = parsed;
            }
            if (parts.size() > 2) {
              terms.mode = parts[2] == "shared" ? DelegationMode::Shared
                                                : DelegationMode::Exclusive;
            }
            if (parts.size() > 3 && !parts[3].empty()) {
              terms.weight = static_cast<std::uint32_t>(std::stoul(parts[3]));
            }
            constitution.delegated.push_back(std::move(terms));
          }
        }
      }
      if (comma == std::string::npos) {
        break;
      }
      start = comma + 1;
    }
  }
  constitution.canonicalize();
  return constitution;
}

inline MemberDeclaration make_declaration(const MemberConstitution& constitution,
                                          const NodeId& node, Incarnation incarnation,
                                          Tick tick = Tick(1)) {
  MemberDeclaration declaration;
  declaration.constitution = constitution;
  declaration.incarnation = incarnation;
  declaration.node = node;
  declaration.declared_at = tick;
  return declaration;
}

// A fully specified member: identity, domain, node and declaration.
struct FixtureMember {
  MemberId member;
  FabricDomainId domain;
  NodeId node;
  MemberConstitution constitution;
  Incarnation incarnation = Incarnation(1);
  MemberDeclaration declaration;

  [[nodiscard]] MemberIdentity identity() const { return declaration.identity(); }
};

inline FixtureMember make_member(const std::string& seed, std::uint64_t index,
                                 const MemberSpec& spec = MemberSpec{}) {
  FixtureMember member;
  member.member = MemberId::derive(seed + "|member", index);
  member.domain = FabricDomainId::derive(seed + "|domain", index);
  member.node = NodeId::derive(seed + "|node", index);
  member.incarnation = spec.incarnation;
  member.constitution = make_constitution(member.member, member.domain, spec);
  member.declaration = make_declaration(member.constitution, member.node, member.incarnation);
  return member;
}

// Builds one artefact with an identifier derived from its content, so building
// the same artefact twice yields the same evidence identifier.
inline Artifact build_artifact(const FederationId& federation, ArtifactKind kind,
                               const MemberDeclaration& subject, const MemberIdentity& issuer,
                               const NodeId& issuer_node, Lineage lineage, Epoch epoch, Tick tick,
                               ReasonCode reason = ReasonCode::EvidenceUnknown,
                               std::string text = std::string(),
                               std::vector<ScopeGrant> withdrawn = {},
                               std::vector<DelegationTerms> terms = {},
                               std::vector<MemberId> parties = {}) {
  ArtifactBody body;
  body.declaration = subject;
  body.declared_identity = subject.identity();
  body.lineage = lineage;
  body.epoch = epoch;
  body.logical_time = tick;
  body.reason_code = reason;
  body.fence_reason = reason;
  body.reason_text = std::move(text);
  body.withdrawn_grants = std::move(withdrawn);
  body.delegated_terms = std::move(terms);
  body.parties = std::move(parties);
  canonicalize_body(body);

  ArtifactEnvelope envelope;
  envelope.kind = kind;
  envelope.federation = federation;
  envelope.subject = subject.constitution.member;
  envelope.issuer.node = issuer_node;
  envelope.issuer.member = issuer.member;
  envelope.issuer.generation = issuer.generation;
  envelope.issuer.incarnation = issuer.incarnation;
  envelope.issuer.constitution = issuer.constitution;
  envelope.issuer.epoch = epoch;
  envelope.issuer.issued_at = tick;
  Artifact artifact = Artifact::make(std::move(envelope), std::move(body));
  artifact.envelope.evidence = EvidenceId::derive(
      federation.to_string() + "|" + std::string(to_string(kind)) + "|" +
          subject.constitution.member.to_string() + "|" + issuer.member.to_string() + "|" +
          std::to_string(epoch.value()) + "|" + std::to_string(lineage.value()) + "|" +
          artifact.body.digest().to_hex(),
      0);
  return artifact;
}

// Convenience wrappers for the common artefacts.
inline Artifact proposal(const FederationId& federation, const FixtureMember& candidate,
                         const FixtureMember& sponsor, Lineage lineage = Lineage(0),
                         Epoch epoch = Epoch(1)) {
  return build_artifact(federation, ArtifactKind::MembershipProposal, candidate.declaration,
                        sponsor.identity(), sponsor.node, lineage, epoch, Tick(1));
}

inline Artifact acceptance(const FederationId& federation, const FixtureMember& candidate,
                           Lineage lineage = Lineage(0), Epoch epoch = Epoch(1)) {
  return build_artifact(federation, ArtifactKind::MembershipAcceptance, candidate.declaration,
                        candidate.identity(), candidate.node, lineage, epoch, Tick(1));
}

inline Artifact endorsement(const FederationId& federation, const FixtureMember& candidate,
                            const FixtureMember& endorser, Lineage lineage = Lineage(0),
                            Epoch epoch = Epoch(1)) {
  return build_artifact(federation, ArtifactKind::MembershipEndorsement, candidate.declaration,
                        endorser.identity(), endorser.node, lineage, epoch, Tick(1));
}

inline Artifact reattestation(const FederationId& federation, const FixtureMember& member,
                              Epoch epoch, Incarnation incarnation) {
  MemberDeclaration declaration = member.declaration;
  declaration.incarnation = incarnation;
  return build_artifact(federation, ArtifactKind::MemberReattestation, declaration,
                        declaration.identity(), member.node, Lineage(0), epoch, Tick(1));
}

inline Artifact leave_notice(const FederationId& federation, const FixtureMember& member,
                             Lineage lineage = Lineage(0), Epoch epoch = Epoch(1)) {
  return build_artifact(federation, ArtifactKind::MembershipLeave, member.declaration,
                        member.identity(), member.node, lineage, epoch, Tick(1),
                        ReasonCode::MembershipLeaving, "the member left");
}

inline Artifact fence_order(const FederationId& federation, const FixtureMember& member,
                            Epoch epoch, Lineage lineage = Lineage(0)) {
  return build_artifact(federation, ArtifactKind::MembershipFence, member.declaration,
                        MemberIdentity(), NodeId::derive("coordinator", 1), lineage, epoch,
                        Tick(1), ReasonCode::MembershipFencedByOrder, "fenced by the coordinator");
}

inline Artifact withdrawal(const FederationId& federation, const FixtureMember& member,
                           std::vector<ScopeGrant> grants, Lineage lineage = Lineage(0),
                           Epoch epoch = Epoch(1)) {
  return build_artifact(federation, ArtifactKind::DelegationWithdrawal, member.declaration,
                        member.identity(), member.node, lineage, epoch, Tick(1),
                        ReasonCode::EvidenceUnknown, std::string(), std::move(grants));
}

// Runs the whole join sequence against a coordinator and returns how many
// artefacts were applied.
inline int join_member(FederationCoordinator& coordinator, const FederationId& federation,
                       const FixtureMember& candidate, const FixtureMember& sponsor,
                       Lineage lineage = Lineage(0)) {
  int applied = 0;
  for (const Artifact& artifact : {proposal(federation, candidate, sponsor, lineage),
                                   acceptance(federation, candidate, lineage),
                                   endorsement(federation, candidate, sponsor, lineage)}) {
    auto outcome = coordinator.submit_artifact(artifact);
    if (outcome.has_value()) {
      ++applied;
    }
  }
  return applied;
}

// Reports full mutual reachability for every member the federation currently
// tracks. This is what a deployment observes once the members can reach each
// other over the transport. Without it the partition assessment is
// INDETERMINATE and global-mutation authority stays suspended, which is the
// conservative default rather than a test artefact.
inline void observe_mutual_reachability(FederationCoordinator& coordinator) {
  auto state = coordinator.state();
  if (!state.has_value()) {
    return;
  }
  const std::vector<MemberState> members = state.value().members;
  for (const MemberState& observer : members) {
    MemberObservation observation;
    observation.observer = observer.member;
    observation.observer_incarnation = observer.current_identity.incarnation;
    observation.epoch = state.value().epoch;
    observation.recorded_at = coordinator.logical_time();
    for (const MemberState& peer : members) {
      if (peer.member == observer.member) {
        continue;
      }
      PeerObservation entry;
      entry.peer = peer.member;
      entry.peer_incarnation = peer.current_identity.incarnation;
      entry.state = ReachabilityState::Reachable;
      entry.observed_at = coordinator.logical_time();
      entry.detail = "mutually confirmed reachability";
      observation.peers.push_back(std::move(entry));
    }
    const Status status = coordinator.report_observation(observation);
    (void)status;
  }
}

// Joins a member and then reports the reachability evidence the federation
// needs before global-mutation authority can be exercised.
inline void join_and_observe(FederationCoordinator& coordinator, const FederationId& federation,
                             const FixtureMember& candidate, const FixtureMember& sponsor) {
  join_member(coordinator, federation, candidate, sponsor);
  observe_mutual_reachability(coordinator);
}

struct FederationFixture {
  FederationId federation;
  NodeId coordinator_node;
  FederationPolicy policy;
  FixtureMember founder;

  explicit FederationFixture(const MemberSpec& founder_spec = MemberSpec{})
      : federation(FederationId::derive("fixture", 1)),
        coordinator_node(NodeId::derive("fixture-coordinator", 1)),
        policy(default_policy()),
        founder(make_member("fixture-founder", 0, founder_spec)) {}
};

// Creates a coordinator that bootstraps the given founder.
inline Result<std::unique_ptr<FederationCoordinator>> make_coordinator(
    const FederationFixture& fixture, const std::filesystem::path& journal = {}) {
  CoordinatorConfig config;
  config.federation = fixture.federation;
  config.node = fixture.coordinator_node;
  config.policy = fixture.policy;
  config.description = "test federation";
  config.bootstrap = true;
  config.founder = fixture.founder.declaration;
  if (!journal.empty()) {
    config.journal_path = journal;
  }
  return FederationCoordinator::create(config);
}

}  // namespace ffed_test
