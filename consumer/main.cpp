// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Downstream consumer. Built against an installed Fabric Federation prefix
// only; it never sees this repository's source tree.
#include <cstdio>
#include <memory>

#include <fabric_federation/coordinator.hpp>
#include <fabric_federation/member_runtime.hpp>
#include <fabric_federation/version.hpp>

using namespace fabric_federation;

namespace {

MemberConstitution make_constitution(const MemberId& member, const FabricDomainId& domain) {
  MemberConstitution constitution;
  constitution.member = member;
  constitution.domain = domain;
  constitution.generation = Generation(1);
  constitution.software_major = static_cast<std::uint32_t>(kVersionMajor);
  constitution.software_minor = static_cast<std::uint32_t>(kVersionMinor);
  constitution.software_patch = static_cast<std::uint32_t>(kVersionPatch);
  constitution.description = "downstream consumer member";
  CapabilityStatement capability;
  capability.capability = CapabilityId::parse("federation.protocol.v1").value();
  capability.version = 1;
  capability.evidence = EvidenceState::Known;
  capability.evidence_digest = Digest::of("consumer");
  constitution.capabilities.push_back(capability);
  ScopeGrant retained;
  retained.scope = ScopeId::parse("domain.consumer.control").value();
  retained.verb = AuthorityVerb::Administer;
  constitution.retained.push_back(retained);
  DelegationTerms terms;
  terms.grant.scope = ScopeId::parse("federation.route.advertise").value();
  terms.grant.verb = AuthorityVerb::Mutate;
  constitution.delegated.push_back(terms);
  constitution.canonicalize();
  return constitution;
}

MemberDeclaration declaration_of(const MemberConstitution& constitution, const NodeId& node) {
  MemberDeclaration declaration;
  declaration.constitution = constitution;
  declaration.incarnation = Incarnation(1);
  declaration.node = node;
  return declaration;
}

}  // namespace

int main() {
  const FederationId federation = FederationId::derive("consumer", 1);
  const NodeId coordinator_node = NodeId::derive("consumer-coordinator", 1);
  const MemberId sponsor_id = MemberId::derive("consumer-sponsor", 1);
  const FabricDomainId sponsor_domain = FabricDomainId::derive("consumer-sponsor-domain", 1);
  const MemberId candidate_id = MemberId::derive("consumer-candidate", 1);
  const FabricDomainId candidate_domain = FabricDomainId::derive("consumer-candidate-domain", 1);

  CoordinatorConfig config;
  config.federation = federation;
  config.node = coordinator_node;
  config.description = "downstream consumer federation";
  config.policy = default_policy();
  config.listen = true;
  config.bootstrap = true;
  const MemberConstitution sponsor_constitution = make_constitution(sponsor_id, sponsor_domain);
  config.founder = declaration_of(sponsor_constitution, NodeId::derive("consumer-sponsor-node", 1));

  auto coordinator_result = FederationCoordinator::create(config);
  if (!coordinator_result.has_value()) {
    std::fprintf(stderr, "coordinator: %s\n", coordinator_result.status().to_string().c_str());
    return 1;
  }
  std::unique_ptr<FederationCoordinator> coordinator = std::move(coordinator_result.value());
  if (!coordinator->start().ok()) {
    std::fprintf(stderr, "coordinator did not start\n");
    return 1;
  }
  const Endpoint endpoint{"127.0.0.1", coordinator->listen_port()};

  const MemberConstitution candidate_constitution =
      make_constitution(candidate_id, candidate_domain);
  const auto make_runtime = [&](const MemberConstitution& constitution, const char* node_seed) {
    MemberConfig member_config;
    member_config.federation = federation;
    member_config.constitution = constitution;
    member_config.node = NodeId::derive(node_seed, 1);
    member_config.incarnation = Incarnation(1);
    member_config.coordinator = endpoint;
    return MemberFabricRuntime::create(member_config);
  };
  auto sponsor_result = make_runtime(sponsor_constitution, "consumer-sponsor-node");
  auto candidate_result = make_runtime(candidate_constitution, "consumer-candidate-node");
  if (!sponsor_result.has_value() || !candidate_result.has_value()) {
    std::fprintf(stderr, "member runtime could not be created\n");
    return 1;
  }
  std::unique_ptr<MemberFabricRuntime> sponsor = std::move(sponsor_result.value());
  std::unique_ptr<MemberFabricRuntime> candidate = std::move(candidate_result.value());
  if (!sponsor->attach().ok() || !candidate->attach().ok()) {
    std::fprintf(stderr, "member could not attach\n");
    return 1;
  }

  const MemberDeclaration candidate_declaration =
      declaration_of(candidate_constitution, NodeId::derive("consumer-candidate-node", 1));
  if (!sponsor->propose(candidate_declaration, Lineage(0)).has_value() ||
      !candidate->accept(Lineage(0)).has_value() ||
      !sponsor->endorse(candidate_declaration, Lineage(0)).has_value()) {
    std::fprintf(stderr, "the join sequence did not complete\n");
    return 1;
  }

  auto state = coordinator->state();
  if (!state.has_value()) {
    std::fprintf(stderr, "state could not be derived\n");
    return 1;
  }
  const MemberState* candidate_state = state.value().find(candidate_id);
  if (candidate_state == nullptr) {
    std::fprintf(stderr, "the candidate is not tracked\n");
    return 1;
  }
  std::printf("lifecycle:            %s\n", std::string(to_string(candidate_state->lifecycle)).c_str());
  std::printf("local authority:      %s\n",
              render_grants(candidate_state->retained_local_authority).c_str());
  std::printf("federation authority: %s\n",
              render_grants(candidate_state->federation_authority).c_str());
  std::printf("state digest:         %s\n", coordinator->state_digest().to_hex().c_str());
  std::printf("library version:      %s\n", std::string(kVersionString).c_str());
  std::printf("transport:            %s\n", transport_description().c_str());

  const Status stopped = coordinator->stop();
  return stopped.ok() ? 0 : 1;
}
