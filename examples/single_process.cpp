// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Example: one federation, one coordinator, two member fabrics, all inside a
// single process. The members still talk to the coordinator over real loopback
// TCP; only the process boundary is absent. See ffed_example_multi_process for
// the version that uses separate operating-system processes.
#include <cstdio>
#include <memory>

#include "fabric_federation/coordinator.hpp"
#include "fabric_federation/member_runtime.hpp"
#include "fabric_federation/version.hpp"

using namespace fabric_federation;

namespace {

MemberConstitution make_constitution(const MemberId& member, const FabricDomainId& domain,
                                     const char* delegated_scope) {
  MemberConstitution constitution;
  constitution.member = member;
  constitution.domain = domain;
  constitution.generation = Generation(1);
  constitution.software_major = static_cast<std::uint32_t>(kVersionMajor);
  constitution.software_minor = static_cast<std::uint32_t>(kVersionMinor);
  constitution.software_patch = static_cast<std::uint32_t>(kVersionPatch);
  constitution.description = "example member fabric";
  CapabilityStatement capability;
  capability.capability = CapabilityId::parse("federation.protocol.v1").value();
  capability.version = 1;
  capability.evidence = EvidenceState::Known;
  capability.evidence_digest = Digest::of("example");
  constitution.capabilities.push_back(capability);
  ScopeGrant retained;
  retained.scope = ScopeId::parse("domain.example.control").value();
  retained.verb = AuthorityVerb::Administer;
  constitution.retained.push_back(retained);
  DelegationTerms terms;
  terms.grant.scope = ScopeId::parse(delegated_scope).value();
  terms.grant.verb = AuthorityVerb::Mutate;
  terms.mode = DelegationMode::Exclusive;
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
  const FederationId federation = FederationId::derive("example-single-process", 1);
  const NodeId coordinator_node = NodeId::derive("example-coordinator", 1);
  const MemberId sponsor_id = MemberId::derive("example-sponsor", 1);
  const MemberId candidate_id = MemberId::derive("example-candidate", 1);
  const FabricDomainId sponsor_domain = FabricDomainId::derive("example-sponsor-domain", 1);
  const FabricDomainId candidate_domain = FabricDomainId::derive("example-candidate-domain", 1);

  CoordinatorConfig config;
  config.federation = federation;
  config.node = coordinator_node;
  config.description = "single-process example";
  config.policy = default_policy();
  config.listen = true;
  config.bootstrap = true;
  const MemberConstitution sponsor_constitution =
      make_constitution(sponsor_id, sponsor_domain, "federation.route.advertise");
  config.founder = declaration_of(sponsor_constitution, NodeId::derive("example-sponsor-node", 1));

  auto coordinator_result = FederationCoordinator::create(config);
  if (!coordinator_result.has_value()) {
    std::fprintf(stderr, "coordinator: %s\n", coordinator_result.status().to_string().c_str());
    return 1;
  }
  std::unique_ptr<FederationCoordinator> coordinator = std::move(coordinator_result.value());
  if (!coordinator->start().ok()) {
    std::fprintf(stderr, "coordinator failed to start\n");
    return 1;
  }
  const Endpoint endpoint{"127.0.0.1", coordinator->listen_port()};

  const MemberConstitution candidate_constitution =
      make_constitution(candidate_id, candidate_domain, "federation.route.advertise");
  MemberConfig candidate_config;
  candidate_config.federation = federation;
  candidate_config.constitution = candidate_constitution;
  candidate_config.node = NodeId::derive("example-candidate-node", 1);
  candidate_config.incarnation = Incarnation(1);
  candidate_config.coordinator = endpoint;
  auto candidate_result = MemberFabricRuntime::create(candidate_config);
  if (!candidate_result.has_value()) {
    std::fprintf(stderr, "member: %s\n", candidate_result.status().to_string().c_str());
    return 1;
  }
  std::unique_ptr<MemberFabricRuntime> candidate = std::move(candidate_result.value());
  if (!candidate->attach().ok()) {
    std::fprintf(stderr, "member failed to attach\n");
    return 1;
  }

  const MemberDeclaration candidate_declaration =
      declaration_of(candidate_constitution, NodeId::derive("example-candidate-node", 1));

  // The sponsor proposes, the candidate consents, the sponsor endorses.
  auto proposal = candidate->build_proposal(candidate_declaration, Lineage(0));
  (void)proposal;
  MemberConfig sponsor_config;
  sponsor_config.federation = federation;
  sponsor_config.constitution = sponsor_constitution;
  sponsor_config.node = NodeId::derive("example-sponsor-node", 1);
  sponsor_config.incarnation = Incarnation(1);
  sponsor_config.coordinator = endpoint;
  auto sponsor_result = MemberFabricRuntime::create(sponsor_config);
  if (!sponsor_result.has_value()) {
    std::fprintf(stderr, "sponsor: %s\n", sponsor_result.status().to_string().c_str());
    return 1;
  }
  std::unique_ptr<MemberFabricRuntime> sponsor = std::move(sponsor_result.value());
  if (!sponsor->attach().ok()) {
    std::fprintf(stderr, "sponsor failed to attach\n");
    return 1;
  }

  auto sponsored = sponsor->propose(candidate_declaration, Lineage(0));
  auto consented = candidate->accept(Lineage(0));
  auto endorsed = sponsor->endorse(candidate_declaration, Lineage(0));
  if (!sponsored.has_value() || !consented.has_value() || !endorsed.has_value()) {
    std::fprintf(stderr, "the join sequence did not complete\n");
    return 1;
  }

  auto state = coordinator->state();
  if (!state.has_value()) {
    std::fprintf(stderr, "state could not be derived\n");
    return 1;
  }
  std::printf("member lifecycle for the candidate: %s\n",
              std::string(to_string(
                              state.value().find(candidate_id) == nullptr
                                  ? MemberLifecycleState::Absent
                                  : state.value().find(candidate_id)->lifecycle))
                  .c_str());
  std::printf("retained local authority: %s\n",
              render_grants(state.value().find(candidate_id)->retained_local_authority).c_str());
  std::printf("federation authority:     %s\n",
              render_grants(state.value().find(candidate_id)->federation_authority).c_str());
  std::printf("canonical state digest:   %s\n", coordinator->state_digest().to_hex().c_str());
  std::printf("transport:                %s\n", transport_description().c_str());

  const Status stopped = coordinator->stop();
  return stopped.ok() ? 0 : 1;
}
