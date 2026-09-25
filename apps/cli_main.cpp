// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// ffed-cli: inspection and operator tooling for a running federation, plus two
// self-contained commands (demo and permutation) that exercise the whole model
// in one process.
#include <algorithm>
#include <cstdio>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "common.hpp"
#include "fabric_federation/client.hpp"
#include "fabric_federation/coordinator.hpp"
#include "fabric_federation/json.hpp"
#include "fabric_federation/member_runtime.hpp"
#include "fabric_federation/random.hpp"
#include "fabric_federation/version.hpp"

namespace {

using namespace fabric_federation;

int run_remote(const ffed::app::Arguments& arguments);
int run_demo(const ffed::app::Arguments& arguments);
int run_permutation(const ffed::app::Arguments& arguments);

struct Connection {
  FederationId federation;
  Endpoint endpoint;
  NodeId node;
};

bool parse_connection(const ffed::app::Arguments& arguments, Connection& out) {
  auto federation = FederationId::parse(arguments.get("--federation"));
  if (!federation.has_value()) {
    std::fprintf(stderr, "ffed-cli: --federation is required and must be a valid identifier\n");
    return false;
  }
  out.federation = federation.value();
  out.endpoint.host = arguments.get("--host", "127.0.0.1");
  const std::uint64_t port = arguments.get_u64("--port", 0);
  if (port == 0 || port > 65535) {
    std::fprintf(stderr, "ffed-cli: --port is required\n");
    return false;
  }
  out.endpoint.port = static_cast<std::uint16_t>(port);
  out.node = NodeId::derive("ffed-cli", 1);
  return true;
}

std::string outcome_line(const CoordinatorStats& stats) {
  std::ostringstream out;
  out << "state_digest=" << stats.state_digest.to_hex() << "\n"
      << "epoch=" << stats.epoch.value() << "\n"
      << "logical_tick=" << stats.logical_time.value() << "\n"
      << "coordinator_incarnation=" << stats.coordinator_incarnation.value() << "\n"
      << "artifacts=" << stats.artifacts << "\n"
      << "rejected_artifacts=" << stats.rejected_artifacts << "\n"
      << "duplicate_artifacts=" << stats.duplicate_artifacts << "\n"
      << "members=" << stats.members << "\n"
      << "active_members=" << stats.active_members << "\n"
      << "leases=" << stats.leases << "\n"
      << "replay_entries=" << stats.replay_entries << "\n"
      << "partition=" << stats.partition_state << "\n"
      << "reconciling=" << (stats.reconciling ? "true" : "false") << "\n"
      << "durable=" << (stats.durable ? "true" : "false") << "\n"
      << "transport=" << stats.transport << "\n"
      << "recovery=" << stats.recovery << "\n";
  return out.str();
}

int run_remote(const ffed::app::Arguments& arguments) {
  Connection connection;
  if (!parse_connection(arguments, connection)) {
    return 2;
  }
  auto client = CoordinatorClient::connect(connection.endpoint, connection.federation,
                                           connection.node, Incarnation(1));
  if (!client.has_value()) {
    std::fprintf(stderr, "ffed-cli: %s\n", client.status().to_string().c_str());
    return 1;
  }
  const std::string command = arguments.get("--command", arguments.raw.empty() ? "" : arguments.raw[0]);
  const bool json = arguments.has("--json");

  if (command == "status" || command == "digest" || command == "stats") {
    auto stats = client.value().query_stats();
    if (!stats.has_value()) {
      std::fprintf(stderr, "ffed-cli: %s\n", stats.status().to_string().c_str());
      return 1;
    }
    if (json) {
      JsonWriter writer(true);
      writer.begin_object();
      writer.key("state_digest");
      writer.string(stats.value().state_digest.to_hex());
      writer.key("epoch");
      writer.number(stats.value().epoch.value());
      writer.key("logical_tick");
      writer.number(stats.value().logical_time.value());
      writer.key("artifacts");
      writer.number(stats.value().artifacts);
      writer.key("members");
      writer.number(stats.value().members);
      writer.key("active_members");
      writer.number(stats.value().active_members);
      writer.key("leases");
      writer.number(stats.value().leases);
      writer.key("replay_entries");
      writer.number(stats.value().replay_entries);
      writer.key("partition");
      writer.string(stats.value().partition_state);
      writer.key("reconciling");
      writer.boolean(stats.value().reconciling);
      writer.key("transport");
      writer.string(stats.value().transport);
      writer.end_object();
      std::printf("%s\n", writer.str().c_str());
      return 0;
    }
    CoordinatorStats plain;
    plain.state_digest = stats.value().state_digest;
    plain.epoch = stats.value().epoch;
    plain.logical_time = stats.value().logical_time;
    plain.artifacts = stats.value().artifacts;
    plain.rejected_artifacts = stats.value().rejected_artifacts;
    plain.duplicate_artifacts = stats.value().duplicate_artifacts;
    plain.members = stats.value().members;
    plain.active_members = stats.value().active_members;
    plain.leases = stats.value().leases;
    plain.replay_entries = stats.value().replay_entries;
    plain.partition_state = stats.value().partition_state;
    plain.reconciling = stats.value().reconciling;
    plain.transport = stats.value().transport;
    std::printf("%s", outcome_line(plain).c_str());
    return 0;
  }

  if (command == "state" || command == "members") {
    auto state = client.value().query_state();
    if (!state.has_value()) {
      std::fprintf(stderr, "ffed-cli: %s\n", state.status().to_string().c_str());
      return 1;
    }
    if (json) {
      std::printf("%s\n", state.value().json.c_str());
      return 0;
    }
    std::printf("state_digest=%s\n%s\n", state.value().state_digest.to_hex().c_str(),
                state.value().json.c_str());
    return 0;
  }

  if (command == "explain") {
    AuthorityRequest request;
    auto member = MemberId::parse(arguments.get("--member"));
    auto domain = FabricDomainId::parse(arguments.get("--domain"));
    auto scope = ScopeId::parse(arguments.get("--scope"));
    if (!member.has_value() || !domain.has_value() || !scope.has_value()) {
      std::fprintf(stderr, "ffed-cli: --member, --domain and --scope are required\n");
      return 2;
    }
    AuthorityVerb verb = AuthorityVerb::Observe;
    if (!parse_verb(arguments.get("--verb", "observe"), verb)) {
      std::fprintf(stderr, "ffed-cli: unknown verb\n");
      return 2;
    }
    request.id = RequestId::random();
    request.federation = connection.federation;
    request.epoch_seen = Epoch(arguments.get_u64("--epoch", client.value().welcome().epoch.value()));
    request.actor.member = member.value();
    request.actor.domain = domain.value();
    request.actor.generation = Generation(arguments.get_u64("--generation", 1));
    request.actor.incarnation = Incarnation(arguments.get_u64("--incarnation", 1));
    const std::string digest_text = arguments.get("--digest");
    if (!digest_text.empty()) {
      auto digest = Digest::from_hex(digest_text);
      if (!digest.has_value()) {
        std::fprintf(stderr, "ffed-cli: --digest must be 64 lowercase hex digits\n");
        return 2;
      }
      request.actor.constitution = digest.value();
    }
    request.actor.node = NodeId::derive(member.value().to_string(), 1);
    request.requested.scope = std::move(scope.value());
    request.requested.verb = verb;
    const std::string lease_text = arguments.get("--lease");
    if (!lease_text.empty()) {
      auto lease = LeaseId::parse(lease_text);
      if (lease.has_value()) {
        request.lease = lease.value();
      }
    }
    auto decision = client.value().query_authority(request);
    if (!decision.has_value()) {
      std::fprintf(stderr, "ffed-cli: %s\n", decision.status().to_string().c_str());
      return 1;
    }
    std::printf("%s", ffed::app::render_decision(decision.value(), json).c_str());
    if (!json) {
      std::printf("decision_digest=%s\n", decision.value().digest().to_hex().c_str());
    }
    return decision.value().outcome == Outcome::Granted ? 0 : 3;
  }

  if (command == "leases") {
    auto leases = client.value().query_leases();
    if (!leases.has_value()) {
      std::fprintf(stderr, "ffed-cli: %s\n", leases.status().to_string().c_str());
      return 1;
    }
    for (const AuthorityLease& lease : leases.value().leases) {
      std::printf("%s\n", lease.to_string().c_str());
    }
    return 0;
  }

  if (command == "fence" || command == "retire") {
    auto member = MemberId::parse(arguments.get("--member"));
    if (!member.has_value()) {
      std::fprintf(stderr, "ffed-cli: --member is required\n");
      return 2;
    }
    auto response = command == "fence"
                        ? client.value().fence_member(member.value(), Lineage(),
                                                      ReasonCode::MembershipFencedByOrder,
                                                      arguments.get("--reason", "operator fence"))
                        : client.value().advance_epoch(Epoch(), ReasonCode::EvidenceUnknown, "");
    if (command == "retire") {
      std::fprintf(stderr, "ffed-cli: retire is issued by the coordinator control channel\n");
      return 2;
    }
    if (!response.has_value()) {
      std::fprintf(stderr, "ffed-cli: %s\n", response.status().to_string().c_str());
      return 1;
    }
    std::printf("%s\n", response.value().detail.c_str());
    return response.value().code == ErrorCode::Ok ? 0 : 1;
  }

  if (command == "advance-epoch") {
    const std::uint64_t epoch = arguments.get_u64("--epoch", 0);
    if (epoch == 0) {
      std::fprintf(stderr, "ffed-cli: --epoch is required\n");
      return 2;
    }
    auto response = client.value().advance_epoch(
        Epoch(epoch), ReasonCode::PartitionSplitSuspendsGlobalMutation,
        arguments.get("--reason", "operator requested re-constitution"));
    if (!response.has_value()) {
      std::fprintf(stderr, "ffed-cli: %s\n", response.status().to_string().c_str());
      return 1;
    }
    std::printf("%s\n", response.value().detail.c_str());
    return response.value().code == ErrorCode::Ok ? 0 : 1;
  }

  if (command == "reconcile") {
    const std::uint64_t epoch = arguments.get_u64("--epoch", 0);
    auto response = client.value().complete_reconciliation(Epoch(epoch));
    if (!response.has_value()) {
      std::fprintf(stderr, "ffed-cli: %s\n", response.status().to_string().c_str());
      return 1;
    }
    std::printf("%s\n", response.value().detail.c_str());
    return response.value().code == ErrorCode::Ok ? 0 : 1;
  }

  if (command == "advance-time") {
    const std::uint64_t tick = arguments.get_u64("--tick", 0);
    auto response = client.value().advance_time(Tick(tick));
    if (!response.has_value()) {
      std::fprintf(stderr, "ffed-cli: %s\n", response.status().to_string().c_str());
      return 1;
    }
    std::printf("%s\n", response.value().detail.c_str());
    return response.value().code == ErrorCode::Ok ? 0 : 1;
  }

  if (command == "artifacts") {
    auto artifacts = client.value().query_artifacts();
    if (!artifacts.has_value()) {
      std::fprintf(stderr, "ffed-cli: %s\n", artifacts.status().to_string().c_str());
      return 1;
    }
    for (const Artifact& artifact : artifacts.value().artifacts) {
      std::printf("%s\n", artifact.to_string().c_str());
    }
    std::printf("count=%zu state_digest=%s\n", artifacts.value().artifacts.size(),
                artifacts.value().state_digest.to_hex().c_str());
    return 0;
  }

  std::fprintf(stderr,
               "ffed-cli: unknown command '%s' (status, state, members, explain, leases, "
               "artifacts, fence, advance-epoch, reconcile, advance-time, demo, permutation)\n",
               command.c_str());
  return 2;
}

}  // namespace

namespace {

struct ScenarioMember {
  MemberId member;
  FabricDomainId domain;
  MemberConstitution constitution;
  Incarnation incarnation;
  NodeId node;
};

ScenarioMember make_member(std::string_view seed, std::uint64_t index, Generation generation,
                           const std::string& delegated, const std::string& retained) {
  ScenarioMember member;
  member.member = MemberId::derive(std::string(seed) + "|member", index);
  member.domain = FabricDomainId::derive(std::string(seed) + "|domain", index);
  member.incarnation = Incarnation(1);
  member.node = NodeId::derive(member.member.to_string(), 1);
  std::string spec = "gen=" + std::to_string(generation.value()) + ";";
  if (!delegated.empty()) {
    spec += "delegated=" + delegated + ";";
  }
  if (!retained.empty()) {
    spec += "retained=" + retained + ";";
  }
  spec += "caps=federation.protocol.v1:1:known";
  auto constitution = ffed::app::parse_constitution(spec, member.member, member.domain);
  member.constitution = constitution.has_value() ? constitution.value() : MemberConstitution();
  return member;
}

MemberDeclaration make_declaration(const ScenarioMember& member, Tick tick) {
  MemberDeclaration declaration;
  declaration.constitution = member.constitution;
  declaration.incarnation = member.incarnation;
  declaration.node = member.node;
  declaration.declared_at = tick;
  return declaration;
}

Artifact build_artifact(const FederationId& federation, ArtifactKind kind,
                        const MemberDeclaration& subject_declaration, const MemberIdentity& issuer,
                        const NodeId& issuer_node, Lineage lineage, Epoch epoch, Tick tick,
                        const std::vector<ScopeGrant>& withdrawn,
                        const std::vector<DelegationTerms>& terms, ReasonCode reason,
                        std::string_view text) {
  ArtifactBody body;
  body.declaration = subject_declaration;
  body.declared_identity = subject_declaration.identity();
  body.lineage = lineage;
  body.epoch = epoch;
  body.logical_time = tick;
  body.withdrawn_grants = withdrawn;
  body.delegated_terms = terms;
  body.reason_code = reason;
  body.reason_text = std::string(text);
  canonicalize_grants(body.withdrawn_grants);
  canonicalize_terms(body.delegated_terms);

  ArtifactEnvelope envelope;
  envelope.kind = kind;
  envelope.federation = federation;
  envelope.subject = subject_declaration.constitution.member;
  envelope.issuer.node = issuer_node;
  envelope.issuer.member = issuer.member;
  envelope.issuer.generation = issuer.generation;
  envelope.issuer.incarnation = issuer.incarnation;
  envelope.issuer.epoch = epoch;
  envelope.issuer.issued_at = tick;
  Artifact artifact = Artifact::make(std::move(envelope), std::move(body));
  artifact.envelope.evidence = EvidenceId::derive(
      federation.to_string() + "|" + std::string(to_string(kind)) + "|" +
          subject_declaration.constitution.member.to_string() + "|" + issuer.member.to_string(),
      artifact.body.digest().bytes()[0]);
  return artifact;
}

Result<MemberObservation> probe_local(MemberId observer, Incarnation incarnation, Epoch epoch,
                                      Tick tick, const std::vector<MemberId>& peers,
                                      const std::vector<Incarnation>& peer_incarnations,
                                      const std::vector<bool>& reachable) {
  MemberObservation observation;
  observation.observer = observer;
  observation.observer_incarnation = incarnation;
  observation.epoch = epoch;
  observation.recorded_at = tick;
  for (std::size_t i = 0; i < peers.size(); ++i) {
    PeerObservation entry;
    entry.peer = peers[i];
    entry.observed_at = tick;
    if (i < reachable.size() && reachable[i]) {
      entry.state = ReachabilityState::Reachable;
      entry.peer_incarnation = peer_incarnations[i];
      entry.detail = "mutually confirmed over loopback TCP";
    } else {
      entry.state = ReachabilityState::Unreachable;
      entry.detail = "connection refused";
    }
    observation.peers.push_back(std::move(entry));
  }
  return observation;
}

void print_decision(const char* label, const AuthorityDecision& decision) {
  std::printf("  %-34s %-14s %s\n", label, std::string(to_string(decision.outcome)).c_str(),
              decision.explanation.summary.c_str());
}

}  // namespace

namespace {

int run_demo(const ffed::app::Arguments& arguments) {
  const std::uint64_t seed = arguments.get_u64("--seed", 20260101);
  const FederationId federation = FederationId::derive("ffed-demo", seed);
  const NodeId coordinator_node = NodeId::derive("ffed-demo-coordinator", 1);

  CoordinatorConfig config;
  config.federation = federation;
  config.node = coordinator_node;
  config.description = "ffed-cli demo federation";
  config.policy = default_policy();
  config.listen = true;
  config.listen_port = 0;
  config.bootstrap = true;

  ScenarioMember founder = make_member("ffed-demo-founder", 0, Generation(1),
                                       "federation.route.advertise:mutate:shared",
                                       "domain.founder.control:administer");
  config.founder = make_declaration(founder, Tick(1));
  config.founder_grants.push_back(ScopeGrant{ScopeId::parse("federation.membership.admit").value(),
                                             AuthorityVerb::Administer});

  auto created = FederationCoordinator::create(config);
  if (!created.has_value()) {
    std::fprintf(stderr, "ffed-cli demo: %s\n", created.status().to_string().c_str());
    return 1;
  }
  std::unique_ptr<FederationCoordinator> coordinator = std::move(created.value());
  const Status started = coordinator->start();
  if (!started.ok()) {
    std::fprintf(stderr, "ffed-cli demo: %s\n", started.to_string().c_str());
    return 1;
  }
  const Endpoint endpoint{"127.0.0.1", coordinator->listen_port()};

  std::printf("federation %s\n", federation.to_string().c_str());
  std::printf("coordinator %s listening on %s\n", coordinator_node.to_string().c_str(),
              endpoint.to_string().c_str());
  std::printf("transport: %s\n\n", transport_description().c_str());

  // Two ordinary members join over the real framed transport. Each runs as its
  // own MemberFabricRuntime, so the artefacts they issue carry their own
  // identity, generation and incarnation.
  ScenarioMember b = make_member("ffed-demo", 1, Generation(1),
                                 "federation.route.advertise:mutate:shared",
                                 "domain.one.control:administer");
  ScenarioMember c = make_member("ffed-demo", 2, Generation(1),
                                 "federation.route.advertise:mutate:shared",
                                 "domain.two.control:administer");
  c.constitution.delegated.push_back(DelegationTerms{
      ScopeGrant{ScopeId::parse("federation.delegation.grant").value(), AuthorityVerb::Mutate},
      DelegationMode::Exclusive, 1, Tick(), ConstraintToken()});
  canonicalize_terms(c.constitution.delegated);
  b.constitution.delegated.push_back(DelegationTerms{
      ScopeGrant{ScopeId::parse("federation.delegation.grant").value(), AuthorityVerb::Mutate},
      DelegationMode::Exclusive, 1, Tick(), ConstraintToken()});
  canonicalize_terms(b.constitution.delegated);

  const auto make_runtime = [&](const ScenarioMember& member) {
    MemberConfig member_config;
    member_config.federation = federation;
    member_config.constitution = member.constitution;
    member_config.node = member.node;
    member_config.incarnation = member.incarnation;
    member_config.coordinator = endpoint;
    member_config.listen_for_probes = true;
    member_config.probe_port = 0;
    return MemberFabricRuntime::create(member_config);
  };

  auto runtime_founder = make_runtime(founder);
  auto runtime_b = make_runtime(b);
  auto runtime_c = make_runtime(c);
  if (!runtime_founder.has_value() || !runtime_b.has_value() || !runtime_c.has_value()) {
    std::fprintf(stderr, "ffed-cli demo: a member runtime could not be created\n");
    return 1;
  }
  std::unique_ptr<MemberFabricRuntime> member_founder = std::move(runtime_founder.value());
  std::unique_ptr<MemberFabricRuntime> member_b = std::move(runtime_b.value());
  std::unique_ptr<MemberFabricRuntime> member_c = std::move(runtime_c.value());
  if (!member_founder->attach().ok() || !member_b->attach().ok() || !member_c->attach().ok()) {
    std::fprintf(stderr, "ffed-cli demo: a member could not attach to the coordinator\n");
    return 1;
  }

  // The founder sponsors each candidate; the candidate consents; the other
  // member endorses. Nothing is admitted on one party's word.
  std::printf("join sequence\n");
  for (const std::pair<ScenarioMember, MemberFabricRuntime*>& entry :
       {std::pair<ScenarioMember, MemberFabricRuntime*>{b, member_b.get()},
        std::pair<ScenarioMember, MemberFabricRuntime*>{c, member_c.get()}}) {
    const MemberDeclaration declaration = make_declaration(entry.first, Tick(1));
    // The founder sponsors and endorses; the candidate consents. Three distinct
    // parties are involved and no one of them can admit the candidate alone.
    auto proposal = member_founder->propose(declaration, Lineage(0));
    if (!proposal.has_value()) {
      std::fprintf(stderr, "ffed-cli demo: proposal failed: %s\n",
                   proposal.status().to_string().c_str());
      return 1;
    }
    auto acceptance = entry.second->accept(Lineage(0));
    if (!acceptance.has_value()) {
      std::fprintf(stderr, "ffed-cli demo: acceptance failed: %s\n",
                   acceptance.status().to_string().c_str());
      return 1;
    }
    auto endorsement = member_founder->endorse(declaration, Lineage(0));
    if (!endorsement.has_value()) {
      std::fprintf(stderr, "ffed-cli demo: endorsement failed: %s\n",
                   endorsement.status().to_string().c_str());
      return 1;
    }
    std::printf("  %s: sponsor=%s candidate=%s endorsement=%s\n",
                entry.first.member.to_string().c_str(),
                std::string(to_string(proposal.value().outcome)).c_str(),
                std::string(to_string(acceptance.value().outcome)).c_str(),
                std::string(to_string(endorsement.value().outcome)).c_str());
  }

  auto state = coordinator->state();
  if (!state.has_value()) {
    std::fprintf(stderr, "ffed-cli demo: state could not be derived\n");
    return 1;
  }
  std::printf("\nartefacts applied=%zu rejected=%zu duplicates=%zu\n",
              state.value().artifact_count, state.value().rejected_artifact_count,
              state.value().duplicate_artifact_count);
  for (const Reason& reason : state.value().global_reasons) {
    std::printf("    %s\n", reason.to_string().c_str());
  }
  std::printf("\nmembers\n");
  for (const MemberState& member : state.value().members) {
    std::printf("  %s %-8s gen=%llu inc=%llu digest=%s\n", member.member.to_string().c_str(),
                std::string(to_string(member.lifecycle)).c_str(),
                static_cast<unsigned long long>(member.current_identity.generation.value()),
                static_cast<unsigned long long>(member.current_identity.incarnation.value()),
                member.current_identity.constitution.to_hex().substr(0, 16).c_str());
    std::printf("      local=[%s] federation=[%s]\n",
                render_grants(member.retained_local_authority).c_str(),
                render_grants(member.federation_authority).c_str());
  }
  std::printf("  conflicts: %zu\n", state.value().conflicts.size());
  for (const ConflictRecord& conflict : state.value().conflicts) {
    std::printf("    %s\n", conflict.to_string().c_str());
  }

  // Reachability evidence comes from real connections between the members'
  // own probe listeners over loopback TCP.
  std::printf("\nreachability (real loopback TCP between the member runtimes)\n");
  // One observation per member covering every peer it can see, because the
  // coordinator keeps the latest observation per observer.
  const std::vector<std::pair<MemberFabricRuntime*, MemberFabricRuntime*>> pairs = {
      {member_founder.get(), member_b.get()},
      {member_founder.get(), member_c.get()},
      {member_b.get(), member_founder.get()},
      {member_b.get(), member_c.get()},
      {member_c.get(), member_founder.get()},
      {member_c.get(), member_b.get()}};
  const auto probe_all = [](MemberFabricRuntime* observer,
                            const std::vector<MemberFabricRuntime*>& peers) {
    std::vector<MemberFabricRuntime::PeerTarget> targets;
    for (MemberFabricRuntime* peer : peers) {
      MemberFabricRuntime::PeerTarget target;
      target.member = peer->constitution().member;
      target.endpoint = Endpoint{"127.0.0.1", peer->probe_port()};
      targets.push_back(std::move(target));
    }
    const MemberObservation observation = observer->probe_peers(targets);
    const auto reported = observer->report_observation(observation);
    std::string detail;
    for (const PeerObservation& entry : observation.peers) {
      if (!detail.empty()) {
        detail.append(", ");
      }
      detail.append(entry.peer.to_string());
      detail.push_back('=');
      detail.append(std::string(to_string(entry.state)));
    }
    if (!reported.has_value() || reported.value().code != ErrorCode::Ok) {
      detail.append(" (the observation could not be reported)");
    }
    return detail;
  };
  std::printf("  %s: %s\n", member_founder->constitution().member.to_string().c_str(),
              probe_all(member_founder.get(), {member_b.get(), member_c.get()}).c_str());
  std::printf("  %s: %s\n", member_b->constitution().member.to_string().c_str(),
              probe_all(member_b.get(), {member_founder.get(), member_c.get()}).c_str());
  std::printf("  %s: %s\n", member_c->constitution().member.to_string().c_str(),
              probe_all(member_c.get(), {member_founder.get(), member_b.get()}).c_str());

  {
    auto snapshot = coordinator->state();
    if (snapshot.has_value()) {
      std::printf("  partition after probing: %s (%s; %zu component(s), %zu unobserved, %zu "
                  "mutually reachable, %zu stale)\n",
                  std::string(to_string(snapshot.value().partition.state)).c_str(),
                  snapshot.value().partition.summary.c_str(),
                  snapshot.value().partition.components.size(),
                  snapshot.value().partition.unobserved.size(),
                  snapshot.value().partition.mutually_reachable.size(),
                  snapshot.value().partition.stale_observations.size());
    }
  }

  // Delegation conflict: two members hold the same exclusive grant.
  std::printf("\nauthority questions\n");
  const ScopeGrant advertise{ScopeId::parse("federation.route.advertise").value(),
                             AuthorityVerb::Mutate};
  const ScopeGrant delegation{ScopeId::parse("federation.delegation.grant").value(),
                              AuthorityVerb::Mutate};
  auto without_lease = member_b->request_authority(advertise, LeaseId());
  if (without_lease.has_value()) {
    print_decision("advertise without a lease", without_lease.value());
  }
  auto conflicted = member_c->request_authority(delegation, LeaseId());
  if (conflicted.has_value()) {
    print_decision("conflicting exclusive grant", conflicted.value());
  }

  LeaseRequest lease_request;
  lease_request.holder = b.member;
  lease_request.scopes = {advertise};
  lease_request.lifetime_ticks = Tick(500);
  auto lease = coordinator->issue_lease(lease_request);
  if (!lease.has_value()) {
    std::fprintf(stderr, "ffed-cli demo: lease refused: %s\n",
                 lease.status().to_string().c_str());
    return 1;
  }
  auto with_lease = member_b->request_authority(advertise, lease.value().id);
  if (with_lease.has_value()) {
    print_decision("advertise with a valid lease", with_lease.value());
  }

  // Local authority is decided by the member and never depends on the
  // federation.
  const AuthorityDecision local =
      member_b->evaluate_local(ScopeGrant{ScopeId::parse("domain.one.control").value(),
                                          AuthorityVerb::Administer});
  std::printf("  %-34s %-14s %s\n", "retained local authority",
              std::string(to_string(local.outcome)).c_str(), local.explanation.summary.c_str());

  // Partition: one member's probe listener is closed, so its peers genuinely
  // stop being able to reach it while it can still reach them.
  std::printf("\npartition\n");
  const Epoch epoch = coordinator->epoch();
  if (!member_c->stop_probe_listener().ok()) {
    std::fprintf(stderr, "ffed-cli demo: the probe listener could not be closed\n");
    return 1;
  }
  std::printf("  %s: %s\n", member_founder->constitution().member.to_string().c_str(),
              probe_all(member_founder.get(), {member_b.get(), member_c.get()}).c_str());
  std::printf("  %s: %s\n", member_b->constitution().member.to_string().c_str(),
              probe_all(member_b.get(), {member_founder.get(), member_c.get()}).c_str());
  std::printf("  %s: %s\n", member_c->constitution().member.to_string().c_str(),
              probe_all(member_c.get(), {member_founder.get(), member_b.get()}).c_str());
  {
    auto snapshot = coordinator->state();
    if (snapshot.has_value()) {
      std::printf("  partition: %s (%s; %zu component(s))\n",
                  std::string(to_string(snapshot.value().partition.state)).c_str(),
                  snapshot.value().partition.summary.c_str(),
                  snapshot.value().partition.components.size());
    }
  }
  auto during_split = member_b->request_authority(advertise, lease.value().id);
  if (during_split.has_value()) {
    print_decision("advertise during a split", during_split.value());
  }

  std::printf("\nrecovery\n");
  const Epoch recovery_epoch(epoch.value() + 1);
  const Status advanced = coordinator->advance_epoch(
      recovery_epoch, ReasonCode::PartitionSplitSuspendsGlobalMutation,
      "the operator re-constituted the federation after the partition");
  if (!advanced.ok()) {
    std::fprintf(stderr, "ffed-cli demo: epoch advance refused: %s\n",
                 advanced.to_string().c_str());
    return 1;
  }
  if (!member_c->start_probe_listener().ok()) {
    std::fprintf(stderr, "ffed-cli demo: the probe listener could not be reopened\n");
    return 1;
  }
  std::printf("  %s: %s\n", member_founder->constitution().member.to_string().c_str(),
              probe_all(member_founder.get(), {member_b.get(), member_c.get()}).c_str());
  std::printf("  %s: %s\n", member_b->constitution().member.to_string().c_str(),
              probe_all(member_b.get(), {member_founder.get(), member_c.get()}).c_str());
  std::printf("  %s: %s\n", member_c->constitution().member.to_string().c_str(),
              probe_all(member_c.get(), {member_founder.get(), member_b.get()}).c_str());
  auto still_reconciling = member_b->request_authority(advertise, lease.value().id);
  if (still_reconciling.has_value()) {
    print_decision("advertise while reconciling", still_reconciling.value());
  }
  // Every active member re-attests at the new epoch. The founder is included:
  // re-attestation is what lets a member be re-activated after an epoch change.
  auto reattest_founder = member_founder->reattest();
  auto reattest_b = member_b->reattest();
  auto reattest_c = member_c->reattest();
  if (!reattest_founder.has_value() || !reattest_b.has_value() || !reattest_c.has_value()) {
    std::fprintf(stderr, "ffed-cli demo: re-attestation failed\n");
    return 1;
  }
  const Status reconciled = coordinator->complete_reconciliation(recovery_epoch);
  if (!reconciled.ok()) {
    std::fprintf(stderr, "ffed-cli demo: reconciliation refused: %s\n",
                 reconciled.to_string().c_str());
    return 1;
  }

  LeaseRequest renewed_request;
  renewed_request.holder = b.member;
  renewed_request.scopes = {advertise};
  renewed_request.lifetime_ticks = Tick(500);
  auto renewed = coordinator->issue_lease(renewed_request);
  if (!renewed.has_value()) {
    std::fprintf(stderr, "ffed-cli demo: renewed lease refused: %s\n",
                 renewed.status().to_string().c_str());
    return 1;
  }
  auto after_recovery = member_b->request_authority(advertise, renewed.value().id);
  if (after_recovery.has_value()) {
    print_decision("advertise after recovery", after_recovery.value());
  }
  auto stale_lease = member_b->request_authority(advertise, lease.value().id);
  if (stale_lease.has_value()) {
    print_decision("pre-partition lease after recovery", stale_lease.value());
  }

  const CoordinatorStats stats = coordinator->stats();
  std::printf("\ncanonical state digest %s\n", stats.state_digest.to_hex().c_str());
  std::printf("epoch=%llu artifacts=%llu members=%llu active=%llu leases=%llu replay=%llu\n",
              static_cast<unsigned long long>(stats.epoch.value()),
              static_cast<unsigned long long>(stats.artifacts),
              static_cast<unsigned long long>(stats.members),
              static_cast<unsigned long long>(stats.active_members),
              static_cast<unsigned long long>(stats.leases),
              static_cast<unsigned long long>(stats.replay_entries));

  const Status stopped_members = member_b->detach();
  (void)stopped_members;
  const Status detach_c = member_c->detach();
  (void)detach_c;
  const Status stopped = coordinator->stop();
  return stopped.ok() ? 0 : 1;
}

int run_permutation(const ffed::app::Arguments& arguments) {
  const std::uint64_t seed = arguments.get_u64("--seed", fabric_federation::kDefaultSeed);
  const std::uint64_t count = arguments.get_u64("--count", 12);
  const std::uint64_t rounds = arguments.get_u64("--rounds", 24);
  if (count == 0 || count > 64 || rounds == 0 || rounds > 512) {
    std::fprintf(stderr, "ffed-cli: --count must be 1..64 and --rounds 1..512\n");
    return 2;
  }
  const FederationId federation = FederationId::derive("ffed-permutation", seed);
  const NodeId node = NodeId::derive("ffed-permutation-node", seed);

  std::vector<ScenarioMember> members;
  for (std::uint64_t i = 0; i < count; ++i) {
    members.push_back(make_member("ffed-permutation",
                                  i + 1, Generation(1),
                                  "federation.route.advertise:mutate:exclusive",
                                  "domain.permutation.control:administer"));
  }

  std::vector<Artifact> artifacts;
  for (std::size_t i = 0; i < members.size(); ++i) {
    const ScenarioMember& candidate = members[i];
    const ScenarioMember& sponsor = members[(i + 1) % members.size()];
    const ScenarioMember& endorser = members[(i + 2) % members.size()];
    const MemberDeclaration declaration = make_declaration(candidate, Tick(1));
    artifacts.push_back(build_artifact(federation, ArtifactKind::MembershipProposal, declaration,
                                       make_declaration(sponsor, Tick(1)).identity(),
                                       sponsor.node, Lineage(0), Epoch(1), Tick(1), {}, {},
                                       ReasonCode::EvidenceUnknown, ""));
    artifacts.push_back(build_artifact(federation, ArtifactKind::MembershipAcceptance, declaration,
                                       make_declaration(candidate, Tick(1)).identity(),
                                       candidate.node, Lineage(0), Epoch(1), Tick(1), {}, {},
                                       ReasonCode::EvidenceUnknown, ""));
    artifacts.push_back(build_artifact(federation, ArtifactKind::MembershipEndorsement, declaration,
                                       make_declaration(endorser, Tick(1)).identity(),
                                       endorser.node, Lineage(0), Epoch(1), Tick(1), {}, {},
                                       ReasonCode::EvidenceUnknown, ""));
  }

  DeterministicRng rng(seed);
  Digest reference;
  std::size_t comparisons = 0;
  for (std::uint64_t round = 0; round < rounds; ++round) {
    std::vector<Artifact> shuffled = artifacts;
    rng.shuffle(shuffled);

    CoordinatorConfig config;
    config.federation = federation;
    config.node = node;
    config.policy = default_policy();
    auto created = FederationCoordinator::create(config);
    if (!created.has_value()) {
      std::fprintf(stderr, "ffed-cli: %s\n", created.status().to_string().c_str());
      return 1;
    }
    std::unique_ptr<FederationCoordinator> coordinator = std::move(created.value());
    const Status started = coordinator->start();
    if (!started.ok()) {
      std::fprintf(stderr, "ffed-cli: %s\n", started.to_string().c_str());
      return 1;
    }
    for (const Artifact& artifact : shuffled) {
      auto outcome = coordinator->submit_artifact(artifact);
      if (!outcome.has_value()) {
        std::fprintf(stderr, "ffed-cli: %s\n", outcome.status().to_string().c_str());
        return 1;
      }
    }
    const Digest digest = coordinator->state_digest();
    if (round == 0) {
      reference = digest;
    } else if (digest != reference) {
      std::fprintf(stderr,
                   "ffed-cli: permutation %llu produced %s, expected %s (seed=%llu)\n",
                   static_cast<unsigned long long>(round), digest.to_hex().c_str(),
                   reference.to_hex().c_str(), static_cast<unsigned long long>(seed));
      return 1;
    }
    ++comparisons;
    const Status stopped = coordinator->stop();
    if (!stopped.ok()) {
      std::fprintf(stderr, "ffed-cli: %s\n", stopped.to_string().c_str());
      return 1;
    }
  }
  std::printf("seed=0x%llx artifacts=%zu rounds=%zu canonical_digest=%s\n",
              static_cast<unsigned long long>(seed), artifacts.size(), comparisons,
              reference.to_hex().c_str());
  return 0;
}

}  // namespace


int main(int argc, char* argv[]) {
  const ffed::app::Arguments arguments = ffed::app::parse_arguments(argc, argv);
  const std::string command = arguments.raw.empty() ? std::string() : arguments.raw[0];
  if (command.empty() || command == "--help" || command == "help") {
    std::printf(
        "ffed-cli %s - %s\n"
        "\n"
        "remote commands (require --federation, --port and usually a coordinator with\n"
        "a control or protocol listener):\n"
        "  status|digest|stats     federation counters and the canonical state digest\n"
        "  state|members           full derived state as JSON\n"
        "  explain                 evaluate one authority question and print its provenance\n"
        "  leases | artifacts      durable lease / evidence listings\n"
        "  fence --member <id>     fence a member's federation authority\n"
        "  advance-epoch --epoch N re-constitute the federation at a new epoch\n"
        "  reconcile --epoch N     record reconciliation for an epoch\n"
        "  advance-time --tick N   move the logical clock forward\n"
        "\n"
        "local commands (no coordinator required):\n"
        "  demo [--seed N]         run a whole federation lifecycle in one process\n"
        "  permutation [--seed N] [--count N] [--rounds N]\n"
        "                          prove canonical state is permutation independent\n"
        "\n"
        "  version | transport     build and transport description\n",
        std::string(kVersionString).c_str(), transport_description().c_str());
    return command.empty() ? 2 : 0;
  }
  if (command == "version") {
    std::printf("%s %s\n%s\n", std::string(kProductName).c_str(),
                std::string(kVersionString).c_str(), transport_description().c_str());
    return 0;
  }
  if (command == "transport") {
    std::printf("%s\n", transport_description().c_str());
    return 0;
  }
  if (command == "demo") {
    return run_demo(arguments);
  }
  if (command == "permutation") {
    return run_permutation(arguments);
  }
  return run_remote(arguments);
}
