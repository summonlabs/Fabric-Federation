// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// ffed-member: one independently governed member fabric, running as its own
// operating-system process.
//
// The process owns its identity, generation, incarnation and delegation terms.
// It attaches to a coordinator over loopback TCP and exposes a newline
// delimited control channel so an operator (or a test) can drive membership
// actions in this process rather than in the caller's process.
#include <atomic>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include "common.hpp"
#include "fabric_federation/member_runtime.hpp"
#include "fabric_federation/net.hpp"
#include "fabric_federation/version.hpp"

namespace {

using namespace fabric_federation;

struct Options {
  FederationId federation;
  MemberConstitution constitution;
  NodeId node;
  Incarnation incarnation = Incarnation(1);
  Endpoint coordinator;
  bool listen_for_probes = false;
  std::uint16_t probe_port = 0;
  std::uint16_t control_port = 0;
  std::string ready_file;
  bool do_join = false;
  Lineage lineage;
};

std::string handle_command(const std::string& line, MemberFabricRuntime& member,
                           std::atomic<bool>& stopping);

void serve_control(std::atomic<bool>& stopping, std::uint16_t port, MemberFabricRuntime& member,
                   Status& startup_status) {
  auto listener = Listener::bind_loopback(port, 8);
  if (!listener.has_value()) {
    startup_status = listener.status();
    return;
  }
  startup_status = Status::success();
  std::printf("CONTROL %u\n", static_cast<unsigned>(listener.value().port()));
  std::fflush(stdout);
  while (!stopping.load()) {
    auto accepted = listener.value().accept();
    if (!accepted.has_value()) {
      break;
    }
    Socket socket = std::move(accepted.value());
    std::string buffer;
    std::byte chunk[512];
    for (;;) {
      auto read = socket.recv_some(std::span<std::byte>(chunk, sizeof(chunk)));
      if (!read.has_value() || read.value() == 0) {
        break;
      }
      buffer.append(reinterpret_cast<const char*>(chunk), read.value());
      std::size_t newline = buffer.find('\n');
      while (newline != std::string::npos) {
        const std::string command = buffer.substr(0, newline);
        buffer.erase(0, newline + 1);
        const std::string response = handle_command(command, member, stopping);
        const Status wrote = socket.send_all(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(response.data()), response.size()));
        (void)wrote;
        if (command == "stop") {
          break;
        }
        newline = buffer.find('\n');
      }
      if (stopping.load()) {
        break;
      }
    }
    const Status closed = socket.shutdown_send();
    (void)closed;
  }
}

std::string handle_command(const std::string& line, MemberFabricRuntime& member,
                           std::atomic<bool>& stopping) {
  std::istringstream stream(line);
  std::string command;
  stream >> command;
  const auto finish = [](const std::string& text) { return text + "\n"; };
  const auto describe_response = [](const ArtifactResponse& response) {
    return std::string(to_string(response.outcome)) + " digest=" +
           response.artifact_digest.to_hex().substr(0, 16) + " state=" +
           response.state_digest.to_hex().substr(0, 16) + " " + response.detail;
  };
  if (command.empty()) {
    return finish("ERR empty");
  }
  if (command == "stop") {
    stopping.store(true);
    return finish("OK stopping");
  }
  if (command == "identity") {
    const MemberIdentity identity = member.identity();
    return finish("OK member=" + identity.member.to_string() +
                  " domain=" + identity.domain.to_string() +
                  " generation=" + std::to_string(identity.generation.value()) +
                  " incarnation=" + std::to_string(identity.incarnation.value()) +
                  " digest=" + identity.constitution.to_hex());
  }
  if (command == "accept") {
    std::uint64_t lineage = 0;
    stream >> lineage;
    auto response = member.accept(Lineage(lineage));
    if (!response.has_value()) {
      return finish("ERR " + response.status().to_string());
    }
    return finish("OK " + describe_response(response.value()));
  }
  if (command == "reattest") {
    auto response = member.reattest();
    if (!response.has_value()) {
      return finish("ERR " + response.status().to_string());
    }
    return finish("OK " + describe_response(response.value()));
  }
  if (command == "leave") {
    std::uint64_t lineage = 0;
    stream >> lineage;
    auto response = member.leave(Lineage(lineage));
    if (!response.has_value()) {
      return finish("ERR " + response.status().to_string());
    }
    return finish("OK " + describe_response(response.value()));
  }
  if (command == "fence-self") {
    std::uint64_t lineage = 0;
    stream >> lineage;
    auto response = member.self_fence(Lineage(lineage), ReasonCode::MembershipFencedByOrder,
                                      "the member fenced its own federation authority");
    if (!response.has_value()) {
      return finish("ERR " + response.status().to_string());
    }
    return finish("OK " + describe_response(response.value()));
  }
  if (command == "restart") {
    std::uint64_t incarnation = 0;
    if (!(stream >> incarnation)) {
      return finish("ERR restart requires an incarnation");
    }
    auto response = member.restart_with_new_incarnation(Incarnation(incarnation));
    if (!response.has_value()) {
      return finish("ERR " + response.status().to_string());
    }
    return finish("OK " + describe_response(response.value()));
  }
  if (command == "withdraw") {
    std::string grants;
    std::uint64_t lineage = 0;
    stream >> grants >> lineage;
    auto parsed = ffed::app::parse_grants(grants, AuthorityVerb::Mutate);
    if (!parsed.has_value()) {
      return finish("ERR " + parsed.status().to_string());
    }
    auto response = member.withdraw(parsed.value(), Lineage(lineage));
    if (!response.has_value()) {
      return finish("ERR " + response.status().to_string());
    }
    return finish("OK " + describe_response(response.value()));
  }
  if (command == "declare") {
    std::string terms;
    stream >> terms;
    auto parsed = ffed::app::parse_terms(terms);
    if (!parsed.has_value()) {
      return finish("ERR " + parsed.status().to_string());
    }
    auto response = member.declare_delegation(parsed.value());
    if (!response.has_value()) {
      return finish("ERR " + response.status().to_string());
    }
    return finish("OK " + describe_response(response.value()));
  }
  if (command == "propose") {
    // propose <member> <domain> <incarnation> <lineage> <spec>
    std::string member_text;
    std::string domain_text;
    std::uint64_t incarnation = 0;
    std::uint64_t lineage = 0;
    if (!(stream >> member_text >> domain_text >> incarnation >> lineage)) {
      return finish("ERR propose requires <member> <domain> <incarnation> <lineage> <spec>");
    }
    std::string spec;
    std::getline(stream, spec);
    while (!spec.empty() && spec.front() == ' ') {
      spec.erase(spec.begin());
    }
    auto candidate_member = MemberId::parse(member_text);
    auto candidate_domain = FabricDomainId::parse(domain_text);
    if (!candidate_member.has_value() || !candidate_domain.has_value()) {
      return finish("ERR the candidate identity is malformed");
    }
    auto constitution =
        ffed::app::parse_constitution(spec, candidate_member.value(), candidate_domain.value());
    if (!constitution.has_value()) {
      return finish("ERR " + constitution.status().to_string());
    }
    MemberDeclaration declaration;
    declaration.constitution = std::move(constitution.value());
    declaration.incarnation = Incarnation(incarnation);
    declaration.node = NodeId::derive(candidate_member.value().to_string(), incarnation);
    auto response = member.propose(declaration, Lineage(lineage));
    if (!response.has_value()) {
      return finish("ERR " + response.status().to_string());
    }
    return finish("OK " + describe_response(response.value()));
  }
  if (command == "endorse") {
    std::string member_text;
    std::string domain_text;
    std::uint64_t incarnation = 0;
    std::uint64_t lineage = 0;
    if (!(stream >> member_text >> domain_text >> incarnation >> lineage)) {
      return finish("ERR endorse requires <member> <domain> <incarnation> <lineage> <spec>");
    }
    std::string spec;
    std::getline(stream, spec);
    while (!spec.empty() && spec.front() == ' ') {
      spec.erase(spec.begin());
    }
    auto candidate_member = MemberId::parse(member_text);
    auto candidate_domain = FabricDomainId::parse(domain_text);
    if (!candidate_member.has_value() || !candidate_domain.has_value()) {
      return finish("ERR the candidate identity is malformed");
    }
    auto constitution =
        ffed::app::parse_constitution(spec, candidate_member.value(), candidate_domain.value());
    if (!constitution.has_value()) {
      return finish("ERR " + constitution.status().to_string());
    }
    MemberDeclaration declaration;
    declaration.constitution = std::move(constitution.value());
    declaration.incarnation = Incarnation(incarnation);
    declaration.node = NodeId::derive(candidate_member.value().to_string(), incarnation);
    auto response = member.endorse(declaration, Lineage(lineage));
    if (!response.has_value()) {
      return finish("ERR " + response.status().to_string());
    }
    return finish("OK " + describe_response(response.value()));
  }
  if (command == "authority") {
    std::string scope;
    std::string verb;
    std::string lease_text;
    stream >> scope >> verb >> lease_text;
    AuthorityVerb parsed_verb = AuthorityVerb::Mutate;
    if (!verb.empty() && !parse_verb(verb, parsed_verb)) {
      return finish("ERR unknown verb");
    }
    auto scope_id = ScopeId::parse(scope);
    if (!scope_id.has_value()) {
      return finish("ERR " + scope_id.status().to_string());
    }
    ScopeGrant grant;
    grant.scope = std::move(scope_id.value());
    grant.verb = parsed_verb;
    LeaseId lease;
    if (!lease_text.empty() && lease_text != "-") {
      auto parsed_lease = LeaseId::parse(lease_text);
      if (!parsed_lease.has_value()) {
        return finish("ERR the lease identifier is malformed");
      }
      lease = parsed_lease.value();
    }
    auto decision = member.request_authority(grant, lease);
    if (!decision.has_value()) {
      return finish("ERR " + decision.status().to_string());
    }
    return finish("OK outcome=" + std::string(to_string(decision.value().outcome)) +
                  " lifecycle=" + std::string(to_string(decision.value().lifecycle)) +
                  " reasons=" + std::to_string(decision.value().explanation.reasons.size()) +
                  " decision_digest=" + decision.value().digest().to_hex() + " summary=" +
                  decision.value().explanation.summary);
  }
  if (command == "local") {
    std::string scope;
    std::string verb;
    stream >> scope >> verb;
    AuthorityVerb parsed_verb = AuthorityVerb::Administer;
    if (!verb.empty() && !parse_verb(verb, parsed_verb)) {
      return finish("ERR unknown verb");
    }
    auto scope_id = ScopeId::parse(scope);
    if (!scope_id.has_value()) {
      return finish("ERR " + scope_id.status().to_string());
    }
    ScopeGrant grant;
    grant.scope = std::move(scope_id.value());
    grant.verb = parsed_verb;
    const AuthorityDecision decision = member.evaluate_local(grant);
    return finish("OK outcome=" + std::string(to_string(decision.outcome)) + " summary=" +
                  decision.explanation.summary);
  }
  if (command == "lease") {
    std::string grants;
    std::uint64_t not_after_epoch = 0;
    std::uint64_t lifetime = 0;
    stream >> grants >> not_after_epoch >> lifetime;
    auto parsed = ffed::app::parse_grants(grants, AuthorityVerb::Mutate);
    if (!parsed.has_value()) {
      return finish("ERR " + parsed.status().to_string());
    }
    auto lease = member.request_lease(parsed.value(), Epoch(not_after_epoch), Tick(lifetime));
    if (!lease.has_value()) {
      return finish("ERR " + lease.status().to_string());
    }
    return finish("OK lease=" + lease.value().id.to_string() +
                  " not_after_tick=" + std::to_string(lease.value().not_after.value()) +
                  " issued_epoch=" + std::to_string(lease.value().issued_epoch.value()) +
                  " issuer_incarnation=" +
                  std::to_string(lease.value().issuer_incarnation.value()));
  }
  if (command == "probe") {
    std::string member_text;
    std::string host;
    std::uint64_t port = 0;
    stream >> member_text >> host >> port;
    auto peer = MemberId::parse(member_text);
    if (!peer.has_value()) {
      return finish("ERR the peer identifier is malformed");
    }
    std::vector<MemberFabricRuntime::PeerTarget> targets;
    MemberFabricRuntime::PeerTarget target;
    target.member = peer.value();
    target.endpoint.host = host.empty() ? "127.0.0.1" : host;
    target.endpoint.port = static_cast<std::uint16_t>(port);
    targets.push_back(std::move(target));
    const MemberObservation observation = member.probe_peers(targets);
    auto reported = member.report_observation(observation);
    std::string detail;
    if (observation.peers.empty()) {
      detail = "no observation";
    } else {
      detail = std::string(to_string(observation.peers.front().state)) + " " +
               observation.peers.front().detail;
    }
    if (!reported.has_value()) {
      return finish("ERR " + reported.status().to_string());
    }
    return finish("OK " + detail);
  }
  if (command == "remote-probe") {
    // Probes a peer without reporting the observation, so a caller can build
    // its own observation set.
    std::string member_text;
    std::string host;
    std::uint64_t port = 0;
    stream >> member_text >> host >> port;
    auto peer = MemberId::parse(member_text);
    if (!peer.has_value()) {
      return finish("ERR the peer identifier is malformed");
    }
    std::vector<MemberFabricRuntime::PeerTarget> targets;
    MemberFabricRuntime::PeerTarget target;
    target.member = peer.value();
    target.endpoint.host = host.empty() ? "127.0.0.1" : host;
    target.endpoint.port = static_cast<std::uint16_t>(port);
    targets.push_back(std::move(target));
    const MemberObservation observation = member.probe_peers(targets);
    if (observation.peers.empty()) {
      return finish("OK UNKNOWN no observation");
    }
    const PeerObservation& entry = observation.peers.front();
    return finish("OK " + std::string(to_string(entry.state)) + " incarnation=" +
                  std::to_string(entry.peer_incarnation.value()) + " " + entry.detail);
  }
  if (command == "stop-probe-listener") {
    const Status status = member.stop_probe_listener();
    return finish(status.ok() ? "OK probe listener closed" : "ERR " + status.to_string());
  }
  if (command == "start-probe-listener") {
    const Status status = member.start_probe_listener();
    return finish(status.ok() ? "OK probe listener open" : "ERR " + status.to_string());
  }
  if (command == "probe-port") {
    return finish("OK " + std::to_string(member.probe_port()));
  }
  if (command == "digest") {
    auto digest = member.coordinator_digest();
    if (!digest.has_value()) {
      return finish("ERR " + digest.status().to_string());
    }
    return finish("OK digest=" + digest.value().state_digest.to_hex() +
                  " epoch=" + std::to_string(digest.value().epoch.value()) +
                  " tick=" + std::to_string(digest.value().logical_time.value()));
  }
  if (command == "describe") {
    return finish("OK " + member.describe());
  }
  return finish("ERR unknown command");
}

}  // namespace

int main(int argc, char* argv[]) {
  using namespace fabric_federation;
  const ffed::app::Arguments arguments = ffed::app::parse_arguments(argc, argv);
  if (arguments.has("--help") || arguments.has("-h") || argc <= 1) {
    std::printf(
        "ffed-member %s\n"
        "usage: ffed-member --federation <id> --member <id> --domain <id> [options]\n"
        "  --spec <spec>          constitution (gen=;caps=;retained=;delegated=;desc=)\n"
        "  --generation <n>       generation counter (default 1)\n"
        "  --incarnation <n>      process incarnation (default 1)\n"
        "  --node <id>            node identity (derived when omitted)\n"
        "  --coordinator-host <h> coordinator host (default 127.0.0.1)\n"
        "  --coordinator-port <n> coordinator port\n"
        "  --listen-for-probes    serve peer reachability probes\n"
        "  --probe-port <n>       probe listener port (0 = ephemeral)\n"
        "  --control-port <n>     control channel (0 = ephemeral)\n"
        "  --reattest             re-declare the identity immediately after attaching\n"
        "  --ready-file <path>    written once the member is attached\n",
        std::string(kVersionString).c_str());
    return argc <= 1 ? 2 : 0;
  }

  Options options;
  const std::string federation_text = arguments.get("--federation");
  auto federation = FederationId::parse(federation_text);
  if (!federation.has_value()) {
    std::fprintf(stderr, "ffed-member: the federation identifier is malformed\n");
    return 2;
  }
  options.federation = federation.value();
  auto member_id = MemberId::parse(arguments.get("--member"));
  auto domain_id = FabricDomainId::parse(arguments.get("--domain"));
  if (!member_id.has_value() || !domain_id.has_value()) {
    std::fprintf(stderr, "ffed-member: the member and domain identifiers are required\n");
    return 2;
  }
  auto constitution = ffed::app::parse_constitution(arguments.get("--spec"), member_id.value(),
                                                    domain_id.value());
  if (!constitution.has_value()) {
    std::fprintf(stderr, "ffed-member: %s\n", constitution.status().to_string().c_str());
    return 2;
  }
  options.constitution = std::move(constitution.value());
  options.constitution.generation =
      Generation(arguments.get_u64("--generation", options.constitution.generation.value()));
  options.incarnation = Incarnation(arguments.get_u64("--incarnation", 1));

  const std::string node_text = arguments.get("--node");
  if (node_text.empty()) {
    options.node = NodeId::derive(member_id.value().to_string(), options.incarnation.value());
  } else {
    auto node = NodeId::parse(node_text);
    if (!node.has_value()) {
      std::fprintf(stderr, "ffed-member: the node identifier is malformed\n");
      return 2;
    }
    options.node = node.value();
  }
  options.coordinator.host = arguments.get("--coordinator-host", "127.0.0.1");
  options.coordinator.port =
      static_cast<std::uint16_t>(arguments.get_u64("--coordinator-port", 0));
  options.listen_for_probes = arguments.has("--listen-for-probes");
  options.probe_port = static_cast<std::uint16_t>(arguments.get_u64("--probe-port", 0));
  options.control_port = static_cast<std::uint16_t>(arguments.get_u64("--control-port", 0));
  options.ready_file = arguments.get("--ready-file");

  MemberConfig config;
  config.federation = options.federation;
  config.constitution = options.constitution;
  config.node = options.node;
  config.incarnation = options.incarnation;
  config.coordinator = options.coordinator;
  config.listen_for_probes = options.listen_for_probes;
  config.probe_port = options.probe_port;

  auto created = MemberFabricRuntime::create(config);
  if (!created.has_value()) {
    std::fprintf(stderr, "ffed-member: %s\n", created.status().to_string().c_str());
    return 1;
  }
  std::unique_ptr<MemberFabricRuntime> member = std::move(created.value());
  const Status attached = member->attach();
  if (!attached.ok()) {
    std::fprintf(stderr, "ffed-member: %s\n", attached.to_string().c_str());
    return 1;
  }

  std::printf("READY member=%s node=%s incarnation=%llu probe-port=%u control-port=%u\n",
              options.constitution.member.to_string().c_str(), options.node.to_string().c_str(),
              static_cast<unsigned long long>(options.incarnation.value()),
              static_cast<unsigned>(member->probe_port()),
              static_cast<unsigned>(options.control_port));
  std::fflush(stdout);

  // A restarted member re-declares its identity immediately when asked. The
  // generation and constitution digest are unchanged, so consent still stands,
  // but the new incarnation has to be presented before authority can follow it.
  if (arguments.has("--reattest")) {
    auto response = member->reattest();
    if (!response.has_value()) {
      std::fprintf(stderr, "ffed-member: re-attestation failed: %s\n",
                   response.status().to_string().c_str());
      return 1;
    }
    std::printf("REATTESTED %s\n", std::string(to_string(response.value().outcome)).c_str());
    std::fflush(stdout);
  }

  if (!options.ready_file.empty()) {
    std::ofstream ready(options.ready_file, std::ios::binary | std::ios::trunc);
    if (ready) {
      ready << options.constitution.member.to_string() << "\n" << member->probe_port() << "\n";
      ready.flush();
    }
  }

  std::atomic<bool> stopping{false};
  if (arguments.has("--control-port")) {
    Status startup = Status::success();
    std::thread control(
        [&] { serve_control(stopping, options.control_port, *member, startup); });
    control.join();
    if (!startup.ok()) {
      std::fprintf(stderr, "ffed-member: %s\n", startup.to_string().c_str());
      return 1;
    }
  } else {
    std::string line;
    while (std::getline(std::cin, line)) {
      if (line == "stop") {
        break;
      }
    }
  }
  std::printf("STOPPED\n");
  std::fflush(stdout);
  return 0;
}
