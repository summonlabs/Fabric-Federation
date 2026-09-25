// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// ffed-coordinator: the federation coordinator daemon.
//
// It prints a single READY line once it is listening, then serves the framed
// protocol on loopback TCP and, when a control port is configured, a
// newline-delimited operator channel used by the tests and the CLI.
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>

#include "common.hpp"
#include "fabric_federation/client.hpp"
#include "fabric_federation/coordinator.hpp"
#include "fabric_federation/net.hpp"
#include "fabric_federation/version.hpp"

namespace {

using namespace fabric_federation;

struct Options {
  FederationId federation;
  NodeId node;
  std::string description = "fabric federation";
  std::string state_path;
  bool listen = false;
  std::uint16_t port = 0;
  std::uint16_t control_port = 0;
  std::string ready_file;
  std::size_t workers = 4;
  bool bootstrap = false;
  MemberId founder_member;
  FabricDomainId founder_domain;
  std::string founder_grants;
  Incarnation founder_incarnation = Incarnation(1);
  bool print_stats_and_exit = false;
};

std::string control_response(const std::string& line, FederationCoordinator& coordinator);

void serve_control(std::atomic<bool>& stopping, std::uint16_t port, FederationCoordinator& coordinator,
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
        const std::string line = buffer.substr(0, newline);
        buffer.erase(0, newline + 1);
        const std::string response = control_response(line, coordinator);
        const Status wrote = socket.send_all(std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(response.data()), response.size()));
        (void)wrote;
        if (line == "stop") {
          stopping.store(true);
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

std::string control_response(const std::string& line, FederationCoordinator& coordinator) {
  std::istringstream stream(line);
  std::string command;
  stream >> command;
  const auto finish = [](const std::string& text) { return text + "\n"; };
  if (command.empty()) {
    return finish("ERR empty");
  }
  if (command == "stop") {
    return finish("OK stopping");
  }
  if (command == "stats" || command == "digest") {
    const CoordinatorStats stats = coordinator.stats();
    std::string out = "OK digest=" + stats.state_digest.to_hex() +
                      " epoch=" + std::to_string(stats.epoch.value()) +
                      " tick=" + std::to_string(stats.logical_time.value()) +
                      " incarnation=" + std::to_string(stats.coordinator_incarnation.value()) +
                      " artifacts=" + std::to_string(stats.artifacts) +
                      " rejected=" + std::to_string(stats.rejected_artifacts) +
                      " duplicates=" + std::to_string(stats.duplicate_artifacts) +
                      " journal=" + std::to_string(stats.journal_records) +
                      " members=" + std::to_string(stats.members) +
                      " active=" + std::to_string(stats.active_members) +
                      " leases=" + std::to_string(stats.leases) +
                      " replay=" + std::to_string(stats.replay_entries) +
                      " partition=" + stats.partition_state +
                      (stats.reconciling ? " reconciling" : "");
    return finish(out);
  }
  if (command == "state") {
    auto state = coordinator.state();
    if (!state.has_value()) {
      return finish("ERR " + state.status().to_string());
    }
    std::string text = render_state_text(state.value());
    for (char& c : text) {
      if (c == '\n') {
        c = '|';
      }
    }
    return finish("OK " + text);
  }
  std::uint64_t value = 0;
  if (command == "advance-time") {
    if (!(stream >> value)) {
      return finish("ERR advance-time requires a tick");
    }
    const Status status = coordinator.advance_time(Tick(value));
    return finish(status.ok() ? "OK advanced" : "ERR " + status.to_string());
  }
  if (command == "advance-epoch") {
    if (!(stream >> value)) {
      return finish("ERR advance-epoch requires an epoch");
    }
    std::string reason;
    std::getline(stream, reason);
    const Status status = coordinator.advance_epoch(Epoch(value),
                                                    ReasonCode::PartitionSplitSuspendsGlobalMutation,
                                                    reason.empty() ? "operator request" : reason);
    return finish(status.ok() ? "OK advanced" : "ERR " + status.to_string());
  }
  if (command == "reconcile") {
    if (!(stream >> value)) {
      return finish("ERR reconcile requires an epoch");
    }
    const Status status = coordinator.complete_reconciliation(Epoch(value));
    return finish(status.ok() ? "OK recorded" : "ERR " + status.to_string());
  }
  if (command == "fence") {
    std::string member_text;
    if (!(stream >> member_text)) {
      return finish("ERR fence requires a member identifier");
    }
    auto member = MemberId::parse(member_text);
    if (!member.has_value()) {
      return finish("ERR the member identifier is malformed");
    }
    const Status status = coordinator.fence_member(member.value(), Lineage(),
                                                   ReasonCode::MembershipFencedByOrder,
                                                   "fenced by the operator");
    return finish(status.ok() ? "OK fenced" : "ERR " + status.to_string());
  }
  if (command == "retire") {
    std::string member_text;
    if (!(stream >> member_text)) {
      return finish("ERR retire requires a member identifier");
    }
    auto member = MemberId::parse(member_text);
    if (!member.has_value()) {
      return finish("ERR the member identifier is malformed");
    }
    const Status status = coordinator.retire_member(member.value(), Lineage(),
                                                    ReasonCode::MembershipRetired,
                                                    "retired by the operator");
    return finish(status.ok() ? "OK retired" : "ERR " + status.to_string());
  }
  if (command == "transport") {
    return finish("OK " + transport_description());
  }
  return finish("ERR unknown command");
}

}  // namespace

int main(int argc, char* argv[]) {
  using namespace fabric_federation;
  const ffed::app::Arguments arguments = ffed::app::parse_arguments(argc, argv);
  if (arguments.has("--help") || arguments.has("-h") || argc <= 1) {
    std::printf(
        "ffed-coordinator %s\n"
        "usage: ffed-coordinator --federation <id> [options]\n"
        "  --node <id>                  coordinator node identity (derived when omitted)\n"
        "  --state <path>               durable journal path (empty = in-memory)\n"
        "  --listen                     serve the framed protocol on loopback TCP\n"
        "  --port <n>                   listening port (0 = ephemeral)\n"
        "  --control-port <n>           operator control channel (0 = ephemeral)\n"
        "  --ready-file <path>          written once the coordinator is serving\n"
        "  --workers <n>                connection worker threads\n"
        "  --bootstrap                  create the genesis record\n"
        "  --founder-member <id>        genesis founder member identity\n"
        "  --founder-domain <id>        genesis founder domain identity\n"
        "  --founder-spec <spec>        founder constitution (name=value;...)\n"
        "  --founder-grants <grants>    bootstrap grants (scope:verb,...)\n"
        "  --stats                      print stats and exit\n"
        "  --describe                   print the transport and version, then exit\n",
        std::string(kVersionString).c_str());
    return argc <= 1 ? 2 : 0;
  }
  if (arguments.has("--describe") || arguments.has("--version")) {
    std::printf("%s %s\n%s\n", std::string(kProductName).c_str(),
                std::string(kVersionString).c_str(), transport_description().c_str());
    return 0;
  }

  Options options;
  const std::string federation_text = arguments.get("--federation", "derive:ffed-default");
  if (federation_text.rfind("derive:", 0) == 0) {
    options.federation = FederationId::derive(federation_text.substr(7), 1);
  } else {
    auto parsed = FederationId::parse(federation_text);
    if (!parsed.has_value()) {
      std::fprintf(stderr, "ffed-coordinator: the federation identifier is malformed\n");
      return 2;
    }
    options.federation = parsed.value();
  }
  const std::string node_text = arguments.get("--node", "derive:coordinator");
  if (node_text.rfind("derive:", 0) == 0) {
    options.node = NodeId::derive(node_text.substr(7), 1);
  } else {
    auto parsed = NodeId::parse(node_text);
    if (!parsed.has_value()) {
      std::fprintf(stderr, "ffed-coordinator: the node identifier is malformed\n");
      return 2;
    }
    options.node = parsed.value();
  }

  options.state_path = arguments.get("--state");
  options.listen = arguments.has("--listen");
  options.port = static_cast<std::uint16_t>(arguments.get_u64("--port", 0));
  options.control_port = static_cast<std::uint16_t>(arguments.get_u64("--control-port", 0));
  options.ready_file = arguments.get("--ready-file");
  options.workers = static_cast<std::size_t>(arguments.get_u64("--workers", 4));
  options.bootstrap = arguments.has("--bootstrap");
  options.print_stats_and_exit = arguments.has("--stats");
  options.description = arguments.get("--description", "fabric federation");

  CoordinatorConfig config;
  config.federation = options.federation;
  config.node = options.node;
  config.description = options.description;
  config.policy = default_policy();
  config.listen = options.listen;
  config.listen_port = options.port;
  config.worker_threads = options.workers;
  config.bootstrap = options.bootstrap;
  if (!options.state_path.empty()) {
    config.journal_path = options.state_path;
  }

  if (options.bootstrap) {
    const std::string member_text = arguments.get("--founder-member", "derive:founder");
    const std::string domain_text = arguments.get("--founder-domain", "derive:founder-domain");
    auto member = member_text.rfind("derive:", 0) == 0
                      ? MemberId::derive(member_text.substr(7), 1)
                      : MemberId::parse(member_text).value_or(MemberId());
    auto domain = domain_text.rfind("derive:", 0) == 0
                      ? FabricDomainId::derive(domain_text.substr(7), 1)
                      : FabricDomainId::parse(domain_text).value_or(FabricDomainId());
    if (member.is_nil() || domain.is_nil()) {
      std::fprintf(stderr, "ffed-coordinator: the founder identity is malformed\n");
      return 2;
    }
    auto constitution = ffed::app::parse_constitution(
        arguments.get("--founder-spec", "gen=1;delegated=federation.route.advertise:mutate:exclusive;"
                                        "retained=domain.founder.control:administer"),
        member, domain);
    if (!constitution.has_value()) {
      std::fprintf(stderr, "ffed-coordinator: %s\n", constitution.status().to_string().c_str());
      return 2;
    }
    MemberDeclaration founder;
    founder.constitution = std::move(constitution.value());
    founder.incarnation = options.founder_incarnation;
    founder.node = options.node;
    config.founder = founder;
    auto grants = ffed::app::parse_grants(arguments.get("--founder-grants", ""),
                                          AuthorityVerb::Administer);
    if (!grants.has_value()) {
      std::fprintf(stderr, "ffed-coordinator: %s\n", grants.status().to_string().c_str());
      return 2;
    }
    config.founder_grants = std::move(grants.value());
  }

  auto created = FederationCoordinator::create(config);
  if (!created.has_value()) {
    std::fprintf(stderr, "ffed-coordinator: %s\n", created.status().to_string().c_str());
    return 1;
  }
  std::unique_ptr<FederationCoordinator> coordinator = std::move(created.value());
  const Status started = coordinator->start();
  if (!started.ok()) {
    std::fprintf(stderr, "ffed-coordinator: %s\n", started.to_string().c_str());
    return 1;
  }

  if (options.print_stats_and_exit) {
    const CoordinatorStats stats = coordinator->stats();
    std::printf("digest=%s\nepoch=%llu\ntick=%llu\nartifacts=%llu\nmembers=%llu\nactive=%llu\n"
                "transport=%s\nrecovery=%s\n",
                stats.state_digest.to_hex().c_str(),
                static_cast<unsigned long long>(stats.epoch.value()),
                static_cast<unsigned long long>(stats.logical_time.value()),
                static_cast<unsigned long long>(stats.artifacts),
                static_cast<unsigned long long>(stats.members),
                static_cast<unsigned long long>(stats.active_members), stats.transport.c_str(),
                stats.recovery.c_str());
    const Status stopped = coordinator->stop();
    return stopped.ok() ? 0 : 1;
  }

  std::printf("READY port=%u federation=%s node=%s incarnation=%llu durable=%s\n",
              static_cast<unsigned>(coordinator->listen_port()),
              options.federation.to_string().c_str(), options.node.to_string().c_str(),
              static_cast<unsigned long long>(coordinator->incarnation().value()),
              config.journal_path.empty() ? "no" : "yes");
  std::fflush(stdout);

  if (!options.ready_file.empty()) {
    std::ofstream ready(options.ready_file, std::ios::binary | std::ios::trunc);
    if (ready) {
      ready << coordinator->listen_port() << "\n"
            << config.journal_path.string() << "\n"
            << options.federation.to_string() << "\n";
      ready.flush();
    }
  }

  std::atomic<bool> stopping{false};
  if (arguments.has("--control-port")) {
    Status startup = Status::success();
    std::thread control([&] { serve_control(stopping, options.control_port, *coordinator, startup); });
    control.join();
    if (!startup.ok()) {
      std::fprintf(stderr, "ffed-coordinator: %s\n", startup.to_string().c_str());
      const Status stopped = coordinator->stop();
      (void)stopped;
      return 1;
    }
  } else {
    // Without a control channel the process serves until its standard input is
    // closed, which is the harness's deterministic shutdown signal.
    std::string line;
    while (std::getline(std::cin, line)) {
      if (line == "stop") {
        break;
      }
    }
  }
  const Status stopped = coordinator->stop();
  std::printf("STOPPED\n");
  std::fflush(stdout);
  return stopped.ok() ? 0 : 1;
}
