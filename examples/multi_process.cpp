// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Example: a federation made of separate operating-system processes.
//
//   ffed-coordinator   (one process)
//   ffed-member x2     (two more processes, each an independent fabric domain)
//
// Every membership artefact is issued by the process that owns the identity:
// the sponsor proposes from its own process, the candidate consents from its
// own process, and each member answers authority questions itself. Nothing is
// simulated; these are real processes over real loopback TCP.
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "fabric_federation/control.hpp"
#include "fabric_federation/ids.hpp"
#include "fabric_federation/net.hpp"
#include "fabric_federation/process.hpp"
#include "fabric_federation/version.hpp"

using namespace fabric_federation;

#ifndef FFED_COORDINATOR_BIN
#define FFED_COORDINATOR_BIN "ffed-coordinator"
#endif
#ifndef FFED_MEMBER_BIN
#define FFED_MEMBER_BIN "ffed-member"
#endif

namespace {

std::uint16_t first_line_as_port(const std::string& content) {
  const std::size_t newline = content.find('\n');
  const std::string first = content.substr(0, newline);
  return static_cast<std::uint16_t>(std::stoi(first));
}

std::filesystem::path scratch_directory() {
  const auto base = std::filesystem::temp_directory_path() / "ffed-example-multiprocess";
  std::error_code error;
  std::filesystem::remove_all(base, error);
  std::filesystem::create_directories(base, error);
  return base;
}

}  // namespace

int main() {
  const std::filesystem::path scratch = scratch_directory();
  const std::string federation = FederationId::derive("example-multi-process", 1).to_string();
  const std::string sponsor = MemberId::derive("example-mp-sponsor", 1).to_string();
  const std::string sponsor_domain =
      FabricDomainId::derive("example-mp-sponsor-domain", 1).to_string();
  const std::string candidate = MemberId::derive("example-mp-candidate", 1).to_string();
  const std::string candidate_domain =
      FabricDomainId::derive("example-mp-candidate-domain", 1).to_string();
  const std::string spec =
      "gen=1;delegated=federation.route.advertise:mutate:exclusive;"
      "retained=domain.example.control:administer;caps=federation.protocol.v1:1:known";

  const std::filesystem::path coordinator_ready = scratch / "coordinator.ready";
  ProcessSpec coordinator_spec;
  coordinator_spec.executable = FFED_COORDINATOR_BIN;
  coordinator_spec.arguments = {"--federation", federation,
                                "--state", (scratch / "federation.fedjournal").string(),
                                "--listen",
                                "--port", "0",
                                "--control-port", "0",
                                "--bootstrap",
                                "--founder-member", sponsor,
                                "--founder-domain", sponsor_domain,
                                "--founder-spec", spec,
                                "--ready-file", coordinator_ready.string(),
                                "--description", "multi-process example"};
  coordinator_spec.stdout_path = (scratch / "coordinator.out").string();
  coordinator_spec.stderr_path = (scratch / "coordinator.err").string();
  auto coordinator = ChildProcess::spawn(coordinator_spec);
  if (!coordinator.has_value()) {
    std::fprintf(stderr, "coordinator could not be started: %s\n",
                 coordinator.status().to_string().c_str());
    return 1;
  }
  auto ready = wait_for_ready_file(coordinator_ready);
  if (!ready.has_value()) {
    std::fprintf(stderr, "%s\n", ready.status().to_string().c_str());
    const Status killed = coordinator.value().terminate_now();
    (void)killed;
    return 1;
  }
  const std::uint16_t protocol_port = first_line_as_port(ready.value());
  std::printf("coordinator: process %llu, protocol port %u, transport %s\n",
              static_cast<unsigned long long>(coordinator.value().pid()),
              static_cast<unsigned>(protocol_port), transport_description().c_str());

  const std::vector<std::pair<std::string, std::string>> identities = {
      {sponsor, sponsor_domain}, {candidate, candidate_domain}};
  const std::vector<std::uint16_t> control_ports = {7411, 7412};
  std::vector<ChildProcess> members;
  std::vector<std::uint16_t> probe_ports;
  for (std::size_t i = 0; i < identities.size(); ++i) {
    const std::filesystem::path member_ready = scratch / (identities[i].first + ".ready");
    ProcessSpec member_spec;
    member_spec.executable = FFED_MEMBER_BIN;
    member_spec.arguments = {"--federation", federation,
                             "--member", identities[i].first,
                             "--domain", identities[i].second,
                             "--spec", spec,
                             "--coordinator-port", std::to_string(protocol_port),
                             "--control-port", std::to_string(control_ports[i]),
                             "--listen-for-probes",
                             "--probe-port", "0",
                             "--ready-file", member_ready.string()};
    member_spec.stdout_path = (scratch / (identities[i].first + ".out")).string();
    member_spec.stderr_path = (scratch / (identities[i].first + ".err")).string();
    auto member = ChildProcess::spawn(member_spec);
    if (!member.has_value()) {
      std::fprintf(stderr, "member could not be started: %s\n",
                   member.status().to_string().c_str());
      const Status killed = coordinator.value().terminate_now();
      (void)killed;
      return 1;
    }
    auto member_ready_content = wait_for_ready_file(member_ready);
    if (!member_ready_content.has_value()) {
      std::fprintf(stderr, "%s\n", member_ready_content.status().to_string().c_str());
      const Status killed = member.value().terminate_now();
      (void)killed;
      return 1;
    }
    const std::string first = member_ready_content.value();
    const std::size_t newline = first.find('\n');
    probe_ports.push_back(static_cast<std::uint16_t>(
        std::stoi(first.substr(newline + 1, first.find('\n', newline + 1) - newline - 1))));
    members.push_back(std::move(member.value()));
    std::printf("member %s: process %llu, probe port %u, control port %u\n",
                identities[i].first.c_str(),
                static_cast<unsigned long long>(members.back().pid()),
                static_cast<unsigned>(probe_ports.back()),
                static_cast<unsigned>(control_ports[i]));
  }

  const auto step = [&](std::size_t index, const std::string& command) {
    auto reply = send_control_command(control_ports[index], command);
    std::printf("  -> %s\n", reply.has_value() ? reply.value().c_str()
                                              : reply.status().to_string().c_str());
    return reply;
  };

  std::printf("join sequence driven through the members' own processes\n");
  step(0, "propose " + candidate + " " + candidate_domain + " 1 0 " + spec);
  step(1, "accept 0");
  step(0, "endorse " + candidate + " " + candidate_domain + " 1 0 " + spec);

  std::printf("authority questions answered by the coordinator\n");
  step(1, "authority federation.route.advertise mutate -");
  step(1, "local domain.example.control administer");

  std::printf("reachability observed by the members themselves\n");
  step(0, "probe " + candidate + " 127.0.0.1 " + std::to_string(probe_ports[1]));
  step(1, "probe " + sponsor + " 127.0.0.1 " + std::to_string(probe_ports[0]));

  step(0, "digest");
  step(0, "describe");

  std::printf("shutting the members down\n");
  for (std::size_t i = 0; i < members.size(); ++i) {
    step(i, "stop");
    auto exit_code = members[i].wait();
    std::printf("  member %zu exited with %d\n", i,
                exit_code.has_value() ? exit_code.value() : -1);
  }
  const Status killed = coordinator.value().terminate_now();
  (void)killed;
  std::printf("coordinator terminated (hard kill) to show that no graceful path is required\n");

  std::error_code error;
  std::filesystem::remove_all(scratch, error);
  return 0;
}
