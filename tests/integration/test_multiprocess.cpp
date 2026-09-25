// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Multi-process proof. Every claim below is made about separate operating
// system processes talking over real loopback TCP:
//
//   * independent fabrics form a federation and answer authority questions,
//   * one member cannot create multi-party authority on its own,
//   * a stale member incarnation cannot exercise federation authority,
//   * a partition suspends global mutation for every side and recovery is
//     conservative,
//   * a coordinator restart does not revive leases, and
//   * canonical state is permutation independent across processes.
#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "fabric_federation/client.hpp"
#include "fabric_federation/control.hpp"
#include "fabric_federation/process.hpp"
#include "test_harness.hpp"

using namespace fabric_federation;

namespace {

struct Scratch {
  std::filesystem::path directory;

  Scratch() {
    static std::atomic<unsigned long long> counter{0};
    directory = std::filesystem::temp_directory_path() /
                ("ffed-multiprocess-" + std::to_string(counter.fetch_add(1)));
    std::error_code error;
    std::filesystem::remove_all(directory, error);
    std::filesystem::create_directories(directory, error);
  }
  ~Scratch() {
    std::error_code error;
    std::filesystem::remove_all(directory, error);
  }
  [[nodiscard]] std::filesystem::path file(const std::string& name) const {
    return directory / name;
  }
  [[nodiscard]] std::string text() const { return directory.string(); }
};

std::uint16_t first_line_as_port(const std::string& content) {
  const std::size_t newline = content.find('\n');
  return static_cast<std::uint16_t>(std::stoi(content.substr(0, newline)));
}

std::uint16_t second_line_as_port(const std::string& content) {
  const std::size_t first = content.find('\n');
  const std::size_t second = content.find('\n', first + 1);
  return static_cast<std::uint16_t>(std::stoi(content.substr(first + 1, second - first - 1)));
}

// Ports are chosen by the test so that the parent knows where to talk; the
// protocol ports stay ephemeral and are read from the readiness files.
std::atomic<std::uint16_t> g_port_base{24000};

struct Cluster {
  Scratch* scratch = nullptr;
  std::string tag;
  std::string federation;
  std::string sponsor;
  std::string sponsor_domain;
  std::string candidate;
  std::string candidate_domain;
  std::string spec;
  std::filesystem::path journal;

  std::uint16_t coordinator_control = 0;
  std::uint16_t sponsor_control = 0;
  std::uint16_t candidate_control = 0;
  std::uint16_t protocol_port = 0;
  std::uint16_t sponsor_probe = 0;
  std::uint16_t candidate_probe = 0;

  ChildProcess coordinator_process;
  ChildProcess sponsor_process;
  ChildProcess candidate_process;

  bool start_coordinator(bool bootstrap) {
    const std::filesystem::path ready = scratch->file("coordinator-" + tag + ".ready");
    ProcessSpec process_spec;
    process_spec.executable = FFED_COORDINATOR_BIN;
    process_spec.arguments = {"--federation", federation, "--state", journal.string(),
                              "--listen", "--port", "0", "--control-port",
                              std::to_string(coordinator_control)};
    if (bootstrap) {
      process_spec.arguments.push_back("--bootstrap");
      process_spec.arguments.push_back("--founder-member");
      process_spec.arguments.push_back(sponsor);
      process_spec.arguments.push_back("--founder-domain");
      process_spec.arguments.push_back(sponsor_domain);
      process_spec.arguments.push_back("--founder-spec");
      process_spec.arguments.push_back(spec);
    }
    process_spec.arguments.push_back("--ready-file");
    process_spec.arguments.push_back(ready.string());
    process_spec.stdout_path = scratch->file("coordinator-" + tag + ".out").string();
    process_spec.stderr_path = scratch->file("coordinator-" + tag + ".err").string();
    auto spawned = ChildProcess::spawn(process_spec);
    if (!spawned.has_value()) {
      return false;
    }
    coordinator_process = std::move(spawned.value());
    auto content = wait_for_ready_file(ready);
    if (!content.has_value()) {
      return false;
    }
    protocol_port = first_line_as_port(content.value());
    auto control = wait_for_control(coordinator_control, "stats");
    return control.has_value();
  }

  bool start_member(const std::string& member, const std::string& domain, std::uint16_t control,
                    std::uint16_t probe_port, Incarnation incarnation, bool reattest,
                    ChildProcess& out_process, std::uint16_t& out_probe) {
    const std::filesystem::path ready =
        scratch->file("member-" + tag + "-" + std::to_string(control) + ".ready");
    ProcessSpec process_spec;
    process_spec.executable = FFED_MEMBER_BIN;
    process_spec.arguments = {"--federation", federation, "--member", member, "--domain", domain,
                              "--spec", spec, "--coordinator-port", std::to_string(protocol_port),
                              "--control-port", std::to_string(control),
                              "--incarnation", std::to_string(incarnation.value()),
                              "--listen-for-probes", "--probe-port",
                              std::to_string(probe_port)};
    if (reattest) {
      process_spec.arguments.push_back("--reattest");
    }
    process_spec.arguments.push_back("--ready-file");
    process_spec.arguments.push_back(ready.string());
    process_spec.stdout_path =
        scratch->file("member-" + tag + "-" + std::to_string(control) + ".out").string();
    process_spec.stderr_path =
        scratch->file("member-" + tag + "-" + std::to_string(control) + ".err").string();
    auto spawned = ChildProcess::spawn(process_spec);
    if (!spawned.has_value()) {
      return false;
    }
    out_process = std::move(spawned.value());
    auto content = wait_for_ready_file(ready);
    if (!content.has_value()) {
      return false;
    }
    out_probe = second_line_as_port(content.value());
    auto alive = wait_for_control(control, "identity");
    return alive.has_value();
  }

  bool start_members() {
    return start_member(sponsor, sponsor_domain, sponsor_control, 0, Incarnation(1), false,
                        sponsor_process, sponsor_probe) &&
           start_member(candidate, candidate_domain, candidate_control, 0, Incarnation(1), false,
                        candidate_process, candidate_probe);
  }

  [[nodiscard]] Result<std::string> sponsor_command(const std::string& command) const {
    return send_control_command(sponsor_control, command);
  }
  [[nodiscard]] Result<std::string> candidate_command(const std::string& command) const {
    return send_control_command(candidate_control, command);
  }
  [[nodiscard]] Result<std::string> coordinator_command(const std::string& command) const {
    return send_control_command(coordinator_control, command);
  }

  void stop_member(ChildProcess& process, std::uint16_t control) {
    if (!process.valid()) {
      return;
    }
    const auto reply = send_control_command(control, "stop");
    (void)reply;
    if (process.running()) {
      auto code = process.wait();
      (void)code;
      return;
    }
    auto code = process.wait();
    (void)code;
  }

  void stop_coordinator() {
    if (!coordinator_process.valid()) {
      return;
    }
    const auto reply = send_control_command(coordinator_control, "stop");
    (void)reply;
    auto code = coordinator_process.wait();
    (void)code;
  }

  void shutdown() {
    stop_member(sponsor_process, sponsor_control);
    stop_member(candidate_process, candidate_control);
    stop_coordinator();
  }
};

Cluster make_cluster(Scratch& scratch, const std::string& tag,
                     const std::string& federation_seed = std::string()) {
  Cluster cluster;
  cluster.scratch = &scratch;
  cluster.tag = tag;
  cluster.federation =
      FederationId::derive("multiprocess-" + (federation_seed.empty() ? tag : federation_seed), 1)
          .to_string();
  cluster.sponsor = MemberId::derive("multiprocess-sponsor", 1).to_string();
  cluster.sponsor_domain =
      FabricDomainId::derive("multiprocess-sponsor-domain", 1).to_string();
  cluster.candidate = MemberId::derive("multiprocess-candidate", 1).to_string();
  cluster.candidate_domain =
      FabricDomainId::derive("multiprocess-candidate-domain", 1).to_string();
  cluster.spec =
      "gen=1;delegated=federation.route.advertise:mutate:exclusive;"
      "retained=domain.mp.control:administer;caps=federation.protocol.v1:1:known";
  cluster.journal = scratch.file("federation-" + tag + ".fedjournal");
  cluster.coordinator_control = g_port_base.fetch_add(3);
  cluster.sponsor_control = cluster.coordinator_control + 1;
  cluster.candidate_control = cluster.coordinator_control + 2;
  return cluster;
}

// Runs the standard multi-party join through the members' own processes, then
// has each member probe the other over the real transport. Without that
// reachability evidence the federation is INDETERMINATE and its members are
// degraded, which is the conservative default rather than a test artefact.
void join_through_processes(const Cluster& cluster) {
  auto proposal = cluster.sponsor_command(
      "propose " + cluster.candidate + " " + cluster.candidate_domain + " 1 0 " + cluster.spec);
  (void)proposal;
  auto acceptance = cluster.candidate_command("accept 0");
  (void)acceptance;
  auto endorsement = cluster.sponsor_command(
      "endorse " + cluster.candidate + " " + cluster.candidate_domain + " 1 0 " + cluster.spec);
  (void)endorsement;
  auto probe = cluster.candidate_command("probe " + cluster.sponsor + " 127.0.0.1 " +
                                         std::to_string(cluster.sponsor_probe));
  (void)probe;
  auto reverse = cluster.sponsor_command("probe " + cluster.candidate + " 127.0.0.1 " +
                                         std::to_string(cluster.candidate_probe));
  (void)reverse;
}

std::string extract_lease_id(const std::string& reply) {
  const std::size_t start = reply.find("lease=");
  if (start == std::string::npos) {
    return std::string();
  }
  const std::size_t end = reply.find(' ', start);
  return reply.substr(start + 6, end == std::string::npos ? std::string::npos : end - start - 6);
}

}  // namespace

FFED_TEST(multiprocess, independent_fabrics_join_and_answer_authority_questions) {
  Scratch scratch;
  Cluster cluster = make_cluster(scratch, "join");
  FFED_REQUIRE(cluster.start_coordinator(true));
  FFED_REQUIRE(cluster.start_members());

  // Multi-party evidence: a member that sponsors, consents to and endorses
  // itself gets nothing.
  FFED_REQUIRE(cluster.candidate_command("propose " + cluster.candidate + " " +
                                         cluster.candidate_domain + " 1 0 " + cluster.spec)
                   .has_value());
  FFED_REQUIRE(cluster.candidate_command("accept 0").has_value());
  auto alone =
      cluster.candidate_command("authority federation.route.advertise mutate -");
  FFED_REQUIRE(alone.has_value());
  FFED_CHECK(alone.value().find("outcome=GRANTED") == std::string::npos);

  join_through_processes(cluster);
  auto state = cluster.coordinator_command("digest");
  FFED_REQUIRE(state.has_value());
  FFED_CHECK(state.value().find("active=2") != std::string::npos);
  FFED_CHECK(state.value().find("partition=CONNECTED") != std::string::npos);

  auto without_lease =
      cluster.candidate_command("authority federation.route.advertise mutate -");
  FFED_REQUIRE(without_lease.has_value());
  FFED_CHECK(without_lease.value().find("outcome=REFUSED") != std::string::npos);

  auto lease =
      cluster.candidate_command("lease federation.route.advertise 0 500");
  FFED_REQUIRE(lease.has_value());
  FFED_REQUIRE(lease.value().rfind("OK", 0) == 0);
  const std::string lease_id = extract_lease_id(lease.value());
  FFED_REQUIRE(!lease_id.empty());
  auto granted = cluster.candidate_command("authority federation.route.advertise mutate " +
                                           lease_id);
  FFED_REQUIRE(granted.has_value());
  FFED_CHECK(granted.value().find("outcome=GRANTED") != std::string::npos);

  auto local = cluster.candidate_command("local domain.mp.control administer");
  FFED_REQUIRE(local.has_value());
  FFED_CHECK(local.value().find("outcome=GRANTED") != std::string::npos);

  // Reachability evidence produced by real connections between the two member
  // processes.
  auto probe = cluster.candidate_command("probe " + cluster.sponsor + " 127.0.0.1 " +
                                         std::to_string(cluster.sponsor_probe));
  FFED_REQUIRE(probe.has_value());
  FFED_CHECK(probe.value().find("REACHABLE") != std::string::npos);
  auto reverse = cluster.sponsor_command("probe " + cluster.candidate + " 127.0.0.1 " +
                                         std::to_string(cluster.candidate_probe));
  FFED_REQUIRE(reverse.has_value());
  FFED_CHECK(reverse.value().find("REACHABLE") != std::string::npos);

  cluster.shutdown();
}

FFED_TEST(multiprocess, a_stale_incarnation_cannot_use_the_authority_it_held) {
  Scratch scratch;
  Cluster cluster = make_cluster(scratch, "incarnation");
  FFED_REQUIRE(cluster.start_coordinator(true));
  FFED_REQUIRE(cluster.start_members());
  join_through_processes(cluster);

  auto lease = cluster.candidate_command("lease federation.route.advertise 0 5000");
  FFED_REQUIRE(lease.has_value());
  const std::string old_lease = extract_lease_id(lease.value());
  FFED_REQUIRE(!old_lease.empty());
  auto granted =
      cluster.candidate_command("authority federation.route.advertise mutate " + old_lease);
  FFED_REQUIRE(granted.has_value());
  FFED_CHECK(granted.value().find("outcome=GRANTED") != std::string::npos);

  // The member process is killed with no chance to shut down cleanly, then
  // restarted with a fresh incarnation.
  const Status killed = cluster.candidate_process.terminate_now();
  FFED_REQUIRE(killed.ok());
  auto exit_code = cluster.candidate_process.wait();
  FFED_REQUIRE(exit_code.has_value());

  ChildProcess restarted;
  std::uint16_t probe = 0;
  FFED_REQUIRE(cluster.start_member(cluster.candidate, cluster.candidate_domain,
                                    cluster.candidate_control, 0, Incarnation(2), true,
                                    restarted, probe));
  cluster.candidate_process = std::move(restarted);
  cluster.candidate_probe = probe;

  // The authority that was bound to incarnation 1 is fenced. The lease records
  // the identity it was issued to, so it cannot be spent by the new run.
  auto stale = cluster.candidate_command("authority federation.route.advertise mutate " +
                                         old_lease);
  FFED_REQUIRE(stale.has_value());
  FFED_CHECK(stale.value().find("outcome=GRANTED") == std::string::npos);

  // The member recovers by presenting new authority for its new incarnation:
  // the federation issues a fresh lease bound to incarnation 2.
  auto renewed = cluster.candidate_command("lease federation.route.advertise 0 5000");
  FFED_REQUIRE(renewed.has_value());
  FFED_REQUIRE(renewed.value().rfind("OK", 0) == 0);
  const std::string new_lease = extract_lease_id(renewed.value());
  FFED_REQUIRE(!new_lease.empty());
  FFED_CHECK(new_lease != old_lease);
  auto fresh =
      cluster.candidate_command("authority federation.route.advertise mutate " + new_lease);
  FFED_REQUIRE(fresh.has_value());
  FFED_CHECK(fresh.value().find("outcome=GRANTED") != std::string::npos);

  cluster.shutdown();
}

FFED_TEST(multiprocess, partition_suspends_global_mutation_and_recovery_is_conservative) {
  Scratch scratch;
  Cluster cluster = make_cluster(scratch, "partition");
  FFED_REQUIRE(cluster.start_coordinator(true));
  FFED_REQUIRE(cluster.start_members());
  join_through_processes(cluster);

  auto lease = cluster.candidate_command("lease federation.route.advertise 0 5000");
  FFED_REQUIRE(lease.has_value());
  const std::string lease_id = extract_lease_id(lease.value());
  FFED_REQUIRE(!lease_id.empty());
  auto healthy =
      cluster.candidate_command("authority federation.route.advertise mutate " + lease_id);
  FFED_REQUIRE(healthy.has_value());
  FFED_CHECK(healthy.value().find("outcome=GRANTED") != std::string::npos);

  // Mutual reachability, observed by the members themselves.
  FFED_REQUIRE(cluster.candidate_command("probe " + cluster.sponsor + " 127.0.0.1 " +
                                         std::to_string(cluster.sponsor_probe))
                   .has_value());
  FFED_REQUIRE(cluster.sponsor_command("probe " + cluster.candidate + " 127.0.0.1 " +
                                       std::to_string(cluster.candidate_probe))
                   .has_value());
  auto connected = cluster.coordinator_command("digest");
  FFED_REQUIRE(connected.has_value());
  FFED_CHECK(connected.value().find("partition=CONNECTED") != std::string::npos);

  // The candidate stops answering probes. This is a real transport-level
  // partition: the sponsor's connection attempt is refused.
  FFED_REQUIRE(cluster.candidate_command("stop-probe-listener").has_value());
  auto refused = cluster.sponsor_command("probe " + cluster.candidate + " 127.0.0.1 " +
                                         std::to_string(cluster.candidate_probe));
  FFED_REQUIRE(refused.has_value());
  FFED_CHECK(refused.value().find("UNREACHABLE") != std::string::npos);
  // The candidate can still reach the sponsor, so the evidence is
  // one-directional and must not count as an edge.
  auto one_way = cluster.candidate_command("probe " + cluster.sponsor + " 127.0.0.1 " +
                                           std::to_string(cluster.sponsor_probe));
  FFED_REQUIRE(one_way.has_value());
  FFED_CHECK(one_way.value().find("REACHABLE") != std::string::npos);

  auto split = cluster.coordinator_command("digest");
  FFED_REQUIRE(split.has_value());
  FFED_CHECK(split.value().find("partition=SPLIT") != std::string::npos);
  // No side keeps global-mutation authority, even though the lease is still
  // inside its lifetime.
  auto during_split =
      cluster.candidate_command("authority federation.route.advertise mutate " + lease_id);
  FFED_REQUIRE(during_split.has_value());
  FFED_CHECK(during_split.value().find("outcome=GRANTED") == std::string::npos);
  auto sponsor_during_split =
      cluster.sponsor_command("authority federation.route.advertise mutate -");
  FFED_REQUIRE(sponsor_during_split.has_value());
  FFED_CHECK(sponsor_during_split.value().find("outcome=GRANTED") == std::string::npos);

  // Recovery: the listener comes back, both members confirm each other, the
  // federation advances to a new epoch.
  FFED_REQUIRE(cluster.candidate_command("start-probe-listener").has_value());
  FFED_REQUIRE(cluster.candidate_command("probe " + cluster.sponsor + " 127.0.0.1 " +
                                         std::to_string(cluster.sponsor_probe))
                   .has_value());
  FFED_REQUIRE(cluster.sponsor_command("probe " + cluster.candidate + " 127.0.0.1 " +
                                       std::to_string(cluster.candidate_probe))
                   .has_value());
  auto recovered_transport = cluster.coordinator_command("digest");
  FFED_REQUIRE(recovered_transport.has_value());
  FFED_CHECK(recovered_transport.value().find("partition=CONNECTED") != std::string::npos);

  FFED_REQUIRE(cluster.coordinator_command("advance-epoch 2 partition recovery").has_value());
  auto reconciling = cluster.coordinator_command("digest");
  FFED_REQUIRE(reconciling.has_value());
  FFED_CHECK(reconciling.value().find("reconciling") != std::string::npos);
  auto still_fenced =
      cluster.candidate_command("authority federation.route.advertise mutate " + lease_id);
  FFED_REQUIRE(still_fenced.has_value());
  FFED_CHECK(still_fenced.value().find("outcome=GRANTED") == std::string::npos);

  // Every active member re-attests, then reconciliation is recorded.
  FFED_REQUIRE(cluster.candidate_command("reattest").has_value());
  FFED_REQUIRE(cluster.sponsor_command("reattest").has_value());
  FFED_REQUIRE(cluster.coordinator_command("reconcile 2").has_value());
  auto healed = cluster.coordinator_command("digest");
  FFED_REQUIRE(healed.has_value());
  FFED_CHECK(healed.value().find("reconciling") == std::string::npos);

  // The pre-partition lease belongs to the previous epoch and stays fenced; a
  // fresh lease is required.
  auto stale =
      cluster.candidate_command("authority federation.route.advertise mutate " + lease_id);
  FFED_REQUIRE(stale.has_value());
  FFED_CHECK(stale.value().find("outcome=GRANTED") == std::string::npos);
  auto renewed = cluster.candidate_command("lease federation.route.advertise 0 5000");
  FFED_REQUIRE(renewed.has_value());
  const std::string fresh_lease = extract_lease_id(renewed.value());
  FFED_REQUIRE(!fresh_lease.empty());
  auto granted =
      cluster.candidate_command("authority federation.route.advertise mutate " + fresh_lease);
  FFED_REQUIRE(granted.has_value());
  FFED_CHECK(granted.value().find("outcome=GRANTED") != std::string::npos);

  cluster.shutdown();
}

FFED_TEST(multiprocess, coordinator_restart_does_not_revive_leases_or_authority) {
  Scratch scratch;
  Cluster cluster = make_cluster(scratch, "restart");
  FFED_REQUIRE(cluster.start_coordinator(true));
  FFED_REQUIRE(cluster.start_members());
  join_through_processes(cluster);

  auto lease = cluster.candidate_command("lease federation.route.advertise 0 5000");
  FFED_REQUIRE(lease.has_value());
  const std::string lease_id = extract_lease_id(lease.value());
  FFED_REQUIRE(!lease_id.empty());
  auto digest_before = cluster.coordinator_command("digest");
  FFED_REQUIRE(digest_before.has_value());

  // The members are stopped, then the coordinator is stopped cleanly. Its
  // durable history stays behind.
  cluster.stop_member(cluster.sponsor_process, cluster.sponsor_control);
  cluster.stop_member(cluster.candidate_process, cluster.candidate_control);
  cluster.stop_coordinator();

  // A fresh coordinator process recovers the same federation from the journal.
  Cluster restarted = make_cluster(scratch, "restart-recovered");
  restarted.journal = cluster.journal;
  FFED_REQUIRE(restarted.start_coordinator(false));
  auto state = restarted.coordinator_command("digest");
  FFED_REQUIRE(state.has_value());
  FFED_CHECK(state.value().find("active=2") != std::string::npos);
  FFED_CHECK(state.value().find("artifacts=") != std::string::npos);

  // The lease survived as evidence but is bound to the previous coordinator
  // incarnation, so it is stale rather than live.
  auto leases = restarted.coordinator_command("state");
  FFED_REQUIRE(leases.has_value());
  FFED_CHECK(leases.value().find("STALE_ISSUER") != std::string::npos);

  // Members reattach and must obtain new authority; the old lease is refused.
  FFED_REQUIRE(restarted.start_members());
  auto stale =
      restarted.candidate_command("authority federation.route.advertise mutate " + lease_id);
  FFED_REQUIRE(stale.has_value());
  FFED_CHECK(stale.value().find("outcome=GRANTED") == std::string::npos);

  restarted.shutdown();
}

FFED_TEST(multiprocess, canonical_state_is_permutation_independent_across_processes) {
  Scratch first_scratch;
  Scratch second_scratch;
  // The same identity and the same evidence, delivered in two different orders
  // by two independent sets of processes.
  Cluster first = make_cluster(first_scratch, "order-a", "permutation");
  Cluster second = make_cluster(second_scratch, "order-b", "permutation");
  FFED_REQUIRE(first.start_coordinator(true));
  FFED_REQUIRE(first.start_members());
  FFED_REQUIRE(second.start_coordinator(true));
  FFED_REQUIRE(second.start_members());

  // The same evidence, delivered in two different orders.
  const std::string proposal_command = "propose " + first.candidate + " " +
                                       first.candidate_domain + " 1 0 " + first.spec;
  const std::string endorse_command = "endorse " + first.candidate + " " +
                                      first.candidate_domain + " 1 0 " + first.spec;
  FFED_REQUIRE(first.sponsor_command(proposal_command).has_value());
  FFED_REQUIRE(first.candidate_command("accept 0").has_value());
  FFED_REQUIRE(first.sponsor_command(endorse_command).has_value());

  FFED_REQUIRE(second.sponsor_command(endorse_command).has_value());
  FFED_REQUIRE(second.candidate_command("accept 0").has_value());
  FFED_REQUIRE(second.sponsor_command(proposal_command).has_value());

  auto first_digest = first.coordinator_command("digest");
  auto second_digest = second.coordinator_command("digest");
  FFED_REQUIRE(first_digest.has_value());
  FFED_REQUIRE(second_digest.has_value());
  const auto digest_of = [](const std::string& line) {
    const std::size_t start = line.find("digest=");
    return start == std::string::npos ? std::string()
                                      : line.substr(start + 7, line.find(' ', start) - start - 7);
  };
  FFED_CHECK_EQ(digest_of(second_digest.value()), digest_of(first_digest.value()));

  first.shutdown();
  second.shutdown();
}

FFED_TEST_MAIN()
