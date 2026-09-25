// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Concurrency and ownership tests. These exercise the documented locking rules:
// no socket write under the state mutex, no thread joined while holding it, no
// lock inversion between the state mutex and the connection registry, and no
// callback into user code under a lock.
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <thread>
#include <vector>

#include "fixture.hpp"
#include "fabric_federation/client.hpp"
#include "fabric_federation/net.hpp"
#include "test_harness.hpp"

using namespace fabric_federation;
using namespace ffed_test;

FFED_TEST(concurrency, concurrent_submissions_lose_nothing) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  constexpr std::size_t kThreads = 8;
  constexpr std::size_t kPerThread = 12;
  std::vector<FixtureMember> members;
  for (std::size_t i = 0; i < kThreads * kPerThread; ++i) {
    members.push_back(make_member("concurrent", i + 1));
  }
  std::vector<std::thread> workers;
  std::atomic<std::size_t> applied{0};
  std::atomic<std::size_t> rejected{0};
  for (std::size_t t = 0; t < kThreads; ++t) {
    workers.emplace_back([&, t] {
      for (std::size_t k = 0; k < kPerThread; ++k) {
        const FixtureMember& candidate = members[t * kPerThread + k];
        for (const Artifact& artifact : {proposal(fixture.federation, candidate, fixture.founder),
                                         acceptance(fixture.federation, candidate),
                                         endorsement(fixture.federation, candidate,
                                                     fixture.founder)}) {
          auto outcome = coordinator.value()->submit_artifact(artifact);
          if (!outcome.has_value()) {
            rejected.fetch_add(1);
            continue;
          }
          if (outcome.value().disposition == SubmissionDisposition::Applied) {
            applied.fetch_add(1);
          }
        }
      }
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }
  FFED_CHECK_EQ(rejected.load(), std::size_t{0});
  FFED_CHECK_EQ(applied.load(), kThreads * kPerThread * 3);
  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());
  std::size_t established = 0;
  for (const MemberState& member : state.value().members) {
    // Established membership. Whether a member is currently activated depends
    // on reachability evidence, which this scenario deliberately does not
    // provide.
    if (member.lifecycle != MemberLifecycleState::Proposed &&
        member.lifecycle != MemberLifecycleState::Absent) {
      ++established;
    }
  }
  // Every submitted member plus the bootstrap founder.
  FFED_CHECK_EQ(established, kThreads * kPerThread + 1);
}

FFED_TEST(concurrency, concurrent_authority_questions_commit_exactly_once) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  const FixtureMember candidate = make_member("concurrent-authority", 1);
  FFED_REQUIRE(join_member(*coordinator.value(), fixture.federation, candidate,
                           fixture.founder) == 3);
  auto state = coordinator.value()->state();
  FFED_REQUIRE(state.has_value());

  constexpr std::size_t kThreads = 8;
  constexpr std::size_t kPerThread = 25;
  std::atomic<std::size_t> granted{0};
  std::atomic<std::size_t> unexpected{0};
  std::vector<std::thread> workers;
  for (std::size_t t = 0; t < kThreads; ++t) {
    workers.emplace_back([&, t] {
      for (std::size_t k = 0; k < kPerThread; ++k) {
        AuthorityRequest request;
        request.id = RequestId::derive("concurrent-authority", t * kPerThread + k);
        request.federation = fixture.federation;
        request.epoch_seen = state.value().epoch;
        request.actor = candidate.identity();
        request.requested = ScopeGrant{ScopeId::parse("federation.route.observe").value(),
                                       AuthorityVerb::Observe};
        auto decision = coordinator.value()->evaluate(request);
        if (!decision.has_value()) {
          unexpected.fetch_add(1);
          continue;
        }
        if (decision.value().outcome == Outcome::Granted) {
          granted.fetch_add(1);
        } else if (decision.value().outcome != Outcome::Replayed) {
          unexpected.fetch_add(1);
        }
      }
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }
  FFED_CHECK_EQ(unexpected.load(), std::size_t{0});
  FFED_CHECK_EQ(granted.load(), kThreads * kPerThread);
  FFED_CHECK_EQ(coordinator.value()->stats().replay_entries,
                static_cast<std::uint64_t>(kThreads * kPerThread));
}

FFED_TEST(concurrency, readers_observe_consistent_states_while_writing) {
  const FederationFixture fixture;
  auto coordinator = make_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  std::atomic<bool> stop{false};
  std::atomic<std::size_t> reads{0};
  std::atomic<std::size_t> zero_digests{0};
  std::vector<std::thread> readers;
  for (int i = 0; i < 4; ++i) {
    readers.emplace_back([&] {
      while (!stop.load()) {
        auto state = coordinator.value()->state();
        if (!state.has_value()) {
          zero_digests.fetch_add(1);
          continue;
        }
        if (state.value().digest().is_zero()) {
          zero_digests.fetch_add(1);
        }
        reads.fetch_add(1);
      }
    });
  }
  for (std::uint64_t i = 0; i < 40; ++i) {
    const FixtureMember candidate = make_member("reader-writer", i + 1);
    join_member(*coordinator.value(), fixture.federation, candidate, fixture.founder);
  }
  stop.store(true);
  for (std::thread& reader : readers) {
    reader.join();
  }
  FFED_CHECK(reads.load() > 0);
  FFED_CHECK_EQ(zero_digests.load(), std::size_t{0});
}

namespace {

Result<std::unique_ptr<FederationCoordinator>> make_listening_coordinator(
    const FederationFixture& fixture, const std::filesystem::path& journal = {}) {
  CoordinatorConfig config;
  config.federation = fixture.federation;
  config.node = fixture.coordinator_node;
  config.policy = fixture.policy;
  config.bootstrap = true;
  config.founder = fixture.founder.declaration;
  config.listen = true;
  config.listen_port = 0;
  if (!journal.empty()) {
    config.journal_path = journal;
  }
  return FederationCoordinator::create(config);
}

}  // namespace

FFED_TEST(concurrency, repeated_start_and_stop_is_stable) {
  const FederationFixture fixture;
  auto coordinator = make_listening_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  for (int cycle = 0; cycle < 20; ++cycle) {
    FFED_REQUIRE(coordinator.value()->start().ok());
    FFED_CHECK(coordinator.value()->running());
    const std::uint16_t port = coordinator.value()->listen_port();
    FFED_CHECK(port != 0);
    // Starting an already-running coordinator is refused, not ignored.
    FFED_CHECK_EQ(coordinator.value()->start().code(), ErrorCode::AlreadyExists);
    // A client can connect, exchange and disconnect while the server runs.
    auto client = CoordinatorClient::connect(
        Endpoint{"127.0.0.1", port}, fixture.federation,
        NodeId::derive("cycle-client", static_cast<std::uint64_t>(cycle)), Incarnation(1));
    FFED_REQUIRE(client.has_value());
    FFED_REQUIRE(client.value().ping().ok());
    FFED_REQUIRE(client.value().close().ok());
    FFED_REQUIRE(coordinator.value()->stop().ok());
    FFED_CHECK(!coordinator.value()->running());
    // The listener is really closed: a fresh connection attempt fails.
    auto after = Socket::connect(Endpoint{"127.0.0.1", port});
    FFED_CHECK(!after.has_value());
  }
}

FFED_TEST(concurrency, stopping_closes_live_connections_without_hanging) {
  const FederationFixture fixture;
  auto coordinator = make_listening_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  FFED_REQUIRE(coordinator.value()->start().ok());
  const std::uint16_t port = coordinator.value()->listen_port();
  constexpr std::size_t kClients = 6;
  std::vector<std::thread> clients;
  std::atomic<std::size_t> refused{0};
  std::atomic<std::size_t> served{0};
  std::atomic<std::size_t> finished{0};
  std::mutex gate_mutex;
  std::condition_variable gate;
  for (std::size_t i = 0; i < kClients; ++i) {
    clients.emplace_back([&, i] {
      const auto finish = [&] {
        finished.fetch_add(1);
        gate.notify_all();
      };
      auto client = CoordinatorClient::connect(Endpoint{"127.0.0.1", port}, fixture.federation,
                                               NodeId::derive("stop-client", i), Incarnation(1));
      if (!client.has_value()) {
        refused.fetch_add(1);
        finish();
        return;
      }
      for (int k = 0; k < 200; ++k) {
        auto digest = client.value().query_digest();
        if (!digest.has_value()) {
          refused.fetch_add(1);
          break;
        }
        served.fetch_add(1);
        gate.notify_all();
      }
      const Status closed = client.value().close();
      (void)closed;
      finish();
    });
  }
  // Wait until at least one client has actually completed a query, so the
  // coordinator is stopped while the connections are genuinely mid-conversation.
  // A fixed sleep would be a guess; this is a fact. The wait also ends when
  // every client has finished, so a client that cannot be served reports a
  // failure through the assertion below instead of hanging the suite.
  {
    std::unique_lock<std::mutex> lock(gate_mutex);
    gate.wait(lock, [&] {
      return served.load() > 0 || finished.load() == kClients;
    });
  }
  FFED_REQUIRE(coordinator.value()->stop().ok());
  for (std::thread& client : clients) {
    client.join();
  }
  FFED_CHECK(served.load() > 0);
  FFED_CHECK(!coordinator.value()->running());
}

FFED_TEST(concurrency, concurrent_clients_each_get_a_welcome) {
  const FederationFixture fixture;
  auto coordinator = make_listening_coordinator(fixture);
  FFED_REQUIRE(coordinator.has_value());
  FFED_REQUIRE(coordinator.value()->start().ok());
  const std::uint16_t port = coordinator.value()->listen_port();
  constexpr std::size_t kClients = 12;
  std::atomic<std::size_t> welcomed{0};
  std::vector<std::thread> clients;
  for (std::size_t i = 0; i < kClients; ++i) {
    clients.emplace_back([&, i] {
      auto client = CoordinatorClient::connect(Endpoint{"127.0.0.1", port}, fixture.federation,
                                               NodeId::derive("welcome-client", i), Incarnation(1));
      if (!client.has_value()) {
        return;
      }
      if (client.value().welcome().federation == fixture.federation) {
        welcomed.fetch_add(1);
      }
      const Status closed = client.value().close();
      (void)closed;
    });
  }
  for (std::thread& client : clients) {
    client.join();
  }
  FFED_CHECK_EQ(welcomed.load(), kClients);
  FFED_CHECK_EQ(coordinator.value()->stats().protocol_errors, std::uint64_t{0});
  FFED_REQUIRE(coordinator.value()->stop().ok());
}

FFED_TEST_MAIN()
