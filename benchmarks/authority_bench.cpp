// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Measures authority evaluation, including the first-time path that commits a
// decision to the replay ledger and the replay-fenced path.
#include <memory>

#include "bench_common.hpp"
#include "fabric_federation/coordinator.hpp"
#include "fixture.hpp"

using namespace ffed_test;

using namespace fabric_federation;
using namespace ffed::bench;
using namespace ffed_test;

int main() {
  std::printf("fabric-federation authority evaluation\n");
  FederationFixture fixture;
  const FixtureMember sponsor = make_member("bench-authority", 0);
  auto coordinator = make_coordinator(fixture).value();
  const FixtureMember candidate = make_member("bench-authority", 1);
  join_member(*coordinator, fixture.federation, candidate, sponsor);

  const ScopeGrant grant{ScopeId::parse("federation.route.advertise").value(),
                         AuthorityVerb::Mutate};
  constexpr unsigned long long kIterations = 20000;
  {
    Timer timer;
    for (unsigned long long i = 0; i < kIterations; ++i) {
      AuthorityRequest request;
      request.id = RequestId::derive("bench", i);
      request.federation = fixture.federation;
      request.epoch_seen = coordinator->epoch();
      request.actor = candidate.identity();
      request.requested = grant;
      auto decision = coordinator->evaluate(request);
      if (!decision.has_value()) {
        std::fprintf(stderr, "evaluation failed\n");
        return 1;
      }
    }
    report("evaluate (first time, commits to the ledger)", kIterations, timer.milliseconds());
  }
  {
    Timer timer;
    AuthorityRequest request;
    request.id = RequestId::derive("bench", 0);
    request.federation = fixture.federation;
    request.epoch_seen = coordinator->epoch();
    request.actor = candidate.identity();
    request.requested = grant;
    for (unsigned long long i = 0; i < kIterations; ++i) {
      auto decision = coordinator->evaluate(request);
      if (!decision.has_value() || decision.value().outcome != Outcome::Replayed) {
        std::fprintf(stderr, "the replay fence did not answer REPLAYED\n");
        return 1;
      }
    }
    report("evaluate (replayed identifier, fenced)", kIterations, timer.milliseconds());
  }
  const Status stopped = coordinator->stop();
  if (!stopped.ok()) {
    std::fprintf(stderr, "stop failed: %s\n", stopped.to_string().c_str());
    return 1;
  }
  return 0;
}
