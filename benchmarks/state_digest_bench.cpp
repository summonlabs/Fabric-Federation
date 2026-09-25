// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Measures full state derivation plus canonical digest for federations of
// increasing size. Derivation is a full recomputation by design, so this number
// is the honest cost of the determinism guarantee.
#include <memory>
#include <vector>

#include "bench_common.hpp"
#include "fabric_federation/coordinator.hpp"
#include "fixture.hpp"

using namespace fabric_federation;
using namespace ffed::bench;
using namespace ffed_test;

int main() {
  std::printf("fabric-federation state derivation + canonical digest\n");
  for (std::uint64_t members : {1u, 4u, 16u, 64u, 128u}) {
    FederationFixture fixture;
    const MemberSpec sponsor_spec;
    FixtureMember sponsor = make_member("bench", 0, sponsor_spec);
    CoordinatorConfig config;
    config.federation = fixture.federation;
    config.node = fixture.coordinator_node;
    config.policy = fixture.policy;
    config.bootstrap = true;
    config.founder = sponsor.declaration;
    auto coordinator = FederationCoordinator::create(config).value();

    for (std::uint64_t i = 0; i < members; ++i) {
      const FixtureMember candidate = make_member("bench", i + 1);
      join_member(*coordinator, fixture.federation, candidate, sponsor);
    }
    const auto state = coordinator->state();
    if (!state.has_value()) {
      std::fprintf(stderr, "state derivation failed\n");
      return 1;
    }
    constexpr unsigned long long kIterations = 20;
    Timer timer;
    for (unsigned long long i = 0; i < kIterations; ++i) {
      const Digest digest = coordinator->state_digest();
      if (digest.is_zero()) {
        std::fprintf(stderr, "digest computation failed\n");
        return 1;
      }
    }
    report("derive+digest members=" + std::to_string(members) + " artifacts=" +
               std::to_string(state.value().artifact_count),
           kIterations, timer.milliseconds());
    const Status stopped = coordinator->stop();
    if (!stopped.ok()) {
      std::fprintf(stderr, "stop failed: %s\n", stopped.to_string().c_str());
      return 1;
    }
  }
  return 0;
}
