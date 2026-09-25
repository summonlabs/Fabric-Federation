#include <cstdio>
#include "fixture.hpp"
#include "fabric_federation/coordinator.hpp"
using namespace fabric_federation;
using namespace ffed_test;
int main() {
  const FederationFixture fixture;
  CoordinatorConfig config;
  config.federation = fixture.federation;
  config.node = fixture.coordinator_node;
  config.policy = fixture.policy;
  config.bootstrap = true;
  config.founder = fixture.founder.declaration;
  auto created = FederationCoordinator::create(config);
  if (!created.has_value()) {
    std::printf("create failed: %s\n", created.status().to_string().c_str());
    return 1;
  }
  auto state = created.value()->state();
  if (!state.has_value()) {
    std::printf("derive failed: %s\n", state.status().to_string().c_str());
    return 1;
  }
  std::printf("members=%zu active=%zu digest=%s\n", state.value().member_count(),
              state.value().active_member_count(), state.value().digest_hex().c_str());
  for (const MemberState& m : state.value().members) {
    std::printf("  %s %s boot=%d fa=%zu\n", m.member.to_string().c_str(),
                std::string(to_string(m.lifecycle)).c_str(), m.bootstrap ? 1 : 0,
                m.federation_authority.size());
    for (const Reason& r : m.reasons) std::printf("      %s\n", r.to_string().c_str());
  }
  return 0;
}
