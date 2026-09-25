// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/member_runtime.hpp"

#include <atomic>
#include <thread>

#include "fabric_federation/protocol.hpp"
#include "fabric_federation/version.hpp"

namespace fabric_federation {
namespace {

Digest digest_of(const std::function<Status(Writer&)>& fill) {
  Writer writer;
  if (!fill(writer).ok()) {
    return Digest();
  }
  return writer.sha256();
}

EvidenceId evidence_id_from(const FederationId& federation, const MemberId& member,
                            ArtifactKind kind, const Digest& body_digest) {
  const Digest digest = digest_of([&](Writer& writer) {
    Status status = writer.id16(federation.bytes());
    if (!status.ok()) {
      return status;
    }
    status = writer.id16(member.bytes());
    if (!status.ok()) {
      return status;
    }
    status = writer.u16(static_cast<std::uint16_t>(kind));
    if (!status.ok()) {
      return status;
    }
    return writer.digest(body_digest);
  });
  std::array<std::uint8_t, 16> bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = digest.bytes()[i];
  }
  return EvidenceId::from_bytes(bytes);
}

}  // namespace

struct MemberFabricRuntime::Impl {
  MemberConfig config;
  ScopeCatalog catalog;
  CoordinatorClient client;
  bool attached = false;
  Tick tick;
  // The epoch the coordinator last reported. Every artefact this member issues
  // is stamped with it, so a stale cache would attach stale epochs to fresh
  // evidence. mark_stale() invalidates it; refresh() renews it.
  Epoch epoch{1};
  bool clock_current = false;

  Listener probe_listener;
  std::thread probe_thread;
  std::atomic<bool> probe_stopping{false};
  bool probe_open = false;
};

MemberFabricRuntime::MemberFabricRuntime() : impl_(new Impl()) {}

MemberFabricRuntime::~MemberFabricRuntime() {
  stop_probe_thread();
  const Status status = detach();
  (void)status;
}

Result<std::unique_ptr<MemberFabricRuntime>> MemberFabricRuntime::create(
    const MemberConfig& config) {
  if (config.federation.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument, "a member requires a federation identity");
  }
  if (config.node.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument, "a member requires a node identity");
  }
  if (config.constitution.member.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument, "a member requires a member identity");
  }
  const Status validation =
      validate_constitution(config.constitution, ScopeCatalog::builtin());
  if (!validation.ok()) {
    return Status::make(ErrorCode::InvalidArgument,
                        "the member constitution is not valid: " + validation.to_string());
  }
  std::unique_ptr<MemberFabricRuntime> runtime(new MemberFabricRuntime());
  runtime->impl_->config = config;
  runtime->impl_->catalog = ScopeCatalog::builtin();
  runtime->impl_->tick = config.initial_tick;
  return runtime;
}

namespace {

// Refreshes the member's cached clock and epoch from the coordinator. Called
// before every artefact is built so that evidence never carries a stale epoch.
Status refresh_clock(CoordinatorClient& client, Tick& tick, Epoch& epoch, bool& current) {
  auto digest = client.query_digest();
  if (!digest.has_value()) {
    current = false;
    return digest.status();
  }
  tick = digest.value().logical_time;
  epoch = digest.value().epoch;
  current = true;
  return Status::success();
}

}  // namespace

Status MemberFabricRuntime::attach() {
  Impl& impl = *impl_;
  if (impl.attached) {
    return Status::success();
  }
  auto client = CoordinatorClient::connect(impl.config.coordinator, impl.config.federation,
                                           impl.config.node, impl.config.incarnation);
  if (!client.has_value()) {
    return client.status();
  }
  impl.client = std::move(client.value());
  impl.attached = true;
  impl.tick = impl.client.welcome().logical_time;
  impl.epoch = impl.epoch;
  const Status refreshed = refresh_clock(impl.client, impl.tick, impl.epoch, impl.clock_current);
  if (!refreshed.ok()) {
    return refreshed;
  }
  if (impl.config.listen_for_probes && !impl.probe_open) {
    return start_probe_listener();
  }
  return Status::success();
}

Status MemberFabricRuntime::detach() {
  Impl& impl = *impl_;
  if (!impl.attached) {
    return Status::success();
  }
  impl.attached = false;
  return impl.client.close();
}

bool MemberFabricRuntime::attached() const noexcept { return impl_->attached; }

const MemberConstitution& MemberFabricRuntime::constitution() const noexcept {
  return impl_->config.constitution;
}

MemberIdentity MemberFabricRuntime::identity() const {
  const Impl& impl = *impl_;
  MemberDeclaration declaration;
  declaration.constitution = impl.config.constitution;
  declaration.incarnation = impl.config.incarnation;
  declaration.node = impl.config.node;
  declaration.declared_at = impl.tick;
  return declaration.identity();
}

const Endpoint& MemberFabricRuntime::coordinator_endpoint() const noexcept {
  return impl_->config.coordinator;
}

std::uint16_t MemberFabricRuntime::probe_port() const noexcept { return impl_->probe_listener.port(); }

Incarnation MemberFabricRuntime::incarnation() const noexcept { return impl_->config.incarnation; }

namespace {

ArtifactEnvelope make_envelope(const MemberConfig& config, Tick tick, ArtifactKind kind,
                               const MemberId& subject) {
  ArtifactEnvelope envelope;
  envelope.kind = kind;
  envelope.federation = config.federation;
  envelope.subject = subject;
  envelope.issuer.node = config.node;
  envelope.issuer.member = config.constitution.member;
  envelope.issuer.generation = config.constitution.generation;
  envelope.issuer.incarnation = config.incarnation;
  envelope.issuer.constitution = config.constitution.digest();
  envelope.issuer.issued_at = tick;
  return envelope;
}

MemberDeclaration make_declaration(const MemberConfig& config, Tick tick) {
  MemberDeclaration declaration;
  declaration.constitution = config.constitution;
  declaration.incarnation = config.incarnation;
  declaration.node = config.node;
  declaration.declared_at = tick;
  return declaration;
}

}  // namespace

Result<Artifact> MemberFabricRuntime::build_proposal(const MemberDeclaration& candidate,
                                                     Lineage lineage) const {
  const Impl& impl = *impl_;
  ArtifactBody body;
  body.declaration = candidate;
  body.declared_identity = candidate.identity();
  body.lineage = lineage;
  body.epoch = impl.epoch;
  body.logical_time = Tick();
  ArtifactEnvelope envelope = make_envelope(impl.config, impl.tick, ArtifactKind::MembershipProposal,
                                            candidate.constitution.member);
  envelope.issuer.epoch = impl.epoch;
  Artifact artifact = Artifact::make(std::move(envelope), std::move(body));
  artifact.envelope.evidence =
      evidence_id_from(impl.config.federation, impl.config.constitution.member,
                       ArtifactKind::MembershipProposal, artifact.body.digest());
  return artifact;
}

Result<Artifact> MemberFabricRuntime::build_acceptance(Lineage lineage) const {
  const Impl& impl = *impl_;
  ArtifactBody body;
  body.declaration = make_declaration(impl.config, impl.tick);
  body.declared_identity = body.declaration.identity();
  body.lineage = lineage;
  body.epoch = impl.epoch;
  ArtifactEnvelope envelope = make_envelope(impl.config, impl.tick,
                                            ArtifactKind::MembershipAcceptance,
                                            impl.config.constitution.member);
  envelope.issuer.epoch = impl.epoch;
  Artifact artifact = Artifact::make(std::move(envelope), std::move(body));
  artifact.envelope.evidence =
      evidence_id_from(impl.config.federation, impl.config.constitution.member,
                       ArtifactKind::MembershipAcceptance, artifact.body.digest());
  return artifact;
}

Result<Artifact> MemberFabricRuntime::build_endorsement(const MemberDeclaration& candidate,
                                                        Lineage lineage) const {
  const Impl& impl = *impl_;
  ArtifactBody body;
  body.declaration = candidate;
  body.declared_identity = candidate.identity();
  body.lineage = lineage;
  body.epoch = impl.epoch;
  ArtifactEnvelope envelope = make_envelope(impl.config, impl.tick,
                                            ArtifactKind::MembershipEndorsement,
                                            candidate.constitution.member);
  envelope.issuer.epoch = impl.epoch;
  Artifact artifact = Artifact::make(std::move(envelope), std::move(body));
  artifact.envelope.evidence = evidence_id_from(
      impl.config.federation, impl.config.constitution.member,
      ArtifactKind::MembershipEndorsement, artifact.body.digest());
  return artifact;
}

Result<Artifact> MemberFabricRuntime::build_reattestation() const {
  const Impl& impl = *impl_;
  ArtifactBody body;
  body.declaration = make_declaration(impl.config, impl.tick);
  body.declared_identity = body.declaration.identity();
  body.epoch = impl.epoch;
  ArtifactEnvelope envelope = make_envelope(impl.config, impl.tick,
                                            ArtifactKind::MemberReattestation,
                                            impl.config.constitution.member);
  envelope.issuer.epoch = impl.epoch;
  Artifact artifact = Artifact::make(std::move(envelope), std::move(body));
  artifact.envelope.evidence = evidence_id_from(
      impl.config.federation, impl.config.constitution.member, ArtifactKind::MemberReattestation,
      artifact.body.digest());
  return artifact;
}

Result<Artifact> MemberFabricRuntime::build_delegation_declaration(
    const std::vector<DelegationTerms>& terms) const {
  const Impl& impl = *impl_;
  MemberConstitution updated = impl.config.constitution;
  updated.delegated = terms;
  const Status validation = validate_constitution(updated, ScopeCatalog::builtin());
  if (!validation.ok()) {
    return Status::make(ErrorCode::InvalidArgument,
                        "the delegation declaration is not valid: " + validation.to_string());
  }
  ArtifactBody body;
  body.declaration = make_declaration(impl.config, impl.tick);
  body.declaration.constitution = updated;
  body.declared_identity = body.declaration.identity();
  body.delegated_terms = terms;
  body.epoch = impl.epoch;
  ArtifactEnvelope envelope = make_envelope(impl.config, impl.tick,
                                            ArtifactKind::DelegationDeclaration,
                                            impl.config.constitution.member);
  envelope.issuer.epoch = impl.epoch;
  Artifact artifact = Artifact::make(std::move(envelope), std::move(body));
  artifact.envelope.evidence = evidence_id_from(
      impl.config.federation, impl.config.constitution.member,
      ArtifactKind::DelegationDeclaration, artifact.body.digest());
  return artifact;
}

Result<Artifact> MemberFabricRuntime::build_withdrawal(const std::vector<ScopeGrant>& grants,
                                                       Lineage lineage) const {
  const Impl& impl = *impl_;
  if (grants.empty()) {
    return Status::make(ErrorCode::InvalidArgument, "a withdrawal must name at least one grant");
  }
  ArtifactBody body;
  body.declared_identity = identity();
  body.withdrawn_grants = grants;
  canonicalize_grants(body.withdrawn_grants);
  body.lineage = lineage;
  body.epoch = impl.epoch;
  ArtifactEnvelope envelope = make_envelope(impl.config, impl.tick,
                                            ArtifactKind::DelegationWithdrawal,
                                            impl.config.constitution.member);
  envelope.issuer.epoch = impl.epoch;
  Artifact artifact = Artifact::make(std::move(envelope), std::move(body));
  artifact.envelope.evidence = evidence_id_from(
      impl.config.federation, impl.config.constitution.member, ArtifactKind::DelegationWithdrawal,
      artifact.body.digest());
  return artifact;
}

Result<Artifact> MemberFabricRuntime::build_leave(Lineage lineage, ReasonCode reason,
                                                  std::string_view detail) const {
  const Impl& impl = *impl_;
  ArtifactBody body;
  body.declared_identity = identity();
  body.lineage = lineage;
  body.epoch = impl.epoch;
  body.reason_code = reason;
  body.reason_text = std::string(detail);
  body.outcome = Outcome::Refused;
  ArtifactEnvelope envelope = make_envelope(impl.config, impl.tick, ArtifactKind::MembershipLeave,
                                            impl.config.constitution.member);
  envelope.issuer.epoch = impl.epoch;
  Artifact artifact = Artifact::make(std::move(envelope), std::move(body));
  artifact.envelope.evidence = evidence_id_from(
      impl.config.federation, impl.config.constitution.member, ArtifactKind::MembershipLeave,
      artifact.body.digest());
  return artifact;
}

Result<Artifact> MemberFabricRuntime::build_self_fence(Lineage lineage, ReasonCode reason,
                                                       std::string_view detail) const {
  const Impl& impl = *impl_;
  ArtifactBody body;
  body.declared_identity = identity();
  body.lineage = lineage;
  body.epoch = impl.epoch;
  body.fence_reason = reason;
  body.reason_code = reason;
  body.reason_text = std::string(detail);
  body.outcome = Outcome::Fenced;
  ArtifactEnvelope envelope = make_envelope(impl.config, impl.tick, ArtifactKind::MembershipFence,
                                            impl.config.constitution.member);
  envelope.issuer.epoch = impl.epoch;
  Artifact artifact = Artifact::make(std::move(envelope), std::move(body));
  artifact.envelope.evidence = evidence_id_from(
      impl.config.federation, impl.config.constitution.member, ArtifactKind::MembershipFence,
      artifact.body.digest());
  return artifact;
}

Result<ArtifactResponse> MemberFabricRuntime::submit(const Artifact& artifact) {
  Impl& impl = *impl_;
  if (!impl.attached) {
    return Status::make(ErrorCode::NotInitialized, "the member is not attached to a coordinator");
  }
  if (!impl.clock_current) {
    return Status::make(ErrorCode::Stale,
                        "the member's cached epoch is not current; refresh before issuing "
                        "evidence");
  }
  auto response = impl.client.submit(artifact);
  if (response.has_value()) {
    const Status after = refresh_clock(impl.client, impl.tick, impl.epoch, impl.clock_current);
    (void)after;
  }
  return response;
}

Result<ArtifactResponse> MemberFabricRuntime::propose(const MemberDeclaration& candidate,
                                                      Lineage lineage) {
  Impl& impl = *impl_;
  if (impl.attached) {
    const Status refreshed = refresh_clock(impl.client, impl.tick, impl.epoch, impl.clock_current);
    if (!refreshed.ok()) {
      return refreshed;
    }
  }
  auto artifact = build_proposal(candidate, lineage);
  if (!artifact.has_value()) {
    return artifact.status();
  }
  return submit(artifact.value());
}

Result<ArtifactResponse> MemberFabricRuntime::accept(Lineage lineage) {
  Impl& impl = *impl_;
  if (impl.attached) {
    const Status refreshed = refresh_clock(impl.client, impl.tick, impl.epoch, impl.clock_current);
    if (!refreshed.ok()) {
      return refreshed;
    }
  }
  auto artifact = build_acceptance(lineage);
  if (!artifact.has_value()) {
    return artifact.status();
  }
  return submit(artifact.value());
}

Result<ArtifactResponse> MemberFabricRuntime::endorse(const MemberDeclaration& candidate,
                                                      Lineage lineage) {
  Impl& impl = *impl_;
  if (impl.attached) {
    const Status refreshed = refresh_clock(impl.client, impl.tick, impl.epoch, impl.clock_current);
    if (!refreshed.ok()) {
      return refreshed;
    }
  }
  auto artifact = build_endorsement(candidate, lineage);
  if (!artifact.has_value()) {
    return artifact.status();
  }
  return submit(artifact.value());
}

Result<ArtifactResponse> MemberFabricRuntime::reattest() {
  Impl& impl = *impl_;
  if (impl.attached) {
    const Status refreshed = refresh_clock(impl.client, impl.tick, impl.epoch, impl.clock_current);
    if (!refreshed.ok()) {
      return refreshed;
    }
  }
  auto artifact = build_reattestation();
  if (!artifact.has_value()) {
    return artifact.status();
  }
  return submit(artifact.value());
}

Result<ArtifactResponse> MemberFabricRuntime::declare_delegation(
    const std::vector<DelegationTerms>& terms) {
  Impl& impl = *impl_;
  if (impl.attached) {
    const Status refreshed = refresh_clock(impl.client, impl.tick, impl.epoch, impl.clock_current);
    if (!refreshed.ok()) {
      return refreshed;
    }
  }
  auto artifact = build_delegation_declaration(terms);
  if (!artifact.has_value()) {
    return artifact.status();
  }
  return submit(artifact.value());
}

Result<ArtifactResponse> MemberFabricRuntime::withdraw(const std::vector<ScopeGrant>& grants,
                                                       Lineage lineage) {
  Impl& impl = *impl_;
  if (impl.attached) {
    const Status refreshed = refresh_clock(impl.client, impl.tick, impl.epoch, impl.clock_current);
    if (!refreshed.ok()) {
      return refreshed;
    }
  }
  auto artifact = build_withdrawal(grants, lineage);
  if (!artifact.has_value()) {
    return artifact.status();
  }
  return submit(artifact.value());
}

Result<ArtifactResponse> MemberFabricRuntime::leave(Lineage lineage) {
  Impl& impl = *impl_;
  if (impl.attached) {
    const Status refreshed = refresh_clock(impl.client, impl.tick, impl.epoch, impl.clock_current);
    if (!refreshed.ok()) {
      return refreshed;
    }
  }
  auto artifact = build_leave(lineage, ReasonCode::MembershipLeaving,
                              "the member left the federation; its local authority is untouched");
  if (!artifact.has_value()) {
    return artifact.status();
  }
  return submit(artifact.value());
}

Result<ArtifactResponse> MemberFabricRuntime::self_fence(Lineage lineage, ReasonCode reason,
                                                         std::string_view detail) {
  Impl& impl = *impl_;
  if (impl.attached) {
    const Status refreshed = refresh_clock(impl.client, impl.tick, impl.epoch, impl.clock_current);
    if (!refreshed.ok()) {
      return refreshed;
    }
  }
  auto artifact = build_self_fence(lineage, reason, detail);
  if (!artifact.has_value()) {
    return artifact.status();
  }
  return submit(artifact.value());
}

Result<ArtifactResponse> MemberFabricRuntime::restart_with_new_incarnation(
    Incarnation new_incarnation) {
  Impl& impl = *impl_;
  if (!(impl.config.incarnation < new_incarnation)) {
    return Status::make(ErrorCode::InvalidArgument,
                        "a restart must use a strictly greater incarnation");
  }
  impl.config.incarnation = new_incarnation;
  auto artifact = build_reattestation();
  if (!artifact.has_value()) {
    return artifact.status();
  }
  return submit(artifact.value());
}

AuthorityDecision MemberFabricRuntime::evaluate_local(const ScopeGrant& grant) const {
  const Impl& impl = *impl_;
  return evaluate_local_authority(impl.config.constitution, grant, impl.tick);
}

Result<AuthorityDecision> MemberFabricRuntime::request_authority(const ScopeGrant& grant,
                                                                LeaseId lease) {
  Impl& impl = *impl_;
  if (!impl.attached) {
    return Status::make(ErrorCode::NotInitialized, "the member is not attached to a coordinator");
  }
  auto digest = impl.client.query_digest();
  if (!digest.has_value()) {
    return digest.status();
  }
  impl.tick = digest.value().logical_time;
  AuthorityRequest request;
  request.id = RequestId::random();
  request.federation = impl.config.federation;
  request.epoch_seen = digest.value().epoch;
  request.actor = identity();
  request.requested = grant;
  request.lease = lease;
  request.issued_at = impl.tick;
  auto decision = impl.client.query_authority(request);
  if (decision.has_value()) {
    auto after = impl.client.query_digest();
    if (after.has_value()) {
      impl.tick = after.value().logical_time;
    }
  }
  return decision;
}

Result<DigestResponse> MemberFabricRuntime::coordinator_digest() {
  Impl& impl = *impl_;
  if (!impl.attached) {
    return Status::make(ErrorCode::NotInitialized, "the member is not attached to a coordinator");
  }
  auto digest = impl.client.query_digest();
  if (digest.has_value()) {
    impl.tick = digest.value().logical_time;
  }
  return digest;
}

Result<MemberStatus> MemberFabricRuntime::status() {
  Impl& impl = *impl_;
  if (!impl.attached) {
    return Status::make(ErrorCode::NotInitialized, "the member is not attached to a coordinator");
  }
  auto response = impl.client.query_state();
  if (!response.has_value()) {
    return response.status();
  }
  MemberStatus status;
  status.federation_state_digest = response.value().state_digest;
  const auto found = response.value().json.find(impl.config.constitution.member.to_string());
  if (found == std::string::npos) {
    status.lifecycle = MemberLifecycleState::Absent;
  }
  status.identity = identity();
  status.local_authority = impl.config.constitution.retained;
  auto digest = impl.client.query_digest();
  if (digest.has_value()) {
    status.epoch = digest.value().epoch;
    status.logical_time = digest.value().logical_time;
    impl.tick = digest.value().logical_time;
  }
  return status;
}

Result<AuthorityLease> MemberFabricRuntime::request_lease(const std::vector<ScopeGrant>& scopes,
                                                          Epoch not_after_epoch,
                                                          Tick lifetime_ticks) {
  Impl& impl = *impl_;
  if (!impl.attached) {
    return Status::make(ErrorCode::NotInitialized, "the member is not attached to a coordinator");
  }
  LeaseIssueRequest request;
  request.holder = impl.config.constitution.member;
  request.scopes = scopes;
  request.not_after_epoch = not_after_epoch;
  request.lifetime_ticks = lifetime_ticks;
  return impl.client.issue_lease(request);
}

MemberObservation MemberFabricRuntime::probe_peers(const std::vector<PeerTarget>& peers) {
  Impl& impl = *impl_;
  if (impl.attached) {
    const Status refreshed =
        refresh_clock(impl.client, impl.tick, impl.epoch, impl.clock_current);
    if (!refreshed.ok()) {
      impl.clock_current = false;
    }
  }
  MemberObservation observation;
  observation.observer = impl.config.constitution.member;
  observation.observer_incarnation = impl.config.incarnation;
  observation.recorded_at = impl.tick;
  if (impl.attached) {
    observation.epoch = impl.epoch;
  }
  for (const PeerTarget& target : peers) {
    PeerObservation entry;
    entry.peer = target.member;
    entry.observed_at = impl.tick;
    auto socket = Socket::connect(target.endpoint);
    if (!socket.has_value()) {
      entry.state = ReachabilityState::Unreachable;
      entry.detail = socket.status().message();
      observation.peers.push_back(std::move(entry));
      continue;
    }
    HelloRequest hello;
    hello.federation = impl.config.federation;
    hello.node = impl.config.node;
    hello.incarnation = impl.config.incarnation;
    hello.protocol_version = kWireProtocolVersion;
    hello.product = "ffed-probe";
    Writer writer;
    Status status = hello.encode(writer);
    if (status.ok()) {
      status = write_message(socket.value(), MessageType::ProbeRequest, writer.span());
    }
    if (!status.ok()) {
      entry.state = ReachabilityState::Unreachable;
      entry.detail = status.message();
      observation.peers.push_back(std::move(entry));
      continue;
    }
    auto response = read_message(socket.value());
    if (!response.has_value()) {
      entry.state = ReachabilityState::Unreachable;
      entry.detail = response.status().message();
      observation.peers.push_back(std::move(entry));
      continue;
    }
    auto probe = decode_payload<ProbeResponse>(response.value().span());
    if (!probe.has_value() || response.value().type != MessageType::ProbeResult) {
      entry.state = ReachabilityState::Unknown;
      entry.detail = "the peer answered something this runtime does not understand";
      observation.peers.push_back(std::move(entry));
      continue;
    }
    if (probe.value().member != target.member) {
      entry.state = ReachabilityState::Unknown;
      entry.detail = "the peer at this endpoint reports a different member identity";
      observation.peers.push_back(std::move(entry));
      continue;
    }
    entry.state = ReachabilityState::Reachable;
    entry.peer_incarnation = probe.value().incarnation;
    entry.detail = "reached " + probe.value().node.to_string();
    observation.peers.push_back(std::move(entry));
    const Status shutdown = socket.value().shutdown_send();
    (void)shutdown;
  }
  return observation;
}

Result<SimpleResponse> MemberFabricRuntime::report_observation(
    const MemberObservation& observation) {
  Impl& impl = *impl_;
  if (!impl.attached) {
    return Status::make(ErrorCode::NotInitialized, "the member is not attached to a coordinator");
  }
  return impl.client.report_observation(observation);
}

Status MemberFabricRuntime::start_probe_listener() {
  Impl& impl = *impl_;
  if (impl.probe_open) {
    return Status::success();
  }
  auto listener = Listener::bind_loopback(impl.config.probe_port, 32);
  if (!listener.has_value()) {
    return listener.status();
  }
  impl.probe_listener = std::move(listener.value());
  impl.probe_open = true;
  impl.probe_stopping.store(false, std::memory_order_release);
  impl.probe_thread = std::thread([this] {
    Impl& state = *impl_;
    while (!state.probe_stopping.load(std::memory_order_acquire) && state.probe_listener.valid()) {
      auto accepted = state.probe_listener.accept();
      if (!accepted.has_value()) {
        break;
      }
      auto request = read_message(accepted.value());
      if (!request.has_value() || request.value().type != MessageType::ProbeRequest) {
        continue;
      }
      auto hello = decode_payload<HelloRequest>(request.value().span());
      if (!hello.has_value() || hello.value().federation != state.config.federation) {
        continue;
      }
      ProbeResponse response;
      response.federation = state.config.federation;
      response.member = state.config.constitution.member;
      response.incarnation = state.config.incarnation;
      response.node = state.config.node;
      response.logical_time = state.tick;
      response.constitution = state.config.constitution.digest();
      if (state.attached) {
        response.epoch = state.client.welcome().epoch;
      }
      Writer writer;
      if (response.encode(writer).ok()) {
        const Status status =
            write_message(accepted.value(), MessageType::ProbeResult, writer.span());
        (void)status;
      }
      const Status shutdown = accepted.value().shutdown_send();
      (void)shutdown;
    }
  });
  return Status::success();
}

Status MemberFabricRuntime::stop_probe_listener() {
  Impl& impl = *impl_;
  if (!impl.probe_open) {
    return Status::success();
  }
  impl.probe_open = false;
  impl.probe_stopping.store(true, std::memory_order_release);
  const Status closed = impl.probe_listener.close();
  (void)closed;
  if (impl.probe_thread.joinable()) {
    impl.probe_thread.join();
  }
  return Status::success();
}

Status MemberFabricRuntime::serve_probes_once() { return Status::success(); }

void MemberFabricRuntime::stop_probe_thread() { (void)stop_probe_listener(); }

std::string MemberFabricRuntime::describe() const {
  const Impl& impl = *impl_;
  std::string out = "member ";
  out.append(impl.config.constitution.member.to_string());
  out.append(" node=");
  out.append(impl.config.node.to_string());
  out.append(" generation=");
  out.append(std::to_string(impl.config.constitution.generation.value()));
  out.append(" incarnation=");
  out.append(std::to_string(impl.config.incarnation.value()));
  out.append(impl.attached ? " attached to " : " detached from ");
  out.append(impl.config.coordinator.to_string());
  if (impl.probe_open) {
    out.append(" probe-listener=127.0.0.1:");
    out.append(std::to_string(impl.probe_listener.port()));
  }
  return out;
}

}  // namespace fabric_federation
