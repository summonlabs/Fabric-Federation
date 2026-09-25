// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/coordinator.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <thread>

#include "fabric_federation/json.hpp"
#include "fabric_federation/net.hpp"
#include "fabric_federation/protocol.hpp"
#include "fabric_federation/version.hpp"

namespace fabric_federation {

std::string_view to_string(SubmissionDisposition disposition) noexcept {
  switch (disposition) {
    case SubmissionDisposition::Applied:
      return "APPLIED";
    case SubmissionDisposition::Duplicate:
      return "DUPLICATE";
    case SubmissionDisposition::Rejected:
      return "REJECTED";
    case SubmissionDisposition::Invalid:
      return "INVALID";
  }
  return "INVALID";
}

namespace {

// Every coordinator-issued decision record gets an identifier derived from its
// content so that re-issuing the same decision is idempotent instead of
// creating a second record that disagrees with the first.
Digest decision_key(const FederationId& federation, ArtifactKind kind, const MemberId& subject,
                    Epoch epoch, Lineage lineage, const Digest& identity, const Digest& extra) {
  Writer writer;
  if (!writer.id16(federation.bytes()).ok() ||
      !writer.u16(static_cast<std::uint16_t>(kind)).ok() ||
      !writer.id16(subject.bytes()).ok() || !writer.u64(epoch.value()).ok() ||
      !writer.u64(lineage.value()).ok() || !writer.digest(identity).ok() ||
      !writer.digest(extra).ok()) {
    return Digest();
  }
  return writer.sha256();
}

// Runs a bounded encoder and returns the digest of what it wrote. Encoding
// failures are reported by returning the zero digest, which the callers reject.
template <class Fill>
Digest digest_of(Fill&& fill) {
  Writer writer;
  const Status status = fill(writer);
  if (!status.ok()) {
    return Digest();
  }
  return writer.sha256();
}

// Every coordinator-issued record gets an identifier derived from its content,
// so issuing the same decision twice produces the same identifier instead of a
// second record that disagrees with the first.
EvidenceId evidence_id_from(const FederationId& federation, const Digest& key) {
  const Digest digest = digest_of([&](Writer& writer) {
    Status status = writer.id16(federation.bytes());
    if (!status.ok()) {
      return status;
    }
    return writer.digest(key);
  });
  std::array<std::uint8_t, 16> bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = digest.bytes()[i];
  }
  return EvidenceId::from_bytes(bytes);
}

Digest digest_of_parties(const std::vector<MemberId>& parties) {
  Writer writer;
  std::vector<MemberId> sorted = parties;
  std::sort(sorted.begin(), sorted.end());
  sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());
  if (!writer.count(sorted.size(), kMaxMembers).ok()) {
    return Digest();
  }
  for (const MemberId& member : sorted) {
    if (!writer.id16(member.bytes()).ok()) {
      return Digest();
    }
  }
  return writer.sha256();
}

}  // namespace

struct FederationCoordinator::Impl {
  CoordinatorConfig config;
  ScopeCatalog catalog;
  FederationPolicy policy;

  mutable std::mutex mutex;
  std::vector<Artifact> artifacts;
  std::map<LeaseId, AuthorityLease> leases;
  std::map<MemberId, MemberObservation> observations;
  std::vector<ReplayEntry> replay;
  Tick tick;
  Incarnation incarnation;
  std::uint64_t lease_sequence = 1;
  std::uint64_t duplicate_artifacts = 0;
  std::uint64_t rejected_artifacts = 0;
  Journal journal;
  bool durable = false;
  std::string recovery_detail;
  bool bootstrapped = false;

  // ---- server side --------------------------------------------------------
  Listener listener;
  std::thread accept_thread;
  std::vector<std::thread> workers;
  std::deque<std::shared_ptr<Socket>> queue;
  std::mutex queue_mutex;
  std::condition_variable queue_cv;
  std::mutex sockets_mutex;
  std::vector<std::weak_ptr<Socket>> active_sockets;
  std::atomic<bool> stopping{false};
  std::atomic<bool> started{false};
  std::atomic<std::uint64_t> connections_accepted{0};
  std::atomic<std::uint64_t> protocol_errors{0};

  // ---- helpers (all require mutex to be held unless stated otherwise) -----
  // Advances the logical clock and returns the tick the caller should stamp on
  // the record it is about to write. Callers that only need the advance may
  // ignore the result.
  Tick next_tick_locked() {
    const Tick issued = tick;
    tick = Tick(tick.value() + 1u);
    return issued;
  }
  [[nodiscard]] Status journal_append(JournalRecordType type, const Writer& writer);
  [[nodiscard]] Result<FederationState> derive_locked() const;
  [[nodiscard]] Result<SubmissionOutcome> admit_locked(const Artifact& artifact);
  [[nodiscard]] Status record_decision_locked(const Artifact& artifact,
                                              std::vector<Artifact>& issued);
  void decide_locked(std::vector<Artifact>& issued);
  [[nodiscard]] bool has_evidence_locked(const EvidenceId& evidence) const;
  [[nodiscard]] Status load_journal();
  [[nodiscard]] Status ensure_genesis();
};

Status FederationCoordinator::Impl::journal_append(JournalRecordType type, const Writer& writer) {
  if (!durable) {
    return Status::success();
  }
  return journal.append(type, writer.span());
}

Result<FederationState> FederationCoordinator::Impl::derive_locked() const {
  DerivationInputs inputs;
  inputs.federation = config.federation;
  inputs.coordinator = config.node;
  inputs.coordinator_incarnation = incarnation;
  inputs.logical_time = tick;
  inputs.policy = &policy;
  inputs.catalog = &catalog;
  inputs.artifacts = artifacts;
  inputs.replay_ledger = replay;
  inputs.observations.reserve(observations.size());
  for (const auto& entry : observations) {
    inputs.observations.push_back(entry.second);
  }
  inputs.leases.reserve(leases.size());
  for (const auto& entry : leases) {
    inputs.leases.push_back(entry.second);
  }
  auto derived = derive_state(inputs);
  if (!derived.has_value()) {
    return derived.status();
  }
  return derived.value().state;
}

bool FederationCoordinator::Impl::has_evidence_locked(const EvidenceId& evidence) const {
  for (const Artifact& artifact : artifacts) {
    if (artifact.envelope.evidence == evidence) {
      return true;
    }
  }
  return false;
}

Status FederationCoordinator::Impl::load_journal() {
  if (config.journal_path.empty()) {
    durable = false;
    recovery_detail = "no journal configured: state does not survive a restart";
    return Status::success();
  }
  bool fresh = !std::filesystem::exists(config.journal_path);
  auto opened = Journal::open(config.journal_path, JournalOpenMode::OpenOrCreateReadWrite);
  if (!opened.has_value()) {
    return opened.status();
  }
  journal = std::move(opened.value());
  durable = true;
  recovery_detail =
      std::string(to_string(journal.recovery().outcome)) + ": " + journal.recovery().detail;
  if (!journal.recovery().writable) {
    return Status::make(ErrorCode::Refused,
                        "recovered journal is not writable: " + journal.recovery().detail);
  }
  auto records = journal.load(kMaxArtifacts * 4u, kMaxJournalRecordBytes);
  if (!records.has_value()) {
    return records.status();
  }
  std::map<LeaseId, std::pair<ReasonCode, std::string>> revocations;
  std::uint64_t highest_incarnation = 0;
  std::uint64_t highest_tick = config.initial_tick.value();
  std::uint64_t highest_lease_sequence = 0;
  for (const JournalRecord& record : records.value()) {
    Reader reader(std::span<const std::byte>(record.payload.data(), record.payload.size()));
    switch (record.type) {
      case JournalRecordType::Artifact:
      case JournalRecordType::FederationGenesis: {
        auto artifact = Artifact::decode(reader);
        if (!artifact.has_value()) {
          return Status::make(ErrorCode::Corrupt,
                              "journal holds an artefact that cannot be decoded: " +
                                  artifact.status().to_string());
        }
        artifacts.push_back(std::move(artifact.value()));
        break;
      }
      case JournalRecordType::Lease: {
        auto lease = AuthorityLease::decode(reader);
        if (!lease.has_value()) {
          return Status::make(ErrorCode::Corrupt, "journal holds a lease that cannot be decoded: " +
                                                      lease.status().to_string());
        }
        highest_lease_sequence = std::max(highest_lease_sequence, record.sequence);
        highest_tick = std::max(highest_tick, lease.value().issued_at.value());
        leases[lease.value().id] = std::move(lease.value());
        break;
      }
      case JournalRecordType::LeaseRevocation: {
        auto id = reader.id16();
        if (!id.has_value()) {
          return id.status();
        }
        auto reason = reader.u16();
        if (!reason.has_value()) {
          return reason.status();
        }
        auto detail = reader.text(kMaxTextLength);
        if (!detail.has_value()) {
          return detail.status();
        }
        revocations[LeaseId::from_bytes(id.value())] = {
            static_cast<ReasonCode>(reason.value()), std::move(detail.value())};
        break;
      }
      case JournalRecordType::RequestDecision: {
        auto decision = AuthorityDecision::decode(reader);
        if (!decision.has_value()) {
          return Status::make(ErrorCode::Corrupt,
                              "journal holds a decision that cannot be decoded: " +
                                  decision.status().to_string());
        }
        ReplayEntry entry;
        entry.request = decision.value().request;
        entry.decision = decision.value().digest();
        entry.decided_at = decision.value().decided_at;
        replay.push_back(entry);
        highest_tick = std::max(highest_tick, decision.value().decided_at.value());
        break;
      }
      case JournalRecordType::CoordinatorIncarnation: {
        auto value = reader.u64();
        if (!value.has_value()) {
          return value.status();
        }
        highest_incarnation = std::max(highest_incarnation, value.value());
        break;
      }
      case JournalRecordType::TickHighWater: {
        auto value = reader.u64();
        if (!value.has_value()) {
          return value.status();
        }
        highest_tick = std::max(highest_tick, value.value());
        break;
      }
      case JournalRecordType::PartitionObservation: {
        auto observation = MemberObservation::decode(reader);
        if (!observation.has_value()) {
          return Status::make(ErrorCode::Corrupt,
                              "journal holds an observation that cannot be decoded: " +
                                  observation.status().to_string());
        }
        observations[observation.value().observer] = std::move(observation.value());
        break;
      }
      case JournalRecordType::Policy: {
        auto restored = FederationPolicy::decode(reader);
        if (!restored.has_value()) {
          return Status::make(ErrorCode::Corrupt, "journal holds a policy that cannot be decoded: " +
                                                      restored.status().to_string());
        }
        if (restored.value().generation > policy.generation) {
          policy = std::move(restored.value());
        }
        break;
      }
      case JournalRecordType::FederationIdentity:
      case JournalRecordType::EpochState:
        break;
    }
  }
  for (const auto& entry : revocations) {
    auto found = leases.find(entry.first);
    if (found == leases.end()) {
      // A durable revocation whose lease is absent means the recovered history
      // is not self-consistent. It is refused rather than ignored.
      return Status::make(ErrorCode::Corrupt,
                          "journal holds a revocation for a lease that is not in the history");
    }
    found->second.revoked = true;
    found->second.revoked_at = Tick(highest_tick);
    found->second.revoke_reason = entry.second.first;
    found->second.revoke_detail = entry.second.second;
  }
  tick = Tick(highest_tick);
  // A restart always runs a fresh incarnation, so every lease issued by the
  // previous incarnation becomes historical evidence (LeaseState::StaleIssuer)
  // rather than live authority.
  incarnation = Incarnation(highest_incarnation + 1u);
  lease_sequence = highest_lease_sequence + 1u;
  if (fresh) {
    recovery_detail = "fresh journal created";
  }
  Writer writer;
  if (!writer.u64(incarnation.value()).ok()) {
    return Status::make(ErrorCode::Internal, "incarnation cannot be encoded");
  }
  return journal_append(JournalRecordType::CoordinatorIncarnation, writer);
}

Status FederationCoordinator::Impl::ensure_genesis() {
  for (const Artifact& artifact : artifacts) {
    if (artifact.envelope.kind == ArtifactKind::FederationGenesis) {
      bootstrapped = true;
      return Status::success();
    }
  }
  if (!config.bootstrap) {
    return Status::success();
  }
  if (config.founder.constitution.member.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument,
                        "bootstrap requires a founder with a member identity");
  }
  ArtifactBody body;
  body.genesis.federation = config.federation;
  body.genesis.coordinator = config.node;
  body.genesis.founder = config.founder;
  body.genesis.founder_grants = config.founder_grants;
  canonicalize_grants(body.genesis.founder_grants);
  body.genesis.policy = policy;
  body.genesis.description = config.description;
  body.genesis.created_at = tick;
  body.lineage = Lineage(0);
  body.epoch = Epoch(1);
  body.policy_generation = policy.generation;
  body.policy_digest = policy.digest();
  body.logical_time = tick;

  ArtifactEnvelope envelope;
  envelope.kind = ArtifactKind::FederationGenesis;
  envelope.federation = config.federation;
  envelope.subject = config.founder.constitution.member;
  envelope.issuer.node = config.node;
  envelope.issuer.epoch = Epoch(1);
  envelope.issuer.issued_at = tick;
  const Digest key = decision_key(config.federation, ArtifactKind::FederationGenesis,
                                  envelope.subject, Epoch(1), Lineage(0),
                                  body.genesis.founder.constitution.digest(), Digest());
  envelope.evidence = evidence_id_from(config.federation, key);

  Artifact genesis = Artifact::make(std::move(envelope), std::move(body));
  const Status status = genesis.validate(catalog);
  if (!status.ok()) {
    return status;
  }
  artifacts.push_back(genesis);
  bootstrapped = true;
  Writer writer;
  Status encoded = genesis.encode(writer);
  if (!encoded.ok()) {
    return encoded;
  }
  return journal_append(JournalRecordType::Artifact, writer);
}

Status FederationCoordinator::Impl::record_decision_locked(const Artifact& artifact,
                                                           std::vector<Artifact>& issued) {
  const Status status = artifact.validate(catalog);
  if (!status.ok()) {
    return status;
  }
  if (has_evidence_locked(artifact.envelope.evidence)) {
    return Status::success();
  }
  Writer writer;
  Status encoded = artifact.encode(writer);
  if (!encoded.ok()) {
    return encoded;
  }
  const Status appended = journal_append(JournalRecordType::Artifact, writer);
  if (!appended.ok()) {
    return appended;
  }
  artifacts.push_back(artifact);
  issued.push_back(artifact);
  return Status::success();
}

void FederationCoordinator::Impl::decide_locked(std::vector<Artifact>& issued) {
  // Bounded: each pass can only add decision records for members that do not
  // already have one, and the member set is bounded.
  for (std::size_t pass = 0; pass < kMaxMembers + 2; ++pass) {
    auto derived = derive_locked();
    if (!derived.has_value()) {
      return;
    }
    const FederationState state = std::move(derived.value());

    std::vector<MemberId> bootstrap_members;
    for (const Artifact& artifact : artifacts) {
      if (artifact.envelope.kind == ArtifactKind::FederationGenesis) {
        bootstrap_members.push_back(artifact.body.genesis.founder.constitution.member);
      }
    }
    std::vector<MemberId> active_members;
    for (const MemberState& member : state.members) {
      if (lifecycle_holds_federation_authority(member.lifecycle)) {
        active_members.push_back(member.member);
      }
    }

    // One pass over the evidence set builds the per-member view. Scanning the
    // whole set once per member per pass made this quadratic in the size of the
    // federation, which showed up as minutes of runtime under an instrumented
    // build.
    std::map<MemberId, std::vector<Artifact>> by_subject;
    for (const Artifact& artifact : artifacts) {
      if (!artifact.envelope.subject.is_nil()) {
        by_subject[artifact.envelope.subject].push_back(artifact);
      }
    }

    std::vector<Artifact> batch;
    for (const MemberState& member : state.members) {
      const auto bucket = by_subject.find(member.member);
      const std::vector<Artifact> for_member =
          bucket == by_subject.end() ? std::vector<Artifact>{} : bucket->second;
      MembershipContext context;
      context.federation = config.federation;
      context.current_epoch = state.epoch;
      context.now = tick;
      context.policy = &policy;
      context.catalog = &catalog;
      context.partition = state.partition;
      context.reconciling = state.reconciling;
      context.established_members = active_members;
      context.bootstrap_members = bootstrap_members;
      for (const Artifact& artifact : artifacts) {
        if (artifact.envelope.kind == ArtifactKind::FederationGenesis) {
          context.bootstrap_declarations.push_back(artifact.body.genesis.founder);
        }
      }
      const MembershipDerivation derivation =
          derive_membership(member.member, for_member, context);

      ArtifactEnvelope envelope;
      envelope.federation = config.federation;
      envelope.subject = member.member;
      envelope.issuer.node = config.node;
      envelope.issuer.epoch = state.epoch;
      envelope.issuer.issued_at = tick;

      if (derivation.lifecycle == MemberLifecycleState::Proposed) {
        const Artifact* proposal = nullptr;
        for (const Artifact& artifact : for_member) {
          if (artifact.envelope.kind != ArtifactKind::MembershipProposal) {
            continue;
          }
          if (proposal == nullptr || artifact.envelope.evidence < proposal->envelope.evidence) {
            proposal = &artifact;
          }
        }
        if (proposal == nullptr) {
          continue;
        }
        const bool proposer_active =
            std::find(active_members.begin(), active_members.end(),
                      proposal->envelope.issuer.member) != active_members.end();
        const MultiPartyAssessment multi =
            assess_multi_party(member.member, proposal->envelope.issuer.member, proposer_active,
                               derivation.facts.endorsers, policy, false);
        if (!multi.satisfied || !derivation.facts.acceptance_matches_declaration) {
          continue;
        }
        ArtifactBody body;
        body.declared_identity = derivation.facts.current_identity;
        body.epoch = state.epoch;
        body.lineage = derivation.facts.lineage;
        body.parties = multi.parties;
        body.required_endorsements = policy.required_endorsements();
        body.required_distinct_parties = policy.required_distinct_parties();
        body.outcome = Outcome::Granted;
        body.reason_code = ReasonCode::MultiPartySatisfied;
        body.reason_text = "admitted by policy: " + std::to_string(multi.distinct_parties) +
                           " distinct parties, " + std::to_string(multi.endorsements) +
                           " third-party endorsement(s)";
        body.policy_generation = state.policy_generation;
        body.policy_digest = state.policy_digest;
        body.logical_time = tick;
        ArtifactEnvelope admission = envelope;
        admission.kind = ArtifactKind::MembershipAdmission;
        // The lineage is part of the key: a member that left and rejoined has a
        // fresh lineage and must receive a fresh decision record rather than
        // inheriting the one from the previous lineage.
        const Digest key =
            decision_key(config.federation, ArtifactKind::MembershipAdmission, member.member,
                         state.epoch, body.lineage, body.declared_identity.constitution,
                         digest_of_parties(body.parties));
        admission.evidence = evidence_id_from(config.federation, key);
        batch.push_back(Artifact::make(std::move(admission), std::move(body)));
        continue;
      }

      // A member whose activation belongs to an earlier epoch is re-activated
      // once it has re-attested at the current epoch. Re-attestation is the
      // member declaring its identity; the consent on record already covers
      // that constitution digest, so no new acceptance is required.
      const bool needs_reactivation =
          derivation.lifecycle == MemberLifecycleState::Admitted ||
          (derivation.lifecycle == MemberLifecycleState::Degraded &&
           derivation.facts.has_reattestation && !derivation.facts.activation_at_current_epoch);
      if (needs_reactivation) {
        ArtifactBody body;
        body.declared_identity = derivation.facts.current_identity;
        body.epoch = state.epoch;
        body.lineage = derivation.facts.lineage;
        body.outcome = Outcome::Granted;
        body.reason_code = ReasonCode::MembershipActive;
        body.reason_text = "activated at epoch " + std::to_string(state.epoch.value());
        body.policy_generation = state.policy_generation;
        body.policy_digest = state.policy_digest;
        body.logical_time = tick;
        ArtifactEnvelope activation = envelope;
        activation.kind = ArtifactKind::MembershipActivation;
        const Digest key = decision_key(config.federation, ArtifactKind::MembershipActivation,
                                        member.member, state.epoch, body.lineage,
                                        body.declared_identity.constitution, state.policy_digest);
        activation.evidence = evidence_id_from(config.federation, key);
        batch.push_back(Artifact::make(std::move(activation), std::move(body)));
        continue;
      }
    }

    if (batch.empty()) {
      return;
    }
    bool progressed = false;
    for (Artifact& artifact : batch) {
      if (record_decision_locked(artifact, issued).ok()) {
        progressed = true;
      }
    }
    if (!progressed) {
      return;
    }
  }
}

Result<SubmissionOutcome> FederationCoordinator::Impl::admit_locked(const Artifact& artifact) {
  SubmissionOutcome outcome;
  outcome.artifact_digest = artifact.digest();

  const Status validation = artifact.validate(catalog);
  if (!validation.ok()) {
    outcome.disposition = SubmissionDisposition::Invalid;
    outcome.reason = ReasonCode::ArtifactMalformed;
    outcome.detail = validation.to_string();
    return outcome;
  }
  if (artifact.envelope.federation != config.federation) {
    outcome.disposition = SubmissionDisposition::Rejected;
    outcome.reason = ReasonCode::FederationIdentityMismatch;
    outcome.detail = "artefact belongs to federation " + artifact.envelope.federation.to_string();
    return outcome;
  }
  if (artifacts.size() >= kMaxArtifacts) {
    outcome.disposition = SubmissionDisposition::Rejected;
    outcome.reason = ReasonCode::LimitExceeded;
    outcome.detail = "the evidence set has reached its configured bound";
    return outcome;
  }

  bool same_present = false;
  bool conflicting_present = false;
  for (const Artifact& existing : artifacts) {
    if (existing.envelope.evidence != artifact.envelope.evidence) {
      continue;
    }
    if (existing.digest() == outcome.artifact_digest) {
      same_present = true;
    } else {
      conflicting_present = true;
    }
  }
  if (same_present) {
    ++duplicate_artifacts;
    outcome.disposition = SubmissionDisposition::Duplicate;
    outcome.reason = ReasonCode::EvidenceDuplicateIdentical;
    outcome.detail = "identical evidence was already accepted; applying it again changes nothing";
    auto derived = derive_locked();
    if (derived.has_value()) {
      outcome.state_digest = derived.value().digest();
      outcome.artifact_count = derived.value().artifact_count;
    }
    return outcome;
  }

  // The artefact is recorded either way: when its identifier was already used
  // with different content, the derivation quarantines both copies and records
  // the disagreement rather than picking a winner.
  Writer writer;
  const Status encoded = artifact.encode(writer);
  if (!encoded.ok()) {
    outcome.disposition = SubmissionDisposition::Invalid;
    outcome.reason = ReasonCode::ArtifactMalformed;
    outcome.detail = encoded.to_string();
    return outcome;
  }
  const Status appended = journal_append(JournalRecordType::Artifact, writer);
  if (!appended.ok()) {
    outcome.disposition = SubmissionDisposition::Rejected;
    outcome.reason = ReasonCode::LimitExceeded;
    outcome.detail = "the artefact could not be persisted: " + appended.to_string();
    return outcome;
  }
  artifacts.push_back(artifact);

  if (conflicting_present) {
    ++rejected_artifacts;
    outcome.disposition = SubmissionDisposition::Rejected;
    outcome.reason = ReasonCode::EvidenceDuplicateConflicting;
    outcome.detail = "evidence " + artifact.envelope.evidence.to_string() +
                     " was already used with different content; both copies are quarantined";
  } else {
    outcome.disposition = SubmissionDisposition::Applied;
    outcome.reason = ReasonCode::ArtifactAccepted;
    outcome.detail = "evidence accepted";
  }

  decide_locked(outcome.issued);
  auto derived = derive_locked();
  if (derived.has_value()) {
    outcome.state_digest = derived.value().digest();
    outcome.artifact_count = derived.value().artifact_count;
  }
  return outcome;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

FederationCoordinator::FederationCoordinator() : impl_(new Impl()) {}

FederationCoordinator::~FederationCoordinator() {
  const Status status = stop();
  (void)status;
}

Result<std::unique_ptr<FederationCoordinator>> FederationCoordinator::create(
    const CoordinatorConfig& config) {
  if (config.federation.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument, "a coordinator requires a federation identity");
  }
  if (config.node.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument, "a coordinator requires a node identity");
  }
  const Status validation = validate_policy(config.policy);
  if (!validation.ok()) {
    return Status::make(ErrorCode::InvalidArgument,
                        "the configured policy is not valid: " + validation.to_string());
  }
  if (config.worker_threads == 0 || config.worker_threads > 64) {
    return Status::make(ErrorCode::OutOfRange, "worker thread count is out of range");
  }
  if (config.max_connections == 0 || config.max_connections > kMaxConnections) {
    return Status::make(ErrorCode::OutOfRange, "connection bound is out of range");
  }

  std::unique_ptr<FederationCoordinator> coordinator(new FederationCoordinator());
  Impl& impl = *coordinator->impl_;
  impl.config = config;
  impl.policy = config.policy;
  impl.catalog = ScopeCatalog::builtin();
  impl.tick = config.initial_tick;
  impl.incarnation = Incarnation(1);

  Status status = impl.load_journal();
  if (!status.ok()) {
    return status;
  }
  status = impl.ensure_genesis();
  if (!status.ok()) {
    return status;
  }
  // Bootstrap produces the founder's activation record, so a freshly created
  // federation already has an active founder.
  std::vector<Artifact> issued;
  impl.decide_locked(issued);
  return coordinator;
}

Status FederationCoordinator::start() {
  Impl& impl = *impl_;
  if (impl.started.load(std::memory_order_acquire)) {
    return Status::make(ErrorCode::AlreadyExists, "the coordinator is already running");
  }
  if (impl.config.listen) {
    auto listener = Listener::bind_loopback(impl.config.listen_port, impl.config.max_connections);
    if (!listener.has_value()) {
      return listener.status();
    }
    impl.listener = std::move(listener.value());
    impl.stopping.store(false, std::memory_order_release);
    impl.accept_thread = std::thread([this] { accept_loop(); });
    impl.workers.reserve(impl.config.worker_threads);
    for (std::size_t i = 0; i < impl.config.worker_threads; ++i) {
      impl.workers.emplace_back([this] { worker_loop(); });
    }
  }
  impl.started.store(true, std::memory_order_release);
  return Status::success();
}

Status FederationCoordinator::stop() {
  Impl& impl = *impl_;
  if (!impl.started.exchange(false, std::memory_order_acq_rel)) {
    // Even when never started, a journal may be open and must be closed.
    std::lock_guard<std::mutex> lock(impl.mutex);
    if (impl.journal.is_open()) {
      return impl.journal.close();
    }
    return Status::success();
  }
  impl.stopping.store(true, std::memory_order_release);
  const Status closed = impl.listener.close();
  (void)closed;
  if (impl.accept_thread.joinable()) {
    impl.accept_thread.join();
  }
  // Wake the workers, then shut down the sockets they own so that a worker
  // blocked in a read returns instead of waiting forever. No lock is held
  // while the sockets are shut down and no thread is joined while holding the
  // state mutex.
  impl.queue_cv.notify_all();
  shutdown_connections();
  impl.queue_cv.notify_all();
  for (std::thread& worker : impl.workers) {
    if (worker.joinable()) {
      worker.join();
    }
  }
  impl.workers.clear();
  {
    std::lock_guard<std::mutex> lock(impl.queue_mutex);
    impl.queue.clear();
  }
  std::lock_guard<std::mutex> lock(impl.mutex);
  if (impl.journal.is_open()) {
    return impl.journal.close();
  }
  return Status::success();
}

bool FederationCoordinator::running() const noexcept {
  return impl_->started.load(std::memory_order_acquire) &&
         !impl_->stopping.load(std::memory_order_acquire);
}

Result<SubmissionOutcome> FederationCoordinator::submit_artifact(const Artifact& artifact) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  return impl.admit_locked(artifact);
}

Result<AuthorityDecision> FederationCoordinator::evaluate(const AuthorityRequest& request) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  if (request.federation.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument, "the request names no federation");
  }
  auto derived = impl.derive_locked();
  if (!derived.has_value()) {
    return derived.status();
  }
  const FederationState& state = derived.value();
  AuthorityDecision decision = evaluate_authority(request, state, impl.policy, impl.catalog);
  // Every decision that is not a malformed request is committed to the replay
  // ledger, including refusals: a repeated identifier must never be answered
  // differently.
  if (decision.outcome != Outcome::Invalid) {
    ReplayEntry entry;
    entry.request = request.id;
    entry.decision = decision.digest();
    entry.decided_at = decision.decided_at;
    bool present = false;
    for (const ReplayEntry& existing : impl.replay) {
      if (existing.request == entry.request) {
        present = true;
        break;
      }
    }
    if (!present) {
      if (impl.replay.size() >= kMaxReplayEntries) {
        return Status::make(ErrorCode::CapacityExceeded,
                            "the replay ledger has reached its configured bound");
      }
      Writer writer;
      Status encoded = decision.encode(writer);
      if (!encoded.ok()) {
        return encoded;
      }
      const Status appended =
          impl.journal_append(JournalRecordType::RequestDecision, writer);
      if (!appended.ok()) {
        return appended;
      }
      impl.replay.push_back(entry);
    }
    impl.next_tick_locked();
  }
  return decision;
}

Result<AuthorityLease> FederationCoordinator::issue_lease(const LeaseRequest& request) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  auto derived = impl.derive_locked();
  if (!derived.has_value()) {
    return derived.status();
  }
  const FederationState state = std::move(derived.value());
  const MemberState* member = state.find(request.holder);
  if (member == nullptr) {
    return Status::make(ErrorCode::NotFound, "the lease holder is not a member of this federation");
  }
  if (!lifecycle_holds_federation_authority(member->lifecycle)) {
    return Status::make(ErrorCode::Refused,
                        "the lease holder is " +
                            std::string(to_string(member->lifecycle)) +
                            " and holds no federation authority to lease");
  }
  if (request.scopes.empty()) {
    return Status::make(ErrorCode::InvalidArgument, "a lease must cover at least one grant");
  }
  if (request.scopes.size() > kMaxScopesPerLease) {
    return Status::make(ErrorCode::BoundsExceeded, "the lease covers too many grants");
  }
  for (const ScopeGrant& grant : request.scopes) {
    if (!grants_cover(member->federation_authority, grant)) {
      return Status::make(ErrorCode::Refused,
                          "the member does not hold " + grant.to_string() +
                              "; a lease cannot grant authority that was never delegated");
    }
  }
  const std::uint64_t maximum = impl.policy.max_lease_lifetime_ticks();
  const std::uint64_t lifetime =
      request.lifetime_ticks.is_zero() ? maximum : request.lifetime_ticks.value();
  if (lifetime == 0 || lifetime > maximum) {
    return Status::make(ErrorCode::OutOfRange,
                        "the requested lease lifetime exceeds the policy bound of " +
                            std::to_string(maximum) + " ticks");
  }
  std::uint64_t deadline = 0;
  if (!checked_add_u64(impl.tick.value(), lifetime, deadline)) {
    return Status::make(ErrorCode::Overflow, "the lease deadline would overflow the logical clock");
  }
  if (state.leases.size() >= kMaxLeases) {
    return Status::make(ErrorCode::CapacityExceeded, "the lease table has reached its bound");
  }

  AuthorityLease lease;
  const Digest id_digest = digest_of([&](Writer& writer) {
    Status status = writer.id16(impl.config.federation.bytes());
    if (!status.ok()) {
      return status;
    }
    return writer.u64(impl.lease_sequence);
  });
  if (id_digest.is_zero()) {
    return Status::make(ErrorCode::Internal, "the lease identifier cannot be derived");
  }
  std::array<std::uint8_t, 16> id_bytes{};
  for (std::size_t i = 0; i < id_bytes.size(); ++i) {
    id_bytes[i] = id_digest.bytes()[i];
  }
  lease.id = LeaseId::from_bytes(id_bytes);
  lease.federation = impl.config.federation;
  lease.holder = member->current_identity;
  lease.scopes = request.scopes;
  canonicalize_grants(lease.scopes);
  lease.issued_epoch = state.epoch;
  lease.not_after_epoch = request.not_after_epoch.is_zero() ? state.epoch
                                                            : request.not_after_epoch;
  if (lease.not_after_epoch < state.epoch) {
    return Status::make(ErrorCode::InvalidArgument,
                        "a lease cannot expire in an epoch that has already passed");
  }
  lease.issued_at = impl.tick;
  lease.not_after = Tick(deadline);
  lease.issuer_node = impl.config.node;
  lease.issuer_incarnation = impl.incarnation;

  Writer writer;
  Status encoded = lease.encode(writer);
  if (!encoded.ok()) {
    return encoded;
  }
  const Status appended = impl.journal_append(JournalRecordType::Lease, writer);
  if (!appended.ok()) {
    return appended;
  }
  impl.leases[lease.id] = lease;
  ++impl.lease_sequence;
  impl.next_tick_locked();
  return lease;
}

Status FederationCoordinator::revoke_lease(const LeaseId& lease, ReasonCode reason,
                                           std::string_view detail) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  auto found = impl.leases.find(lease);
  if (found == impl.leases.end()) {
    return Status::make(ErrorCode::NotFound, "no such lease");
  }
  if (found->second.revoked) {
    // Revocation is idempotent and is never undone.
    return Status::success();
  }
  found->second.revoked = true;
  found->second.revoked_at = impl.tick;
  found->second.revoke_reason = reason;
  found->second.revoke_detail = std::string(detail);
  Writer writer;
  Status encoded = writer.id16(lease.bytes());
  if (encoded.ok()) {
    encoded = writer.u16(static_cast<std::uint16_t>(reason));
  }
  if (encoded.ok()) {
    encoded = writer.text(detail, kMaxTextLength);
  }
  if (!encoded.ok()) {
    return encoded;
  }
  const Status appended = impl.journal_append(JournalRecordType::LeaseRevocation, writer);
  if (!appended.ok()) {
    return appended;
  }
  impl.next_tick_locked();
  return Status::success();
}

Status FederationCoordinator::report_observation(const MemberObservation& observation) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  if (observation.observer.is_nil()) {
    return Status::make(ErrorCode::InvalidArgument, "an observation must name its observer");
  }
  if (observation.peers.size() > kMaxMembersPerObservation) {
    return Status::make(ErrorCode::BoundsExceeded, "the observation covers too many peers");
  }
  Writer writer;
  Status encoded = observation.encode(writer);
  if (!encoded.ok()) {
    return encoded;
  }
  const Status appended = impl.journal_append(JournalRecordType::PartitionObservation, writer);
  if (!appended.ok()) {
    return appended;
  }
  impl.observations[observation.observer] = observation;
  impl.next_tick_locked();
  return Status::success();
}

Status FederationCoordinator::advance_time(Tick to) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  if (to <= impl.tick) {
    return Status::make(ErrorCode::OutOfRange,
                        "the logical clock only moves forward: current tick is " +
                            std::to_string(impl.tick.value()));
  }
  impl.tick = to;
  Writer writer;
  Status encoded = writer.u64(to.value());
  if (!encoded.ok()) {
    return encoded;
  }
  return impl.journal_append(JournalRecordType::TickHighWater, writer);
}

namespace {

Artifact make_lifecycle_record(const CoordinatorConfig& config, const FederationState& state,
                               Tick tick, ArtifactKind kind, const MemberId& member,
                               Lineage lineage, Epoch epoch, ReasonCode reason,
                               std::string_view detail) {
  ArtifactBody body;
  body.lineage = lineage;
  body.epoch = epoch;
  body.reason_code = reason;
  body.fence_reason = reason;
  body.reason_text = std::string(detail);
  body.logical_time = tick;
  body.outcome = Outcome::Fenced;
  body.policy_generation = state.policy_generation;
  body.policy_digest = state.policy_digest;

  ArtifactEnvelope envelope;
  envelope.kind = kind;
  envelope.federation = config.federation;
  envelope.subject = member;
  envelope.issuer.node = config.node;
  envelope.issuer.epoch = epoch;
  envelope.issuer.issued_at = tick;

  const Digest key = digest_of([&](Writer& writer) {
    Status status = writer.id16(config.federation.bytes());
    if (!status.ok()) {
      return status;
    }
    status = writer.u16(static_cast<std::uint16_t>(kind));
    if (!status.ok()) {
      return status;
    }
    status = writer.id16(member.bytes());
    if (!status.ok()) {
      return status;
    }
    status = writer.u64(epoch.value());
    if (!status.ok()) {
      return status;
    }
    status = writer.u16(static_cast<std::uint16_t>(reason));
    if (!status.ok()) {
      return status;
    }
    return writer.u64(lineage.value());
  });
  envelope.evidence = evidence_id_from(config.federation, key);
  return Artifact::make(std::move(envelope), std::move(body));
}

}  // namespace

Status FederationCoordinator::fence_member(const MemberId& member, Lineage lineage,
                                           ReasonCode reason, std::string_view detail) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  auto derived = impl.derive_locked();
  if (!derived.has_value()) {
    return derived.status();
  }
  const FederationState state = std::move(derived.value());
  const MemberState* found = state.find(member);
  if (found == nullptr) {
    return Status::make(ErrorCode::NotFound, "no such member in this federation");
  }
  const Lineage effective = lineage.is_zero() ? found->lineage : lineage;
  Artifact artifact = make_lifecycle_record(impl.config, state, impl.tick,
                                           ArtifactKind::MembershipFence, member, effective,
                                           state.epoch, reason, detail);
  std::vector<Artifact> issued;
  const Status status = impl.record_decision_locked(artifact, issued);
  if (!status.ok()) {
    return status;
  }
  impl.next_tick_locked();
  return Status::success();
}

Status FederationCoordinator::retire_member(const MemberId& member, Lineage lineage,
                                            ReasonCode reason, std::string_view detail) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  auto derived = impl.derive_locked();
  if (!derived.has_value()) {
    return derived.status();
  }
  const FederationState state = std::move(derived.value());
  const MemberState* found = state.find(member);
  if (found == nullptr) {
    return Status::make(ErrorCode::NotFound, "no such member in this federation");
  }
  if (found->lifecycle != MemberLifecycleState::Leaving &&
      found->lifecycle != MemberLifecycleState::Fenced) {
    return Status::make(ErrorCode::Refused,
                        "a membership lineage is retired only after the member has left or been "
                        "fenced; the member is currently " +
                            std::string(to_string(found->lifecycle)));
  }
  const Lineage effective = lineage.is_zero() ? found->lineage : lineage;
  Artifact artifact = make_lifecycle_record(impl.config, state, impl.tick,
                                           ArtifactKind::MembershipRetirement, member, effective,
                                           state.epoch, reason, detail);
  std::vector<Artifact> issued;
  const Status status = impl.record_decision_locked(artifact, issued);
  if (!status.ok()) {
    return status;
  }
  impl.next_tick_locked();
  return Status::success();
}

Status FederationCoordinator::advance_epoch(Epoch epoch, ReasonCode reason,
                                            std::string_view detail) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  auto derived = impl.derive_locked();
  if (!derived.has_value()) {
    return derived.status();
  }
  const FederationState state = std::move(derived.value());
  if (epoch <= state.epoch) {
    return Status::make(ErrorCode::OutOfRange,
                        "the federation epoch only moves forward: current epoch is " +
                            std::to_string(state.epoch.value()));
  }
  ArtifactBody body;
  body.epoch = epoch;
  body.reason_code = reason;
  body.reason_text = std::string(detail);
  body.logical_time = impl.tick;
  body.policy_generation = state.policy_generation;
  body.policy_digest = state.policy_digest;
  body.outcome = Outcome::Granted;

  ArtifactEnvelope envelope;
  envelope.kind = ArtifactKind::EpochAdvance;
  envelope.federation = impl.config.federation;
  envelope.issuer.node = impl.config.node;
  envelope.issuer.epoch = epoch;
  envelope.issuer.issued_at = impl.tick;
  const Digest derived_key = digest_of([&](Writer& writer) {
    Status status = writer.id16(impl.config.federation.bytes());
    if (!status.ok()) {
      return status;
    }
    status = writer.u64(epoch.value());
    if (!status.ok()) {
      return status;
    }
    return writer.u16(static_cast<std::uint16_t>(reason));
  });
  envelope.evidence = evidence_id_from(impl.config.federation, derived_key);

  std::vector<Artifact> issued;
  const Status status = impl.record_decision_locked(Artifact::make(std::move(envelope),
                                                                  std::move(body)),
                                                    issued);
  if (!status.ok()) {
    return status;
  }
  impl.next_tick_locked();
  return Status::success();
}

Status FederationCoordinator::complete_reconciliation(Epoch epoch) {
  Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  auto derived = impl.derive_locked();
  if (!derived.has_value()) {
    return derived.status();
  }
  const FederationState state = std::move(derived.value());
  if (epoch > state.epoch) {
    return Status::make(ErrorCode::OutOfRange,
                        "reconciliation cannot complete for an epoch the federation has not "
                        "reached");
  }
  // The record is only meaningful if every member the federation currently
  // considers active has re-attested. The derivation re-checks this and keeps
  // the federation reconciling when it does not hold, so recording the attempt
  // is safe and honest.
  ArtifactBody body;
  body.epoch = epoch;
  body.reason_code = ReasonCode::PartitionReattestationComplete;
  body.reason_text = "reconciliation recorded for epoch " + std::to_string(epoch.value());
  body.logical_time = impl.tick;
  body.policy_generation = state.policy_generation;
  body.policy_digest = state.policy_digest;
  body.outcome = Outcome::Granted;

  ArtifactEnvelope envelope;
  envelope.kind = ArtifactKind::ReconciliationComplete;
  envelope.federation = impl.config.federation;
  envelope.issuer.node = impl.config.node;
  envelope.issuer.epoch = epoch;
  envelope.issuer.issued_at = impl.tick;
  const Digest derived_key = digest_of([&](Writer& writer) {
    Status status = writer.id16(impl.config.federation.bytes());
    if (!status.ok()) {
      return status;
    }
    return writer.u64(epoch.value());
  });
  envelope.evidence = evidence_id_from(impl.config.federation, derived_key);

  std::vector<Artifact> issued;
  const Status status = impl.record_decision_locked(Artifact::make(std::move(envelope),
                                                                  std::move(body)),
                                                    issued);
  if (!status.ok()) {
    return status;
  }
  impl.next_tick_locked();
  return Status::success();
}

Result<FederationState> FederationCoordinator::state() const {
  const Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  return impl.derive_locked();
}

Result<std::vector<Artifact>> FederationCoordinator::artifacts() const {
  const Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  return impl.artifacts;
}

Result<std::vector<AuthorityLease>> FederationCoordinator::leases() const {
  const Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  std::vector<AuthorityLease> out;
  out.reserve(impl.leases.size());
  for (const auto& entry : impl.leases) {
    out.push_back(entry.second);
  }
  return out;
}

Result<std::vector<MemberObservation>> FederationCoordinator::observations() const {
  const Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  std::vector<MemberObservation> out;
  out.reserve(impl.observations.size());
  for (const auto& entry : impl.observations) {
    out.push_back(entry.second);
  }
  return out;
}

Digest FederationCoordinator::state_digest() const {
  auto current = state();
  if (!current.has_value()) {
    return Digest();
  }
  return current.value().digest();
}

CoordinatorStats FederationCoordinator::stats() const {
  const Impl& impl = *impl_;
  CoordinatorStats stats;
  std::lock_guard<std::mutex> lock(impl.mutex);
  auto derived = impl.derive_locked();
  if (derived.has_value()) {
    stats.state_digest = derived.value().digest();
    stats.epoch = derived.value().epoch;
    stats.logical_time = derived.value().logical_time;
    stats.artifacts = derived.value().artifact_count;
    stats.rejected_artifacts = derived.value().rejected_artifact_count;
    stats.duplicate_artifacts = derived.value().duplicate_artifact_count;
    stats.members = derived.value().member_count();
    stats.active_members = derived.value().active_member_count();
    stats.reconciling = derived.value().reconciling;
    stats.partition_state = std::string(to_string(derived.value().partition.state));
  }
  stats.coordinator_incarnation = impl.incarnation;
  stats.leases = impl.leases.size();
  stats.replay_entries = impl.replay.size();
  stats.durable = impl.durable;
  stats.connections_accepted = impl.connections_accepted.load(std::memory_order_relaxed);
  stats.protocol_errors = impl.protocol_errors.load(std::memory_order_relaxed);
  stats.journal_records = impl.journal.next_sequence() - 1u;
  stats.journal_bytes = impl.journal.size_bytes();
  stats.transport = transport_description();
  stats.recovery = impl.recovery_detail;
  return stats;
}

const FederationPolicy& FederationCoordinator::policy() const { return impl_->policy; }

const ScopeCatalog& FederationCoordinator::catalog() const { return impl_->catalog; }

Epoch FederationCoordinator::epoch() const {
  auto current = state();
  if (!current.has_value()) {
    return Epoch();
  }
  return current.value().epoch;
}

Tick FederationCoordinator::logical_time() const {
  const Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  return impl.tick;
}

Incarnation FederationCoordinator::incarnation() const {
  const Impl& impl = *impl_;
  std::lock_guard<std::mutex> lock(impl.mutex);
  return impl.incarnation;
}

std::uint16_t FederationCoordinator::listen_port() const { return impl_->listener.port(); }

std::string FederationCoordinator::describe() const {
  const Impl& impl = *impl_;
  std::string out = "coordinator ";
  out.append(impl.config.node.to_string());
  out.append(" for federation ");
  out.append(impl.config.federation.to_string());
  if (impl.config.listen) {
    out.append(" listening on 127.0.0.1:");
    out.append(std::to_string(impl.listener.port()));
  } else {
    out.append(" (not listening)");
  }
  if (impl.durable) {
    out.append(" durable at ");
    out.append(impl.config.journal_path.string());
  } else {
    out.append(" (in-memory only)");
  }
  return out;
}

// ---------------------------------------------------------------------------
// Server threads
// ---------------------------------------------------------------------------

void FederationCoordinator::accept_loop() {
  Impl& impl = *impl_;
  std::size_t consecutive_failures = 0;
  while (!impl.stopping.load(std::memory_order_acquire) && impl.listener.valid()) {
    auto accepted = impl.listener.accept();
    if (!accepted.has_value()) {
      if (impl.stopping.load(std::memory_order_acquire) || !impl.listener.valid()) {
        break;
      }
      ++consecutive_failures;
      if (consecutive_failures > 64) {
        // A listener that keeps failing without being closed is not going to
        // recover; the thread stops rather than spinning.
        impl.protocol_errors.fetch_add(1, std::memory_order_relaxed);
        break;
      }
      continue;
    }
    consecutive_failures = 0;
    impl.connections_accepted.fetch_add(1, std::memory_order_relaxed);
    auto socket = std::make_shared<Socket>(std::move(accepted.value()));
    {
      std::lock_guard<std::mutex> lock(impl.queue_mutex);
      if (impl.queue.size() >= impl.config.max_pending_connections) {
        // The queue is full: the connection is closed immediately rather than
        // letting the backlog grow without bound.
        continue;
      }
      impl.queue.push_back(std::move(socket));
    }
    impl.queue_cv.notify_one();
  }
}

void FederationCoordinator::worker_loop() {
  Impl& impl = *impl_;
  for (;;) {
    std::shared_ptr<Socket> socket;
    {
      std::unique_lock<std::mutex> lock(impl.queue_mutex);
      impl.queue_cv.wait(lock, [&impl] {
        return impl.stopping.load(std::memory_order_acquire) || !impl.queue.empty();
      });
      if (impl.queue.empty()) {
        if (impl.stopping.load(std::memory_order_acquire)) {
          return;
        }
        continue;
      }
      socket = impl.queue.front();
      impl.queue.pop_front();
    }
    if (socket) {
      serve(socket);
    }
  }
}

void FederationCoordinator::shutdown_connections() {
  Impl& impl = *impl_;
  std::vector<std::shared_ptr<Socket>> sockets;
  {
    std::lock_guard<std::mutex> lock(impl.sockets_mutex);
    for (auto& weak : impl.active_sockets) {
      if (auto socket = weak.lock()) {
        sockets.push_back(std::move(socket));
      }
    }
    impl.active_sockets.clear();
  }
  for (const auto& socket : sockets) {
    // shutdown (not close): the owning worker still releases the handle.
    const Status status = socket->shutdown_both();
    (void)status;
  }
}

void FederationCoordinator::serve(const std::shared_ptr<Socket>& socket) {
  Impl& impl = *impl_;
  {
    std::lock_guard<std::mutex> lock(impl.sockets_mutex);
    impl.active_sockets.push_back(socket);
  }
  const auto unregister = [&impl, &socket]() {
    std::lock_guard<std::mutex> lock(impl.sockets_mutex);
    impl.active_sockets.erase(
        std::remove_if(impl.active_sockets.begin(), impl.active_sockets.end(),
                       [&socket](const std::weak_ptr<Socket>& weak) {
                         auto locked = weak.lock();
                         return !locked || locked == socket;
                       }),
        impl.active_sockets.end());
  };
  const auto fail = [&socket](ErrorCode code, const std::string& message) {
    ErrorResponse response;
    response.code = code;
    response.message = message;
    Writer writer;
    if (response.encode(writer).ok()) {
      const Status status = write_message(*socket, MessageType::ErrorMessage, writer.span());
      (void)status;
    }
  };

  auto hello_message = read_message(*socket);
  if (!hello_message.has_value()) {
    impl.protocol_errors.fetch_add(1, std::memory_order_relaxed);
    fail(hello_message.status().code(), hello_message.status().message());
    unregister();
    return;
  }
  if (hello_message.value().type != MessageType::Hello) {
    impl.protocol_errors.fetch_add(1, std::memory_order_relaxed);
    fail(ErrorCode::ProtocolViolation, "the first message on a connection must be a hello");
    unregister();
    return;
  }
  auto hello = decode_payload<HelloRequest>(hello_message.value().span());
  if (!hello.has_value()) {
    impl.protocol_errors.fetch_add(1, std::memory_order_relaxed);
    fail(hello.status().code(), hello.status().message());
    unregister();
    return;
  }
  if (hello.value().federation != impl.config.federation) {
    impl.protocol_errors.fetch_add(1, std::memory_order_relaxed);
    fail(ErrorCode::Refused, "the connection names a different federation");
    unregister();
    return;
  }
  if (hello.value().protocol_version != kWireProtocolVersion) {
    impl.protocol_errors.fetch_add(1, std::memory_order_relaxed);
    fail(ErrorCode::UnsupportedVersion, "the connection declares an unsupported protocol version");
    unregister();
    return;
  }

  WelcomeResponse welcome;
  {
    // The payload is assembled under the lock; the socket write happens after
    // the lock is released, so a slow peer can never block other callers.
    std::lock_guard<std::mutex> lock(impl.mutex);
    welcome.federation = impl.config.federation;
    welcome.coordinator = impl.config.node;
    welcome.coordinator_incarnation = impl.incarnation;
    welcome.logical_time = impl.tick;
    welcome.policy_id = impl.policy.id;
    welcome.policy_generation = impl.policy.generation;
    welcome.protocol_version = kWireProtocolVersion;
    auto derived = impl.derive_locked();
    if (derived.has_value()) {
      welcome.state_digest = derived.value().digest();
      welcome.epoch = derived.value().epoch;
    }
    welcome.detail = impl.durable ? "durable" : "in-memory";
  }
  {
    Writer writer;
    if (!welcome.encode(writer).ok() ||
        !write_message(*socket, MessageType::Welcome, writer.span()).ok()) {
      unregister();
      return;
    }
  }

  for (;;) {
    if (impl.stopping.load(std::memory_order_acquire)) {
      break;
    }
    auto message = read_message(*socket);
    if (!message.has_value()) {
      break;
    }
    if (message.value().type == MessageType::Goodbye) {
      break;
    }
    const Status status = handle_message(message.value(), *socket);
    if (!status.ok()) {
      impl.protocol_errors.fetch_add(1, std::memory_order_relaxed);
      fail(status.code(), status.message());
      break;
    }
  }
  const Status shutdown = socket->shutdown_send();
  (void)shutdown;
  unregister();
}

Status FederationCoordinator::handle_message(const Message& message, Socket& socket) {
  switch (message.type) {
    case MessageType::Ping: {
      Writer writer;
      return write_message(socket, MessageType::Pong, writer.span());
    }
    case MessageType::SubmitArtifact: {
      auto artifact = decode_payload<Artifact>(message.span());
      if (!artifact.has_value()) {
        return artifact.status();
      }
      auto outcome = submit_artifact(artifact.value());
      if (!outcome.has_value()) {
        return outcome.status();
      }
      ArtifactResponse response;
      response.code = outcome.value().disposition == SubmissionDisposition::Invalid
                          ? ErrorCode::InvalidArgument
                          : ErrorCode::Ok;
      response.detail = std::string(to_string(outcome.value().disposition)) + ": " +
                        outcome.value().detail;
      response.artifact_digest = outcome.value().artifact_digest;
      response.state_digest = outcome.value().state_digest;
      response.outcome = outcome.value().disposition == SubmissionDisposition::Applied
                             ? Outcome::Granted
                             : Outcome::Refused;
      response.already_present = outcome.value().disposition == SubmissionDisposition::Duplicate;
      response.rejected = outcome.value().disposition == SubmissionDisposition::Rejected ||
                          outcome.value().disposition == SubmissionDisposition::Invalid;
      response.artifact_count = outcome.value().artifact_count;
      Writer writer;
      Status status = response.encode(writer);
      if (!status.ok()) {
        return status;
      }
      return write_message(socket, MessageType::SubmitArtifactResult, writer.span());
    }
    case MessageType::QueryDigest: {
      const CoordinatorStats current = stats();
      DigestResponse response;
      response.state_digest = current.state_digest;
      response.epoch = current.epoch;
      response.logical_time = current.logical_time;
      response.artifact_count = current.artifacts;
      response.member_count = current.members;
      response.active_member_count = current.active_members;
      response.reconciling = current.reconciling;
      Writer writer;
      Status status = response.encode(writer);
      if (!status.ok()) {
        return status;
      }
      return write_message(socket, MessageType::DigestValue, writer.span());
    }
    case MessageType::QueryState: {
      auto current = state();
      if (!current.has_value()) {
        return current.status();
      }
      JsonWriter json;
      render_state_json(current.value(), json);
      StateResponse response;
      response.state_digest = current.value().digest();
      response.json = json.str();
      Writer writer;
      Status status = response.encode(writer);
      if (!status.ok()) {
        return status;
      }
      return write_message(socket, MessageType::StateValue, writer.span());
    }
    case MessageType::AuthorityQuery: {
      auto request = decode_payload<AuthorityRequest>(message.span());
      if (!request.has_value()) {
        return request.status();
      }
      auto decision = evaluate(request.value());
      if (!decision.has_value()) {
        return decision.status();
      }
      AuthorityResponse response;
      response.decision = decision.value();
      Writer writer;
      Status status = response.encode(writer);
      if (!status.ok()) {
        return status;
      }
      return write_message(socket, MessageType::AuthorityResult, writer.span());
    }
    case MessageType::IssueLease: {
      auto request = decode_payload<LeaseIssueRequest>(message.span());
      if (!request.has_value()) {
        return request.status();
      }
      LeaseRequest lease_request;
      lease_request.holder = request.value().holder;
      lease_request.scopes = request.value().scopes;
      lease_request.not_after_epoch = request.value().not_after_epoch;
      lease_request.lifetime_ticks = request.value().lifetime_ticks;
      auto lease = issue_lease(lease_request);
      LeaseResponse response;
      if (lease.has_value()) {
        response.code = ErrorCode::Ok;
        response.detail = "lease issued";
        response.lease = lease.value();
      } else {
        response.code = lease.status().code();
        response.detail = lease.status().message();
      }
      Writer writer;
      Status status = response.encode(writer);
      if (!status.ok()) {
        return status;
      }
      return write_message(socket, MessageType::LeaseResult, writer.span());
    }
    case MessageType::RevokeLease: {
      auto request = decode_payload<LeaseRevokeRequest>(message.span());
      if (!request.has_value()) {
        return request.status();
      }
      const Status result =
          revoke_lease(request.value().lease, request.value().reason, request.value().detail);
      SimpleResponse response;
      response.code = result.code();
      response.detail = result.ok() ? "lease revoked" : result.message();
      Writer writer;
      Status encoded = response.encode(writer);
      if (!encoded.ok()) {
        return encoded;
      }
      return write_message(socket, MessageType::SimpleResult, writer.span());
    }
    case MessageType::ReportObservation: {
      auto request = decode_payload<ObservationRequest>(message.span());
      if (!request.has_value()) {
        return request.status();
      }
      const Status result = report_observation(request.value().observation);
      SimpleResponse response;
      response.code = result.code();
      response.detail = result.ok() ? "observation recorded" : result.message();
      Writer writer;
      Status encoded = response.encode(writer);
      if (!encoded.ok()) {
        return encoded;
      }
      return write_message(socket, MessageType::SimpleResult, writer.span());
    }
    case MessageType::AdvanceTime: {
      auto request = decode_payload<TimeAdvanceRequest>(message.span());
      if (!request.has_value()) {
        return request.status();
      }
      const Status result = advance_time(request.value().to);
      SimpleResponse response;
      response.code = result.code();
      response.detail = result.ok() ? "logical clock advanced" : result.message();
      Writer writer;
      Status encoded = response.encode(writer);
      if (!encoded.ok()) {
        return encoded;
      }
      return write_message(socket, MessageType::SimpleResult, writer.span());
    }
    case MessageType::FenceMember:
    case MessageType::AdvanceEpoch:
    case MessageType::CompleteReconciliation: {
      auto request = decode_payload<MemberActionRequest>(message.span());
      if (!request.has_value()) {
        return request.status();
      }
      Status result = Status::success();
      if (message.type == MessageType::FenceMember) {
        result = fence_member(request.value().subject, request.value().lineage,
                              request.value().reason, request.value().detail);
      } else if (message.type == MessageType::AdvanceEpoch) {
        result = advance_epoch(request.value().epoch, request.value().reason,
                               request.value().detail);
      } else {
        result = complete_reconciliation(request.value().epoch);
      }
      SimpleResponse response;
      response.code = result.code();
      response.detail = result.ok() ? "accepted" : result.message();
      Writer writer;
      Status encoded = response.encode(writer);
      if (!encoded.ok()) {
        return encoded;
      }
      return write_message(socket, MessageType::SimpleResult, writer.span());
    }
    case MessageType::QueryArtifacts: {
      auto list = artifacts();
      if (!list.has_value()) {
        return list.status();
      }
      ArtifactListResponse response;
      response.artifacts = list.value();
      auto current = state();
      if (current.has_value()) {
        response.state_digest = current.value().digest();
      }
      Writer writer;
      Status status = response.encode(writer);
      if (!status.ok()) {
        return status;
      }
      return write_message(socket, MessageType::ArtifactListValue, writer.span());
    }
    case MessageType::QueryLeases: {
      auto list = leases();
      if (!list.has_value()) {
        return list.status();
      }
      LeaseListResponse response;
      response.leases = list.value();
      Writer writer;
      Status status = response.encode(writer);
      if (!status.ok()) {
        return status;
      }
      return write_message(socket, MessageType::LeaseListValue, writer.span());
    }
    case MessageType::StatsQuery: {
      const CoordinatorStats current = stats();
      StatsResponse response;
      response.state_digest = current.state_digest;
      response.epoch = current.epoch;
      response.logical_time = current.logical_time;
      response.artifacts = current.artifacts;
      response.rejected_artifacts = current.rejected_artifacts;
      response.duplicate_artifacts = current.duplicate_artifacts;
      response.members = current.members;
      response.active_members = current.active_members;
      response.leases = current.leases;
      response.replay_entries = current.replay_entries;
      response.connections_accepted = current.connections_accepted;
      response.protocol_errors = current.protocol_errors;
      response.journal_records = current.journal_records;
      response.journal_bytes = current.journal_bytes;
      response.reconciling = current.reconciling;
      response.partition_state = current.partition_state;
      response.transport = current.transport;
      Writer writer;
      Status status = response.encode(writer);
      if (!status.ok()) {
        return status;
      }
      return write_message(socket, MessageType::StatsValue, writer.span());
    }
    default:
      return Status::make(ErrorCode::ProtocolViolation,
                          "message type " + std::string(to_string(message.type)) +
                              " is not accepted by this coordinator");
  }
}

}  // namespace fabric_federation

