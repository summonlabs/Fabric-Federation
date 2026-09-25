// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Persistence tests: versioned layout, integrity checking, conservative
// recovery of torn and corrupt state, bounds, compaction and restart
// behaviour.
#include <atomic>
#include <filesystem>
#include <fstream>

#include "fixture.hpp"
#include "test_harness.hpp"

using namespace fabric_federation;
using namespace ffed_test;

namespace {

struct Scratch {
  std::filesystem::path directory;

  Scratch() {
    static std::atomic<unsigned long long> counter{0};
    directory = std::filesystem::temp_directory_path() /
                ("ffed-journal-" + std::to_string(counter.fetch_add(1)));
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
};

std::vector<std::byte> read_file(const std::filesystem::path& path) {
  std::ifstream stream(path, std::ios::binary);
  std::vector<char> raw((std::istreambuf_iterator<char>(stream)),
                        std::istreambuf_iterator<char>());
  std::vector<std::byte> out(raw.size());
  for (std::size_t i = 0; i < raw.size(); ++i) {
    out[i] = static_cast<std::byte>(static_cast<unsigned char>(raw[i]));
  }
  return out;
}

void write_file(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
}

}  // namespace

FFED_TEST(journal, append_load_round_trip_and_reopen) {
  Scratch scratch;
  const auto path = scratch.file("round-trip.fedjournal");
  {
    auto journal = Journal::open(path, JournalOpenMode::CreateTruncating);
    FFED_REQUIRE(journal.has_value());
    FFED_CHECK_EQ(journal.value().recovery().outcome, RecoveryOutcome::Empty);
    for (std::uint64_t i = 0; i < 8; ++i) {
      std::vector<std::byte> payload(32, std::byte{static_cast<unsigned char>(i)});
      FFED_REQUIRE(journal.value().append(JournalRecordType::Artifact, payload).ok());
    }
    FFED_CHECK(journal.value().recovery().writable);
    FFED_REQUIRE(journal.value().close().ok());
  }
  {
    auto journal = Journal::open(path, JournalOpenMode::ReadOnlyExisting);
    FFED_REQUIRE(journal.has_value());
    FFED_CHECK_EQ(journal.value().recovery().outcome, RecoveryOutcome::Clean);
    FFED_CHECK_EQ(journal.value().recovery().record_count, std::size_t{8});
    auto records = journal.value().load(1024, 1024);
    FFED_REQUIRE(records.has_value());
    FFED_CHECK_EQ(records.value().size(), std::size_t{8});
    for (std::size_t i = 0; i < records.value().size(); ++i) {
      FFED_CHECK_EQ(records.value()[i].sequence, static_cast<std::uint64_t>(i + 1));
      FFED_CHECK_EQ(std::to_integer<int>(records.value()[i].payload.front()),
                    static_cast<int>(i));
    }
  }
}

FFED_TEST(journal, torn_tail_is_recovered_and_reported) {
  Scratch scratch;
  const auto path = scratch.file("torn.fedjournal");
  {
    auto journal = Journal::open(path, JournalOpenMode::CreateTruncating);
    FFED_REQUIRE(journal.has_value());
    for (std::uint64_t i = 0; i < 4; ++i) {
      std::vector<std::byte> payload(64, std::byte{static_cast<unsigned char>(i)});
      FFED_REQUIRE(journal.value().append(JournalRecordType::Artifact, payload).ok());
    }
    FFED_REQUIRE(journal.value().close().ok());
  }
  const std::vector<std::byte> complete = read_file(path);
  // Remove the last 20 bytes: the final record is now incomplete.
  std::vector<std::byte> torn(complete.begin(), complete.end() - 20);
  write_file(path, torn);

  auto journal = Journal::open(path, JournalOpenMode::OpenOrCreateReadWrite);
  FFED_REQUIRE(journal.has_value());
  FFED_CHECK_EQ(journal.value().recovery().outcome, RecoveryOutcome::TornTailRecovered);
  FFED_CHECK(journal.value().recovery().writable);
  FFED_CHECK_EQ(journal.value().recovery().record_count, std::size_t{3});
  auto records = journal.value().load(1024, 1024);
  FFED_REQUIRE(records.has_value());
  FFED_CHECK_EQ(records.value().size(), std::size_t{3});
  // Appending after recovery continues the history.
  std::vector<std::byte> payload(16, std::byte{0x7f});
  FFED_REQUIRE(journal.value().append(JournalRecordType::Artifact, payload).ok());
  FFED_REQUIRE(journal.value().close().ok());

  auto reopened = Journal::open(path, JournalOpenMode::ReadOnlyExisting);
  FFED_REQUIRE(reopened.has_value());
  FFED_CHECK_EQ(reopened.value().recovery().outcome, RecoveryOutcome::Clean);
  FFED_CHECK_EQ(reopened.value().recovery().record_count, std::size_t{4});
}

FFED_TEST(journal, corrupt_record_stops_recovery_and_forbids_appending) {
  Scratch scratch;
  const auto path = scratch.file("corrupt.fedjournal");
  {
    auto journal = Journal::open(path, JournalOpenMode::CreateTruncating);
    FFED_REQUIRE(journal.has_value());
    for (std::uint64_t i = 0; i < 3; ++i) {
      std::vector<std::byte> payload(48, std::byte{static_cast<unsigned char>(i)});
      FFED_REQUIRE(journal.value().append(JournalRecordType::Artifact, payload).ok());
    }
    FFED_REQUIRE(journal.value().close().ok());
  }
  std::vector<std::byte> bytes = read_file(path);
  // Flip one byte in the middle of the second record's payload.
  bytes[bytes.size() / 2] = static_cast<std::byte>(
      std::to_integer<unsigned char>(bytes[bytes.size() / 2]) ^ 0xffu);
  write_file(path, bytes);

  auto journal = Journal::open(path, JournalOpenMode::OpenOrCreateReadWrite);
  FFED_REQUIRE(journal.has_value());
  FFED_CHECK_EQ(journal.value().recovery().outcome, RecoveryOutcome::CorruptRecord);
  FFED_CHECK(!journal.value().recovery().writable);
  FFED_CHECK(!journal.value().recovery().diagnostics.empty());
  std::vector<std::byte> payload(8, std::byte{0});
  FFED_CHECK_EQ(journal.value().append(JournalRecordType::Artifact, payload).code(),
                ErrorCode::Refused);
  // The corrupt file is never silently rewritten.
  FFED_CHECK_EQ(read_file(path).size(), bytes.size());
}

FFED_TEST(journal, unsupported_format_version_is_refused) {
  Scratch scratch;
  const auto path = scratch.file("version.fedjournal");
  {
    auto journal = Journal::open(path, JournalOpenMode::CreateTruncating);
    FFED_REQUIRE(journal.has_value());
    FFED_REQUIRE(journal.value().close().ok());
  }
  std::vector<std::byte> bytes = read_file(path);
  FFED_REQUIRE(bytes.size() >= 48);
  // Rewrite the format version and repair the header digest so the failure is
  // specifically about the version.
  store_u32_le(bytes.data() + 8, kJournalFormatVersion + 7);
  const Digest header_digest = Sha256::hash(std::span<const std::byte>(bytes.data(), 16));
  for (std::size_t i = 0; i < Digest::kSize; ++i) {
    bytes[16 + i] = static_cast<std::byte>(header_digest.bytes()[i]);
  }
  write_file(path, bytes);
  auto journal = Journal::open(path, JournalOpenMode::OpenOrCreateReadWrite);
  FFED_REQUIRE(journal.has_value());
  FFED_CHECK_EQ(journal.value().recovery().outcome, RecoveryOutcome::UnsupportedRecord);
  FFED_CHECK(!journal.value().recovery().writable);
}

FFED_TEST(journal, invalid_header_is_refused) {
  Scratch scratch;
  const auto path = scratch.file("header.fedjournal");
  std::vector<std::byte> bytes(64, std::byte{0x11});
  write_file(path, bytes);
  auto journal = Journal::open(path, JournalOpenMode::OpenOrCreateReadWrite);
  FFED_REQUIRE(journal.has_value());
  FFED_CHECK_EQ(journal.value().recovery().outcome, RecoveryOutcome::InvalidHeader);
  FFED_CHECK(!journal.value().recovery().writable);

  const auto short_path = scratch.file("short.fedjournal");
  write_file(short_path, std::vector<std::byte>(10, std::byte{0x22}));
  auto short_journal = Journal::open(short_path, JournalOpenMode::OpenOrCreateReadWrite);
  FFED_REQUIRE(short_journal.has_value());
  FFED_CHECK_EQ(short_journal.value().recovery().outcome, RecoveryOutcome::InvalidHeader);
  FFED_CHECK(!short_journal.value().recovery().writable);
}

FFED_TEST(journal, non_monotonic_sequence_is_treated_as_a_rolled_back_history) {
  Scratch scratch;
  const auto path = scratch.file("sequence.fedjournal");
  {
    auto journal = Journal::open(path, JournalOpenMode::CreateTruncating);
    FFED_REQUIRE(journal.has_value());
    for (std::uint64_t i = 0; i < 3; ++i) {
      std::vector<std::byte> payload(16, std::byte{static_cast<unsigned char>(i)});
      FFED_REQUIRE(journal.value().append(JournalRecordType::Artifact, payload).ok());
    }
    FFED_REQUIRE(journal.value().close().ok());
  }
  std::vector<std::byte> bytes = read_file(path);
  // Overwrite the second record's sequence with a value lower than the first
  // record's, then repair that record's digest so the sequence check is what
  // fails.
  const std::size_t first_record = kJournalHeaderBytes;
  const std::size_t second_record =
      first_record + kJournalRecordHeaderBytes + 16 + Digest::kSize + 4;
  store_u64_le(bytes.data() + second_record + 8, 1);
  const Digest record_digest = Sha256::hash(
      std::span<const std::byte>(bytes.data() + second_record, kJournalRecordHeaderBytes + 16));
  for (std::size_t i = 0; i < Digest::kSize; ++i) {
    bytes[second_record + kJournalRecordHeaderBytes + 16 + i] =
        static_cast<std::byte>(record_digest.bytes()[i]);
  }
  write_file(path, bytes);
  auto journal = Journal::open(path, JournalOpenMode::OpenOrCreateReadWrite);
  FFED_REQUIRE(journal.has_value());
  FFED_CHECK_EQ(journal.value().recovery().outcome, RecoveryOutcome::CorruptRecord);
  FFED_CHECK(!journal.value().recovery().writable);
}

FFED_TEST(journal, growth_is_bounded_and_oversized_payloads_are_refused) {
  Scratch scratch;
  auto journal = Journal::open(scratch.file("bounded.fedjournal"),
                               JournalOpenMode::CreateTruncating,
                               JournalOptions{.max_bytes = 4096, .max_records = 16});
  FFED_REQUIRE(journal.has_value());
  std::vector<std::byte> large(kMaxJournalRecordBytes + 1, std::byte{0});
  FFED_CHECK_EQ(journal.value().append(JournalRecordType::Artifact, large).code(),
                ErrorCode::BoundsExceeded);

  bool hit_bound = false;
  for (int i = 0; i < 1000 && !hit_bound; ++i) {
    std::vector<std::byte> payload(256, std::byte{0});
    const Status status = journal.value().append(JournalRecordType::Artifact, payload);
    if (status.code() == ErrorCode::CapacityExceeded) {
      hit_bound = true;
    } else {
      FFED_REQUIRE(status.ok());
    }
  }
  FFED_CHECK(hit_bound);
  FFED_CHECK(journal.value().size_bytes() <= 4096);
}

FFED_TEST(journal, compaction_replaces_the_history_atomically) {
  Scratch scratch;
  const auto path = scratch.file("compact.fedjournal");
  auto journal = Journal::open(path, JournalOpenMode::CreateTruncating);
  FFED_REQUIRE(journal.has_value());
  for (std::uint64_t i = 0; i < 32; ++i) {
    std::vector<std::byte> payload(64, std::byte{static_cast<unsigned char>(i)});
    FFED_REQUIRE(journal.value().append(JournalRecordType::Artifact, payload).ok());
  }
  std::vector<JournalRecord> keep;
  for (std::uint64_t i = 0; i < 4; ++i) {
    JournalRecord record;
    record.type = JournalRecordType::Artifact;
    record.payload.assign(32, std::byte{static_cast<unsigned char>(i)});
    keep.push_back(std::move(record));
  }
  FFED_REQUIRE(journal.value().compact(keep).ok());
  FFED_CHECK_EQ(journal.value().recovery().record_count, std::size_t{4});
  auto records = journal.value().load(64, 1024);
  FFED_REQUIRE(records.has_value());
  FFED_CHECK_EQ(records.value().size(), std::size_t{4});
  FFED_CHECK_EQ(records.value().front().sequence, std::uint64_t{1});
  FFED_REQUIRE(journal.value().close().ok());
  FFED_CHECK(!std::filesystem::exists(path.string() + ".tmp"));
}

FFED_TEST(journal, coordinator_restart_fences_leases_and_keeps_history) {
  Scratch scratch;
  const FederationFixture fixture;
  const auto path = scratch.file("coordinator.fedjournal");
  const FixtureMember candidate = make_member("restart", 1);
  Digest baseline;
  {
    auto coordinator = make_coordinator(fixture, path);
    FFED_REQUIRE(coordinator.has_value());
    join_and_observe(*coordinator.value(), fixture.federation, candidate, fixture.founder);
    LeaseRequest request;
    request.holder = candidate.member;
    request.scopes = {ScopeGrant{ScopeId::parse("federation.route.advertise").value(),
                                 AuthorityVerb::Mutate}};
    request.lifetime_ticks = Tick(1000);
    auto lease = coordinator.value()->issue_lease(request);
    FFED_REQUIRE(lease.has_value());
    baseline = coordinator.value()->state_digest();
    FFED_CHECK(!baseline.is_zero());
    FFED_REQUIRE(coordinator.value()->stop().ok());
  }
  {
    auto coordinator = make_coordinator(fixture, path);
    FFED_REQUIRE(coordinator.has_value());
    // The evidence survived.
    auto state = coordinator.value()->state();
    FFED_REQUIRE(state.has_value());
    const MemberState* member = state.value().find(candidate.member);
    FFED_REQUIRE(member != nullptr);
    FFED_CHECK_EQ(member->lifecycle, MemberLifecycleState::Active);
    FFED_CHECK_EQ(member->current_identity.constitution, candidate.constitution.digest());

    // Every lease from the previous incarnation is historical evidence.
    auto leases = coordinator.value()->leases();
    FFED_REQUIRE(leases.has_value());
    FFED_CHECK_EQ(leases.value().size(), std::size_t{1});
    auto decision = coordinator.value()->state();
    FFED_REQUIRE(decision.has_value());
    FFED_CHECK_EQ(decision.value().leases.front().state, LeaseState::StaleIssuer);
    FFED_CHECK_EQ(decision.value().leases.front().reason, ReasonCode::LeaseStaleIssuer);

    AuthorityRequest request;
    request.id = RequestId::derive("restart", 1);
    request.federation = fixture.federation;
    request.epoch_seen = decision.value().epoch;
    request.actor = candidate.identity();
    request.requested = ScopeGrant{ScopeId::parse("federation.route.advertise").value(),
                                   AuthorityVerb::Mutate};
    request.lease = leases.value().front().id;
    auto verdict = coordinator.value()->evaluate(request);
    FFED_REQUIRE(verdict.has_value());
    FFED_CHECK_EQ(verdict.value().outcome, Outcome::Stale);
    FFED_CHECK(verdict.value().explanation.has(ReasonCode::LeaseStaleIssuer));
    FFED_REQUIRE(coordinator.value()->stop().ok());
  }
}

FFED_TEST(journal, revocation_and_replay_ledger_survive_a_restart) {
  Scratch scratch;
  const FederationFixture fixture;
  const auto path = scratch.file("revocation.fedjournal");
  const FixtureMember candidate = make_member("revival", 1);
  LeaseId lease_id;
  RequestId request_id;
  {
    auto coordinator = make_coordinator(fixture, path);
    FFED_REQUIRE(coordinator.has_value());
    join_and_observe(*coordinator.value(), fixture.federation, candidate, fixture.founder);
    LeaseRequest request;
    request.holder = candidate.member;
    request.scopes = {ScopeGrant{ScopeId::parse("federation.route.advertise").value(),
                                 AuthorityVerb::Mutate}};
    request.lifetime_ticks = Tick(10000);
    auto lease = coordinator.value()->issue_lease(request);
    FFED_REQUIRE(lease.has_value());
    lease_id = lease.value().id;
    FFED_REQUIRE(coordinator.value()
                     ->revoke_lease(lease_id, ReasonCode::LeaseRevoked, "revoked before restart")
                     .ok());

    auto state = coordinator.value()->state();
    FFED_REQUIRE(state.has_value());
    AuthorityRequest query;
    query.id = RequestId::derive("revival", 77);
    query.federation = fixture.federation;
    query.epoch_seen = state.value().epoch;
    query.actor = candidate.identity();
    query.requested = ScopeGrant{ScopeId::parse("federation.route.observe").value(),
                                 AuthorityVerb::Observe};
    request_id = query.id;
    auto decision = coordinator.value()->evaluate(query);
    FFED_REQUIRE(decision.has_value());
    FFED_CHECK_EQ(decision.value().outcome, Outcome::Granted);
    FFED_REQUIRE(coordinator.value()->stop().ok());
  }
  {
    auto coordinator = make_coordinator(fixture, path);
    FFED_REQUIRE(coordinator.has_value());
    auto leases = coordinator.value()->leases();
    FFED_REQUIRE(leases.has_value());
    FFED_REQUIRE(leases.value().size() == 1);
    // A revoked lease is not revived by a restart.
    FFED_CHECK(leases.value().front().revoked);
    FFED_CHECK_EQ(leases.value().front().revoke_reason, ReasonCode::LeaseRevoked);

    auto state = coordinator.value()->state();
    FFED_REQUIRE(state.has_value());
    AuthorityRequest replay;
    replay.id = request_id;
    replay.federation = fixture.federation;
    replay.epoch_seen = state.value().epoch;
    replay.actor = candidate.identity();
    replay.requested = ScopeGrant{ScopeId::parse("federation.route.observe").value(),
                                  AuthorityVerb::Observe};
    auto decision = coordinator.value()->evaluate(replay);
    FFED_REQUIRE(decision.has_value());
    FFED_CHECK_EQ(decision.value().outcome, Outcome::Replayed);
    FFED_CHECK_EQ(coordinator.value()->stats().replay_entries, std::uint64_t{1});
    FFED_REQUIRE(coordinator.value()->stop().ok());
  }
}

FFED_TEST_MAIN()
