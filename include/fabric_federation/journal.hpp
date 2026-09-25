// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Versioned, integrity-checked, bounded, append-only persistence.
//
// Layout
//   header : magic "FFEDJRNL" | u32 format_version | u32 flags | u32 header_size
//            | 32-byte sha256 over the preceding header bytes
//   record : u32 payload_length | u16 record_type | u16 record_version
//            | u64 sequence | payload | 32-byte sha256 over the record header
//            and payload | u32 trailer magic
//
// Recovery is conservative and is reported, never silent:
//   * a torn tail (a record whose length prefix or payload is incomplete) is
//     truncated back to the last complete record and reported as recovered;
//     the recovered prefix is a valid history,
//   * a complete record that fails its digest means the file is not a
//     prefix-consistent history. The journal is opened read-only and the
//     operator must repair or discard it. It is never silently truncated,
//   * an unknown record type or an unsupported record version stops recovery at
//     that record and marks the journal non-writable. Unknown semantics are not
//     skipped.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/bounds.hpp"
#include "fabric_federation/digest.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/export.hpp"

namespace fabric_federation {

inline constexpr std::uint64_t kJournalRecordTrailerMagic = 0x4a4e4452u;  // "RDNJ" little-endian
inline constexpr std::size_t kJournalHeaderBytes = 16 + Digest::kSize;
inline constexpr std::size_t kJournalRecordHeaderBytes = 4 + 2 + 2 + 8;

enum class JournalRecordType : std::uint16_t {
  FederationIdentity = 1,
  FederationGenesis = 2,
  Policy = 3,
  Artifact = 4,
  Lease = 5,
  LeaseRevocation = 6,
  RequestDecision = 7,
  PartitionObservation = 8,
  TickHighWater = 9,
  CoordinatorIncarnation = 10,
  EpochState = 11,
};

[[nodiscard]] FFED_API std::string_view to_string(JournalRecordType type) noexcept;
[[nodiscard]] FFED_API bool parse_journal_record_type(std::string_view text,
                                                      JournalRecordType& out) noexcept;

enum class JournalOpenMode {
  // The file must exist. Nothing is written.
  ReadOnlyExisting,
  // The file is created if absent and opened for appending; a torn tail is
  // truncated when the options permit it.
  OpenOrCreateReadWrite,
  // The file is truncated to a fresh journal.
  CreateTruncating,
};

enum class RecoveryOutcome : std::uint8_t {
  Clean = 0,
  // The tail was incomplete and was discarded; the recovered prefix is valid.
  TornTailRecovered,
  // A complete record failed its digest. The prefix before it is valid but the
  // journal cannot be appended to.
  CorruptRecord,
  // A record declares a format or type this build does not implement.
  UnsupportedRecord,
  // The header is missing, short or invalid.
  InvalidHeader,
  // The file exists but holds zero records.
  Empty,
  // Record or byte bounds were exceeded.
  BoundsExceeded,
};

[[nodiscard]] FFED_API std::string_view to_string(RecoveryOutcome outcome) noexcept;

struct RecoveryDiagnostic {
  RecoveryOutcome outcome = RecoveryOutcome::Clean;
  std::uint64_t offset = 0;
  std::string detail;
};

struct JournalRecovery {
  RecoveryOutcome outcome = RecoveryOutcome::Empty;
  std::uint64_t good_bytes = 0;
  std::uint64_t file_bytes = 0;
  std::size_t record_count = 0;
  // False when appending would risk building on an inconsistent history.
  bool writable = true;
  std::string detail;
  std::vector<RecoveryDiagnostic> diagnostics;
};

struct JournalOptions {
  std::uint64_t max_bytes = kMaxJournalBytes;
  std::size_t max_records = kMaxArtifacts * 4u;
  std::uint32_t max_payload_bytes = static_cast<std::uint32_t>(kMaxJournalRecordBytes);
  // Truncating a torn tail is the only automatic repair this runtime performs,
  // and it is always reported. A digest failure is never auto-repaired.
  bool truncate_torn_tail = true;
};

struct JournalRecord {
  JournalRecordType type = JournalRecordType::Artifact;
  std::uint64_t sequence = 0;
  std::vector<std::byte> payload;

  [[nodiscard]] Digest payload_digest() const;
};

class FFED_API Journal {
 public:
  Journal() = default;
  Journal(Journal&& other) noexcept;
  Journal& operator=(Journal&& other) noexcept;
  Journal(const Journal&) = delete;
  Journal& operator=(const Journal&) = delete;
  ~Journal();

  [[nodiscard]] static Result<Journal> open(const std::filesystem::path& path,
                                            JournalOpenMode mode,
                                            const JournalOptions& options = JournalOptions{});

  [[nodiscard]] const JournalRecovery& recovery() const noexcept { return recovery_; }
  [[nodiscard]] bool writable() const noexcept { return handle_ != nullptr && recovery_.writable; }
  [[nodiscard]] bool is_open() const noexcept { return handle_ != nullptr; }
  [[nodiscard]] std::uint64_t size_bytes() const noexcept { return size_bytes_; }
  [[nodiscard]] std::uint64_t next_sequence() const noexcept { return next_sequence_; }
  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

  // Appends one record and flushes it to the operating system. Returns
  // CapacityExceeded once max_bytes would be crossed, so growth is bounded.
  [[nodiscard]] Status append(JournalRecordType type, std::span<const std::byte> payload);
  [[nodiscard]] Status append(const JournalRecord& record);
  [[nodiscard]] Status flush();

  // Reads the whole recovered history. Bounded by the supplied limits; a
  // history larger than the bound fails instead of allocating without limit.
  [[nodiscard]] Result<std::vector<JournalRecord>> load(std::size_t max_records,
                                                        std::size_t max_payload_bytes) const;

  // Atomically replaces the journal contents with `records`. The new content is
  // written to a sibling temporary file, flushed, and moved over the original,
  // so a crash leaves either the old or the new complete history.
  [[nodiscard]] Status compact(const std::vector<JournalRecord>& records);

  [[nodiscard]] Status close();

 private:
  void release() noexcept;

  std::filesystem::path path_;
  void* handle_ = nullptr;  // HANDLE on Windows, int fd elsewhere, stored as void*
  JournalOptions options_;
  JournalRecovery recovery_;
  std::uint64_t size_bytes_ = 0;
  std::uint64_t next_sequence_ = 1;
};

}  // namespace fabric_federation
