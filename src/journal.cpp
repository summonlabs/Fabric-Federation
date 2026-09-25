// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/journal.hpp"

#include "fabric_federation/codec.hpp"
#include "fabric_federation/version.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fabric_federation {
namespace {

constexpr char kMagic[8] = {'F', 'F', 'E', 'D', 'J', 'R', 'N', 'L'};
constexpr std::uint32_t kRecordTrailerMagicValue = 0x4a4e4452u;  // written little-endian
constexpr std::uint16_t kRecordVersion = 1;

std::string windows_error_text(unsigned long code) {
  return "operating system error " + std::to_string(code);
}

std::filesystem::path temporary_path_for(const std::filesystem::path& path) {
  std::filesystem::path temporary = path;
  temporary += ".tmp";
  return temporary;
}

}  // namespace

std::string_view to_string(JournalRecordType type) noexcept {
  switch (type) {
    case JournalRecordType::FederationIdentity:
      return "federation-identity";
    case JournalRecordType::FederationGenesis:
      return "federation-genesis";
    case JournalRecordType::Policy:
      return "policy";
    case JournalRecordType::Artifact:
      return "artifact";
    case JournalRecordType::Lease:
      return "lease";
    case JournalRecordType::LeaseRevocation:
      return "lease-revocation";
    case JournalRecordType::RequestDecision:
      return "request-decision";
    case JournalRecordType::PartitionObservation:
      return "partition-observation";
    case JournalRecordType::TickHighWater:
      return "tick-high-water";
    case JournalRecordType::CoordinatorIncarnation:
      return "coordinator-incarnation";
    case JournalRecordType::EpochState:
      return "epoch-state";
  }
  return "unknown";
}

bool parse_journal_record_type(std::string_view text, JournalRecordType& out) noexcept {
  for (std::uint16_t value = static_cast<std::uint16_t>(JournalRecordType::FederationIdentity);
       value <= static_cast<std::uint16_t>(JournalRecordType::EpochState); ++value) {
    const auto type = static_cast<JournalRecordType>(value);
    if (to_string(type) == text) {
      out = type;
      return true;
    }
  }
  return false;
}

std::string_view to_string(RecoveryOutcome outcome) noexcept {
  switch (outcome) {
    case RecoveryOutcome::Clean:
      return "CLEAN";
    case RecoveryOutcome::TornTailRecovered:
      return "TORN_TAIL_RECOVERED";
    case RecoveryOutcome::CorruptRecord:
      return "CORRUPT_RECORD";
    case RecoveryOutcome::UnsupportedRecord:
      return "UNSUPPORTED_RECORD";
    case RecoveryOutcome::InvalidHeader:
      return "INVALID_HEADER";
    case RecoveryOutcome::Empty:
      return "EMPTY";
    case RecoveryOutcome::BoundsExceeded:
      return "BOUNDS_EXCEEDED";
  }
  return "INVALID_HEADER";
}

Digest JournalRecord::payload_digest() const {
  return Sha256::hash(std::span<const std::byte>(payload.data(), payload.size()));
}

Journal::Journal(Journal&& other) noexcept
    : path_(std::move(other.path_)),
      handle_(other.handle_),
      options_(other.options_),
      recovery_(std::move(other.recovery_)),
      size_bytes_(other.size_bytes_),
      next_sequence_(other.next_sequence_) {
  other.handle_ = nullptr;
  other.size_bytes_ = 0;
  other.next_sequence_ = 1;
}

Journal& Journal::operator=(Journal&& other) noexcept {
  if (this != &other) {
    release();
    path_ = std::move(other.path_);
    handle_ = other.handle_;
    options_ = other.options_;
    recovery_ = std::move(other.recovery_);
    size_bytes_ = other.size_bytes_;
    next_sequence_ = other.next_sequence_;
    other.handle_ = nullptr;
    other.size_bytes_ = 0;
    other.next_sequence_ = 1;
  }
  return *this;
}

Journal::~Journal() { release(); }

void Journal::release() noexcept {
  if (handle_ != nullptr) {
#if defined(_WIN32)
    ::CloseHandle(static_cast<HANDLE>(handle_));
#else
    ::close(static_cast<int>(reinterpret_cast<std::intptr_t>(handle_)));
#endif
    handle_ = nullptr;
  }
}

namespace {

// Portable wrappers over the small set of file operations the journal needs.
struct FileOps {
  static bool read_at(void* handle, std::uint64_t offset, std::byte* out, std::size_t size,
                      std::string& error) {
#if defined(_WIN32)
    LARGE_INTEGER position;
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!::SetFilePointerEx(static_cast<HANDLE>(handle), position, nullptr, FILE_BEGIN)) {
      error = windows_error_text(::GetLastError());
      return false;
    }
    std::size_t done = 0;
    while (done < size) {
      DWORD chunk = 0;
      const DWORD want = static_cast<DWORD>(size - done);
      if (!::ReadFile(static_cast<HANDLE>(handle), out + done, want, &chunk, nullptr)) {
        error = windows_error_text(::GetLastError());
        return false;
      }
      if (chunk == 0) {
        error = "unexpected end of file";
        return false;
      }
      done += chunk;
    }
    return true;
#else
    std::size_t done = 0;
    const int fd = static_cast<int>(reinterpret_cast<std::intptr_t>(handle));
    while (done < size) {
      const ssize_t got = ::pread(fd, out + done, size - done, static_cast<off_t>(offset + done));
      if (got < 0) {
        error = "read failed";
        return false;
      }
      if (got == 0) {
        error = "unexpected end of file";
        return false;
      }
      done += static_cast<std::size_t>(got);
    }
    return true;
#endif
  }

  static bool write_at(void* handle, std::uint64_t offset, const std::byte* data, std::size_t size,
                       std::string& error) {
#if defined(_WIN32)
    LARGE_INTEGER position;
    position.QuadPart = static_cast<LONGLONG>(offset);
    if (!::SetFilePointerEx(static_cast<HANDLE>(handle), position, nullptr, FILE_BEGIN)) {
      error = windows_error_text(::GetLastError());
      return false;
    }
    std::size_t done = 0;
    while (done < size) {
      DWORD written = 0;
      const DWORD want = static_cast<DWORD>(size - done);
      if (!::WriteFile(static_cast<HANDLE>(handle), data + done, want, &written, nullptr)) {
        error = windows_error_text(::GetLastError());
        return false;
      }
      if (written == 0) {
        error = "write made no progress";
        return false;
      }
      done += written;
    }
    return true;
#else
    std::size_t done = 0;
    const int fd = static_cast<int>(reinterpret_cast<std::intptr_t>(handle));
    while (done < size) {
      const ssize_t wrote = ::pwrite(fd, data + done, size - done, static_cast<off_t>(offset + done));
      if (wrote <= 0) {
        error = "write failed";
        return false;
      }
      done += static_cast<std::size_t>(wrote);
    }
    return true;
#endif
  }

  static bool flush(void* handle, std::string& error) {
#if defined(_WIN32)
    if (!::FlushFileBuffers(static_cast<HANDLE>(handle))) {
      error = windows_error_text(::GetLastError());
      return false;
    }
    return true;
#else
    if (::fsync(static_cast<int>(reinterpret_cast<std::intptr_t>(handle))) != 0) {
      error = "fsync failed";
      return false;
    }
    return true;
#endif
  }

  static bool truncate(void* handle, std::uint64_t size, std::string& error) {
#if defined(_WIN32)
    LARGE_INTEGER position;
    position.QuadPart = static_cast<LONGLONG>(size);
    if (!::SetFilePointerEx(static_cast<HANDLE>(handle), position, nullptr, FILE_BEGIN)) {
      error = windows_error_text(::GetLastError());
      return false;
    }
    if (!::SetEndOfFile(static_cast<HANDLE>(handle))) {
      error = windows_error_text(::GetLastError());
      return false;
    }
    return true;
#else
    if (::ftruncate(static_cast<int>(reinterpret_cast<std::intptr_t>(handle)),
                    static_cast<off_t>(size)) != 0) {
      error = "truncate failed";
      return false;
    }
    return true;
#endif
  }

  static bool size_of(void* handle, std::uint64_t& size, std::string& error) {
#if defined(_WIN32)
    LARGE_INTEGER result;
    if (!::GetFileSizeEx(static_cast<HANDLE>(handle), &result)) {
      error = windows_error_text(::GetLastError());
      return false;
    }
    size = static_cast<std::uint64_t>(result.QuadPart);
    return true;
#else
    struct stat info {};
    if (::fstat(static_cast<int>(reinterpret_cast<std::intptr_t>(handle)), &info) != 0) {
      error = "fstat failed";
      return false;
    }
    size = static_cast<std::uint64_t>(info.st_size);
    return true;
#endif
  }

  static void* open(const std::filesystem::path& path, bool read_only, bool create,
                    bool truncate_existing, std::string& error) {
#if defined(_WIN32)
    DWORD access = read_only ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
    DWORD share = FILE_SHARE_READ;
    DWORD disposition = OPEN_EXISTING;
    if (truncate_existing) {
      disposition = CREATE_ALWAYS;
    } else if (create) {
      disposition = OPEN_ALWAYS;
    }
    const HANDLE handle =
        ::CreateFileW(path.wstring().c_str(), access, share, nullptr, disposition,
                      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
      error = windows_error_text(::GetLastError());
      return nullptr;
    }
    return handle;
#else
    int flags = read_only ? O_RDONLY : O_RDWR;
    if (truncate_existing) {
      flags |= O_CREAT | O_TRUNC;
    } else if (create) {
      flags |= O_CREAT;
    }
    const int fd = ::open(path.c_str(), flags, 0644);
    if (fd < 0) {
      error = "open failed";
      return nullptr;
    }
    return reinterpret_cast<void*>(static_cast<std::intptr_t>(fd));
#endif
  }

  static bool replace_file(const std::filesystem::path& from, const std::filesystem::path& to,
                           std::string& error) {
#if defined(_WIN32)
    if (!::MoveFileExW(from.wstring().c_str(), to.wstring().c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
      error = windows_error_text(::GetLastError());
      return false;
    }
    return true;
#else
    if (::rename(from.c_str(), to.c_str()) != 0) {
      error = "rename failed";
      return false;
    }
    return true;
#endif
  }
};

std::vector<std::byte> make_header_bytes() {
  std::vector<std::byte> header(kJournalHeaderBytes, std::byte{0});
  std::memcpy(header.data(), kMagic, sizeof(kMagic));
  store_u32_le(header.data() + 8, kJournalFormatVersion);
  store_u32_le(header.data() + 12, 0);
  const Digest digest = Sha256::hash(std::span<const std::byte>(header.data(), 16));
  std::memcpy(header.data() + 16, digest.data(), Digest::kSize);
  return header;
}

std::vector<std::byte> make_record_bytes(const JournalRecord& record) {
  const std::size_t payload_size = record.payload.size();
  const std::size_t total = payload_size + kJournalRecordHeaderBytes + Digest::kSize + 4;
  std::vector<std::byte> bytes(total, std::byte{0});
  store_u32_le(bytes.data(), static_cast<std::uint32_t>(payload_size));
  std::uint16_t type = static_cast<std::uint16_t>(record.type);
  std::memcpy(bytes.data() + 4, &type, 2);
  std::uint16_t version = kRecordVersion;
  std::memcpy(bytes.data() + 6, &version, 2);
  store_u64_le(bytes.data() + 8, record.sequence);
  if (payload_size != 0) {
    std::memcpy(bytes.data() + kJournalRecordHeaderBytes, record.payload.data(), payload_size);
  }
  const std::size_t digest_offset = kJournalRecordHeaderBytes + payload_size;
  const Digest digest = Sha256::hash(std::span<const std::byte>(
      bytes.data(), kJournalRecordHeaderBytes + payload_size));
  std::memcpy(bytes.data() + digest_offset, digest.data(), Digest::kSize);
  store_u32_le(bytes.data() + digest_offset + Digest::kSize, kRecordTrailerMagicValue);
  return bytes;
}

}  // namespace

Result<Journal> Journal::open(const std::filesystem::path& path, JournalOpenMode mode,
                              const JournalOptions& options) {
  Journal journal;
  journal.path_ = path;
  journal.options_ = options;
  journal.recovery_.diagnostics.clear();

  const bool read_only = mode == JournalOpenMode::ReadOnlyExisting;
  const bool truncate_existing = mode == JournalOpenMode::CreateTruncating;

  std::string error;
  journal.handle_ = FileOps::open(path, read_only, mode != JournalOpenMode::ReadOnlyExisting,
                                  truncate_existing, error);
  if (journal.handle_ == nullptr) {
    if (mode == JournalOpenMode::ReadOnlyExisting) {
      return Status::make(ErrorCode::NotFound, "journal cannot be opened: " + error);
    }
    return Status::make(ErrorCode::IoError, "journal cannot be opened: " + error);
  }

  std::uint64_t file_size = 0;
  if (!FileOps::size_of(journal.handle_, file_size, error)) {
    journal.release();
    return Status::make(ErrorCode::IoError, "journal size cannot be read: " + error);
  }
  journal.recovery_.file_bytes = file_size;

  if (truncate_existing || file_size == 0) {
    const std::vector<std::byte> header = make_header_bytes();
    if (!FileOps::truncate(journal.handle_, 0, error) ||
        !FileOps::write_at(journal.handle_, 0, header.data(), header.size(), error) ||
        !FileOps::flush(journal.handle_, error)) {
      journal.release();
      return Status::make(ErrorCode::IoError, "journal header cannot be written: " + error);
    }
    journal.size_bytes_ = kJournalHeaderBytes;
    journal.next_sequence_ = 1;
    journal.recovery_.outcome = RecoveryOutcome::Empty;
    journal.recovery_.good_bytes = kJournalHeaderBytes;
    journal.recovery_.writable = !read_only;
    journal.recovery_.detail = "fresh journal";
    return journal;
  }

  if (file_size < kJournalHeaderBytes) {
    journal.recovery_.outcome = RecoveryOutcome::InvalidHeader;
    journal.recovery_.good_bytes = 0;
    journal.recovery_.writable = false;
    journal.recovery_.detail = "file is shorter than the journal header";
    RecoveryDiagnostic diagnostic;
    diagnostic.outcome = RecoveryOutcome::InvalidHeader;
    diagnostic.offset = 0;
    diagnostic.detail = journal.recovery_.detail;
    journal.recovery_.diagnostics.push_back(std::move(diagnostic));
    // A file that cannot be interpreted is never rewritten automatically.
    return journal;
  }

  std::vector<std::byte> header(kJournalHeaderBytes);
  if (!FileOps::read_at(journal.handle_, 0, header.data(), header.size(), error)) {
    journal.release();
    return Status::make(ErrorCode::IoError, "journal header cannot be read: " + error);
  }
  bool header_ok = std::memcmp(header.data(), kMagic, sizeof(kMagic)) == 0;
  const std::uint32_t format_version = load_u32_le(header.data() + 8);
  if (header_ok) {
    const Digest stored = Digest::from_bytes(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(header.data()) + 16, Digest::kSize));
    const Digest computed = Sha256::hash(std::span<const std::byte>(header.data(), 16));
    if (stored != computed) {
      header_ok = false;
    }
  }
  if (!header_ok) {
    journal.recovery_.outcome = RecoveryOutcome::InvalidHeader;
    journal.recovery_.writable = false;
    journal.recovery_.detail = "journal header magic or digest does not match";
    RecoveryDiagnostic diagnostic;
    diagnostic.outcome = RecoveryOutcome::InvalidHeader;
    diagnostic.offset = 0;
    diagnostic.detail = journal.recovery_.detail;
    journal.recovery_.diagnostics.push_back(std::move(diagnostic));
    return journal;
  }
  if (format_version != kJournalFormatVersion) {
    journal.recovery_.outcome = RecoveryOutcome::UnsupportedRecord;
    journal.recovery_.writable = false;
    journal.recovery_.detail = "journal format version " + std::to_string(format_version) +
                               " is not implemented by this build";
    RecoveryDiagnostic diagnostic;
    diagnostic.outcome = RecoveryOutcome::UnsupportedRecord;
    diagnostic.offset = 8;
    diagnostic.detail = journal.recovery_.detail;
    journal.recovery_.diagnostics.push_back(std::move(diagnostic));
    return journal;
  }

  // ---- record scan --------------------------------------------------------
  std::uint64_t offset = kJournalHeaderBytes;
  std::size_t records = 0;
  std::uint64_t previous_sequence = 0;
  RecoveryOutcome outcome = RecoveryOutcome::Empty;
  bool writable = !read_only;
  std::uint64_t good_bytes = offset;
  std::string detail = "no records";

  while (offset < file_size) {
    if (records >= options.max_records) {
      outcome = RecoveryOutcome::BoundsExceeded;
      writable = false;
      detail = "journal holds more records than the configured bound";
      RecoveryDiagnostic diagnostic;
      diagnostic.outcome = outcome;
      diagnostic.offset = offset;
      diagnostic.detail = detail;
      journal.recovery_.diagnostics.push_back(std::move(diagnostic));
      break;
    }
    if (file_size - offset < kJournalRecordHeaderBytes) {
      outcome = RecoveryOutcome::TornTailRecovered;
      detail = "trailing bytes are shorter than a record header";
      RecoveryDiagnostic diagnostic;
      diagnostic.outcome = outcome;
      diagnostic.offset = offset;
      diagnostic.detail = detail;
      journal.recovery_.diagnostics.push_back(std::move(diagnostic));
      break;
    }
    std::byte header_bytes[kJournalRecordHeaderBytes];
    if (!FileOps::read_at(journal.handle_, offset, header_bytes, sizeof(header_bytes), error)) {
      journal.release();
      return Status::make(ErrorCode::IoError, "journal record header cannot be read: " + error);
    }
    const std::uint32_t payload_length = load_u32_le(header_bytes);
    if (payload_length > options.max_payload_bytes) {
      outcome = RecoveryOutcome::BoundsExceeded;
      writable = false;
      detail = "record declares a payload larger than the configured bound";
      RecoveryDiagnostic diagnostic;
      diagnostic.outcome = outcome;
      diagnostic.offset = offset;
      diagnostic.detail = detail;
      journal.recovery_.diagnostics.push_back(std::move(diagnostic));
      break;
    }
    const std::uint64_t total =
        static_cast<std::uint64_t>(payload_length) + kJournalRecordHeaderBytes + Digest::kSize + 4;
    if (file_size - offset < total) {
      outcome = RecoveryOutcome::TornTailRecovered;
      detail = "final record is incomplete";
      RecoveryDiagnostic diagnostic;
      diagnostic.outcome = outcome;
      diagnostic.offset = offset;
      diagnostic.detail = detail;
      journal.recovery_.diagnostics.push_back(std::move(diagnostic));
      break;
    }
    std::vector<std::byte> record_bytes(static_cast<std::size_t>(total));
    if (!FileOps::read_at(journal.handle_, offset, record_bytes.data(), record_bytes.size(),
                          error)) {
      journal.release();
      return Status::make(ErrorCode::IoError, "journal record cannot be read: " + error);
    }
    const std::size_t digest_offset = kJournalRecordHeaderBytes + payload_length;
    const std::uint32_t trailer = load_u32_le(record_bytes.data() + digest_offset + Digest::kSize);
    if (trailer != kRecordTrailerMagicValue) {
      outcome = RecoveryOutcome::CorruptRecord;
      writable = false;
      detail = "record trailer magic does not match";
      RecoveryDiagnostic diagnostic;
      diagnostic.outcome = outcome;
      diagnostic.offset = offset;
      diagnostic.detail = detail;
      journal.recovery_.diagnostics.push_back(std::move(diagnostic));
      break;
    }
    const Digest stored = Digest::from_bytes(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(record_bytes.data()) + digest_offset, Digest::kSize));
    const Digest computed = Sha256::hash(
        std::span<const std::byte>(record_bytes.data(), digest_offset));
    if (stored != computed) {
      outcome = RecoveryOutcome::CorruptRecord;
      writable = false;
      detail = "record digest does not match its content";
      RecoveryDiagnostic diagnostic;
      diagnostic.outcome = outcome;
      diagnostic.offset = offset;
      diagnostic.detail = detail;
      journal.recovery_.diagnostics.push_back(std::move(diagnostic));
      break;
    }
    std::uint16_t type_value = 0;
    std::memcpy(&type_value, record_bytes.data() + 4, 2);
    if (type_value < static_cast<std::uint16_t>(JournalRecordType::FederationIdentity) ||
        type_value > static_cast<std::uint16_t>(JournalRecordType::EpochState)) {
      outcome = RecoveryOutcome::UnsupportedRecord;
      writable = false;
      detail = "record type is not implemented by this build";
      RecoveryDiagnostic diagnostic;
      diagnostic.outcome = outcome;
      diagnostic.offset = offset;
      diagnostic.detail = detail;
      journal.recovery_.diagnostics.push_back(std::move(diagnostic));
      break;
    }
    std::uint16_t record_version = 0;
    std::memcpy(&record_version, record_bytes.data() + 6, 2);
    if (record_version > kRecordVersion) {
      outcome = RecoveryOutcome::UnsupportedRecord;
      writable = false;
      detail = "record version " + std::to_string(record_version) +
               " is newer than this build implements";
      RecoveryDiagnostic diagnostic;
      diagnostic.outcome = outcome;
      diagnostic.offset = offset;
      diagnostic.detail = detail;
      journal.recovery_.diagnostics.push_back(std::move(diagnostic));
      break;
    }
    const std::uint64_t sequence = load_u64_le(record_bytes.data() + 8);
    if (records != 0 && sequence <= previous_sequence) {
      // A non-monotonic sequence means the history was spliced or rolled back.
      outcome = RecoveryOutcome::CorruptRecord;
      writable = false;
      detail = "record sequence is not strictly increasing";
      RecoveryDiagnostic diagnostic;
      diagnostic.outcome = outcome;
      diagnostic.offset = offset;
      diagnostic.detail = detail;
      journal.recovery_.diagnostics.push_back(std::move(diagnostic));
      break;
    }
    previous_sequence = sequence;
    ++records;
    offset += total;
    good_bytes = offset;
    outcome = RecoveryOutcome::Clean;
    detail = "all records verified";
  }

  journal.recovery_.outcome = outcome;
  journal.recovery_.record_count = records;
  journal.recovery_.good_bytes = good_bytes;
  journal.recovery_.writable = writable;
  journal.recovery_.detail = detail;
  journal.next_sequence_ = previous_sequence + 1;
  journal.size_bytes_ = file_size;

  if (outcome == RecoveryOutcome::TornTailRecovered && writable && options.truncate_torn_tail) {
    std::string truncate_error;
    if (FileOps::truncate(journal.handle_, good_bytes, truncate_error) &&
        FileOps::flush(journal.handle_, truncate_error)) {
      journal.size_bytes_ = good_bytes;
      journal.recovery_.detail = detail + "; the incomplete tail was discarded";
    } else {
      journal.recovery_.writable = false;
      journal.recovery_.detail = detail + "; the tail could not be discarded: " + truncate_error;
    }
  } else if (outcome == RecoveryOutcome::TornTailRecovered) {
    journal.recovery_.writable = false;
    journal.recovery_.detail = detail + "; automatic truncation is disabled";
  }
  return journal;
}

Status Journal::append(JournalRecordType type, std::span<const std::byte> payload) {
  JournalRecord record;
  record.type = type;
  record.sequence = next_sequence_;
  record.payload.assign(payload.begin(), payload.end());
  return append(record);
}

Status Journal::append(const JournalRecord& record) {
  if (handle_ == nullptr) {
    return Status::make(ErrorCode::NotInitialized, "journal is not open");
  }
  if (!recovery_.writable) {
    return Status::make(ErrorCode::Refused,
                        "journal is not writable: " + recovery_.detail);
  }
  if (record.payload.size() > options_.max_payload_bytes) {
    return Status::make(ErrorCode::BoundsExceeded, "record payload exceeds the configured bound");
  }
  JournalRecord stored = record;
  stored.sequence = next_sequence_;
  const std::vector<std::byte> bytes = make_record_bytes(stored);
  std::uint64_t total = 0;
  if (!checked_add_u64(size_bytes_, bytes.size(), total) || total > options_.max_bytes) {
    return Status::make(ErrorCode::CapacityExceeded,
                        "appending would exceed the configured journal size bound; compact the "
                        "journal before writing more");
  }
  std::string error;
  if (!FileOps::write_at(handle_, size_bytes_, bytes.data(), bytes.size(), error)) {
    return Status::make(ErrorCode::IoError, "journal append failed: " + error);
  }
  if (!FileOps::flush(handle_, error)) {
    return Status::make(ErrorCode::IoError, "journal flush failed: " + error);
  }
  size_bytes_ = total;
  if (!checked_inc_u64(next_sequence_)) {
    return Status::make(ErrorCode::Overflow, "journal sequence is exhausted");
  }
  return Status::success();
}

Status Journal::flush() {
  if (handle_ == nullptr) {
    return Status::make(ErrorCode::NotInitialized, "journal is not open");
  }
  std::string error;
  if (!FileOps::flush(handle_, error)) {
    return Status::make(ErrorCode::IoError, "journal flush failed: " + error);
  }
  return Status::success();
}

Result<std::vector<JournalRecord>> Journal::load(std::size_t max_records,
                                                 std::size_t max_payload_bytes) const {
  if (handle_ == nullptr) {
    return Status::make(ErrorCode::NotInitialized, "journal is not open");
  }
  std::vector<JournalRecord> records;
  std::uint64_t offset = kJournalHeaderBytes;
  const std::uint64_t limit = recovery_.good_bytes;
  std::string error;
  while (offset < limit) {
    if (records.size() >= max_records) {
      return Status::make(ErrorCode::BoundsExceeded, "journal holds more records than the bound");
    }
    std::byte header_bytes[kJournalRecordHeaderBytes];
    if (!FileOps::read_at(handle_, offset, header_bytes, sizeof(header_bytes), error)) {
      return Status::make(ErrorCode::IoError, "journal record header cannot be read: " + error);
    }
    const std::uint32_t payload_length = load_u32_le(header_bytes);
    if (payload_length > max_payload_bytes) {
      return Status::make(ErrorCode::BoundsExceeded, "record payload exceeds the load bound");
    }
    const std::uint64_t total =
        static_cast<std::uint64_t>(payload_length) + kJournalRecordHeaderBytes + Digest::kSize + 4;
    if (limit - offset < total) {
      return Status::make(ErrorCode::Truncated, "journal record extends past the recovered prefix");
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(total));
    if (!FileOps::read_at(handle_, offset, bytes.data(), bytes.size(), error)) {
      return Status::make(ErrorCode::IoError, "journal record cannot be read: " + error);
    }
    std::uint16_t type_value = 0;
    std::memcpy(&type_value, bytes.data() + 4, 2);
    JournalRecord record;
    record.type = static_cast<JournalRecordType>(type_value);
    record.sequence = load_u64_le(bytes.data() + 8);
    record.payload.assign(bytes.begin() + kJournalRecordHeaderBytes,
                          bytes.begin() + kJournalRecordHeaderBytes + payload_length);
    records.push_back(std::move(record));
    offset += total;
  }
  return records;
}

Status Journal::compact(const std::vector<JournalRecord>& records) {
  if (handle_ == nullptr) {
    return Status::make(ErrorCode::NotInitialized, "journal is not open");
  }
  if (records.size() > options_.max_records) {
    return Status::make(ErrorCode::BoundsExceeded, "compacted journal would exceed the record bound");
  }
  const std::filesystem::path temporary = temporary_path_for(path_);
  std::string error;
  void* out = FileOps::open(temporary, false, true, true, error);
  if (out == nullptr) {
    return Status::make(ErrorCode::IoError, "compaction target cannot be created: " + error);
  }
  std::uint64_t offset = 0;
  std::uint64_t sequence = 1;
  bool ok = true;
  const std::vector<std::byte> header = make_header_bytes();
  if (!FileOps::write_at(out, offset, header.data(), header.size(), error)) {
    ok = false;
  }
  offset += header.size();
  for (const JournalRecord& record : records) {
    if (!ok) {
      break;
    }
    JournalRecord stored = record;
    stored.sequence = sequence;
    const std::vector<std::byte> bytes = make_record_bytes(stored);
    std::uint64_t projected = 0;
    if (!checked_add_u64(offset, bytes.size(), projected) || projected > options_.max_bytes) {
      error = "compacted journal would exceed the configured size bound";
      ok = false;
      break;
    }
    if (!FileOps::write_at(out, offset, bytes.data(), bytes.size(), error)) {
      ok = false;
      break;
    }
    offset += bytes.size();
    ++sequence;
  }
  if (ok && !FileOps::flush(out, error)) {
    ok = false;
  }
#if defined(_WIN32)
  ::CloseHandle(static_cast<HANDLE>(out));
#else
  ::close(static_cast<int>(reinterpret_cast<std::intptr_t>(out)));
#endif
  if (!ok) {
    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    return Status::make(ErrorCode::IoError, "journal compaction failed: " + error);
  }
  release();
  if (!FileOps::replace_file(temporary, path_, error)) {
    return Status::make(ErrorCode::IoError, "compacted journal cannot replace the original: " +
                                                error);
  }
  auto reopened = Journal::open(path_, JournalOpenMode::OpenOrCreateReadWrite, options_);
  if (!reopened.has_value()) {
    return reopened.status();
  }
  *this = std::move(reopened.value());
  return Status::success();
}

Status Journal::close() {
  if (handle_ == nullptr) {
    return Status::success();
  }
  std::string error;
  const bool flushed = FileOps::flush(handle_, error);
  release();
  if (!flushed) {
    return Status::make(ErrorCode::IoError, "journal flush on close failed: " + error);
  }
  return Status::success();
}

}  // namespace fabric_federation
