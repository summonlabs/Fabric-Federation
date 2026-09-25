// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Measures durable append throughput and recovery scan throughput. Each append
// is flushed to the operating system, so the number reflects durability rather
// than buffered writes.
#include <filesystem>
#include <vector>

#include "bench_common.hpp"
#include "fabric_federation/journal.hpp"

using namespace fabric_federation;
using namespace ffed::bench;

int main() {
  std::printf("fabric-federation journal append and recovery\n");
  const auto directory = std::filesystem::temp_directory_path() / "ffed-bench-journal";
  std::error_code error;
  std::filesystem::remove_all(directory, error);
  std::filesystem::create_directories(directory, error);
  const auto path = directory / "bench.fedjournal";

  constexpr unsigned long long kRecords = 2000;
  {
    auto journal = Journal::open(path, JournalOpenMode::CreateTruncating).value();
    std::vector<std::byte> payload(256, std::byte{0x5a});
    Timer timer;
    for (unsigned long long i = 0; i < kRecords; ++i) {
      payload[0] = static_cast<std::byte>(i & 0xffu);
      const Status status = journal.append(JournalRecordType::Artifact, payload);
      if (!status.ok()) {
        std::fprintf(stderr, "append failed: %s\n", status.to_string().c_str());
        return 1;
      }
    }
    report("append+flush 256-byte records", kRecords, timer.milliseconds());
    const Status closed = journal.close();
    if (!closed.ok()) {
      std::fprintf(stderr, "close failed\n");
      return 1;
    }
  }
  {
    auto journal = Journal::open(path, JournalOpenMode::ReadOnlyExisting).value();
    Timer timer;
    constexpr unsigned long long kScans = 10;
    for (unsigned long long i = 0; i < kScans; ++i) {
      auto records = journal.load(kMaxArtifacts * 4u, kMaxJournalRecordBytes);
      if (!records.has_value() || records.value().size() != kRecords) {
        std::fprintf(stderr, "recovery did not return every record\n");
        return 1;
      }
    }
    report("recovery scan of 2000 records", kScans, timer.milliseconds());
  }
  std::filesystem::remove_all(directory, error);
  return 0;
}
