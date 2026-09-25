// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Deterministic pseudo-random generator used by property tests, adversarial
// generators and synthetic fixtures. Every failing case is reproducible from
// the printed seed, so the generator is part of the reproducibility contract
// rather than a test-only convenience.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/export.hpp"

namespace fabric_federation {

// xoshiro256** with SplitMix64 seeding. Deterministic across platforms: the
// algorithm uses fixed-width unsigned arithmetic only.
class FFED_API DeterministicRng {
 public:
  explicit DeterministicRng(std::uint64_t seed);

  [[nodiscard]] std::uint64_t next_u64() noexcept;
  [[nodiscard]] std::uint32_t next_u32() noexcept;
  [[nodiscard]] bool next_bool() noexcept;

  // Uniform in [0, bound). Unbiased: values in the rejection region are
  // discarded rather than folded, so property tests cannot be skewed by a
  // modulo bias. Returns 0 when bound == 0.
  [[nodiscard]] std::uint64_t below(std::uint64_t bound) noexcept;
  // Uniform in [low, high]; returns low when high < low.
  [[nodiscard]] std::uint64_t range(std::uint64_t low, std::uint64_t high) noexcept;
  [[nodiscard]] std::int64_t range_i64(std::int64_t low, std::int64_t high) noexcept;

  void fill_bytes(std::span<std::byte> out) noexcept;
  [[nodiscard]] std::string hex(std::size_t digits);
  [[nodiscard]] std::string token(std::size_t length);

  template <class T>
  void shuffle(std::vector<T>& items) {
    for (std::size_t i = items.size(); i > 1; --i) {
      const std::size_t j = static_cast<std::size_t>(below(i));
      T tmp = std::move(items[i - 1]);
      items[i - 1] = std::move(items[j]);
      items[j] = std::move(tmp);
    }
  }

  [[nodiscard]] std::uint64_t seed() const noexcept { return seed_; }
  [[nodiscard]] std::string state_hex() const;

 private:
  void reseed(std::uint64_t seed) noexcept;

  std::array<std::uint64_t, 4> state_{};
  std::uint64_t seed_ = 0;
};

// Parses a seed from decimal or from the "0x" hex form printed by the tools.
[[nodiscard]] FFED_API bool parse_seed(std::string_view text, std::uint64_t& out);

// Seed used when a test binary is invoked without --seed. Not a secret.
inline constexpr std::uint64_t kDefaultPropertySeed = 0x5eed1234c0ffeeULL;
// Seed used by the self-contained tooling commands when none is supplied.
inline constexpr std::uint64_t kDefaultSeed = 0x5eed1234c0ffeeULL;

}  // namespace fabric_federation
