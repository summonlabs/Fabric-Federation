// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/random.hpp"

#include <cstdio>

#include "fabric_federation/text.hpp"

namespace fabric_federation {
namespace {

constexpr std::uint64_t rotl(std::uint64_t x, unsigned k) noexcept {
  return (x << k) | (x >> (64u - k));
}

std::uint64_t splitmix64(std::uint64_t& state) noexcept {
  state += 0x9e3779b97f4a7c15ull;
  std::uint64_t z = state;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
  return z ^ (z >> 31);
}

}  // namespace

DeterministicRng::DeterministicRng(std::uint64_t seed) { reseed(seed); }

void DeterministicRng::reseed(std::uint64_t seed) noexcept {
  seed_ = seed;
  std::uint64_t state = seed;
  for (std::size_t i = 0; i < state_.size(); ++i) {
    state_[i] = splitmix64(state);
  }
  // A zero state would make xoshiro256** degenerate; SplitMix64 cannot produce
  // an all-zero quad in practice, but the guard keeps the generator total.
  bool all_zero = true;
  for (const std::uint64_t word : state_) {
    if (word != 0) {
      all_zero = false;
      break;
    }
  }
  if (all_zero) {
    state_[0] = 0x9e3779b97f4a7c15ull;
  }
}

std::uint64_t DeterministicRng::next_u64() noexcept {
  const std::uint64_t result = rotl(state_[1] * 5ull, 7) * 9ull;
  const std::uint64_t t = state_[1] << 17;
  state_[2] ^= state_[0];
  state_[3] ^= state_[1];
  state_[1] ^= state_[2];
  state_[0] ^= state_[3];
  state_[2] ^= t;
  state_[3] = rotl(state_[3], 45);
  return result;
}

std::uint32_t DeterministicRng::next_u32() noexcept {
  return static_cast<std::uint32_t>(next_u64() >> 32);
}

bool DeterministicRng::next_bool() noexcept { return (next_u64() & 1ull) != 0ull; }

std::uint64_t DeterministicRng::below(std::uint64_t bound) noexcept {
  if (bound == 0) {
    return 0;
  }
  const std::uint64_t limit = bound;
  // Rejection sampling keeps the distribution exactly uniform.
  const std::uint64_t threshold = (0ull - limit) % limit;
  for (;;) {
    const std::uint64_t value = next_u64();
    if (value >= threshold) {
      return value % limit;
    }
  }
}

std::uint64_t DeterministicRng::range(std::uint64_t low, std::uint64_t high) noexcept {
  if (high <= low) {
    return low;
  }
  return low + below(high - low + 1ull);
}

std::int64_t DeterministicRng::range_i64(std::int64_t low, std::int64_t high) noexcept {
  if (high <= low) {
    return low;
  }
  const std::uint64_t span = static_cast<std::uint64_t>(high - low) + 1ull;
  return low + static_cast<std::int64_t>(below(span));
}

void DeterministicRng::fill_bytes(std::span<std::byte> out) noexcept {
  std::size_t i = 0;
  while (i < out.size()) {
    const std::uint64_t word = next_u64();
    for (std::size_t k = 0; k < 8 && i < out.size(); ++k, ++i) {
      out[i] = static_cast<std::byte>((word >> (k * 8)) & 0xffu);
    }
  }
}

std::string DeterministicRng::hex(std::size_t digits) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(digits);
  for (std::size_t i = 0; i < digits; ++i) {
    out.push_back(kDigits[next_u64() & 0x0fu]);
  }
  return out;
}

std::string DeterministicRng::token(std::size_t length) {
  static constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  std::string out;
  out.reserve(length);
  for (std::size_t i = 0; i < length; ++i) {
    out.push_back(kAlphabet[below(sizeof(kAlphabet) - 1)]);
  }
  return out;
}

std::string DeterministicRng::state_hex() const {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(state_.size() * 16);
  for (const std::uint64_t word : state_) {
    for (int shift = 60; shift >= 0; shift -= 4) {
      out.push_back(kDigits[(word >> shift) & 0x0full]);
    }
  }
  return out;
}

bool parse_seed(std::string_view text, std::uint64_t& out) {
  if (text.empty()) {
    return false;
  }
  std::uint64_t value = 0;
  std::size_t index = 0;
  unsigned base = 10;
  if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    base = 16;
    index = 2;
  }
  if (index >= text.size()) {
    return false;
  }
  for (; index < text.size(); ++index) {
    const char c = text[index];
    unsigned digit = 0;
    if (c >= '0' && c <= '9') {
      digit = static_cast<unsigned>(c - '0');
    } else if (base == 16 && c >= 'a' && c <= 'f') {
      digit = static_cast<unsigned>(c - 'a') + 10u;
    } else if (base == 16 && c >= 'A' && c <= 'F') {
      digit = static_cast<unsigned>(c - 'A') + 10u;
    } else {
      return false;
    }
    if (digit >= base) {
      return false;
    }
    if (value > (0xffffffffffffffffull - digit) / base) {
      return false;
    }
    value = value * base + digit;
  }
  out = value;
  return true;
}

}  // namespace fabric_federation
