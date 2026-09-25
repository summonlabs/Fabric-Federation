// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/ids.hpp"

#include <atomic>
#include <chrono>
#include <random>

#include "fabric_federation/text.hpp"

namespace fabric_federation {
namespace detail {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

int hex_nibble(char c) noexcept {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

}  // namespace

std::string format_id(std::string_view prefix, const std::array<std::uint8_t, 16>& bytes) {
  std::string out;
  out.reserve(prefix.size() + 1 + 32);
  out.append(prefix);
  out.push_back('-');
  for (const std::uint8_t b : bytes) {
    out.push_back(kHexDigits[(b >> 4) & 0x0fu]);
    out.push_back(kHexDigits[b & 0x0fu]);
  }
  return out;
}

std::optional<std::array<std::uint8_t, 16>> parse_id(std::string_view text,
                                                     std::string_view expected_prefix) {
  if (text.size() != expected_prefix.size() + 1 + 32) {
    return std::nullopt;
  }
  if (text.substr(0, expected_prefix.size()) != expected_prefix) {
    return std::nullopt;
  }
  if (text[expected_prefix.size()] != '-') {
    return std::nullopt;
  }
  std::array<std::uint8_t, 16> bytes{};
  for (std::size_t i = 0; i < 16; ++i) {
    const int hi = hex_nibble(text[expected_prefix.size() + 1 + i * 2]);
    const int lo = hex_nibble(text[expected_prefix.size() + 2 + i * 2]);
    if (hi < 0 || lo < 0) {
      return std::nullopt;
    }
    bytes[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return bytes;
}

}  // namespace detail

namespace {

std::uint64_t entropy_word() {
  static std::atomic<std::uint64_t> counter{0};
  std::random_device device;
  const std::uint64_t a = (static_cast<std::uint64_t>(device()) << 32) ^ device();
  const std::uint64_t b = static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  const std::uint64_t c = counter.fetch_add(1, std::memory_order_relaxed);
  return a ^ (b * 0x9e3779b97f4a7c15ull) ^ (c + 0x165667b19e3779f9ull);
}

}  // namespace

template <class Tag>
BasicId<Tag> BasicId<Tag>::random() {
  bytes_type bytes{};
  for (std::size_t i = 0; i < bytes.size(); i += 8) {
    const std::uint64_t word = entropy_word();
    for (std::size_t j = 0; j < 8 && i + j < bytes.size(); ++j) {
      bytes[i + j] = static_cast<std::uint8_t>((word >> (j * 8)) & 0xffu);
    }
  }
  return BasicId(bytes);
}

template class BasicId<FederationIdTag>;
template class BasicId<MemberIdTag>;
template class BasicId<FabricDomainIdTag>;
template class BasicId<NodeIdTag>;
template class BasicId<LeaseIdTag>;
template class BasicId<EvidenceIdTag>;
template class BasicId<RequestIdTag>;
template class BasicId<LineageIdTag>;

}  // namespace fabric_federation
