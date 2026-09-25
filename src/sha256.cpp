// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// SHA-256 (FIPS 180-4). Verified against the published test vectors in
// tests/unit/test_digest.cpp, including the 1,000,000 x 'a' vector.
#include "fabric_federation/digest.hpp"

#include <cstring>

namespace fabric_federation {
namespace {

constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

constexpr std::uint32_t rotr(std::uint32_t value, unsigned shift) noexcept {
  return (value >> shift) | (value << (32u - shift));
}

constexpr std::uint32_t choose(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
  return (x & y) ^ (~x & z);
}

constexpr std::uint32_t majority(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
  return (x & y) ^ (x & z) ^ (y & z);
}

constexpr std::uint32_t big_sigma0(std::uint32_t x) noexcept {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

constexpr std::uint32_t big_sigma1(std::uint32_t x) noexcept {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

constexpr std::uint32_t small_sigma0(std::uint32_t x) noexcept {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

constexpr std::uint32_t small_sigma1(std::uint32_t x) noexcept {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

constexpr std::array<std::uint32_t, 8> kInitialState = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u,
                                                        0xa54ff53au, 0x510e527fu, 0x9b05688cu,
                                                        0x1f83d9abu, 0x5be0cd19u};

}  // namespace

Sha256::Sha256() { state_ = kInitialState; }

void Sha256::reset() noexcept {
  state_ = kInitialState;
  buffer_.fill(0);
  buffered_ = 0;
  total_bytes_ = 0;
  finished_ = false;
}

void Sha256::compress(const std::uint8_t* block) noexcept {
  std::uint32_t w[64];
  for (std::size_t i = 0; i < 16; ++i) {
    w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
           (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
           static_cast<std::uint32_t>(block[i * 4 + 3]);
  }
  for (std::size_t i = 16; i < 64; ++i) {
    w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t t1 = h + big_sigma1(e) + choose(e, f, g) + kRoundConstants[i] + w[i];
    const std::uint32_t t2 = big_sigma0(a) + majority(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(const std::uint8_t* data, std::size_t size) noexcept {
  if (finished_ || size == 0) {
    return;
  }
  total_bytes_ += static_cast<std::uint64_t>(size);
  std::size_t offset = 0;
  if (buffered_ > 0) {
    const std::size_t need = 64 - buffered_;
    const std::size_t take = (size < need) ? size : need;
    std::memcpy(buffer_.data() + buffered_, data, take);
    buffered_ += take;
    offset += take;
    if (buffered_ == 64) {
      compress(buffer_.data());
      buffered_ = 0;
    }
  }
  while (size - offset >= 64) {
    compress(data + offset);
    offset += 64;
  }
  if (offset < size) {
    const std::size_t rest = size - offset;
    std::memcpy(buffer_.data() + buffered_, data + offset, rest);
    buffered_ += rest;
  }
}

void Sha256::update(std::span<const std::byte> data) noexcept {
  update(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

void Sha256::update(std::string_view data) noexcept {
  update(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

Digest Sha256::finish() noexcept {
  if (!finished_) {
    const std::uint64_t bit_length = total_bytes_ * 8ull;
    std::uint8_t padding[72];
    std::memset(padding, 0, sizeof(padding));
    padding[0] = 0x80u;
    const std::size_t pad_len = (buffered_ < 56) ? (56 - buffered_) : (120 - buffered_);
    update(padding, pad_len);
    std::uint8_t length_bytes[8];
    for (std::size_t i = 0; i < 8; ++i) {
      length_bytes[i] = static_cast<std::uint8_t>((bit_length >> (56 - i * 8)) & 0xffu);
    }
    update(length_bytes, sizeof(length_bytes));
    finished_ = true;
  }
  Digest::bytes_type out{};
  for (std::size_t i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xffu);
    out[i * 4 + 1] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xffu);
    out[i * 4 + 2] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xffu);
    out[i * 4 + 3] = static_cast<std::uint8_t>(state_[i] & 0xffu);
  }
  return Digest(out);
}

Digest Sha256::hash(std::span<const std::byte> data) noexcept {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

Digest Sha256::hash(std::string_view data) noexcept {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

Digest Digest::from_bytes(std::span<const std::uint8_t> value) {
  bytes_type bytes{};
  const std::size_t count = (value.size() < kSize) ? value.size() : kSize;
  for (std::size_t i = 0; i < count; ++i) {
    bytes[i] = value[i];
  }
  return Digest(bytes);
}

std::optional<Digest> Digest::from_hex(std::string_view hex) {
  if (hex.size() != kSize * 2) {
    return std::nullopt;
  }
  bytes_type bytes{};
  for (std::size_t i = 0; i < kSize; ++i) {
    const char hi = hex[i * 2];
    const char lo = hex[i * 2 + 1];
    const auto nibble = [](char c) -> int {
      if (c >= '0' && c <= '9') {
        return c - '0';
      }
      if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
      }
      return -1;
    };
    const int h = nibble(hi);
    const int l = nibble(lo);
    if (h < 0 || l < 0) {
      return std::nullopt;
    }
    bytes[i] = static_cast<std::uint8_t>((h << 4) | l);
  }
  return Digest(bytes);
}

Digest Digest::of(std::string_view text) { return Sha256::hash(text); }

bool Digest::is_zero() const noexcept {
  for (const std::uint8_t b : bytes_) {
    if (b != 0) {
      return false;
    }
  }
  return true;
}

std::string Digest::to_hex() const {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(kSize * 2);
  for (std::size_t i = 0; i < kSize; ++i) {
    out[i * 2] = kHex[(bytes_[i] >> 4) & 0x0fu];
    out[i * 2 + 1] = kHex[bytes_[i] & 0x0fu];
  }
  return out;
}

std::size_t Digest::hash_value() const noexcept {
  std::size_t h = 1469598103934665603ull;
  for (std::size_t i = 0; i < 8; ++i) {
    h ^= static_cast<std::size_t>(bytes_[i]);
    h *= 1099511628211ull;
  }
  return h;
}

}  // namespace fabric_federation
