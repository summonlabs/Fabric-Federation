// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Canonical integrity digests.
//
// The digest in this runtime is an integrity and determinism primitive: two
// parties holding equivalent accepted evidence compute the same value. It is
// NOT an authentication mechanism. Transfers in this repository are
// unauthenticated (see docs/limitations.md); no signature, key exchange or
// trust anchor exists.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "fabric_federation/export.hpp"

namespace fabric_federation {

class FFED_API Digest {
 public:
  static constexpr std::size_t kSize = 32;
  using bytes_type = std::array<std::uint8_t, kSize>;

  Digest() = default;
  explicit Digest(bytes_type value) : bytes_(value) {}

  [[nodiscard]] static Digest from_bytes(std::span<const std::uint8_t> value);
  [[nodiscard]] static std::optional<Digest> from_hex(std::string_view hex);
  [[nodiscard]] static Digest of(std::string_view text);

  [[nodiscard]] const bytes_type& bytes() const noexcept { return bytes_; }
  [[nodiscard]] const std::uint8_t* data() const noexcept { return bytes_.data(); }
  [[nodiscard]] bool is_zero() const noexcept;
  [[nodiscard]] std::string to_hex() const;

  friend bool operator==(const Digest& a, const Digest& b) noexcept { return a.bytes_ == b.bytes_; }
  friend bool operator!=(const Digest& a, const Digest& b) noexcept { return !(a == b); }
  friend bool operator<(const Digest& a, const Digest& b) noexcept { return a.bytes_ < b.bytes_; }

  [[nodiscard]] std::size_t hash_value() const noexcept;

 private:
  bytes_type bytes_{};
};

struct DigestHash {
  [[nodiscard]] std::size_t operator()(const Digest& value) const noexcept { return value.hash_value(); }
};

// Streaming SHA-256 (FIPS 180-4). Implemented here so that the canonical state
// digest is verifiable against the published test vectors rather than trusted
// to a platform hash.
class FFED_API Sha256 {
 public:
  Sha256();

  void update(std::span<const std::byte> data) noexcept;
  void update(std::string_view data) noexcept;
  void update(const std::uint8_t* data, std::size_t size) noexcept;

  // Finalizes the digest. The object is left in a finished state; call reset()
  // before reusing it for a new message.
  [[nodiscard]] Digest finish() noexcept;
  void reset() noexcept;

  [[nodiscard]] static Digest hash(std::span<const std::byte> data) noexcept;
  [[nodiscard]] static Digest hash(std::string_view data) noexcept;

 private:
  void compress(const std::uint8_t* block) noexcept;

  std::array<std::uint32_t, 8> state_{};
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t buffered_ = 0;
  std::uint64_t total_bytes_ = 0;
  bool finished_ = false;
};

}  // namespace fabric_federation
