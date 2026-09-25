// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Canonical binary codec.
//
// Encoding rules (docs/canonical-form.md):
//   * little-endian fixed-width integers,
//   * length-prefixed byte strings and text,
//   * ordered collection encoding, where the writer sorts by canonical key,
//   * every length is validated against a caller-supplied bound *before* any
//     allocation happens.
// Two processes that hold equivalent accepted evidence therefore produce
// byte-identical encodings, and the digest of that encoding is the canonical
// state digest.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "fabric_federation/bounds.hpp"
#include "fabric_federation/digest.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/export.hpp"

namespace fabric_federation {

class FFED_API Writer {
 public:
  Writer() = default;
  explicit Writer(std::size_t reserve_bytes);

  [[nodiscard]] Status u8(std::uint8_t value);
  [[nodiscard]] Status u16(std::uint16_t value);
  [[nodiscard]] Status u32(std::uint32_t value);
  [[nodiscard]] Status u64(std::uint64_t value);
  [[nodiscard]] Status boolean(bool value);
  [[nodiscard]] Status raw(std::span<const std::byte> data);
  [[nodiscard]] Status digest(const Digest& value);
  [[nodiscard]] Status id16(const std::array<std::uint8_t, 16>& value);

  // Length-prefixed byte string. The bound is checked before the buffer grows.
  [[nodiscard]] Status bytes(std::span<const std::byte> data, std::size_t max_bytes);
  // Length-prefixed text. Rejects invalid UTF-8.
  [[nodiscard]] Status text(std::string_view value, std::size_t max_bytes);
  // Length-prefixed identifier: same as text with the identifier bound.
  [[nodiscard]] Status identifier(std::string_view value);
  // Collection count. The bound is checked before the caller allocates.
  [[nodiscard]] Status count(std::size_t value, std::size_t max_count);

  [[nodiscard]] const std::vector<std::byte>& data() const noexcept { return buffer_; }
  [[nodiscard]] std::span<const std::byte> span() const noexcept {
    return std::span<const std::byte>(buffer_.data(), buffer_.size());
  }
  [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
  [[nodiscard]] Digest sha256() const noexcept { return Sha256::hash(span()); }
  void clear() noexcept { buffer_.clear(); }

 private:
  std::vector<std::byte> buffer_;
};

class FFED_API Reader {
 public:
  explicit Reader(std::span<const std::byte> data) : data_(data) {}

  [[nodiscard]] Result<std::uint8_t> u8();
  [[nodiscard]] Result<std::uint16_t> u16();
  [[nodiscard]] Result<std::uint32_t> u32();
  [[nodiscard]] Result<std::uint64_t> u64();
  [[nodiscard]] Result<bool> boolean();
  [[nodiscard]] Result<Digest> digest();
  [[nodiscard]] Result<std::array<std::uint8_t, 16>> id16();

  [[nodiscard]] Result<std::span<const std::byte>> bytes(std::size_t max_bytes);
  [[nodiscard]] Result<std::string> text(std::size_t max_bytes);
  [[nodiscard]] Result<std::string> identifier();
  [[nodiscard]] Result<std::uint32_t> count(std::size_t max_count);

  [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - offset_; }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }
  [[nodiscard]] bool at_end() const noexcept { return offset_ == data_.size(); }
  // Fails when unconsumed bytes remain. A canonical reader must consume its
  // input exactly; trailing bytes indicate a forged or mismatched payload.
  [[nodiscard]] Status expect_end() const;

 private:
  [[nodiscard]] Status take(std::size_t count);

  std::span<const std::byte> data_;
  std::size_t offset_ = 0;
};

// Reads a fixed-width little-endian integer without a Reader, for headers.
[[nodiscard]] FFED_API std::uint32_t load_u32_le(const std::byte* data) noexcept;
[[nodiscard]] FFED_API std::uint64_t load_u64_le(const std::byte* data) noexcept;
FFED_API void store_u32_le(std::byte* out, std::uint32_t value) noexcept;
FFED_API void store_u64_le(std::byte* out, std::uint64_t value) noexcept;

}  // namespace fabric_federation
