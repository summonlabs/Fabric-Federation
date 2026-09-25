// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/codec.hpp"

#include <cstring>

#include "fabric_federation/text.hpp"

namespace fabric_federation {

std::uint32_t load_u32_le(const std::byte* data) noexcept {
  return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[0])) |
         (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[1])) << 8) |
         (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[2])) << 16) |
         (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[3])) << 24);
}

std::uint64_t load_u64_le(const std::byte* data) noexcept {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(data[i])) << (i * 8);
  }
  return value;
}

void store_u32_le(std::byte* out, std::uint32_t value) noexcept {
  for (std::size_t i = 0; i < 4; ++i) {
    out[i] = static_cast<std::byte>((value >> (i * 8)) & 0xffu);
  }
}

void store_u64_le(std::byte* out, std::uint64_t value) noexcept {
  for (std::size_t i = 0; i < 8; ++i) {
    out[i] = static_cast<std::byte>((value >> (i * 8)) & 0xffu);
  }
}

Writer::Writer(std::size_t reserve_bytes) { buffer_.reserve(reserve_bytes); }

Status Writer::u8(std::uint8_t value) {
  buffer_.push_back(static_cast<std::byte>(value));
  return Status::success();
}

Status Writer::u16(std::uint16_t value) {
  buffer_.push_back(static_cast<std::byte>(value & 0xffu));
  buffer_.push_back(static_cast<std::byte>((value >> 8) & 0xffu));
  return Status::success();
}

Status Writer::u32(std::uint32_t value) {
  std::byte tmp[4];
  store_u32_le(tmp, value);
  buffer_.insert(buffer_.end(), tmp, tmp + 4);
  return Status::success();
}

Status Writer::u64(std::uint64_t value) {
  std::byte tmp[8];
  store_u64_le(tmp, value);
  buffer_.insert(buffer_.end(), tmp, tmp + 8);
  return Status::success();
}

Status Writer::boolean(bool value) { return u8(value ? 1u : 0u); }

Status Writer::raw(std::span<const std::byte> data) {
  if (data.size() > kMaxJournalRecordBytes) {
    return Status::make(ErrorCode::BoundsExceeded, "raw payload exceeds the record bound");
  }
  buffer_.insert(buffer_.end(), data.begin(), data.end());
  return Status::success();
}

Status Writer::digest(const Digest& value) {
  const auto& bytes = value.bytes();
  buffer_.insert(buffer_.end(), reinterpret_cast<const std::byte*>(bytes.data()),
                 reinterpret_cast<const std::byte*>(bytes.data()) + bytes.size());
  return Status::success();
}

Status Writer::id16(const std::array<std::uint8_t, 16>& value) {
  buffer_.insert(buffer_.end(), reinterpret_cast<const std::byte*>(value.data()),
                 reinterpret_cast<const std::byte*>(value.data()) + value.size());
  return Status::success();
}

Status Writer::bytes(std::span<const std::byte> data, std::size_t max_bytes) {
  if (data.size() > max_bytes) {
    return Status::make(ErrorCode::BoundsExceeded, "byte string exceeds the encoding bound");
  }
  std::uint32_t length = 0;
  if (!narrow_u32(data.size(), length)) {
    return Status::make(ErrorCode::Overflow, "byte string length does not fit a 32-bit prefix");
  }
  Status status = u32(length);
  if (!status.ok()) {
    return status;
  }
  buffer_.insert(buffer_.end(), data.begin(), data.end());
  return Status::success();
}

Status Writer::text(std::string_view value, std::size_t max_bytes) {
  if (value.size() > max_bytes) {
    return Status::make(ErrorCode::BoundsExceeded, "text exceeds the encoding bound");
  }
  if (!utf8_is_valid(value)) {
    return Status::make(ErrorCode::InvalidArgument, "text is not valid UTF-8");
  }
  std::uint32_t length = 0;
  if (!narrow_u32(value.size(), length)) {
    return Status::make(ErrorCode::Overflow, "text length does not fit a 32-bit prefix");
  }
  Status status = u32(length);
  if (!status.ok()) {
    return status;
  }
  buffer_.insert(buffer_.end(), reinterpret_cast<const std::byte*>(value.data()),
                 reinterpret_cast<const std::byte*>(value.data()) + value.size());
  return Status::success();
}

Status Writer::identifier(std::string_view value) { return text(value, kMaxIdentifierLength); }

Status Writer::count(std::size_t value, std::size_t max_count) {
  if (value > max_count) {
    return Status::make(ErrorCode::BoundsExceeded, "collection count exceeds the encoding bound");
  }
  std::uint32_t narrowed = 0;
  if (!narrow_u32(value, narrowed)) {
    return Status::make(ErrorCode::Overflow, "collection count does not fit a 32-bit prefix");
  }
  return u32(narrowed);
}

Status Reader::take(std::size_t count) {
  if (count > data_.size() - offset_) {
    return Status::make(ErrorCode::Truncated, "payload ended before the declared length");
  }
  return Status::success();
}

Result<std::uint8_t> Reader::u8() {
  Status status = take(1);
  if (!status.ok()) {
    return status;
  }
  const auto value = std::to_integer<std::uint8_t>(data_[offset_]);
  ++offset_;
  return value;
}

Result<std::uint16_t> Reader::u16() {
  Status status = take(2);
  if (!status.ok()) {
    return status;
  }
  const std::uint16_t value = static_cast<std::uint16_t>(
      std::to_integer<std::uint8_t>(data_[offset_]) |
      (std::to_integer<std::uint8_t>(data_[offset_ + 1]) << 8));
  offset_ += 2;
  return value;
}

Result<std::uint32_t> Reader::u32() {
  Status status = take(4);
  if (!status.ok()) {
    return status;
  }
  const std::uint32_t value = load_u32_le(data_.data() + offset_);
  offset_ += 4;
  return value;
}

Result<std::uint64_t> Reader::u64() {
  Status status = take(8);
  if (!status.ok()) {
    return status;
  }
  const std::uint64_t value = load_u64_le(data_.data() + offset_);
  offset_ += 8;
  return value;
}

Result<bool> Reader::boolean() {
  auto value = u8();
  if (!value.has_value()) {
    return value.status();
  }
  if (value.value() > 1u) {
    return Status::make(ErrorCode::Corrupt, "boolean field is neither 0 nor 1");
  }
  return value.value() == 1u;
}

Result<Digest> Reader::digest() {
  Status status = take(Digest::kSize);
  if (!status.ok()) {
    return status;
  }
  Digest::bytes_type bytes{};
  std::memcpy(bytes.data(), data_.data() + offset_, Digest::kSize);
  offset_ += Digest::kSize;
  return Digest(bytes);
}

Result<std::array<std::uint8_t, 16>> Reader::id16() {
  Status status = take(16);
  if (!status.ok()) {
    return status;
  }
  std::array<std::uint8_t, 16> bytes{};
  std::memcpy(bytes.data(), data_.data() + offset_, 16);
  offset_ += 16;
  return bytes;
}

Result<std::span<const std::byte>> Reader::bytes(std::size_t max_bytes) {
  auto length = u32();
  if (!length.has_value()) {
    return length.status();
  }
  const std::size_t count = length.value();
  if (count > max_bytes) {
    return Status::make(ErrorCode::BoundsExceeded, "declared byte-string length exceeds the bound");
  }
  Status status = take(count);
  if (!status.ok()) {
    return status;
  }
  const auto view = data_.subspan(offset_, count);
  offset_ += count;
  return view;
}

Result<std::string> Reader::text(std::size_t max_bytes) {
  auto view = bytes(max_bytes);
  if (!view.has_value()) {
    return view.status();
  }
  const auto raw = view.value();
  std::string out(reinterpret_cast<const char*>(raw.data()), raw.size());
  if (!utf8_is_valid(out)) {
    return Status::make(ErrorCode::InvalidArgument, "decoded text is not valid UTF-8");
  }
  return out;
}

Result<std::string> Reader::identifier() { return text(kMaxIdentifierLength); }

Result<std::uint32_t> Reader::count(std::size_t max_count) {
  auto value = u32();
  if (!value.has_value()) {
    return value.status();
  }
  if (static_cast<std::size_t>(value.value()) > max_count) {
    return Status::make(ErrorCode::BoundsExceeded, "declared collection count exceeds the bound");
  }
  return value.value();
}

Status Reader::expect_end() const {
  if (!at_end()) {
    return Status::make(ErrorCode::Corrupt, "trailing bytes after the canonical payload");
  }
  return Status::success();
}

}  // namespace fabric_federation
