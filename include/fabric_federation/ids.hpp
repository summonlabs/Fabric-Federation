// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Strongly typed identities.
//
// Every identity in this runtime is a distinct type, so a federation identity
// cannot be passed where a member identity is expected and a generation cannot
// be compared against an epoch. Identifiers are 128-bit values with a textual
// form "<prefix>-<32 lowercase hex digits>".
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include "fabric_federation/digest.hpp"
#include "fabric_federation/errors.hpp"
#include "fabric_federation/export.hpp"

namespace fabric_federation {

namespace detail {
// Builds the canonical textual form of a 128-bit identifier.
[[nodiscard]] FFED_API std::string format_id(std::string_view prefix,
                                             const std::array<std::uint8_t, 16>& bytes);
// Parses "<prefix>-<32 hex digits>"; returns nullopt on any deviation.
[[nodiscard]] FFED_API std::optional<std::array<std::uint8_t, 16>> parse_id(
    std::string_view text, std::string_view expected_prefix);
}  // namespace detail

// Tag types give each identifier family its own C++ type.
struct FederationIdTag {
  static constexpr std::string_view prefix = "fed";
};
struct MemberIdTag {
  static constexpr std::string_view prefix = "mbr";
};
struct FabricDomainIdTag {
  static constexpr std::string_view prefix = "dom";
};
struct NodeIdTag {
  static constexpr std::string_view prefix = "nod";
};
struct LeaseIdTag {
  static constexpr std::string_view prefix = "lea";
};
struct EvidenceIdTag {
  static constexpr std::string_view prefix = "evd";
};
struct RequestIdTag {
  static constexpr std::string_view prefix = "req";
};
struct LineageIdTag {
  static constexpr std::string_view prefix = "lin";
};

template <class Tag>
class BasicId {
 public:
  using bytes_type = std::array<std::uint8_t, 16>;
  static constexpr std::size_t kSize = 16;

  BasicId() = default;
  explicit BasicId(bytes_type value) : bytes_(value) {}

  [[nodiscard]] static BasicId from_bytes(bytes_type value) { return BasicId(value); }

  // Derives an identifier deterministically from seed material. Used by tests,
  // fixtures and reproducible tooling: the same (prefix, seed, counter) triple
  // always yields the same identifier on every platform.
  [[nodiscard]] static BasicId derive(std::string_view seed, std::uint64_t counter) {
    Sha256 hasher;
    hasher.update(Tag::prefix);
    hasher.update(std::string_view("|derive|"));
    hasher.update(seed);
    const std::uint8_t counter_bytes[8] = {
        static_cast<std::uint8_t>(counter & 0xffu),
        static_cast<std::uint8_t>((counter >> 8) & 0xffu),
        static_cast<std::uint8_t>((counter >> 16) & 0xffu),
        static_cast<std::uint8_t>((counter >> 24) & 0xffu),
        static_cast<std::uint8_t>((counter >> 32) & 0xffu),
        static_cast<std::uint8_t>((counter >> 40) & 0xffu),
        static_cast<std::uint8_t>((counter >> 48) & 0xffu),
        static_cast<std::uint8_t>((counter >> 56) & 0xffu),
    };
    hasher.update(counter_bytes, sizeof(counter_bytes));
    const Digest d = hasher.finish();
    bytes_type out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
      out[i] = d.bytes()[i];
    }
    return BasicId(out);
  }

  // Random identifier from the platform entropy source. Used by long-running
  // processes; never used where reproducibility is required.
  [[nodiscard]] static BasicId random();

  [[nodiscard]] static std::optional<BasicId> parse(std::string_view text) {
    const auto bytes = detail::parse_id(text, Tag::prefix);
    if (!bytes.has_value()) {
      return std::nullopt;
    }
    return BasicId(*bytes);
  }

  [[nodiscard]] const bytes_type& bytes() const noexcept { return bytes_; }
  [[nodiscard]] bool is_nil() const noexcept {
    for (const std::uint8_t b : bytes_) {
      if (b != 0) {
        return false;
      }
    }
    return true;
  }
  [[nodiscard]] std::string to_string() const { return detail::format_id(Tag::prefix, bytes_); }
  [[nodiscard]] std::size_t hash_value() const noexcept {
    std::size_t h = 1469598103934665603ull;
    for (const std::uint8_t b : bytes_) {
      h ^= static_cast<std::size_t>(b);
      h *= 1099511628211ull;
    }
    return h;
  }

  friend bool operator==(const BasicId& a, const BasicId& b) noexcept { return a.bytes_ == b.bytes_; }
  friend bool operator!=(const BasicId& a, const BasicId& b) noexcept { return !(a == b); }
  friend bool operator<(const BasicId& a, const BasicId& b) noexcept { return a.bytes_ < b.bytes_; }

 private:
  bytes_type bytes_{};
};

template <class Tag>
struct BasicIdHash {
  [[nodiscard]] std::size_t operator()(const BasicId<Tag>& value) const noexcept {
    return value.hash_value();
  }
};

using FederationId = BasicId<FederationIdTag>;
using MemberId = BasicId<MemberIdTag>;
using FabricDomainId = BasicId<FabricDomainIdTag>;
using NodeId = BasicId<NodeIdTag>;
using LeaseId = BasicId<LeaseIdTag>;
using EvidenceId = BasicId<EvidenceIdTag>;
using RequestId = BasicId<RequestIdTag>;
using LineageId = BasicId<LineageIdTag>;

using FederationIdHash = BasicIdHash<FederationIdTag>;
using MemberIdHash = BasicIdHash<MemberIdTag>;
using LeaseIdHash = BasicIdHash<LeaseIdTag>;
using EvidenceIdHash = BasicIdHash<EvidenceIdTag>;
using RequestIdHash = BasicIdHash<RequestIdTag>;

// Monotonic counters. Each has its own type so that a generation can never be
// compared against, or substituted for, an epoch, an incarnation or a tick.
template <class Tag, class Underlying = std::uint64_t>
class BasicCounter {
 public:
  using value_type = Underlying;

  constexpr BasicCounter() = default;
  constexpr explicit BasicCounter(Underlying value) : value_(value) {}

  [[nodiscard]] constexpr Underlying value() const noexcept { return value_; }
  [[nodiscard]] constexpr bool is_zero() const noexcept { return value_ == 0; }

  // Returns false on overflow instead of wrapping. Wrapping a generation or an
  // epoch would silently revive stale authority.
  [[nodiscard]] bool try_next(BasicCounter& out) const noexcept {
    if (value_ == static_cast<Underlying>(-1)) {
      return false;
    }
    out = BasicCounter(static_cast<Underlying>(value_ + 1));
    return true;
  }

  [[nodiscard]] bool try_add(Underlying delta, BasicCounter& out) const noexcept {
    if (delta > static_cast<Underlying>(-1) - value_) {
      return false;
    }
    out = BasicCounter(static_cast<Underlying>(value_ + delta));
    return true;
  }

  friend constexpr bool operator==(const BasicCounter& a, const BasicCounter& b) noexcept {
    return a.value_ == b.value_;
  }
  friend constexpr bool operator!=(const BasicCounter& a, const BasicCounter& b) noexcept {
    return a.value_ != b.value_;
  }
  friend constexpr bool operator<(const BasicCounter& a, const BasicCounter& b) noexcept {
    return a.value_ < b.value_;
  }
  friend constexpr bool operator<=(const BasicCounter& a, const BasicCounter& b) noexcept {
    return a.value_ <= b.value_;
  }
  friend constexpr bool operator>(const BasicCounter& a, const BasicCounter& b) noexcept {
    return a.value_ > b.value_;
  }
  friend constexpr bool operator>=(const BasicCounter& a, const BasicCounter& b) noexcept {
    return a.value_ >= b.value_;
  }

 private:
  Underlying value_{};
};

struct GenerationTag {};
struct IncarnationTag {};
struct EpochTag {};
struct TickTag {};
struct LineageTag {};

// Generation: the revision of a member's constitution (identity, capabilities,
// retained authority, delegation terms). Consent is bound to an exact
// generation.
using Generation = BasicCounter<GenerationTag>;
// Incarnation: one run of a controller process. A restart produces a strictly
// greater incarnation.
using Incarnation = BasicCounter<IncarnationTag>;
// Epoch: the federation-wide authority epoch. Leases, activations and
// delegation bindings are bound to an exact epoch.
using Epoch = BasicCounter<EpochTag>;
// Tick: the coordinator's logical clock. Authority decisions never consult the
// wall clock.
using Tick = BasicCounter<TickTag>;
// Lineage: the number of times a membership slot has been (re)constituted. A
// leave/rejoin produces a fresh lineage, so a rejoin can never reuse a previous
// admission.
using Lineage = BasicCounter<LineageTag>;

}  // namespace fabric_federation
