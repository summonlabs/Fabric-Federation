// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Validated qualified names.
//
// Scopes, capabilities, policy rules and constraint tokens are dotted
// lowercase identifiers. Each family is a distinct C++ type with its own
// length bound, so a capability identifier cannot be passed where a scope is
// expected. A trailing ".*" segment (or the single "*") is a wildcard used only
// in delegation patterns; wildcard matching is prefix-based and is never
// resolved by "most recent wins".
#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>

#include "fabric_federation/errors.hpp"
#include "fabric_federation/export.hpp"

namespace fabric_federation {

namespace detail {
// Validates a dotted lowercase name. Returns the canonical form (unchanged;
// names are already required to be canonical) or a typed failure.
[[nodiscard]] FFED_API Result<std::string> validate_qualified_name(std::string_view text,
                                                                  std::size_t max_length,
                                                                  bool allow_wildcard,
                                                                  std::string_view what);
// Prefix match for a pattern that ends in ".*" or is exactly "*".
[[nodiscard]] FFED_API bool qualified_name_covers(std::string_view pattern,
                                                  std::string_view concrete) noexcept;
}  // namespace detail

struct ScopeIdTag {
  static constexpr std::size_t kMaxLength = 96;
  static constexpr bool kAllowWildcard = true;
};
struct CapabilityIdTag {
  static constexpr std::size_t kMaxLength = 64;
  static constexpr bool kAllowWildcard = false;
};
struct PolicyIdTag {
  static constexpr std::size_t kMaxLength = 64;
  static constexpr bool kAllowWildcard = false;
};
struct RuleIdTag {
  static constexpr std::size_t kMaxLength = 64;
  static constexpr bool kAllowWildcard = false;
};
struct ConstraintTag {
  static constexpr std::size_t kMaxLength = 96;
  static constexpr bool kAllowWildcard = false;
};

template <class Tag>
class BasicName {
 public:
  BasicName() = default;

  [[nodiscard]] static Result<BasicName> parse(std::string_view text) {
    auto validated =
        detail::validate_qualified_name(text, Tag::kMaxLength, Tag::kAllowWildcard, kind_name());
    if (!validated.has_value()) {
      return validated.status();
    }
    BasicName name;
    name.value_ = std::move(validated.value());
    return name;
  }

  [[nodiscard]] static bool is_valid(std::string_view text) { return parse(text).has_value(); }

  [[nodiscard]] const std::string& str() const noexcept { return value_; }
  [[nodiscard]] bool empty() const noexcept { return value_.empty(); }
  [[nodiscard]] bool is_wildcard() const noexcept {
    return !value_.empty() && value_.find('*') != std::string::npos;
  }
  // True when this name (used as a pattern) covers the concrete name.
  [[nodiscard]] bool covers(const BasicName& other) const noexcept {
    return detail::qualified_name_covers(value_, other.value_);
  }
  [[nodiscard]] std::string to_string() const { return value_; }
  [[nodiscard]] std::size_t hash_value() const noexcept { return std::hash<std::string>{}(value_); }

  friend bool operator==(const BasicName& a, const BasicName& b) noexcept { return a.value_ == b.value_; }
  friend bool operator!=(const BasicName& a, const BasicName& b) noexcept { return !(a == b); }
  friend bool operator<(const BasicName& a, const BasicName& b) noexcept { return a.value_ < b.value_; }

 private:
  static constexpr std::string_view kind_name() {
    if constexpr (std::is_same_v<Tag, ScopeIdTag>) {
      return "scope";
    } else if constexpr (std::is_same_v<Tag, CapabilityIdTag>) {
      return "capability";
    } else if constexpr (std::is_same_v<Tag, PolicyIdTag>) {
      return "policy";
    } else if constexpr (std::is_same_v<Tag, RuleIdTag>) {
      return "rule";
    } else {
      return "constraint";
    }
  }

  std::string value_;
};

template <class Tag>
struct BasicNameHash {
  [[nodiscard]] std::size_t operator()(const BasicName<Tag>& value) const noexcept {
    return value.hash_value();
  }
};

using ScopeId = BasicName<ScopeIdTag>;
using CapabilityId = BasicName<CapabilityIdTag>;
using PolicyId = BasicName<PolicyIdTag>;
using RuleId = BasicName<RuleIdTag>;
using ConstraintToken = BasicName<ConstraintTag>;

using ScopeIdHash = BasicNameHash<ScopeIdTag>;

}  // namespace fabric_federation
