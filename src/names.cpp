// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/names.hpp"

namespace fabric_federation {
namespace detail {

Result<std::string> validate_qualified_name(std::string_view text, std::size_t max_length,
                                            bool allow_wildcard, std::string_view what) {
  if (text.empty()) {
    return Status::make(ErrorCode::InvalidArgument, std::string(what) + " must not be empty");
  }
  if (text.size() > max_length) {
    return Status::make(ErrorCode::BoundsExceeded,
                        std::string(what) + " exceeds the maximum length");
  }
  const auto is_lower = [](char c) { return c >= 'a' && c <= 'z'; };
  const auto is_digit = [](char c) { return c >= '0' && c <= '9'; };
  if (!is_lower(text[0]) && !(allow_wildcard && text[0] == '*')) {
    return Status::make(ErrorCode::InvalidArgument,
                        std::string(what) + " must start with a lowercase letter");
  }
  bool previous_dot = false;
  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    if (c == '*') {
      if (!allow_wildcard) {
        return Status::make(ErrorCode::InvalidArgument,
                            std::string(what) + " does not accept a wildcard");
      }
      // A wildcard is only permitted as the whole name or as the final segment.
      const bool whole = text.size() == 1;
      const bool final_segment = (i == text.size() - 1) && (i >= 1) && text[i - 1] == '.';
      if (!whole && !final_segment) {
        return Status::make(ErrorCode::InvalidArgument,
                            std::string(what) + " may only use a wildcard as the last segment");
      }
      previous_dot = false;
      continue;
    }
    if (c == '.') {
      if (previous_dot || i == 0 || i + 1 == text.size()) {
        return Status::make(ErrorCode::InvalidArgument,
                            std::string(what) + " has an empty segment");
      }
      previous_dot = true;
      continue;
    }
    if (!is_lower(c) && !is_digit(c) && c != '_' && c != '-') {
      return Status::make(ErrorCode::InvalidArgument,
                          std::string(what) + " contains a character outside [a-z0-9._-]");
    }
    previous_dot = false;
  }
  if (previous_dot) {
    return Status::make(ErrorCode::InvalidArgument, std::string(what) + " ends with a separator");
  }
  return std::string(text);
}

bool qualified_name_covers(std::string_view pattern, std::string_view concrete) noexcept {
  if (pattern == concrete) {
    return true;
  }
  if (pattern.empty() || concrete.empty()) {
    return false;
  }
  if (pattern == "*") {
    return true;
  }
  if (pattern.size() >= 2 && pattern.back() == '*') {
    const std::string_view prefix = pattern.substr(0, pattern.size() - 1);
    return concrete.size() >= prefix.size() && concrete.substr(0, prefix.size()) == prefix;
  }
  return false;
}

}  // namespace detail
}  // namespace fabric_federation
