// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Minimal deterministic JSON writer used by the inspection tools. It has no
// dependency on a JSON library and emits members in the order the caller
// writes them, so tool output is reproducible.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "fabric_federation/export.hpp"

namespace fabric_federation {

class FFED_API JsonWriter {
 public:
  explicit JsonWriter(bool pretty = false) : pretty_(pretty) {}

  void begin_object();
  void end_object();
  void begin_array();
  void end_array();
  void key(std::string_view name);
  void string(std::string_view value);
  void number(std::uint64_t value);
  void number(std::int64_t value);
  void number(double value);
  void boolean(bool value);
  void null_value();

  [[nodiscard]] const std::string& str() const noexcept { return out_; }
  [[nodiscard]] std::string take() { return std::move(out_); }

 private:
  void prepare_value();
  void indent();

  std::string out_;
  bool pretty_ = false;
  bool need_comma_ = false;
  int depth_ = 0;
  bool after_key_ = false;
};

}  // namespace fabric_federation
