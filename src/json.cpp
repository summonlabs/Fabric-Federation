// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/json.hpp"

#include <cmath>
#include <cstdio>

#include "fabric_federation/text.hpp"

namespace fabric_federation {

void JsonWriter::indent() {
  if (!pretty_) {
    return;
  }
  out_.push_back('\n');
  for (int i = 0; i < depth_; ++i) {
    out_.append("  ");
  }
}

void JsonWriter::prepare_value() {
  if (after_key_) {
    after_key_ = false;
    return;
  }
  if (need_comma_) {
    out_.push_back(',');
  }
  if (depth_ > 0) {
    indent();
  }
  need_comma_ = true;
}

void JsonWriter::begin_object() {
  prepare_value();
  out_.push_back('{');
  ++depth_;
  need_comma_ = false;
}

void JsonWriter::end_object() {
  --depth_;
  if (need_comma_) {
    indent();
  }
  out_.push_back('}');
  need_comma_ = true;
}

void JsonWriter::begin_array() {
  prepare_value();
  out_.push_back('[');
  ++depth_;
  need_comma_ = false;
}

void JsonWriter::end_array() {
  --depth_;
  if (need_comma_) {
    indent();
  }
  out_.push_back(']');
  need_comma_ = true;
}

void JsonWriter::key(std::string_view name) {
  if (need_comma_) {
    out_.push_back(',');
  }
  if (depth_ > 0) {
    indent();
  }
  out_.append(json_escape(name));
  out_.push_back(':');
  if (pretty_) {
    out_.push_back(' ');
  }
  need_comma_ = true;
  after_key_ = true;
}

void JsonWriter::string(std::string_view value) {
  prepare_value();
  out_.append(json_escape(value));
}

void JsonWriter::number(std::uint64_t value) {
  prepare_value();
  out_.append(std::to_string(value));
}

void JsonWriter::number(std::int64_t value) {
  prepare_value();
  out_.append(std::to_string(value));
}

void JsonWriter::number(double value) {
  prepare_value();
  if (!std::isfinite(value)) {
    out_.append("null");
    return;
  }
  char buffer[64];
  const int written = std::snprintf(buffer, sizeof(buffer), "%.6f", value);
  if (written <= 0 || static_cast<std::size_t>(written) >= sizeof(buffer)) {
    out_.append("null");
    return;
  }
  out_.append(buffer, static_cast<std::size_t>(written));
}

void JsonWriter::boolean(bool value) {
  prepare_value();
  out_.append(value ? "true" : "false");
}

void JsonWriter::null_value() {
  prepare_value();
  out_.append("null");
}

}  // namespace fabric_federation
