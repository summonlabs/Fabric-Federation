// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Text validation and escaping. Hostile framing includes invalid Unicode, so
// every text field that enters the model is validated before it is stored, and
// every text field that leaves the model for a terminal or JSON document is
// escaped.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "fabric_federation/export.hpp"

namespace fabric_federation {

// Strict UTF-8 validation: rejects overlong encodings, surrogate halves and
// values above U+10FFFF.
[[nodiscard]] FFED_API bool utf8_is_valid(std::string_view text) noexcept;

// Replaces every invalid byte sequence with U+FFFD. Used when rendering
// already-stored bytes for humans; never used to accept input.
[[nodiscard]] FFED_API std::string utf8_sanitize(std::string_view text);

// Escapes a string for single-line diagnostic output.
[[nodiscard]] FFED_API std::string escape_for_display(std::string_view text);

// Escapes a string as a JSON string literal, including the surrounding quotes.
[[nodiscard]] FFED_API std::string json_escape(std::string_view text);

}  // namespace fabric_federation
