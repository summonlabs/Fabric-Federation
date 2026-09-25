// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/text.hpp"

#include <array>

namespace fabric_federation {
namespace {

constexpr char32_t kReplacement = 0xFFFDu;
constexpr char32_t kMaxCodePoint = 0x10FFFFu;

constexpr bool is_surrogate(char32_t cp) noexcept {
  return cp >= 0xD800u && cp <= 0xDFFFu;
}

void append_utf8(std::string& out, char32_t cp) {
  if (cp <= 0x7Fu) {
    out.push_back(static_cast<char>(cp));
  } else if (cp <= 0x7FFu) {
    out.push_back(static_cast<char>(0xC0u | (cp >> 6)));
    out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
  } else if (cp <= 0xFFFFu) {
    out.push_back(static_cast<char>(0xE0u | (cp >> 12)));
    out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
  } else {
    out.push_back(static_cast<char>(0xF0u | (cp >> 18)));
    out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
  }
}

void append_codepoint_hex(std::string& out, char32_t cp) {
  static constexpr char kDigits[] = "0123456789abcdef";
  out.append("\\u");
  for (int shift = 12; shift >= 0; shift -= 4) {
    out.push_back(kDigits[(cp >> shift) & 0x0Fu]);
  }
}

}  // namespace

bool utf8_is_valid(std::string_view text) noexcept {
  std::size_t i = 0;
  const std::size_t n = text.size();
  while (i < n) {
    const auto byte = static_cast<unsigned char>(text[i]);
    std::size_t extra = 0;
    char32_t cp = 0;
    char32_t minimum = 0;
    if (byte <= 0x7Fu) {
      ++i;
      continue;
    } else if ((byte & 0xE0u) == 0xC0u) {
      extra = 1;
      cp = byte & 0x1Fu;
      minimum = 0x80u;
    } else if ((byte & 0xF0u) == 0xE0u) {
      extra = 2;
      cp = byte & 0x0Fu;
      minimum = 0x800u;
    } else if ((byte & 0xF8u) == 0xF0u) {
      extra = 3;
      cp = byte & 0x07u;
      minimum = 0x10000u;
    } else {
      return false;
    }
    if (i + extra >= n) {
      return false;
    }
    for (std::size_t k = 1; k <= extra; ++k) {
      const auto cont = static_cast<unsigned char>(text[i + k]);
      if ((cont & 0xC0u) != 0x80u) {
        return false;
      }
      cp = (cp << 6) | (cont & 0x3Fu);
    }
    if (cp < minimum || cp > kMaxCodePoint || is_surrogate(cp)) {
      return false;
    }
    i += extra + 1;
  }
  return true;
}

std::string utf8_sanitize(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  std::size_t i = 0;
  const std::size_t n = text.size();
  while (i < n) {
    const auto byte = static_cast<unsigned char>(text[i]);
    if (byte <= 0x7Fu) {
      out.push_back(text[i]);
      ++i;
      continue;
    }
    std::size_t extra = 0;
    char32_t cp = 0;
    char32_t minimum = 0;
    bool ok = true;
    if ((byte & 0xE0u) == 0xC0u) {
      extra = 1;
      cp = byte & 0x1Fu;
      minimum = 0x80u;
    } else if ((byte & 0xF0u) == 0xE0u) {
      extra = 2;
      cp = byte & 0x0Fu;
      minimum = 0x800u;
    } else if ((byte & 0xF8u) == 0xF0u) {
      extra = 3;
      cp = byte & 0x07u;
      minimum = 0x10000u;
    } else {
      ok = false;
    }
    if (ok) {
      if (i + extra >= n) {
        ok = false;
      } else {
        for (std::size_t k = 1; k <= extra; ++k) {
          const auto cont = static_cast<unsigned char>(text[i + k]);
          if ((cont & 0xC0u) != 0x80u) {
            ok = false;
            break;
          }
          cp = (cp << 6) | (cont & 0x3Fu);
        }
      }
    }
    if (ok && (cp < minimum || cp > kMaxCodePoint || is_surrogate(cp))) {
      ok = false;
    }
    if (ok) {
      out.append(text.substr(i, extra + 1));
      i += extra + 1;
    } else {
      append_utf8(out, kReplacement);
      ++i;
    }
  }
  return out;
}

std::string escape_for_display(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char raw : text) {
    const auto c = static_cast<unsigned char>(raw);
    switch (c) {
      case '\n':
        out.append("\\n");
        break;
      case '\r':
        out.append("\\r");
        break;
      case '\t':
        out.append("\\t");
        break;
      case '\\':
        out.append("\\\\");
        break;
      default:
        if (c < 0x20u || c == 0x7Fu) {
          append_codepoint_hex(out, c);
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  // Any invalid byte sequence in already-stored text is neutralised so that a
  // terminal never receives a partial code point.
  return utf8_is_valid(out) ? out : utf8_sanitize(out);
}

std::string json_escape(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 2);
  out.push_back('"');
  std::size_t i = 0;
  const std::size_t n = text.size();
  while (i < n) {
    const auto c = static_cast<unsigned char>(text[i]);
    switch (c) {
      case '"':
        out.append("\\\"");
        ++i;
        continue;
      case '\\':
        out.append("\\\\");
        ++i;
        continue;
      case '\n':
        out.append("\\n");
        ++i;
        continue;
      case '\r':
        out.append("\\r");
        ++i;
        continue;
      case '\t':
        out.append("\\t");
        ++i;
        continue;
      case '\b':
        out.append("\\b");
        ++i;
        continue;
      case '\f':
        out.append("\\f");
        ++i;
        continue;
      default:
        break;
    }
    if (c < 0x20u) {
      append_codepoint_hex(out, c);
      ++i;
      continue;
    }
    if (c < 0x80u) {
      out.push_back(static_cast<char>(c));
      ++i;
      continue;
    }
    // Multi-byte sequence: copy it whole when it is valid, otherwise emit a
    // replacement character so the JSON document never contains a partial or
    // invalid sequence.
    std::size_t extra = 0;
    char32_t cp = 0;
    char32_t minimum = 0;
    bool ok = true;
    if ((c & 0xE0u) == 0xC0u) {
      extra = 1;
      cp = c & 0x1Fu;
      minimum = 0x80u;
    } else if ((c & 0xF0u) == 0xE0u) {
      extra = 2;
      cp = c & 0x0Fu;
      minimum = 0x800u;
    } else if ((c & 0xF8u) == 0xF0u) {
      extra = 3;
      cp = c & 0x07u;
      minimum = 0x10000u;
    } else {
      ok = false;
    }
    if (ok) {
      if (i + extra >= n) {
        ok = false;
      } else {
        for (std::size_t k = 1; k <= extra; ++k) {
          const auto cont = static_cast<unsigned char>(text[i + k]);
          if ((cont & 0xC0u) != 0x80u) {
            ok = false;
            break;
          }
          cp = (cp << 6) | (cont & 0x3Fu);
        }
      }
    }
    if (ok && (cp < minimum || cp > kMaxCodePoint || is_surrogate(cp))) {
      ok = false;
    }
    if (ok) {
      out.append(text.substr(i, extra + 1));
      i += extra + 1;
    } else {
      append_utf8(out, kReplacement);
      ++i;
    }
  }
  out.push_back('"');
  return out;
}

}  // namespace fabric_federation
