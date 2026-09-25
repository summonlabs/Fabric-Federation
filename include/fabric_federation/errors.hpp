// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Typed outcomes and error codes. The distinctness of these values is a
// deliberate design property: a caller must be able to tell a refusal from an
// indeterminate result, and missing evidence must never be reported as success.
#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "fabric_federation/export.hpp"

namespace fabric_federation {

// The outcome of an authority question. Every value is reachable in the
// implementation; see docs/authority-model.md for the exact rule that produces
// each one.
enum class Outcome : std::uint8_t {
  // Authority was granted for the requested scope and verb.
  Granted = 0,
  // Authority was granted with reduced reach: the member may act, but the
  // federation has recorded an observational gap, so mutating global state is
  // withheld while observation remains permitted.
  Degraded,
  // The request is well formed and the actor is known, but the federation
  // declines to grant authority.
  Refused,
  // The federation has actively removed authority from the actor, or the
  // actor's presented identity no longer corresponds to the authority it
  // holds. Fenced authority is sticky until an explicit re-activation.
  Fenced,
  // The presented evidence belongs to a superseded generation, incarnation,
  // epoch, lease or attempt.
  Stale,
  // Overlapping delegations disagree and no configured precedence exists. No
  // party is granted the scope; the disagreement is preserved.
  Conflicting,
  // The request cannot be decided because required evidence has not arrived.
  Incomplete,
  // Evidence needed for a decision is missing or mutually contradictory in a
  // way that the federation cannot resolve from what it holds.
  Indeterminate,
  // The request itself is malformed.
  Invalid,
  // The request asks for something this runtime does not implement.
  Unsupported,
  // The request was withdrawn before a decision was committed.
  Cancelled,
  // The request identifier was already decided; a repeated identifier is not
  // re-evaluated and never grants fresh authority.
  Replayed,
  // No evidence about the subject exists at all. Distinct from Incomplete
  // (some evidence exists but is not sufficient) and from Refused (the
  // federation made a decision).
  Unknown,
};

[[nodiscard]] std::string_view to_string(Outcome outcome) noexcept;

// Quality of a single piece of evidence. Kept separate from Outcome because a
// decision can be granted while some contributing evidence is Unknown.
enum class EvidenceState : std::uint8_t {
  Known = 0,
  Unknown,
  Stale,
  Conflicting,
  Incomplete,
  Indeterminate,
  Invalid,
};

[[nodiscard]] std::string_view to_string(EvidenceState state) noexcept;

// Transport/persistence/validation error codes. These are distinct from
// Outcome: they describe why an operation could not be carried out at all.
enum class ErrorCode : std::uint16_t {
  Ok = 0,
  InvalidArgument,
  OutOfRange,
  BoundsExceeded,
  Truncated,
  Corrupt,
  UnsupportedVersion,
  NotFound,
  AlreadyExists,
  Conflict,
  Stale,
  Refused,
  Incomplete,
  Indeterminate,
  Cancelled,
  IoError,
  NetworkError,
  ProtocolViolation,
  Overflow,
  Replay,
  ChecksumMismatch,
  CapacityExceeded,
  NotInitialized,
  Busy,
  Internal,
};

[[nodiscard]] std::string_view to_string(ErrorCode code) noexcept;

class FFED_API Status {
 public:
  Status() = default;
  Status(ErrorCode code, std::string message) : code_(code), message_(std::move(message)) {}

  [[nodiscard]] static Status success() { return Status(); }
  [[nodiscard]] static Status make(ErrorCode code, std::string_view message) {
    return Status(code, std::string(message));
  }

  [[nodiscard]] ErrorCode code() const noexcept { return code_; }
  [[nodiscard]] bool ok() const noexcept { return code_ == ErrorCode::Ok; }
  [[nodiscard]] const std::string& message() const noexcept { return message_; }
  [[nodiscard]] std::string to_string() const;

  friend bool operator==(const Status& a, const Status& b) noexcept {
    return a.code_ == b.code_ && a.message_ == b.message_;
  }

 private:
  ErrorCode code_ = ErrorCode::Ok;
  std::string message_;
};

// A minimal result type. Constructed either from a value or from a failure
// Status; reading the value of a failure is a programming error and is
// reported by throwing std::logic_error rather than returning garbage.
template <class T>
class Result {
 public:
  Result(T value) : value_(std::move(value)) {}   // NOLINT(google-explicit-constructor)
  // The parameter type is qualified because the member function below is also
  // named status(); an unqualified reference would resolve to that function.
  Result(::fabric_federation::Status status)
      : status_(std::move(status)) {}  // NOLINT(google-explicit-constructor)

  [[nodiscard]] bool has_value() const noexcept { return value_.has_value(); }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

  [[nodiscard]] const T& value() const& { return require_ref(); }
  [[nodiscard]] T& value() & { return const_cast<T&>(require_ref()); }
  [[nodiscard]] T&& value() && { return std::move(const_cast<T&>(require_ref())); }

  [[nodiscard]] const ::fabric_federation::Status& status() const noexcept { return status_; }

  [[nodiscard]] const T& value_or(const T& fallback) const& {
    return value_.has_value() ? *value_ : fallback;
  }
  [[nodiscard]] T&& value_or(T&& fallback) && {
    return value_.has_value() ? std::move(*value_) : std::move(fallback);
  }

 private:
  [[nodiscard]] const T& require_ref() const {
    if (!value_.has_value()) {
      throw_status();
    }
    return *value_;
  }
  [[noreturn]] void throw_status() const;

  std::optional<T> value_;
  ::fabric_federation::Status status_;
};

template <class T>
[[noreturn]] void Result<T>::throw_status() const {
  throw std::logic_error("Result::value() on failure: " + status_.to_string());
}

// Specialization for operations that report only success or failure.
template <>
class Result<void> {
 public:
  Result() = default;  // NOLINT(google-explicit-constructor)
  Result(::fabric_federation::Status status)
      : status_(std::move(status)) {}  // NOLINT(google-explicit-constructor)

  [[nodiscard]] bool has_value() const noexcept { return status_.ok(); }
  [[nodiscard]] explicit operator bool() const noexcept { return status_.ok(); }
  void value() const {
    if (!status_.ok()) {
      throw std::logic_error("Result<void>::value() on failure: " + status_.to_string());
    }
  }
  [[nodiscard]] const ::fabric_federation::Status& status() const noexcept { return status_; }

 private:
  ::fabric_federation::Status status_;
};

}  // namespace fabric_federation
