// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/errors.hpp"

namespace fabric_federation {

std::string_view to_string(Outcome outcome) noexcept {
  switch (outcome) {
    case Outcome::Granted:
      return "GRANTED";
    case Outcome::Degraded:
      return "DEGRADED";
    case Outcome::Refused:
      return "REFUSED";
    case Outcome::Fenced:
      return "FENCED";
    case Outcome::Stale:
      return "STALE";
    case Outcome::Conflicting:
      return "CONFLICTING";
    case Outcome::Incomplete:
      return "INCOMPLETE";
    case Outcome::Indeterminate:
      return "INDETERMINATE";
    case Outcome::Invalid:
      return "INVALID";
    case Outcome::Unsupported:
      return "UNSUPPORTED";
    case Outcome::Cancelled:
      return "CANCELLED";
    case Outcome::Replayed:
      return "REPLAYED";
    case Outcome::Unknown:
      return "UNKNOWN";
  }
  return "INVALID";
}

std::string_view to_string(EvidenceState state) noexcept {
  switch (state) {
    case EvidenceState::Known:
      return "KNOWN";
    case EvidenceState::Unknown:
      return "UNKNOWN";
    case EvidenceState::Stale:
      return "STALE";
    case EvidenceState::Conflicting:
      return "CONFLICTING";
    case EvidenceState::Incomplete:
      return "INCOMPLETE";
    case EvidenceState::Indeterminate:
      return "INDETERMINATE";
    case EvidenceState::Invalid:
      return "INVALID";
  }
  return "INVALID";
}

std::string_view to_string(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::Ok:
      return "OK";
    case ErrorCode::InvalidArgument:
      return "INVALID_ARGUMENT";
    case ErrorCode::OutOfRange:
      return "OUT_OF_RANGE";
    case ErrorCode::BoundsExceeded:
      return "BOUNDS_EXCEEDED";
    case ErrorCode::Truncated:
      return "TRUNCATED";
    case ErrorCode::Corrupt:
      return "CORRUPT";
    case ErrorCode::UnsupportedVersion:
      return "UNSUPPORTED_VERSION";
    case ErrorCode::NotFound:
      return "NOT_FOUND";
    case ErrorCode::AlreadyExists:
      return "ALREADY_EXISTS";
    case ErrorCode::Conflict:
      return "CONFLICT";
    case ErrorCode::Stale:
      return "STALE";
    case ErrorCode::Refused:
      return "REFUSED";
    case ErrorCode::Incomplete:
      return "INCOMPLETE";
    case ErrorCode::Indeterminate:
      return "INDETERMINATE";
    case ErrorCode::Cancelled:
      return "CANCELLED";
    case ErrorCode::IoError:
      return "IO_ERROR";
    case ErrorCode::NetworkError:
      return "NETWORK_ERROR";
    case ErrorCode::ProtocolViolation:
      return "PROTOCOL_VIOLATION";
    case ErrorCode::Overflow:
      return "OVERFLOW";
    case ErrorCode::Replay:
      return "REPLAY";
    case ErrorCode::ChecksumMismatch:
      return "CHECKSUM_MISMATCH";
    case ErrorCode::CapacityExceeded:
      return "CAPACITY_EXCEEDED";
    case ErrorCode::NotInitialized:
      return "NOT_INITIALIZED";
    case ErrorCode::Busy:
      return "BUSY";
    case ErrorCode::Internal:
      return "INTERNAL";
  }
  return "INTERNAL";
}

std::string Status::to_string() const {
  // Qualified: the member function hides the namespace-scope overload set.
  std::string out(fabric_federation::to_string(code_));
  if (!message_.empty()) {
    out.append(": ");
    out.append(message_);
  }
  return out;
}

}  // namespace fabric_federation
