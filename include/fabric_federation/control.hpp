// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Operator control channel and readiness helpers.
//
// The daemons expose a newline-delimited command channel so that an operator,
// an example or a test can drive a *different process* instead of calling into
// its own. Both helpers below are deliberately bounded and both fail loudly:
// they never turn "not ready" or "no answer" into success.
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "fabric_federation/errors.hpp"
#include "fabric_federation/export.hpp"

namespace fabric_federation {

// Sends one command to a daemon control channel and returns its single-line
// reply. The connection is opened, used and closed.
[[nodiscard]] FFED_API Result<std::string> send_control_command(std::uint16_t port,
                                                               std::string_view command);

// Waits for a readiness file to appear and returns its contents.
//
// This is a readiness probe with a hard attempt bound, NOT a test timeout: when
// the bound is reached the call FAILS and the caller reports a failure. It is
// never used to classify a slow or hung operation as a pass.
[[nodiscard]] FFED_API Result<std::string> wait_for_ready_file(
    const std::filesystem::path& path, std::size_t max_attempts = 2000,
    std::uint32_t delay_microseconds = 5000);

// Waits until a control channel answers with a line beginning "OK".
[[nodiscard]] FFED_API Result<std::string> wait_for_control(std::uint16_t port,
                                                           std::string_view command,
                                                           std::size_t max_attempts = 2000,
                                                           std::uint32_t delay_microseconds = 5000);

}  // namespace fabric_federation
