// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/control.hpp"

#include <chrono>
#include <fstream>
#include <thread>

#include "fabric_federation/net.hpp"

namespace fabric_federation {

Result<std::string> send_control_command(std::uint16_t port, std::string_view command) {
  auto socket = Socket::connect(Endpoint{"127.0.0.1", port});
  if (!socket.has_value()) {
    return socket.status();
  }
  const std::string request = std::string(command) + "\n";
  Status status = socket.value().send_all(std::span<const std::byte>(
      reinterpret_cast<const std::byte*>(request.data()), request.size()));
  if (!status.ok()) {
    return status;
  }
  const Status shutdown = socket.value().shutdown_send();
  (void)shutdown;
  std::string reply;
  std::byte buffer[1024];
  for (;;) {
    auto read = socket.value().recv_some(std::span<std::byte>(buffer, sizeof(buffer)));
    if (!read.has_value()) {
      return read.status();
    }
    if (read.value() == 0) {
      break;
    }
    reply.append(reinterpret_cast<const char*>(buffer), read.value());
    if (reply.find('\n') != std::string::npos) {
      break;
    }
    if (reply.size() > (1u << 20)) {
      return Status::make(ErrorCode::BoundsExceeded, "the control reply exceeded the bound");
    }
  }
  if (reply.empty()) {
    return Status::make(ErrorCode::Incomplete, "the control channel returned nothing");
  }
  if (!reply.empty() && reply.back() == '\n') {
    reply.pop_back();
  }
  return reply;
}

Result<std::string> wait_for_ready_file(const std::filesystem::path& path,
                                        std::size_t max_attempts,
                                        std::uint32_t delay_microseconds) {
  for (std::size_t attempt = 0; attempt < max_attempts; ++attempt) {
    std::error_code error;
    if (std::filesystem::exists(path, error) && !error) {
      std::ifstream stream(path, std::ios::binary);
      if (stream) {
        std::string content((std::istreambuf_iterator<char>(stream)),
                            std::istreambuf_iterator<char>());
        if (!content.empty()) {
          return content;
        }
      }
    }
    std::this_thread::sleep_for(std::chrono::microseconds(delay_microseconds));
  }
  return Status::make(ErrorCode::NotFound,
                      "the readiness file " + path.string() +
                          " did not appear within the readiness bound; this is reported as a "
                          "failure, not as success");
}

Result<std::string> wait_for_control(std::uint16_t port, std::string_view command,
                                     std::size_t max_attempts, std::uint32_t delay_microseconds) {
  Status last = Status::make(ErrorCode::NotFound, "no attempt was made");
  for (std::size_t attempt = 0; attempt < max_attempts; ++attempt) {
    auto reply = send_control_command(port, command);
    if (reply.has_value() && reply.value().rfind("OK", 0) == 0) {
      return reply.value();
    }
    last = reply.has_value() ? Status::make(ErrorCode::Refused, reply.value()) : reply.status();
    std::this_thread::sleep_for(std::chrono::microseconds(delay_microseconds));
  }
  return Status::make(last.code(),
                      "the control channel did not answer within the readiness bound: " +
                          last.message());
}

}  // namespace fabric_federation
