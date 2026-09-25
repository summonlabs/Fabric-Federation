// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Child-process control, used by the multi-process tests, the examples and the
// operator tooling to start and hard-kill real member and coordinator
// processes.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "fabric_federation/errors.hpp"
#include "fabric_federation/export.hpp"

namespace fabric_federation {

struct ProcessSpec {
  std::string executable;
  std::vector<std::string> arguments;
  std::string working_directory;
  // When set, the child's standard output/error are redirected to these files.
  // An empty path discards the stream.
  std::string stdout_path;
  std::string stderr_path;
};

// A running child process. Move-only.
class FFED_API ChildProcess {
 public:
  ChildProcess() = default;
  ChildProcess(ChildProcess&& other) noexcept;
  ChildProcess& operator=(ChildProcess&& other) noexcept;
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ~ChildProcess();

  [[nodiscard]] static Result<ChildProcess> spawn(const ProcessSpec& spec);

  // Blocks until the process exits and reports its exit code.
  [[nodiscard]] Result<int> wait();
  // Terminates the process immediately. No graceful shutdown is attempted and
  // no signal handler runs, which is what makes this useful for crash tests.
  [[nodiscard]] Status terminate_now();
  // Non-blocking check.
  [[nodiscard]] bool running();
  [[nodiscard]] std::uint64_t pid() const noexcept { return pid_; }
  [[nodiscard]] bool valid() const noexcept { return handle_ != nullptr; }
  [[nodiscard]] Status close();

 private:
  void release() noexcept;

  void* handle_ = nullptr;
  std::uint64_t pid_ = 0;
  bool waited_ = false;
  int exit_code_ = 0;
};

}  // namespace fabric_federation
