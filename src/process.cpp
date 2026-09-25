// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/process.hpp"

#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#endif

namespace fabric_federation {
namespace {

#if defined(_WIN32)
std::string quote_argument(const std::string& value) {
  std::string out = "\"";
  for (const char c : value) {
    if (c == '"') {
      out.append("\\\"");
    } else {
      out.push_back(c);
    }
  }
  out.push_back('"');
  return out;
}
#endif

}  // namespace

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : handle_(other.handle_), pid_(other.pid_), waited_(other.waited_), exit_code_(other.exit_code_) {
  other.handle_ = nullptr;
  other.pid_ = 0;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    release();
    handle_ = other.handle_;
    pid_ = other.pid_;
    waited_ = other.waited_;
    exit_code_ = other.exit_code_;
    other.handle_ = nullptr;
    other.pid_ = 0;
  }
  return *this;
}

ChildProcess::~ChildProcess() { release(); }

void ChildProcess::release() noexcept {
  if (handle_ != nullptr) {
#if defined(_WIN32)
    ::CloseHandle(static_cast<HANDLE>(handle_));
#else
    // The child is reaped by wait(); if it was never waited for, it may remain
    // a zombie until the parent exits, which the test harness tolerates.
#endif
    handle_ = nullptr;
  }
}

Result<ChildProcess> ChildProcess::spawn(const ProcessSpec& spec) {
  if (spec.executable.empty()) {
    return Status::make(ErrorCode::InvalidArgument, "no executable was given");
  }
#if defined(_WIN32)
  std::string command = quote_argument(spec.executable);
  for (const std::string& argument : spec.arguments) {
    command.push_back(' ');
    command.append(quote_argument(argument));
  }
  std::vector<char> mutable_command(command.begin(), command.end());
  mutable_command.push_back('\0');

  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;

  HANDLE stdout_handle = nullptr;
  HANDLE stderr_handle = nullptr;
  const auto open_redirect = [&](const std::string& path, HANDLE& out) -> bool {
    if (path.empty()) {
      return true;
    }
    out = ::CreateFileA(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &attributes, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
    return out != INVALID_HANDLE_VALUE;
  };
  if (!open_redirect(spec.stdout_path, stdout_handle) ||
      !open_redirect(spec.stderr_path, stderr_handle)) {
    if (stdout_handle != nullptr) {
      ::CloseHandle(stdout_handle);
    }
    if (stderr_handle != nullptr) {
      ::CloseHandle(stderr_handle);
    }
    return Status::make(ErrorCode::IoError, "child output files cannot be created");
  }

  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = stdout_handle != nullptr ? stdout_handle : ::GetStdHandle(STD_OUTPUT_HANDLE);
  startup.hStdError = stderr_handle != nullptr ? stderr_handle : ::GetStdHandle(STD_ERROR_HANDLE);

  PROCESS_INFORMATION information{};
  const char* working_directory = spec.working_directory.empty() ? nullptr
                                                                : spec.working_directory.c_str();
  const BOOL created =
      ::CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                       CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr, working_directory,
                       &startup, &information);
  if (stdout_handle != nullptr) {
    ::CloseHandle(stdout_handle);
  }
  if (stderr_handle != nullptr) {
    ::CloseHandle(stderr_handle);
  }
  if (!created) {
    return Status::make(ErrorCode::IoError,
                        "CreateProcess failed with error " + std::to_string(::GetLastError()));
  }
  ::CloseHandle(information.hThread);
  ChildProcess child;
  child.handle_ = information.hProcess;
  child.pid_ = static_cast<std::uint64_t>(information.dwProcessId);
  return child;
#else
  std::vector<std::string> storage;
  storage.push_back(spec.executable);
  for (const std::string& argument : spec.arguments) {
    storage.push_back(argument);
  }
  std::vector<char*> argv;
  argv.reserve(storage.size() + 1);
  for (std::string& item : storage) {
    argv.push_back(item.data());
  }
  argv.push_back(nullptr);

  const pid_t pid = ::fork();
  if (pid < 0) {
    return Status::make(ErrorCode::IoError, std::string("fork failed: ") + std::strerror(errno));
  }
  if (pid == 0) {
    if (!spec.working_directory.empty()) {
      if (::chdir(spec.working_directory.c_str()) != 0) {
        ::_exit(127);
      }
    }
    const auto redirect = [](const std::string& path, int target) {
      if (path.empty()) {
        const int devnull = ::open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
          ::dup2(devnull, target);
          ::close(devnull);
        }
        return;
      }
      const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (fd >= 0) {
        ::dup2(fd, target);
        ::close(fd);
      }
    };
    redirect(spec.stdout_path, STDOUT_FILENO);
    redirect(spec.stderr_path, STDERR_FILENO);
    ::execv(argv[0], argv.data());
    ::_exit(127);
  }
  ChildProcess child;
  child.pid_ = static_cast<std::uint64_t>(pid);
  child.handle_ = reinterpret_cast<void*>(static_cast<std::intptr_t>(pid));
  return child;
#endif
}

Result<int> ChildProcess::wait() {
  if (waited_) {
    return exit_code_;
  }
#if defined(_WIN32)
  if (handle_ == nullptr) {
    return Status::make(ErrorCode::NotInitialized, "process handle is not available");
  }
  const DWORD result = ::WaitForSingleObject(static_cast<HANDLE>(handle_), INFINITE);
  if (result != WAIT_OBJECT_0) {
    return Status::make(ErrorCode::Internal,
                        "WaitForSingleObject returned " + std::to_string(result));
  }
  DWORD code = 0;
  if (!::GetExitCodeProcess(static_cast<HANDLE>(handle_), &code)) {
    return Status::make(ErrorCode::Internal, "GetExitCodeProcess failed");
  }
  waited_ = true;
  exit_code_ = static_cast<int>(code);
  return exit_code_;
#else
  if (pid_ == 0) {
    return Status::make(ErrorCode::NotInitialized, "process has no pid");
  }
  int status = 0;
  const pid_t result = ::waitpid(static_cast<pid_t>(pid_), &status, 0);
  if (result < 0) {
    return Status::make(ErrorCode::Internal, std::string("waitpid failed: ") + std::strerror(errno));
  }
  waited_ = true;
  exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  return exit_code_;
#endif
}

Status ChildProcess::terminate_now() {
#if defined(_WIN32)
  if (handle_ == nullptr) {
    return Status::make(ErrorCode::NotInitialized, "process handle is not available");
  }
  if (waited_) {
    return Status::success();
  }
  if (!::TerminateProcess(static_cast<HANDLE>(handle_), 1)) {
    return Status::make(ErrorCode::Internal,
                        "TerminateProcess failed with error " + std::to_string(::GetLastError()));
  }
  ::WaitForSingleObject(static_cast<HANDLE>(handle_), INFINITE);
  waited_ = true;
  exit_code_ = 1;
  return Status::success();
#else
  if (pid_ == 0) {
    return Status::make(ErrorCode::NotInitialized, "process has no pid");
  }
  if (waited_) {
    return Status::success();
  }
  if (::kill(static_cast<pid_t>(pid_), SIGKILL) != 0) {
    return Status::make(ErrorCode::Internal, std::string("kill failed: ") + std::strerror(errno));
  }
  int status = 0;
  ::waitpid(static_cast<pid_t>(pid_), &status, 0);
  waited_ = true;
  exit_code_ = 1;
  return Status::success();
#endif
}

bool ChildProcess::running() {
#if defined(_WIN32)
  if (handle_ == nullptr || waited_) {
    return false;
  }
  return ::WaitForSingleObject(static_cast<HANDLE>(handle_), 0) == WAIT_TIMEOUT;
#else
  if (pid_ == 0 || waited_) {
    return false;
  }
  int status = 0;
  const pid_t result = ::waitpid(static_cast<pid_t>(pid_), &status, WNOHANG);
  if (result == 0) {
    return true;
  }
  if (result > 0) {
    waited_ = true;
    exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  }
  return false;
#endif
}

Status ChildProcess::close() {
  release();
  return Status::success();
}

}  // namespace fabric_federation
