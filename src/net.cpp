// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "fabric_federation/net.hpp"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace fabric_federation {
namespace {

#if defined(_WIN32)
using NativeSocket = SOCKET;
constexpr NativeSocket kInvalidNative = INVALID_SOCKET;
#else
using NativeSocket = int;
constexpr NativeSocket kInvalidNative = -1;
#endif

std::once_flag g_startup_once;
Status g_startup_status = Status::success();

Status startup_locked() {
#if defined(_WIN32)
  WSADATA data;
  const int result = ::WSAStartup(MAKEWORD(2, 2), &data);
  if (result != 0) {
    return Status::make(ErrorCode::NetworkError,
                        "WSAStartup failed with code " + std::to_string(result));
  }
  return Status::success();
#else
  return Status::success();
#endif
}

NativeSocket to_native(std::uintptr_t handle) { return static_cast<NativeSocket>(handle); }

std::uintptr_t from_native(NativeSocket socket) { return static_cast<std::uintptr_t>(socket); }

std::string last_socket_error() {
#if defined(_WIN32)
  return "winsock error " + std::to_string(::WSAGetLastError());
#else
  return std::string("socket error: ") + std::strerror(errno);
#endif
}

}  // namespace

Status initialize_networking() {
  std::call_once(g_startup_once, [] { g_startup_status = startup_locked(); });
  return g_startup_status;
}

std::string transport_description() {
#if defined(_WIN32)
  return "REAL: TCP over the loopback interface (AF_INET, 127.0.0.1) via Winsock 2.2";
#else
  return "REAL: TCP over the loopback interface (AF_INET, 127.0.0.1) via POSIX sockets";
#endif
}

std::string Endpoint::to_string() const { return host + ":" + std::to_string(port); }

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------

Socket::Socket(Socket&& other) noexcept
    : handle_(other.handle_.exchange(kInvalidHandle, std::memory_order_acq_rel)) {}

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    release();
    handle_.store(other.handle_.exchange(kInvalidHandle, std::memory_order_acq_rel),
                  std::memory_order_release);
  }
  return *this;
}

Socket::~Socket() { release(); }

Socket Socket::adopt(std::uintptr_t handle) {
  Socket socket;
  socket.handle_.store(handle, std::memory_order_release);
  return socket;
}

void Socket::release() noexcept {
  const std::uintptr_t handle = handle_.exchange(kInvalidHandle, std::memory_order_acq_rel);
  if (handle != kInvalidHandle) {
#if defined(_WIN32)
    ::closesocket(to_native(handle));
#else
    ::close(to_native(handle));
#endif
  }
}

Result<Socket> Socket::connect(const Endpoint& endpoint) {
  Status status = initialize_networking();
  if (!status.ok()) {
    return status;
  }
  if (endpoint.host != "127.0.0.1" && endpoint.host != "localhost") {
    // The transport is deliberately loopback-only. Anything else would be a
    // claim about cross-host networking that this runtime does not make.
    return Status::make(ErrorCode::UnsupportedVersion,
                        "only loopback endpoints are supported by this runtime");
  }
  const NativeSocket raw = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (raw == kInvalidNative) {
    return Status::make(ErrorCode::NetworkError, "socket() failed: " + last_socket_error());
  }
  Socket socket = Socket::adopt(from_native(raw));

  int nodelay = 1;
  ::setsockopt(raw, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay),
               sizeof(nodelay));

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(endpoint.port);
  if (::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
    return Status::make(ErrorCode::NetworkError, "loopback address could not be encoded");
  }
  if (::connect(raw, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    return Status::make(ErrorCode::NetworkError,
                        "connect to " + endpoint.to_string() + " failed: " + last_socket_error());
  }
  return socket;
}

Status Socket::send_all(std::span<const std::byte> data) {
  const std::uintptr_t handle = handle_.load(std::memory_order_acquire);
  if (handle == kInvalidHandle) {
    return Status::make(ErrorCode::NotInitialized, "socket is closed");
  }
  std::size_t sent = 0;
  while (sent < data.size()) {
    const std::size_t remaining = data.size() - sent;
    const int chunk = static_cast<int>(remaining > (1u << 20) ? (1u << 20) : remaining);
    const int result = ::send(to_native(handle),
                              reinterpret_cast<const char*>(data.data() + sent), chunk, 0);
    if (result <= 0) {
      return Status::make(ErrorCode::NetworkError, "send failed: " + last_socket_error());
    }
    sent += static_cast<std::size_t>(result);
  }
  return Status::success();
}

Result<std::size_t> Socket::recv_some(std::span<std::byte> buffer) {
  const std::uintptr_t handle = handle_.load(std::memory_order_acquire);
  if (handle == kInvalidHandle) {
    return Status::make(ErrorCode::NotInitialized, "socket is closed");
  }
  if (buffer.empty()) {
    return std::size_t{0};
  }
  const std::size_t remaining = buffer.size();
  const int chunk = static_cast<int>(remaining > (1u << 20) ? (1u << 20) : remaining);
  const int result = ::recv(to_native(handle), reinterpret_cast<char*>(buffer.data()), chunk, 0);
  if (result < 0) {
    return Status::make(ErrorCode::NetworkError, "recv failed: " + last_socket_error());
  }
  return static_cast<std::size_t>(result);
}

Status Socket::recv_exact(std::span<std::byte> buffer) {
  std::size_t received = 0;
  while (received < buffer.size()) {
    auto chunk = recv_some(buffer.subspan(received));
    if (!chunk.has_value()) {
      return chunk.status();
    }
    if (chunk.value() == 0) {
      return Status::make(ErrorCode::Truncated,
                          "peer closed the connection after " + std::to_string(received) +
                              " of " + std::to_string(buffer.size()) + " bytes");
    }
    received += chunk.value();
  }
  return Status::success();
}

Status Socket::shutdown_send() {
  const std::uintptr_t handle = handle_.load(std::memory_order_acquire);
  if (handle == kInvalidHandle) {
    return Status::make(ErrorCode::NotInitialized, "socket is closed");
  }
#if defined(_WIN32)
  ::shutdown(to_native(handle), SD_SEND);
#else
  ::shutdown(to_native(handle), SHUT_WR);
#endif
  return Status::success();
}

Status Socket::shutdown_both() {
  const std::uintptr_t handle = handle_.load(std::memory_order_acquire);
  if (handle == kInvalidHandle) {
    return Status::make(ErrorCode::NotInitialized, "socket is closed");
  }
#if defined(_WIN32)
  ::shutdown(to_native(handle), SD_BOTH);
#else
  ::shutdown(to_native(handle), SHUT_RDWR);
#endif
  return Status::success();
}

Status Socket::close() {
  release();
  return Status::success();
}

std::uint16_t Socket::local_port() const {
  const std::uintptr_t handle = handle_.load(std::memory_order_acquire);
  if (handle == kInvalidHandle) {
    return 0;
  }
  sockaddr_in address{};
#if defined(_WIN32)
  int length = sizeof(address);
#else
  socklen_t length = sizeof(address);
#endif
  if (::getsockname(to_native(handle), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return 0;
  }
  return ntohs(address.sin_port);
}

std::string Socket::describe() const {
  const std::uintptr_t handle = handle_.load(std::memory_order_acquire);
  if (handle == kInvalidHandle) {
    return "closed socket";
  }
  sockaddr_in address{};
#if defined(_WIN32)
  int length = sizeof(address);
#else
  socklen_t length = sizeof(address);
#endif
  if (::getpeername(to_native(handle), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    return "socket (peer unavailable)";
  }
  char text[INET_ADDRSTRLEN] = {0};
  ::inet_ntop(AF_INET, &address.sin_addr, text, sizeof(text));
  return std::string(text) + ":" + std::to_string(ntohs(address.sin_port));
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

Listener::Listener(Listener&& other) noexcept : handle_(other.handle_), port_(other.port_) {
  other.handle_ = kInvalidHandle;
  other.port_ = 0;
}

Listener& Listener::operator=(Listener&& other) noexcept {
  if (this != &other) {
    release();
    handle_ = other.handle_;
    port_ = other.port_;
    other.handle_ = kInvalidHandle;
    other.port_ = 0;
  }
  return *this;
}

Listener::~Listener() { release(); }

void Listener::release() noexcept {
  if (handle_ != kInvalidHandle) {
#if defined(_WIN32)
    ::closesocket(to_native(handle_));
#else
    ::close(to_native(handle_));
#endif
    handle_ = kInvalidHandle;
  }
}

Result<Listener> Listener::bind_loopback(std::uint16_t port, std::size_t backlog) {
  Status status = initialize_networking();
  if (!status.ok()) {
    return status;
  }
  const NativeSocket raw = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (raw == kInvalidNative) {
    return Status::make(ErrorCode::NetworkError, "socket() failed: " + last_socket_error());
  }
  Listener listener;
  listener.handle_ = from_native(raw);

  int reuse = 1;
  ::setsockopt(raw, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
               sizeof(reuse));

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  if (::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
    return Status::make(ErrorCode::NetworkError, "loopback address could not be encoded");
  }
  if (::bind(raw, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    return Status::make(ErrorCode::NetworkError, "bind failed: " + last_socket_error());
  }
  if (::listen(raw, static_cast<int>(backlog)) != 0) {
    return Status::make(ErrorCode::NetworkError, "listen failed: " + last_socket_error());
  }
  sockaddr_in bound{};
#if defined(_WIN32)
  int length = sizeof(bound);
#else
  socklen_t length = sizeof(bound);
#endif
  if (::getsockname(raw, reinterpret_cast<sockaddr*>(&bound), &length) != 0) {
    return Status::make(ErrorCode::NetworkError, "getsockname failed: " + last_socket_error());
  }
  listener.port_ = ntohs(bound.sin_port);
  return listener;
}

Result<Socket> Listener::accept() {
  if (handle_ == kInvalidHandle) {
    return Status::make(ErrorCode::NotInitialized, "listener is closed");
  }
  const NativeSocket raw = ::accept(to_native(handle_), nullptr, nullptr);
  if (raw == kInvalidNative) {
    return Status::make(ErrorCode::NetworkError, "accept failed: " + last_socket_error());
  }
  int nodelay = 1;
  ::setsockopt(raw, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay),
               sizeof(nodelay));
  return Socket::adopt(from_native(raw));
}

Status Listener::close() {
  release();
  return Status::success();
}

}  // namespace fabric_federation
