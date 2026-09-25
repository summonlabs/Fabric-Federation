// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Framed loopback transport.
//
// REAL: this is a real TCP socket over the loopback interface, used by real,
// separate operating-system processes. It is not a socketpair, not a pipe, not
// a thread, and not a simulated network.
//
// This runtime deliberately has no connect or receive timeout. A timeout that
// silently turns into a refusal or a retry obscures the failure; a peer that
// stops responding is a condition the caller must observe or the operator must
// terminate. A hang in a test is therefore a defect, never a pass.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include "fabric_federation/errors.hpp"
#include "fabric_federation/export.hpp"

namespace fabric_federation {

struct Endpoint {
  std::string host = "127.0.0.1";
  std::uint16_t port = 0;

  [[nodiscard]] std::string to_string() const;
  friend bool operator==(const Endpoint& a, const Endpoint& b) {
    return a.host == b.host && a.port == b.port;
  }
};

// Starts the platform socket layer once per process. Idempotent.
[[nodiscard]] FFED_API Status initialize_networking();
// Human-readable description of the transport actually in use (REAL loopback
// TCP), reported by the inspection tools so that the claim is auditable.
[[nodiscard]] FFED_API std::string transport_description();

class FFED_API Socket {
 public:
  Socket() = default;
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  ~Socket();

  [[nodiscard]] static Result<Socket> connect(const Endpoint& endpoint);

  [[nodiscard]] bool valid() const noexcept {
    return handle_.load(std::memory_order_acquire) != kInvalidHandle;
  }
  [[nodiscard]] Status send_all(std::span<const std::byte> data);
  // Reads at least one byte unless the peer closed the connection, in which
  // case it returns zero.
  [[nodiscard]] Result<std::size_t> recv_some(std::span<std::byte> buffer);
  // Reads exactly `size` bytes. Returns Truncated when the peer closes early.
  [[nodiscard]] Status recv_exact(std::span<std::byte> buffer);
  [[nodiscard]] Status shutdown_send();
  // Shuts the connection down in both directions without releasing the handle.
  // This is the coordinated-shutdown primitive: a server shutting down calls it
  // on a connection owned by a worker thread, the worker's blocking read
  // returns an error, and the worker closes its own socket. Nothing is freed
  // under the worker's feet.
  [[nodiscard]] Status shutdown_both();
  [[nodiscard]] Status close();
  [[nodiscard]] std::uint16_t local_port() const;
  [[nodiscard]] std::string describe() const;
  [[nodiscard]] std::uintptr_t native_handle() const noexcept {
    return handle_.load(std::memory_order_acquire);
  }

 private:
  friend class Listener;
  static constexpr std::uintptr_t kInvalidHandle = static_cast<std::uintptr_t>(-1);
  // Adopts an already-connected native handle. Used by Listener::accept().
  [[nodiscard]] static Socket adopt(std::uintptr_t handle);
  void release() noexcept;

  // Atomic because shutdown_both() may be called from another thread while the
  // owning thread is blocked in recv().
  std::atomic<std::uintptr_t> handle_{kInvalidHandle};
};

class FFED_API Listener {
 public:
  Listener() = default;
  Listener(Listener&& other) noexcept;
  Listener& operator=(Listener&& other) noexcept;
  Listener(const Listener&) = delete;
  Listener& operator=(const Listener&) = delete;
  ~Listener();

  // Binds to the loopback interface. Port 0 selects an ephemeral port, which
  // port() then reports.
  [[nodiscard]] static Result<Listener> bind_loopback(std::uint16_t port, std::size_t backlog);
  [[nodiscard]] Result<Socket> accept();
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] bool valid() const noexcept { return handle_ != kInvalidHandle; }
  // Closes the listening socket. An accept() in progress in another thread
  // returns an error rather than blocking forever, which is how the server
  // shuts down without a timeout.
  [[nodiscard]] Status close();

 private:
  static constexpr std::uintptr_t kInvalidHandle = static_cast<std::uintptr_t>(-1);
  void release() noexcept;

  std::uintptr_t handle_ = kInvalidHandle;
  std::uint16_t port_ = 0;
};

}  // namespace fabric_federation
