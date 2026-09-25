// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Measures framed round-trips over real loopback TCP. The peer is a real
// listening socket in this process; that is enough to measure framing and
// syscall cost, and it is explicitly NOT a multi-process claim. The
// multi-process proof lives in tests/integration.
#include <atomic>
#include <thread>

#include "bench_common.hpp"
#include "fabric_federation/net.hpp"
#include "fabric_federation/protocol.hpp"

using namespace fabric_federation;
using namespace ffed::bench;

int main() {
  std::printf("fabric-federation framed transport round-trip (loopback TCP)\n");
  auto listener = Listener::bind_loopback(0, 4);
  if (!listener.has_value()) {
    std::fprintf(stderr, "bind failed\n");
    return 1;
  }
  const std::uint16_t port = listener.value().port();
  constexpr unsigned long long kRoundTrips = 5000;
  std::atomic<bool> serving{true};
  std::thread server([&] {
    auto accepted = listener.value().accept();
    if (!accepted.has_value()) {
      return;
    }
    Socket socket = std::move(accepted.value());
    for (unsigned long long i = 0; i < kRoundTrips; ++i) {
      auto message = read_message(socket);
      if (!message.has_value()) {
        break;
      }
      const Status status = write_message(socket, MessageType::Pong, message.value().span());
      if (!status.ok()) {
        break;
      }
    }
    const Status closed = socket.shutdown_send();
    (void)closed;
    serving.store(false);
  });

  auto client = Socket::connect(Endpoint{"127.0.0.1", port});
  if (!client.has_value()) {
    std::fprintf(stderr, "connect failed\n");
    return 1;
  }
  std::vector<std::byte> payload(256, std::byte{0x42});
  Timer timer;
  for (unsigned long long i = 0; i < kRoundTrips; ++i) {
    const Status sent = write_message(client.value(), MessageType::Ping, payload);
    if (!sent.ok()) {
      std::fprintf(stderr, "send failed\n");
      return 1;
    }
    auto reply = read_message(client.value());
    if (!reply.has_value() || reply.value().type != MessageType::Pong) {
      std::fprintf(stderr, "reply missing\n");
      return 1;
    }
  }
  report("round-trip 256-byte framed payload", kRoundTrips, timer.milliseconds());
  const Status closed = client.value().shutdown_send();
  (void)closed;
  server.join();
  std::printf("transport: %s\n", transport_description().c_str());
  return serving.load() ? 0 : 0;
}
