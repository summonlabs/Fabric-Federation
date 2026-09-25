// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Transport and framing tests: real loopback TCP, framing validation, hostile
// frames and partial delivery.
#include <atomic>
#include <thread>
#include <vector>

#include "fabric_federation/control.hpp"
#include "fabric_federation/net.hpp"
#include "fabric_federation/protocol.hpp"
#include "test_harness.hpp"

#include <filesystem>

using namespace fabric_federation;

namespace {

// A single-use echo peer on loopback TCP. It is a real socket, not a mock; the
// tests that need several messages use the coordinator instead.
class Peer {
 public:
  Peer() {
    auto listener = Listener::bind_loopback(0, 4);
    if (listener.has_value()) {
      listener_ = std::move(listener.value());
      port_ = listener_.port();
    }
  }

  ~Peer() { join(); }

  [[nodiscard]] bool valid() const { return listener_.valid(); }
  [[nodiscard]] std::uint16_t port() const { return port_; }

  // Starts a server that reads one message and replies with Pong.
  void echo_once() {
    thread_ = std::thread([this] {
      auto accepted = listener_.accept();
      if (!accepted.has_value()) {
        served_.store(true);
        return;
      }
      Socket socket = std::move(accepted.value());
      auto message = read_message(socket);
      if (message.has_value()) {
        const Status status = write_message(socket, MessageType::Pong, message.value().span());
        (void)status;
      }
      const Status closed = socket.shutdown_send();
      (void)closed;
      served_.store(true);
    });
  }

  // Starts a server that reads a framed message and reports the status.
  void record_read() {
    thread_ = std::thread([this] {
      auto accepted = listener_.accept();
      if (!accepted.has_value()) {
        served_.store(true);
        return;
      }
      Socket socket = std::move(accepted.value());
      auto message = read_message(socket);
      read_status_ = message.has_value()
                         ? Status::success()
                         : Status(static_cast<ErrorCode>(message.status().code()),
                                  message.status().message());
      served_.store(true);
      const Status closed = socket.shutdown_send();
      (void)closed;
    });
  }

  [[nodiscard]] bool served() const { return served_.load(); }
  [[nodiscard]] const Status& read_status() const { return read_status_; }

  void join() {
    if (thread_.joinable()) {
      thread_.join();
    }
  }

 private:
  Listener listener_;
  std::uint16_t port_ = 0;
  std::thread thread_;
  std::atomic<bool> served_{false};
  Status read_status_;
};

// Builds a frame by hand so that hostile framing can be tested.
std::vector<std::byte> craft_frame(std::uint32_t length, std::uint32_t magic,
                                   std::uint16_t version, std::uint16_t type,
                                   std::uint32_t payload_length,
                                   const std::vector<std::byte>& payload,
                                   bool correct_digest) {
  std::vector<std::byte> frame(4 + length, std::byte{0});
  store_u32_le(frame.data(), length);
  store_u32_le(frame.data() + 4, magic);
  std::memcpy(frame.data() + 8, &version, 2);
  std::memcpy(frame.data() + 10, &type, 2);
  store_u32_le(frame.data() + 12, payload_length);
  if (!payload.empty() && frame.size() >= 16 + payload.size()) {
    std::memcpy(frame.data() + 16, payload.data(), payload.size());
  }
  const std::size_t digest_offset = 16 + payload.size();
  if (frame.size() >= digest_offset + Digest::kSize) {
    Digest digest = Sha256::hash(std::span<const std::byte>(frame.data() + 4, 12 + payload.size()));
    if (!correct_digest) {
      Digest::bytes_type bytes = digest.bytes();
      bytes[0] = static_cast<std::uint8_t>(bytes[0] ^ 0xffu);
      digest = Digest(bytes);
    }
    std::memcpy(frame.data() + digest_offset, digest.bytes().data(), Digest::kSize);
  }
  return frame;
}

}  // namespace

FFED_TEST(protocol, message_round_trip_over_loopback_tcp) {
  Peer peer;
  FFED_REQUIRE(peer.valid());
  peer.echo_once();
  auto client = Socket::connect(Endpoint{"127.0.0.1", peer.port()});
  FFED_REQUIRE(client.has_value());
  const std::vector<std::byte> payload(128, std::byte{0x33});
  FFED_REQUIRE(write_message(client.value(), MessageType::Ping, payload).ok());
  auto reply = read_message(client.value());
  FFED_REQUIRE(reply.has_value());
  FFED_CHECK_EQ(reply.value().type, MessageType::Pong);
  FFED_CHECK_EQ(reply.value().payload.size(), payload.size());
  FFED_CHECK(reply.value().payload == payload);
  peer.join();
  FFED_CHECK(peer.served());
}

FFED_TEST(protocol, payload_structs_round_trip) {
  HelloRequest hello;
  hello.federation = FederationId::derive("protocol", 1);
  hello.node = NodeId::derive("protocol-node", 1);
  hello.incarnation = Incarnation(3);
  hello.product = "fabric federation test";
  Writer writer;
  FFED_REQUIRE(hello.encode(writer).ok());
  auto decoded = decode_payload<HelloRequest>(writer.span());
  FFED_REQUIRE(decoded.has_value());
  FFED_CHECK_EQ(decoded.value().federation, hello.federation);
  FFED_CHECK_EQ(decoded.value().incarnation, hello.incarnation);
  FFED_CHECK_EQ(decoded.value().product, hello.product);
  FFED_CHECK_EQ(decoded.value().protocol_version, kWireProtocolVersion);

  // Trailing bytes are not silently ignored.
  Writer extended;
  FFED_REQUIRE(hello.encode(extended).ok());
  FFED_REQUIRE(extended.u8(0).ok());
  FFED_CHECK(!decode_payload<HelloRequest>(extended.span()).has_value());

  // Invalid UTF-8 in a text field is refused at encode time.
  HelloRequest bad;
  bad.federation = hello.federation;
  bad.node = hello.node;
  bad.product = std::string("bad") + static_cast<char>(0xC0) + "text";
  Writer bad_writer;
  FFED_CHECK_EQ(bad.encode(bad_writer).code(), ErrorCode::InvalidArgument);
}

FFED_TEST(protocol, oversized_frame_is_rejected_before_allocating) {
  Peer peer;
  FFED_REQUIRE(peer.valid());
  peer.record_read();
  auto client = Socket::connect(Endpoint{"127.0.0.1", peer.port()});
  FFED_REQUIRE(client.has_value());
  // A length prefix far beyond the bound, with no payload behind it.
  std::byte length[4];
  store_u32_le(length, 0xfffffff0u);
  FFED_REQUIRE(client.value().send_all(std::span<const std::byte>(length, 4)).ok());
  peer.join();
  FFED_CHECK(peer.served());
  FFED_CHECK_EQ(peer.read_status().code(), ErrorCode::BoundsExceeded);
}

FFED_TEST(protocol, hostile_frames_are_refused) {
  const std::vector<std::byte> payload(16, std::byte{0x11});
  struct Case {
    const char* name;
    std::vector<std::byte> frame;
    ErrorCode expected;
  };
  const std::uint32_t payload_length = static_cast<std::uint32_t>(payload.size());
  const std::uint32_t good_length = 12 + payload_length + static_cast<std::uint32_t>(Digest::kSize);
  std::vector<Case> cases;
  cases.push_back({"wrong magic",
                   craft_frame(good_length, 0xdeadbeefu, kWireProtocolVersion,
                               static_cast<std::uint16_t>(MessageType::Ping), payload_length,
                               payload, true),
                   ErrorCode::ProtocolViolation});
  cases.push_back({"wrong digest",
                   craft_frame(good_length, kFrameMagic, kWireProtocolVersion,
                               static_cast<std::uint16_t>(MessageType::Ping), payload_length,
                               payload, false),
                   ErrorCode::ChecksumMismatch});
  cases.push_back({"unsupported version",
                   craft_frame(good_length, kFrameMagic, 99,
                               static_cast<std::uint16_t>(MessageType::Ping), payload_length,
                               payload, true),
                   ErrorCode::UnsupportedVersion});
  cases.push_back({"unknown message type",
                   craft_frame(good_length, kFrameMagic, kWireProtocolVersion, 9999,
                               payload_length, payload, true),
                   ErrorCode::ProtocolViolation});
  cases.push_back({"length mismatch",
                   craft_frame(good_length, kFrameMagic, kWireProtocolVersion,
                               static_cast<std::uint16_t>(MessageType::Ping),
                               payload_length + 4, payload, true),
                   ErrorCode::ProtocolViolation});
  cases.push_back({"frame shorter than the header",
                   craft_frame(4, kFrameMagic, kWireProtocolVersion,
                               static_cast<std::uint16_t>(MessageType::Ping), 0, {}, true),
                   ErrorCode::ProtocolViolation});
  cases.push_back({"truncated frame", [&] {
                     std::vector<std::byte> frame =
                         craft_frame(good_length, kFrameMagic, kWireProtocolVersion,
                                     static_cast<std::uint16_t>(MessageType::Ping),
                                     payload_length, payload, true);
                     frame.resize(frame.size() - 8);
                     return frame;
                   }(),
                   ErrorCode::Truncated});

  for (const Case& test_case : cases) {
    Peer peer;
    FFED_REQUIRE(peer.valid());
    peer.record_read();
    auto client = Socket::connect(Endpoint{"127.0.0.1", peer.port()});
    FFED_REQUIRE(client.has_value());
    FFED_REQUIRE(client.value().send_all(test_case.frame).ok());
    const Status closed = client.value().shutdown_send();
    (void)closed;
    peer.join();
    FFED_CHECK_EQ(peer.read_status().code(), test_case.expected);
  }
}

FFED_TEST(protocol, a_frame_split_across_reads_is_reassembled) {
  Peer peer;
  FFED_REQUIRE(peer.valid());
  peer.echo_once();
  auto client = Socket::connect(Endpoint{"127.0.0.1", peer.port()});
  FFED_REQUIRE(client.has_value());

  Writer writer;
  const std::vector<std::byte> payload(200, std::byte{0x5a});
  // Build the same bytes write_message would produce.
  std::vector<std::byte> frame(4 + 12 + payload.size() + Digest::kSize);
  const std::uint32_t frame_length =
      12 + static_cast<std::uint32_t>(payload.size()) + static_cast<std::uint32_t>(Digest::kSize);
  store_u32_le(frame.data(), frame_length);
  store_u32_le(frame.data() + 4, kFrameMagic);
  std::uint16_t version = kWireProtocolVersion;
  std::memcpy(frame.data() + 8, &version, 2);
  std::uint16_t type = static_cast<std::uint16_t>(MessageType::Ping);
  std::memcpy(frame.data() + 10, &type, 2);
  store_u32_le(frame.data() + 12, static_cast<std::uint32_t>(payload.size()));
  std::memcpy(frame.data() + 16, payload.data(), payload.size());
  const Digest digest = Sha256::hash(std::span<const std::byte>(frame.data() + 4, 12 + payload.size()));
  std::memcpy(frame.data() + 16 + payload.size(), digest.bytes().data(), Digest::kSize);

  // Send the frame in three pieces.
  const std::size_t first = 3;
  const std::size_t second = frame.size() / 2;
  FFED_REQUIRE(client.value().send_all(std::span<const std::byte>(frame.data(), first)).ok());
  FFED_REQUIRE(client.value()
                   .send_all(std::span<const std::byte>(frame.data() + first, second - first))
                   .ok());
  FFED_REQUIRE(client.value()
                   .send_all(std::span<const std::byte>(frame.data() + second,
                                                        frame.size() - second))
                   .ok());
  auto reply = read_message(client.value());
  FFED_REQUIRE(reply.has_value());
  FFED_CHECK_EQ(reply.value().type, MessageType::Pong);
  peer.join();
}

FFED_TEST(protocol, only_loopback_endpoints_are_accepted) {
  auto remote = Socket::connect(Endpoint{"192.0.2.1", 9});
  FFED_CHECK(!remote.has_value());
  FFED_CHECK_EQ(remote.status().code(), ErrorCode::UnsupportedVersion);
  FFED_CHECK(transport_description().rfind("REAL", 0) == 0);
}

FFED_TEST(protocol, control_channel_helpers_report_failure_loudly) {
  // No daemon is listening on this port, so the readiness helper must fail
  // rather than report success.
  const std::uint16_t unused = 1;
  auto reply = send_control_command(unused, "stats");
  FFED_CHECK(!reply.has_value());
  auto waited = wait_for_control(unused, "stats", 4, 1000);
  FFED_CHECK(!waited.has_value());
  auto missing_file = wait_for_ready_file(
      std::filesystem::temp_directory_path() / "ffed-does-not-exist.ready", 4, 1000);
  FFED_CHECK(!missing_file.has_value());
}

FFED_TEST_MAIN()
