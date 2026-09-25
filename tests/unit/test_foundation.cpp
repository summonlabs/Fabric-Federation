// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Foundation tests: digest, identifiers, codec bounds, text validation and the
// deterministic generator.
#include <string>
#include <vector>

#include "fabric_federation/codec.hpp"
#include "fabric_federation/digest.hpp"
#include "fabric_federation/ids.hpp"
#include "fabric_federation/random.hpp"
#include "fabric_federation/text.hpp"
#include "test_harness.hpp"

using namespace fabric_federation;

FFED_TEST(digest, nist_vectors) {
  FFED_CHECK_EQ(Sha256::hash(std::string_view("")).to_hex(),
           std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  FFED_CHECK_EQ(Sha256::hash(std::string_view("abc")).to_hex(),
           std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  FFED_CHECK_EQ(
      Sha256::hash(std::string_view("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
          .to_hex(),
      std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  FFED_CHECK_EQ(Sha256::hash(std::string_view(
               "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopq"
               "klmnopqrlmnopqrsmnopqrstnopqrstu"))
               .to_hex(),
           std::string("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"));
}

FFED_TEST(digest, million_a_vector) {
  Sha256 hasher;
  const std::string chunk(1000, 'a');
  for (int i = 0; i < 1000; ++i) {
    hasher.update(chunk);
  }
  FFED_CHECK_EQ(hasher.finish().to_hex(),
           std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

FFED_TEST(digest, streaming_matches_oneshot) {
  DeterministicRng rng(ffed_test::property_seed());
  for (int iteration = 0; iteration < 64; ++iteration) {
    const std::size_t size = static_cast<std::size_t>(rng.range(0, 4096));
    std::vector<std::byte> data(size);
    rng.fill_bytes(data);
    Sha256 streaming;
    std::size_t offset = 0;
    while (offset < data.size()) {
      const std::size_t step =
          std::min<std::size_t>(data.size() - offset, static_cast<std::size_t>(rng.range(1, 71)));
      streaming.update(std::span<const std::byte>(data.data() + offset, step));
      offset += step;
    }
    FFED_CHECK_EQ(streaming.finish(), Sha256::hash(data));
  }
}

FFED_TEST(digest, hex_round_trip_and_rejects_bad_input) {
  DeterministicRng rng(ffed_test::property_seed());
  for (int i = 0; i < 32; ++i) {
    Digest::bytes_type bytes{};
    rng.fill_bytes(std::span<std::byte>(reinterpret_cast<std::byte*>(bytes.data()), bytes.size()));
    const Digest original(bytes);
    const auto parsed = Digest::from_hex(original.to_hex());
    FFED_REQUIRE(parsed.has_value());
    FFED_CHECK_EQ(parsed.value(), original);
  }
  FFED_CHECK(!Digest::from_hex("").has_value());
  FFED_CHECK(!Digest::from_hex("zz").has_value());
  FFED_CHECK(!Digest::from_hex(std::string(63, 'a')).has_value());
  FFED_CHECK(!Digest::from_hex(std::string(64, 'A')).has_value());  // uppercase is not canonical
}

FFED_TEST(ids, format_parse_round_trip) {
  const FederationId fed = FederationId::derive("unit-test", 7);
  const std::string text = fed.to_string();
  FFED_CHECK_EQ(text.size(), std::string("fed-").size() + 32);
  FFED_CHECK_EQ(text.substr(0, 4), std::string("fed-"));
  const auto parsed = FederationId::parse(text);
  FFED_REQUIRE(parsed.has_value());
  FFED_CHECK_EQ(parsed.value(), fed);
  // The same seed and counter always produce the same identifier.
  FFED_CHECK_EQ(FederationId::derive("unit-test", 7), fed);
  FFED_CHECK(FederationId::derive("unit-test", 8) != fed);
  FFED_CHECK(!FederationId::parse("mbr-00000000000000000000000000000000").has_value());
  FFED_CHECK(!FederationId::parse("fed-0000000000000000000000000000000").has_value());
  FFED_CHECK(!FederationId::parse("fed-0000000000000000000000000000000Z").has_value());
  FFED_CHECK(!FederationId::parse("").has_value());
}

FFED_TEST(ids, distinct_types_are_distinct_prefixes) {
  FFED_CHECK_EQ(MemberId::derive("x", 1).to_string().substr(0, 3), std::string("mbr"));
  FFED_CHECK_EQ(LeaseId::derive("x", 1).to_string().substr(0, 3), std::string("lea"));
  FFED_CHECK_EQ(NodeId::derive("x", 1).to_string().substr(0, 3), std::string("nod"));
  FFED_CHECK_EQ(EvidenceId::derive("x", 1).to_string().substr(0, 3), std::string("evd"));
  FFED_CHECK_EQ(RequestId::derive("x", 1).to_string().substr(0, 3), std::string("req"));
  FFED_CHECK_EQ(FabricDomainId::derive("x", 1).to_string().substr(0, 3), std::string("dom"));
  FFED_CHECK_EQ(LineageId::derive("x", 1).to_string().substr(0, 3), std::string("lin"));
}

FFED_TEST(counters, checked_increment_refuses_to_wrap) {
  Generation generation(5);
  Generation next;
  FFED_REQUIRE(generation.try_next(next));
  FFED_CHECK_EQ(next.value(), std::uint64_t{6});
  FFED_CHECK(!generation.try_add(std::numeric_limits<std::uint64_t>::max(), next));

  const Generation maximum(std::numeric_limits<std::uint64_t>::max());
  FFED_CHECK(!maximum.try_next(next));

  Generation sum;
  FFED_REQUIRE(generation.try_add(10, sum));
  FFED_CHECK_EQ(sum.value(), std::uint64_t{15});
}

FFED_TEST(codec, round_trip_primitives) {
  Writer writer;
  FFED_REQUIRE(writer.u8(0xAB).ok());
  FFED_REQUIRE(writer.u16(0xBEEF).ok());
  FFED_REQUIRE(writer.u32(0xDEADBEEF).ok());
  FFED_REQUIRE(writer.u64(0x0123456789ABCDEFull).ok());
  FFED_REQUIRE(writer.boolean(true).ok());
  FFED_REQUIRE(writer.identifier("federation.scope").ok());
  FFED_REQUIRE(writer.digest(Digest::of("payload")).ok());

  Reader reader(writer.span());
  auto u8 = reader.u8();
  FFED_REQUIRE(u8.has_value());
  FFED_CHECK_EQ(u8.value(), std::uint8_t{0xAB});
  auto u16 = reader.u16();
  FFED_REQUIRE(u16.has_value());
  FFED_CHECK_EQ(u16.value(), std::uint16_t{0xBEEF});
  auto u32 = reader.u32();
  FFED_REQUIRE(u32.has_value());
  FFED_CHECK_EQ(u32.value(), std::uint32_t{0xDEADBEEF});
  auto u64 = reader.u64();
  FFED_REQUIRE(u64.has_value());
  FFED_CHECK_EQ(u64.value(), std::uint64_t{0x0123456789ABCDEFull});
  auto flag = reader.boolean();
  FFED_REQUIRE(flag.has_value());
  FFED_CHECK(flag.value());
  auto name = reader.identifier();
  FFED_REQUIRE(name.has_value());
  FFED_CHECK_EQ(name.value(), std::string("federation.scope"));
  auto digest = reader.digest();
  FFED_REQUIRE(digest.has_value());
  FFED_CHECK_EQ(digest.value(), Digest::of("payload"));
  FFED_CHECK(reader.at_end());
  FFED_CHECK(reader.expect_end().ok());
}

FFED_TEST(codec, encoding_is_little_endian_and_canonical) {
  Writer writer;
  FFED_REQUIRE(writer.u32(1).ok());
  FFED_REQUIRE(writer.size() == 4);
  FFED_CHECK_EQ(std::to_integer<int>(writer.data()[0]), 1);
  FFED_CHECK_EQ(std::to_integer<int>(writer.data()[1]), 0);
  FFED_CHECK_EQ(std::to_integer<int>(writer.data()[2]), 0);
  FFED_CHECK_EQ(std::to_integer<int>(writer.data()[3]), 0);
}

FFED_TEST(codec, reader_rejects_truncation_and_trailing_bytes) {
  Writer writer;
  FFED_REQUIRE(writer.u32(7).ok());
  for (std::size_t length = 0; length < 4; ++length) {
    Reader reader(std::span<const std::byte>(writer.data().data(), length));
    auto value = reader.u32();
    FFED_CHECK(!value.has_value());
    FFED_CHECK_EQ(value.status().code(), ErrorCode::Truncated);
  }
  Writer extra;
  FFED_REQUIRE(extra.u32(7).ok());
  FFED_REQUIRE(extra.u32(8).ok());
  Reader reader(extra.span());
  auto value = reader.u32();
  FFED_REQUIRE(value.has_value());
  FFED_CHECK_EQ(reader.expect_end().code(), ErrorCode::Corrupt);
}

FFED_TEST(codec, reader_validates_declared_length_before_allocating) {
  Writer writer;
  FFED_REQUIRE(writer.u32(0xFFFFFFF0u).ok());  // absurd declared byte-string length
  Reader reader(writer.span());
  auto text = reader.text(kMaxTextLength);
  FFED_CHECK(!text.has_value());
  FFED_CHECK_EQ(text.status().code(), ErrorCode::BoundsExceeded);

  Writer count_writer;
  FFED_REQUIRE(count_writer.u32(0xFFFFFFF0u).ok());
  Reader count_reader(count_writer.span());
  auto count = count_reader.count(kMaxArtifacts);
  FFED_CHECK(!count.has_value());
  FFED_CHECK_EQ(count.status().code(), ErrorCode::BoundsExceeded);
}

FFED_TEST(codec, writer_rejects_invalid_utf8_text) {
  Writer writer;
  const std::string invalid = std::string("bad") + static_cast<char>(0xC0) + "text";
  FFED_CHECK_EQ(writer.text(invalid, kMaxTextLength).code(), ErrorCode::InvalidArgument);
  // A lone continuation byte and a truncated multi-byte sequence are rejected too.
  FFED_CHECK_EQ(writer.text(std::string(1, static_cast<char>(0x80)), kMaxTextLength).code(),
           ErrorCode::InvalidArgument);
  FFED_CHECK_EQ(writer.text(std::string(1, static_cast<char>(0xE2)), kMaxTextLength).code(),
           ErrorCode::InvalidArgument);
  FFED_CHECK(writer.text("valid \xE2\x82\xAC text", kMaxTextLength).ok());
}

FFED_TEST(text, utf8_validation_matrix) {
  FFED_CHECK(utf8_is_valid(""));
  FFED_CHECK(utf8_is_valid("plain ascii"));
  FFED_CHECK(utf8_is_valid("\xE2\x82\xAC"));            // U+20AC
  FFED_CHECK(utf8_is_valid("\xF0\x9F\x98\x80"));       // U+1F600
  FFED_CHECK(!utf8_is_valid("\xC0\x80"));                // overlong NUL
  FFED_CHECK(!utf8_is_valid("\xE0\x80\x80"));           // overlong
  FFED_CHECK(!utf8_is_valid("\xED\xA0\x80"));           // surrogate half
  FFED_CHECK(!utf8_is_valid("\xF4\x90\x80\x80"));      // above U+10FFFF
  FFED_CHECK(!utf8_is_valid("\xF8\x88\x80\x80\x80")); // 5-byte form
  FFED_CHECK(!utf8_is_valid("\x80"));                     // lone continuation
  FFED_CHECK(!utf8_is_valid("\xE2\x82"));                // truncated
}

FFED_TEST(text, sanitize_and_escape_never_emit_invalid_bytes) {
  const std::string invalid = std::string("a") + static_cast<char>(0xC0) + "b";
  FFED_CHECK(utf8_is_valid(utf8_sanitize(invalid)));
  // The hex escape is split so that C++ does not read \xBDb as one escape.
  FFED_CHECK_EQ(utf8_sanitize(invalid), std::string("a\xEF\xBF\xBD" "b"));
  FFED_CHECK(utf8_is_valid(json_escape(invalid)));
  FFED_CHECK_EQ(json_escape("a\"b\\c"), std::string("\"a\\\"b\\\\c\""));
  FFED_CHECK_EQ(json_escape(std::string("line\nfeed")), std::string("\"line\\nfeed\""));
  FFED_CHECK_EQ(escape_for_display(std::string("tab\there")), std::string("tab\\there"));
}

FFED_TEST(random, generator_is_reproducible) {
  DeterministicRng a(12345);
  DeterministicRng b(12345);
  for (int i = 0; i < 256; ++i) {
    FFED_CHECK_EQ(a.next_u64(), b.next_u64());
  }
  DeterministicRng c(12346);
  DeterministicRng d(12345);
  FFED_CHECK(c.next_u64() != d.next_u64());
}

FFED_TEST(random, range_is_bounded_and_seed_parses) {
  DeterministicRng rng(0xABCDEF);
  bool saw_low = false;
  bool saw_high = false;
  for (int i = 0; i < 20000; ++i) {
    const std::uint64_t value = rng.range(3, 7);
    FFED_REQUIRE(value >= 3);
    FFED_REQUIRE(value <= 7);
    saw_low = saw_low || value == 3;
    saw_high = saw_high || value == 7;
  }
  FFED_CHECK(saw_low);
  FFED_CHECK(saw_high);
  FFED_CHECK_EQ(rng.below(0), std::uint64_t{0});

  std::uint64_t seed = 0;
  FFED_CHECK(parse_seed("1234", seed));
  FFED_CHECK_EQ(seed, std::uint64_t{1234});
  FFED_CHECK(parse_seed("0xff", seed));
  FFED_CHECK_EQ(seed, std::uint64_t{255});
  FFED_CHECK(!parse_seed("", seed));
  FFED_CHECK(!parse_seed("0x", seed));
  FFED_CHECK(!parse_seed("12z", seed));
  FFED_CHECK(!parse_seed("99999999999999999999999", seed));
}

FFED_TEST(bounds, checked_arithmetic_reports_overflow) {
  std::uint64_t out = 0;
  FFED_CHECK(checked_add_u64(1, 2, out));
  FFED_CHECK_EQ(out, std::uint64_t{3});
  FFED_CHECK(!checked_add_u64(std::numeric_limits<std::uint64_t>::max(), 1, out));
  FFED_CHECK(checked_mul_u64(1000, 1000, out));
  FFED_CHECK_EQ(out, std::uint64_t{1000000});
  FFED_CHECK(!checked_mul_u64(std::numeric_limits<std::uint64_t>::max(), 2, out));

  std::uint32_t narrowed = 0;
  FFED_CHECK(narrow_u32(1234, narrowed));
  FFED_CHECK_EQ(narrowed, std::uint32_t{1234});
  FFED_CHECK(!narrow_u32(static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()) + 1u,
                    narrowed));
}

FFED_TEST_MAIN()
