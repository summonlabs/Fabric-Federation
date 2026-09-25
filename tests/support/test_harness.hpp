// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Small self-contained test harness.
//
// Deliberately has no timeout, no watchdog and no "assume success" path: a
// test that hangs has to be diagnosed, not classified as a pass.
#pragma once

#include <cstdint>
#include <exception>
#include <sstream>
#include <typeinfo>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "fabric_federation/errors.hpp"

namespace ffed_test {

class TestFailure : public std::runtime_error {
 public:
  explicit TestFailure(const std::string& message) : std::runtime_error(message) {}
};

struct TestCase {
  std::string suite;
  std::string name;
  void (*fn)();
};

[[nodiscard]] std::vector<TestCase>& registry();

struct Registrar {
  Registrar(const char* suite, const char* name, void (*fn)());
};

void record_failure(const char* file, int line, const std::string& message);
void record_check();
[[nodiscard]] bool current_test_failed();

// Value rendering for failure messages.
[[nodiscard]] std::string repr(const std::string& value);
[[nodiscard]] std::string repr(std::string_view value);
[[nodiscard]] std::string repr(const char* value);
[[nodiscard]] std::string repr(bool value);
[[nodiscard]] std::string repr(fabric_federation::Outcome value);
[[nodiscard]] std::string repr(fabric_federation::EvidenceState value);
[[nodiscard]] std::string repr(fabric_federation::ErrorCode value);
[[nodiscard]] std::string repr(const fabric_federation::Status& value);

template <class T, class = void>
struct has_to_string : std::false_type {};
template <class T>
struct has_to_string<T, std::void_t<decltype(std::declval<const T&>().to_string())>>
    : std::true_type {};

template <class T, class = void>
struct has_stream_insertion : std::false_type {};
template <class T>
struct has_stream_insertion<
    T, std::void_t<decltype(std::declval<std::ostringstream&>() << std::declval<const T&>())>>
    : std::true_type {};

template <class T>
std::string repr(const T& value) {
  if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(static_cast<std::underlying_type_t<T>>(value)));
  } else if constexpr (std::is_same_v<T, char>) {
    return std::string("'") + value + "'";
  } else if constexpr (std::is_arithmetic_v<T>) {
    return std::to_string(value);
  } else if constexpr (has_to_string<T>::value) {
    return value.to_string();
  } else if constexpr (has_stream_insertion<T>::value) {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  } else {
    return std::string("<value of ") + typeid(T).name() + ">";
  }
}

int run_all(int argc, char* argv[]);

// Seed supplied by --seed on the command line, or kDefaultPropertySeed.
[[nodiscard]] std::uint64_t property_seed();
// Prints the seed once so a failing property run is reproducible.
void announce_seed();

}  // namespace ffed_test

#define FFED_TEST(suite, name)                                                          \
  static void ffed_test_##suite##_##name();                                             \
  namespace {                                                                           \
  const ::ffed_test::Registrar ffed_registrar_##suite##_##name(#suite, #name,           \
                                                              &ffed_test_##suite##_##name); \
  }                                                                                     \
  static void ffed_test_##suite##_##name()

#define FFED_FAIL(message) ::ffed_test::record_failure(__FILE__, __LINE__, (message))

#define FFED_CHECK(expr)                                                       \
  do {                                                                         \
    ::ffed_test::record_check();                                               \
    if (!(expr)) {                                                             \
      ::ffed_test::record_failure(__FILE__, __LINE__, "CHECK failed: " #expr); \
    }                                                                          \
  } while (false)

#define FFED_REQUIRE(expr)                                                     \
  do {                                                                         \
    ::ffed_test::record_check();                                               \
    if (!(expr)) {                                                             \
      ::ffed_test::record_failure(__FILE__, __LINE__, "REQUIRE failed: " #expr); \
      throw ::ffed_test::TestFailure("REQUIRE failed: " #expr);                \
    }                                                                          \
  } while (false)

#define FFED_CHECK_EQ(actual, expected)                                                  \
  do {                                                                                   \
    ::ffed_test::record_check();                                                         \
    const auto& ffed_actual_value = (actual);                                            \
    const auto& ffed_expected_value = (expected);                                        \
    if (!(ffed_actual_value == ffed_expected_value)) {                                   \
      ::ffed_test::record_failure(__FILE__, __LINE__,                                    \
                                  "CHECK_EQ failed: " #actual " == " #expected           \
                                  "\n    actual:   " +                                  \
                                      ::ffed_test::repr(ffed_actual_value) +             \
                                      "\n    expected: " +                              \
                                      ::ffed_test::repr(ffed_expected_value));           \
    }                                                                                    \
  } while (false)

#define FFED_CHECK_MSG(expr, message)                                          \
  do {                                                                         \
    ::ffed_test::record_check();                                               \
    if (!(expr)) {                                                             \
      ::ffed_test::record_failure(__FILE__, __LINE__,                          \
                                  std::string("CHECK failed: " #expr " -- ") + (message)); \
    }                                                                          \
  } while (false)

#define FFED_TEST_MAIN()                       \
  int main(int argc, char* argv[]) {           \
    return ::ffed_test::run_all(argc, argv);   \
  }
