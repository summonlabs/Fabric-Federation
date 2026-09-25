// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#include "test_harness.hpp"

#include <cstdio>
#include <cstring>
#include <iostream>

#include "fabric_federation/random.hpp"

namespace ffed_test {
namespace {

std::uint64_t g_property_seed = fabric_federation::kDefaultPropertySeed;
bool g_announced = false;
bool g_current_failed = false;
std::size_t g_checks = 0;
std::size_t g_failures = 0;

struct Options {
  std::string suite_filter;
  std::string test_filter;
  bool list_only = false;
};

Options parse_options(int argc, char* argv[]) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    const auto take_value = [&](std::string_view prefix) -> std::string {
      if (arg.size() > prefix.size() && arg.substr(0, prefix.size()) == prefix) {
        return std::string(arg.substr(prefix.size()));
      }
      return std::string();
    };
    if (arg == "--list") {
      options.list_only = true;
      continue;
    }
    if (arg == "--seed" && i + 1 < argc) {
      std::uint64_t seed = 0;
      if (fabric_federation::parse_seed(argv[++i], seed)) {
        g_property_seed = seed;
      }
      continue;
    }
    std::string value = take_value("--suite=");
    if (!value.empty()) {
      options.suite_filter = value;
      continue;
    }
    value = take_value("--test=");
    if (!value.empty()) {
      options.test_filter = value;
      continue;
    }
    value = take_value("--seed=");
    if (!value.empty()) {
      std::uint64_t seed = 0;
      if (fabric_federation::parse_seed(value, seed)) {
        g_property_seed = seed;
      }
      continue;
    }
  }
  return options;
}

bool matches(const std::string& value, const std::string& filter) {
  return filter.empty() || value.find(filter) != std::string::npos;
}

}  // namespace

std::vector<TestCase>& registry() {
  static std::vector<TestCase> cases;
  return cases;
}

Registrar::Registrar(const char* suite, const char* name, void (*fn)()) {
  registry().push_back(TestCase{suite, name, fn});
}

void record_failure(const char* file, int line, const std::string& message) {
  ++g_failures;
  g_current_failed = true;
  std::cout << "    " << file << ":" << line << ": " << message << "\n";
}

void record_check() { ++g_checks; }

bool current_test_failed() { return g_current_failed; }

std::string repr(const std::string& value) { return value; }
std::string repr(std::string_view value) { return std::string(value); }
std::string repr(const char* value) { return std::string(value == nullptr ? "(null)" : value); }
std::string repr(bool value) { return value ? "true" : "false"; }
std::string repr(fabric_federation::Outcome value) {
  return std::string(fabric_federation::to_string(value));
}
std::string repr(fabric_federation::EvidenceState value) {
  return std::string(fabric_federation::to_string(value));
}
std::string repr(fabric_federation::ErrorCode value) {
  return std::string(fabric_federation::to_string(value));
}
std::string repr(const fabric_federation::Status& value) { return value.to_string(); }

std::uint64_t property_seed() { return g_property_seed; }

void announce_seed() {
  if (!g_announced) {
    g_announced = true;
    std::printf("[ seed ] 0x%llx\n", static_cast<unsigned long long>(g_property_seed));
    std::fflush(stdout);
  }
}

int run_all(int argc, char* argv[]) {
  const Options options = parse_options(argc, argv);
  std::vector<TestCase> selected;
  for (const TestCase& test : registry()) {
    if (matches(test.suite, options.suite_filter) && matches(test.name, options.test_filter)) {
      selected.push_back(test);
    }
  }

  if (options.list_only) {
    for (const TestCase& test : selected) {
      std::printf("%s.%s\n", test.suite.c_str(), test.name.c_str());
    }
    return 0;
  }

  announce_seed();

  std::size_t failed_tests = 0;
  for (const TestCase& test : selected) {
    std::printf("[ RUN  ] %s.%s\n", test.suite.c_str(), test.name.c_str());
    std::fflush(stdout);
    g_current_failed = false;
    try {
      test.fn();
    } catch (const TestFailure& failure) {
      std::printf("    aborted: %s\n", failure.what());
      g_current_failed = true;
    } catch (const std::exception& error) {
      std::printf("    unexpected exception: %s\n", error.what());
      g_current_failed = true;
      ++g_failures;
    } catch (...) {
      std::printf("    unexpected non-standard exception\n");
      g_current_failed = true;
      ++g_failures;
    }
    if (g_current_failed) {
      ++failed_tests;
      std::printf("[ FAIL ] %s.%s\n", test.suite.c_str(), test.name.c_str());
    } else {
      std::printf("[  OK  ] %s.%s\n", test.suite.c_str(), test.name.c_str());
    }
    std::fflush(stdout);
  }

  std::printf("\n%d test case(s) run, %d failed, %d check(s), %d check failure(s)\n",
              static_cast<int>(selected.size()), static_cast<int>(failed_tests),
              static_cast<int>(g_checks), static_cast<int>(g_failures));
  std::fflush(stdout);
  return (failed_tests == 0 && g_failures == 0) ? 0 : 1;
}

}  // namespace ffed_test
