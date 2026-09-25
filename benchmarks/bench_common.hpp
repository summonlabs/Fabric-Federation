// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
//
// Shared benchmark scaffolding. These programs measure completed work and print
// raw numbers; nothing is extrapolated into a claim the program did not
// produce.
#pragma once

#include <chrono>
#include <cstdio>
#include <string>

namespace ffed::bench {

class Timer {
 public:
  Timer() : start_(std::chrono::steady_clock::now()) {}

  [[nodiscard]] double milliseconds() const {
    const auto now = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(now - start_).count();
  }

 private:
  std::chrono::steady_clock::time_point start_;
};

inline void report(const std::string& name, unsigned long long operations, double milliseconds) {
  const double per_operation =
      operations == 0 ? 0.0 : milliseconds * 1000.0 / static_cast<double>(operations);
  std::printf("%-46s %10llu ops %12.3f ms %12.3f us/op\n", name.c_str(), operations, milliseconds,
              per_operation);
  std::fflush(stdout);
}

}  // namespace ffed::bench
