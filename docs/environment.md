# Environment

Results quoted in this repository were produced with the toolchain below. Numbers from one
machine are not a promise about another.

| Item | Value |
| --- | --- |
| Operating system | Windows 10 Pro (10.0.19045) |
| Compiler | MSVC 19.44.35222.0 (Visual Studio 2022 Build Tools, toolset 14.44.35207) |
| Generator | Ninja 1.13.2 |
| CMake | 4.3.2 |
| Build types | Release and Debug, both `/W4 /WX` |
| Sanitizer | MSVC `/fsanitize=address` (Debug configuration) |
| Standard library | Microsoft STL as shipped with the toolset |
| Transport | Winsock 2.2, TCP over 127.0.0.1 |

## Measured platform behaviour that shapes the tests

Two properties of this machine are measured rather than assumed, because they explain how
long some suites take.

* **A refused loopback connect costs about 2.05 seconds.** The SYN is retransmitted rather
  than answered with a reset, so `connect()` to a closed port on `127.0.0.1` returns after
  roughly two seconds. Measured directly against both port 1 and a just-released ephemeral
  port; both took 2.04–2.08 s. This runtime deliberately has **no connect timeout**, so that
  cost is the operating system's, not a wait introduced here. It is why the readiness
  helpers in `tests/unit/test_protocol.cpp` perform the smallest number of refused connects
  that still proves their contract, and why
  `concurrency.repeated_start_and_stop_is_stable` takes about 41 seconds: each of its 20
  cycles verifies that the listener is genuinely closed, and that verification is a refused
  connect.
* **Nothing in the test suite waits on a timer.** There is no CTest `TIMEOUT` property, no
  shell timeout, and no watchdog that turns a hang into a pass. The readiness helpers in
  `include/fabric_federation/control.hpp` retry a bounded number of times and then
  **fail**; they are never used to reclassify a slow or stuck operation as success. The test
  harness prints each case's elapsed time, which is a measurement and not a limit.

## Sanitizers

The AddressSanitizer configuration (`cmake --preset asan`, `FFED_SANITIZE=ON`) is built and
the whole test suite is run under it. It found two real defects that no other
configuration reported:

1. **A dangling reference in the test harness.** `FFED_CHECK_EQ` bound `const auto&` to a
   member of a temporary — for example `state().value().partition.state`. Binding a
   reference to a subobject does not extend the temporary's lifetime, so the reference
   dangled as soon as the declaration statement ended. The macro now takes its operands by
   value.
2. **A range-for over a member of a temporary.** Iterating
   `coordinator->observations().value()` bound the loop's range to a vector inside a
   `Result` temporary that died at the end of the range initialisation. The `Result` is now
   held in a named local.

There is **no** ThreadSanitizer run: MSVC does not provide one. The concurrency work is
covered instead by the ownership audit in `concurrency.md` and by the stress tests in
`tests/unit/test_concurrency.cpp`, including a deterministic wait for real client progress
instead of a fixed sleep. That is a limitation of the verification, not a claim about the
code.

UndefinedBehaviorSanitizer is likewise unavailable for MSVC; the GCC/Clang branch of the
sanitizer configuration enables `-fsanitize=address,undefined` for toolchains that have it.

## Reproducing

```sh
cmake --preset release && cmake --build --preset release && ctest --preset release
cmake --preset debug   && cmake --build --preset debug   && ctest --preset debug
cmake --preset asan    && cmake --build --preset asan    && ctest --preset asan
```

The AddressSanitizer configuration runs the same nine suites; because every state
derivation, allocation and lock path is instrumented, the concurrency suite takes roughly
an order of magnitude longer there than in Release. It is not shortened: the runs complete
naturally.
