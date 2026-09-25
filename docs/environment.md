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
| Sanitizer | MSVC `/fsanitize=address` (Debug). See below. |
| Standard library | Microsoft STL as shipped with the toolset |
| Transport | Winsock 2.2, TCP over 127.0.0.1 |

## Sanitizers

MSVC provides AddressSanitizer but not ThreadSanitizer. The AddressSanitizer preset
(`cmake --preset asan`) is used for the memory-safety runs recorded in the final report.
There is **no** ThreadSanitizer run: it is unavailable for this compiler, and the
concurrency work is covered instead by the ownership audit in `concurrency.md` and by the
stress tests in `tests/unit/test_concurrency.cpp`. That is a limitation of the verification,
not a claim about the code.

UndefinedBehaviorSanitizer is likewise unavailable for MSVC; the GCC/Clang branch of the
sanitizer configuration enables `-fsanitize=address,undefined` for toolchains that have it.

## Reproducing

```sh
cmake --preset release && cmake --build --preset release && ctest --preset release
cmake --preset debug   && cmake --build --preset debug   && ctest --preset debug
cmake --preset asan    && cmake --build --preset asan    && ctest --preset asan
```

No test sets a timeout property and no wrapper reclassifies a hang as a pass. The readiness
helpers in `include/fabric_federation/control.hpp` wait for a daemon to answer with a hard
attempt bound and **fail** when it is reached; they are never used to turn a failure into
success.
