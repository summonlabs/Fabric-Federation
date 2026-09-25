# Contributing to Fabric Federation

Fabric Federation is developed and released by Summon Software Labs under the
Apache License 2.0. Contributions are accepted under the same terms.

## Licensing of contributions

By submitting a contribution (a pull request, patch, or any other form of
change) you agree that:

1. You are legally entitled to submit the contribution.
2. Your contribution is licensed to Summon Software Labs and to every recipient
   of the software under the **Apache License, Version 2.0**, without any
   additional terms or conditions.
3. You retain copyright of your contribution. **No copyright assignment and no
   Contributor License Agreement (CLA) is required.** Inbound contributions are
   accepted under the same license as outbound distribution ("inbound=outbound").

There is no separate corporate CLA, no sign-off bot and no copyright header
requirement. Do not add a copyright header that claims ownership of files you
do not own.

## Development expectations

* C++20, no compiler extensions, no third-party runtime dependencies.
* The tree must build warning-clean with warnings treated as errors in both
  Release and Debug. On MSVC the project uses `/W4 /WX`; on GCC/Clang it uses
  `-Wall -Wextra -Wpedantic -Werror` plus the extra warnings listed in
  `CMakeLists.txt`.
* Every behavioural change needs a test that fails before the change and passes
  after it. Distributed claims need multi-process evidence.
* Never weaken a safety rule to make a test pass. `UNKNOWN`, `UNSUPPORTED`,
  `STALE`, `CONFLICTING`, `INCOMPLETE`, `INDETERMINATE`, `REFUSED`,
  `CANCELLED` and `INVALID` must stay distinguishable, and missing evidence
  must never be converted into success.
* Do not introduce test timeouts, watchdog "success" paths, or any mechanism
  that classifies a hang as a pass. A hang is a defect.
* Document what is actually implemented. Do not describe behaviour that the
  code does not have. Keep the boundaries in `docs/limitations.md` honest and
  current: this runtime does **not** implement consensus, quorum, Byzantine
  fault tolerance, cryptographic trust, multi-host operation or real
  cross-site networking.

## Building and testing

```sh
cmake --preset release
cmake --build --preset release
ctest --preset release
```

Report defects through the issue tracker with the exact command, the observed
output, and the compiler/platform details.
