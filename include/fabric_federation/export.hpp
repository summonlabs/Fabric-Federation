// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs.
#pragma once

#if defined(_WIN32) && defined(FFED_USE_SHARED)
#if defined(FFED_BUILD_SHARED)
#define FFED_API __declspec(dllexport)
#else
#define FFED_API __declspec(dllimport)
#endif
#elif defined(__GNUC__) && defined(FFED_USE_SHARED)
#define FFED_API __attribute__((visibility("default")))
#else
#define FFED_API
#endif
