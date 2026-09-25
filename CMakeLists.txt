cmake_minimum_required(VERSION 3.20)

project(FabricFederation
        VERSION 1.0.0
        DESCRIPTION "Authority-composition runtime for independently governed fabric domains"
        HOMEPAGE_URL "https://github.com/summonlabs/Fabric-Federation"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(FFED_BUILD_TESTS "Build the Fabric Federation test suites" ON)
option(FFED_BUILD_EXAMPLES "Build the Fabric Federation examples" ON)
option(FFED_BUILD_TOOLS "Build the ffed-coordinator / ffed-member / ffed-cli tools" ON)
option(FFED_BUILD_BENCHMARKS "Build the Fabric Federation benchmarks" ON)
option(FFED_SANITIZE "Build with AddressSanitizer where the toolchain supports it" OFF)
option(FFED_WARNINGS_AS_ERRORS "Treat first-party warnings as errors" ON)

set(FFED_LIBRARY_TYPE STATIC CACHE STRING "Library type: STATIC or SHARED")
set_property(CACHE FFED_LIBRARY_TYPE PROPERTY STRINGS STATIC SHARED)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Warning and sanitizer policy
#
# Applied directly to each first-party target rather than through an interface
# library so that the installed export set never leaks a warning policy into a
# downstream consumer's build.
# ---------------------------------------------------------------------------
function(ffed_apply_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE
      /W4 /permissive- /Zc:__cplusplus /Zc:preprocessor /utf-8 /EHsc /bigobj)
    if(FFED_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
      -Wunused -Woverloaded-virtual -Wnull-dereference -Wdouble-promotion -Wformat=2
      -Wconversion -Wsign-conversion)
    if(FFED_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

function(ffed_apply_sanitizers target)
  if(NOT FFED_SANITIZE)
    return()
  endif()
  if(MSVC)
    target_compile_options(${target} PRIVATE /fsanitize=address /Zi /Od)
    target_link_options(${target} PRIVATE /fsanitize=address /INCREMENTAL:NO)
    target_compile_definitions(${target} PRIVATE FFED_SANITIZER_ACTIVE=1)
  else()
    target_compile_options(${target} PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    target_link_options(${target} PRIVATE
      -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_compile_definitions(${target} PRIVATE FFED_SANITIZER_ACTIVE=1)
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
set(FFED_PUBLIC_HEADERS
  include/fabric_federation/version.hpp
  include/fabric_federation/export.hpp
  include/fabric_federation/errors.hpp
  include/fabric_federation/bounds.hpp
  include/fabric_federation/digest.hpp
  include/fabric_federation/text.hpp
  include/fabric_federation/ids.hpp
  include/fabric_federation/random.hpp
  include/fabric_federation/codec.hpp
  include/fabric_federation/json.hpp
  include/fabric_federation/scope.hpp
  include/fabric_federation/capability.hpp
  include/fabric_federation/identity.hpp
  include/fabric_federation/policy.hpp
  include/fabric_federation/evidence.hpp
  include/fabric_federation/membership.hpp
  include/fabric_federation/lease.hpp
  include/fabric_federation/partition.hpp
  include/fabric_federation/explanation.hpp
  include/fabric_federation/authority.hpp
  include/fabric_federation/state.hpp
  include/fabric_federation/journal.hpp
  include/fabric_federation/names.hpp
  include/fabric_federation/net.hpp
  include/fabric_federation/protocol.hpp
  include/fabric_federation/process.hpp
  include/fabric_federation/coordinator.hpp
  include/fabric_federation/client.hpp
  include/fabric_federation/member_runtime.hpp
  include/fabric_federation/control.hpp)

set(FFED_SOURCES
  src/sha256.cpp
  src/ids.cpp
  src/text.cpp
  src/errors.cpp
  src/codec.cpp
  src/json.cpp
  src/random.cpp
  src/names.cpp
  src/scope.cpp
  src/capability.cpp
  src/identity.cpp
  src/explanation.cpp
  src/partition.cpp
  src/policy.cpp
  src/lease.cpp
  src/evidence.cpp
  src/membership.cpp
  src/state.cpp
  src/authority.cpp
  src/journal.cpp
  src/net.cpp
  src/protocol.cpp
  src/process.cpp
  src/coordinator.cpp
  src/client.cpp
  src/member_runtime.cpp
  src/control.cpp)

add_library(FabricFederation ${FFED_LIBRARY_TYPE} ${FFED_SOURCES} ${FFED_PUBLIC_HEADERS})
add_library(SummonSoftwareLabs::FabricFederation ALIAS FabricFederation)

target_include_directories(FabricFederation
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_link_libraries(FabricFederation PUBLIC Threads::Threads)

# The public headers require C++20 (std::span, concepts-free but still C++20).
# Declaring the requirement as a usage requirement means a downstream consumer
# inherits it instead of failing on a missing std::span.
target_compile_features(FabricFederation PUBLIC cxx_std_20)

ffed_apply_warnings(FabricFederation)
ffed_apply_sanitizers(FabricFederation)

target_compile_definitions(FabricFederation PRIVATE FFED_BUILDING_LIBRARY=1)
if(FFED_LIBRARY_TYPE STREQUAL "SHARED")
  target_compile_definitions(FabricFederation PUBLIC FFED_USE_SHARED=1 PRIVATE FFED_BUILD_SHARED=1)
endif()

# ws2_32 provides the loopback sockets used by the framed transport. It is a
# Windows system library, so it does not become a portable dependency of the
# installed package.
if(WIN32)
  target_link_libraries(FabricFederation PRIVATE ws2_32)
endif()

set_target_properties(FabricFederation PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON
  OUTPUT_NAME "FabricFederation")

# ---------------------------------------------------------------------------
# Subprojects
# ---------------------------------------------------------------------------
if(FFED_BUILD_TOOLS)
  add_subdirectory(apps)
endif()
if(FFED_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
if(FFED_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(FFED_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------
install(TARGETS FabricFederation
  EXPORT FabricFederationTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT FabricFederationTargets
  FILE FabricFederationTargets.cmake
  NAMESPACE SummonSoftwareLabs::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FabricFederation)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/FabricFederationConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/FabricFederationConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FabricFederation)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/FabricFederationConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/FabricFederationConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/FabricFederationConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FabricFederation)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/NOTICE
        DESTINATION ${CMAKE_INSTALL_DATADIR}/FabricFederation)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/README.md
        DESTINATION ${CMAKE_INSTALL_DATADIR}/FabricFederation)

message(STATUS "Fabric Federation ${PROJECT_VERSION}: library=${FFED_LIBRARY_TYPE} sanitize=${FFED_SANITIZE} warnings_as_errors=${FFED_WARNINGS_AS_ERRORS}")
