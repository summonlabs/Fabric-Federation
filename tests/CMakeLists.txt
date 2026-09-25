# Test suites. No test sets a TIMEOUT property and no wrapper reclassifies a
# hang as a pass; a test that does not terminate is a defect to be diagnosed.

add_library(ffed_test_support STATIC support/test_harness.cpp)
target_include_directories(ffed_test_support PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/support)
target_link_libraries(ffed_test_support PUBLIC FabricFederation)
ffed_apply_warnings(ffed_test_support)
ffed_apply_sanitizers(ffed_test_support)

function(ffed_add_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE ffed_test_support)
  ffed_apply_warnings(${name})
  ffed_apply_sanitizers(${name})
  add_test(NAME ${name} COMMAND ${name})
endfunction()

ffed_add_test(ffed_test_foundation unit/test_foundation.cpp)
ffed_add_test(ffed_test_model unit/test_model.cpp)
ffed_add_test(ffed_test_lifecycle unit/test_lifecycle.cpp)
ffed_add_test(ffed_test_authority unit/test_authority.cpp)
ffed_add_test(ffed_test_state unit/test_state.cpp)
ffed_add_test(ffed_test_journal unit/test_journal.cpp)
ffed_add_test(ffed_test_protocol unit/test_protocol.cpp)
ffed_add_test(ffed_test_concurrency unit/test_concurrency.cpp)

if(FFED_BUILD_TOOLS)
  ffed_add_test(ffed_test_multiprocess integration/test_multiprocess.cpp)
  target_compile_definitions(ffed_test_multiprocess PRIVATE
    FFED_COORDINATOR_BIN="$<TARGET_FILE:ffed-coordinator>"
    FFED_MEMBER_BIN="$<TARGET_FILE:ffed-member>"
    FFED_CLI_BIN="$<TARGET_FILE:ffed-cli>")
  add_dependencies(ffed_test_multiprocess ffed-coordinator ffed-member ffed-cli)
endif()
