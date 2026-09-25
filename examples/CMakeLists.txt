# Worked examples. Each is a complete program that a reader can build and run.
function(ffed_add_example name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE FabricFederation)
  ffed_apply_warnings(${name})
  ffed_apply_sanitizers(${name})
endfunction()

ffed_add_example(ffed_example_single_process single_process.cpp)

if(FFED_BUILD_TOOLS)
  ffed_add_example(ffed_example_multi_process multi_process.cpp)
  target_compile_definitions(ffed_example_multi_process PRIVATE
    FFED_COORDINATOR_BIN="$<TARGET_FILE:ffed-coordinator>"
    FFED_MEMBER_BIN="$<TARGET_FILE:ffed-member>"
    FFED_CLI_BIN="$<TARGET_FILE:ffed-cli>")
  add_dependencies(ffed_example_multi_process ffed-coordinator ffed-member ffed-cli)
endif()
