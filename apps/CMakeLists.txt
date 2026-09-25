# Operator tools. Each is a real executable; the test suite starts them as
# separate operating-system processes and never links them.

add_library(ffed_app_common STATIC common.cpp)
target_link_libraries(ffed_app_common PUBLIC FabricFederation)
target_include_directories(ffed_app_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
ffed_apply_warnings(ffed_app_common)
ffed_apply_sanitizers(ffed_app_common)

function(ffed_add_tool name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE ffed_app_common)
  ffed_apply_warnings(${name})
  ffed_apply_sanitizers(${name})
endfunction()

ffed_add_tool(ffed-coordinator coordinator_main.cpp)
ffed_add_tool(ffed-member member_main.cpp)
ffed_add_tool(ffed-cli cli_main.cpp)

install(TARGETS ffed-coordinator ffed-member ffed-cli
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
