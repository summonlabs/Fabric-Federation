# Benchmarks measure completed work. They print raw numbers; the documentation
# quotes only what these programs actually printed on the machine named in
# docs/environment.md.
function(ffed_add_benchmark name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/tests/support)
  target_link_libraries(${name} PRIVATE FabricFederation)
  ffed_apply_warnings(${name})
  ffed_apply_sanitizers(${name})
endfunction()

ffed_add_benchmark(ffed_bench_state_digest state_digest_bench.cpp)
ffed_add_benchmark(ffed_bench_authority authority_bench.cpp)
ffed_add_benchmark(ffed_bench_journal journal_bench.cpp)
ffed_add_benchmark(ffed_bench_transport transport_bench.cpp)
