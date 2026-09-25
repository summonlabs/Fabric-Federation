cmake_minimum_required(VERSION 3.20)
project(FabricFederationConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# This project knows nothing about the Fabric Federation source tree. It only
# consumes an installed package, which is exactly what a downstream user does.
find_package(FabricFederation 1.0 REQUIRED)

add_executable(ffed_consumer main.cpp)
target_link_libraries(ffed_consumer PRIVATE SummonSoftwareLabs::FabricFederation)

enable_testing()
add_test(NAME ffed_consumer COMMAND ffed_consumer)
