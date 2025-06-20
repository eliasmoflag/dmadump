cmake_minimum_required(VERSION 3.28)

project(dmadump
  LANGUAGES
    C CXX
)

set(CAPSTONE_ARCHITECTURE_DEFAULT OFF)
set(CAPSTONE_X86_SUPPORT ON)

set(UNICORN_ARCH "x86")

include("./cmake/MemProcFS.cmake")
include("./cmake/cxxopts.cmake")

file(GLOB_RECURSE SOURCES
  "./include/*.hpp"
  "./src/*.cpp"
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${SOURCES})

add_library(dmadump STATIC ${SOURCES})

target_include_directories(dmadump PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(dmadump PUBLIC LeechCore VMM)

target_compile_features(dmadump PRIVATE cxx_std_23)

target_compile_definitions(dmadump PRIVATE NOMINMAX)

add_subdirectory("./cli")
