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
  "./src/*.hpp"
  "./src/*.cpp"
)

source_group(TREE "./" FILES ${SOURCES})

add_executable(dmadump ${SOURCES})

target_link_libraries(dmadump PRIVATE MemProcFS cxxopts::cxxopts)

target_compile_features(dmadump PRIVATE cxx_std_23)

target_compile_definitions(dmadump PRIVATE NOMINMAX)

set_property(DIRECTORY PROPERTY VS_STARTUP_PROJECT "dmadump")
