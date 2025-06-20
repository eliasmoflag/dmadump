
file(GLOB_RECURSE SOURCES
  "./*.hpp"
  "./*.cpp"
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${SOURCES})

add_executable(dmadump-cli ${SOURCES})

target_compile_features(dmadump-cli PRIVATE cxx_std_23)

target_link_libraries(dmadump-cli PRIVATE dmadump cxxopts::cxxopts)

set_property(DIRECTORY PROPERTY VS_STARTUP_PROJECT "dmadump-cli")
