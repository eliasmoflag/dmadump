set(LEECHCORE_GIT_REPOSITORY "https://github.com/ufrisk/LeechCore.git" CACHE STRING "LeechCore git repository")
set(LEECHCORE_GIT_TAG "v2.22" CACHE STRING "LeechCore git tag")
set(MEMPROCFS_GIT_REPOSITORY "https://github.com/ufrisk/MemProcFS.git" CACHE STRING "MemProcFS git repository")
set(MEMPROCFS_GIT_TAG "v5.14" CACHE STRING "MemProcFS git tag")

include(FetchContent)
include(ExternalProject)

message("Fetching LeechCore from ${LEECHCORE_GIT_REPOSITORY} (${LEECHCORE_GIT_TAG})")

FetchContent_Declare(LeechCore
  GIT_REPOSITORY ${LEECHCORE_GIT_REPOSITORY}
  GIT_TAG        ${LEECHCORE_GIT_TAG}
)

FetchContent_MakeAvailable(LeechCore)

message("Fetching MemProcFS from ${MEMPROCFS_GIT_REPOSITORY} (${MEMPROCFS_GIT_TAG})")

FetchContent_Declare(MemProcFS
  GIT_REPOSITORY ${MEMPROCFS_GIT_REPOSITORY}
  GIT_TAG        ${MEMPROCFS_GIT_TAG}
)

FetchContent_MakeAvailable(MemProcFS)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_library(LeechCore INTERFACE)
  target_include_directories(LeechCore INTERFACE ${memprocfs_SOURCE_DIR}/includes)
  target_link_libraries(LeechCore INTERFACE ${memprocfs_SOURCE_DIR}/includes/lib64/leechcore.lib)

  add_library(VMM INTERFACE)
  target_include_directories(VMM INTERFACE ${memprocfs_SOURCE_DIR}/includes)
  target_link_libraries(VMM INTERFACE ${memprocfs_SOURCE_DIR}/includes/lib64/vmm.lib)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_compile_definitions(MACOS)

  set(LeechCore_CFLAGS "-DMACOS -I${leechcore_SOURCE_DIR}/includes")

  ExternalProject_Add(LeechCore_build
    SOURCE_DIR        "${leechcore_SOURCE_DIR}/leechcore"
    CONFIGURE_COMMAND ""
    BUILD_IN_SOURCE   TRUE
    BUILD_COMMAND     make -f Makefile.macos "CFLAGS=${LeechCore_CFLAGS}" > /dev/null 2>&1
    INSTALL_COMMAND   ""
    BYPRODUCTS        "${leechcore_SOURCE_DIR}/files/leechcore.dylib"
  )

  add_library(LeechCore SHARED IMPORTED GLOBAL)
  add_dependencies(LeechCore LeechCore_build)
  set_target_properties(LeechCore PROPERTIES
    IMPORTED_LOCATION "${leechcore_SOURCE_DIR}/files/leechcore.dylib"
    INTERFACE_INCLUDE_DIRECTORIES "${memprocfs_SOURCE_DIR}/includes"
  )

  set(VMM_CFLAGS "-DMACOS -I${memprocfs_SOURCE_DIR}/includes")

  ExternalProject_Add(VMM_build
    SOURCE_DIR         "${memprocfs_SOURCE_DIR}/vmm"
    CONFIGURE_COMMAND  ""
    BUILD_IN_SOURCE    TRUE
    BUILD_COMMAND      make -f Makefile.macos "CFLAGS=${VMM_CFLAGS}" > /dev/null 2>&1
    INSTALL_COMMAND    ""
    BYPRODUCTS         "${memprocfs_SOURCE_DIR}/files/vmm.dylib"
  )

  add_library(VMM SHARED IMPORTED GLOBAL)
  add_dependencies(VMM VMM_build)
  set_target_properties(VMM PROPERTIES
    IMPORTED_LOCATION "${memprocfs_SOURCE_DIR}/files/vmm.dylib"
    INTERFACE_INCLUDE_DIRECTORIES "${memprocfs_SOURCE_DIR}/includes"
  )
endif()
