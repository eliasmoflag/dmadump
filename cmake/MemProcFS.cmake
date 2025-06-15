option(MEMPROCFS_GIT_REPOSITORY "MemProcFS git repository" https://github.com/ufrisk/MemProcFS.git)
option(MEMPROCFS_GIT_TAG "MemProcFS git tag" v5.14)

include(FetchContent)

FetchContent_Declare(MemProcFS
  GIT_REPOSITORY https://github.com/ufrisk/MemProcFS.git
  GIT_TAG        ${MEMPROCFS_GIT_TAG}
)

FetchContent_MakeAvailable(MemProcFS)

add_library(MemProcFS INTERFACE)

target_include_directories(MemProcFS INTERFACE
  ${memprocfs_SOURCE_DIR}/includes
)

target_link_libraries(MemProcFS INTERFACE
  ${memprocfs_SOURCE_DIR}/includes/lib64/vmm.lib
  ${memprocfs_SOURCE_DIR}/includes/lib64/leechcore.lib
)
