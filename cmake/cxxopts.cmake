include(FetchContent)

FetchContent_Declare(cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG        44380e5a44706ab7347f400698c703eb2a196202
)

FetchContent_MakeAvailable(cxxopts)
