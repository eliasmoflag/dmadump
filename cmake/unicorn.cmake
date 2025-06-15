include(FetchContent)

FetchContent_Declare(unicorn
  GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
  GIT_TAG        f8c6db950420d2498700245269d0b647697c5666
)

FetchContent_MakeAvailable(unicorn)
