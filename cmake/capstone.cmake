include(FetchContent)

FetchContent_Declare(capstone
  GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
  GIT_TAG        fe6bdc6ed82057a52754306961b23cf54f746fc6
)

FetchContent_MakeAvailable(capstone)
