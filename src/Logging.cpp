#include "Logging.hpp"
#include <iostream>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace dmadump {
void Logger::init() {
#ifdef _WIN32
  const auto outputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
  if (outputHandle != INVALID_HANDLE_VALUE) {
    if (DWORD mode{0}; GetConsoleMode(outputHandle, &mode)) {
      if ((mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0) {
        SetConsoleMode(outputHandle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
      }
    }
  }
#endif
}

void Logger::write(const std::string_view buffer) {
  std::cout << buffer;
  if (buffer.ends_with('\n')) {
    std::cout << std::flush;
  }
}

void Logger::write(const Level level, const std::string_view buffer) {
  switch (level) {
  case Level::Info:
    return write(
        std::format("\x1b[97m[\x1b[93m*\x1b[97m] \x1b[90m{}\x1b[0m\n", buffer));
  case Level::Warn:
    return write(
        std::format("\x1b[97m[\x1b[93m!\x1b[97m] \x1b[33m{}\x1b[0m\n", buffer));
  case Level::Error:
    return write(
        std::format("\x1b[97m[\x1b[91m-\x1b[97m] \x1b[91m{}\x1b[0m\n", buffer));
  case Level::Success:
    return write(
        std::format("\x1b[97m[\x1b[92m+\x1b[97m] \x1b[37m{}\x1b[0m\n", buffer));
  default:
    return;
  }
}
} // namespace dmadump
