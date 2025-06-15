#include "Logging.hpp"
#include <Windows.h>

namespace dmadump {
Logger::Logger() {
  outputHandle = GetStdHandle(STD_OUTPUT_HANDLE);

  if (outputHandle != INVALID_HANDLE_VALUE) {
    if (DWORD mode{0}; GetConsoleMode(outputHandle, &mode)) {
      if ((mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0) {
        SetConsoleMode(outputHandle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
      }
    }
  } else {
    outputHandle = nullptr;
  }
}

Logger &Logger::get() {
  static Logger instance;
  return instance;
}

void Logger::write(const std::string_view buffer) const {
  if (outputHandle) {
    WriteConsoleA(outputHandle, buffer.data(), buffer.size(), nullptr, nullptr);
  }
}

void Logger::write(const Level level, const std::string_view buffer) const {
  switch (level) {
  case Level::Info:
    return write(
        std::format("\x1b[97m[\x1b[93m*\x1b[37m] \x1b[90m{}\x1b[0m\n", buffer));
  case Level::Warn:
    return write(
        std::format("\x1b[97m[\x1b[93m!\x1b[97m] \x1b[33m{}\x1b[0m\n", buffer));
  case Level::Error:
    return write(
        std::format("\x1b[97m[\x1b[91m-\x1b[97m] \x1b[91m{}\x1b[0m\n", buffer));
  case Level::Success:
    return write(
        std::format("\x1b[97m[\x1b[92m+\x1b[97m] \x1b[37m{}\x1b[0m\n", buffer));
  }
}
} // namespace dmadump
