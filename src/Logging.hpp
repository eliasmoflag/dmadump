#pragma once
#include <string_view>
#include <format>

namespace dmadump {
#define LOG_WRITE(format, ...) Logger::write(format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) Logger::info(format, ##__VA_ARGS__)
#define LOG_WARN(format, ...) Logger::warn(format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) Logger::error(format, ##__VA_ARGS__)
#define LOG_SUCCESS(format, ...) Logger::success(format, ##__VA_ARGS__)

class Logger {
public:
  enum Level { Info, Warn, Error, Success, COUNT };

  static void init();

  static void write(std::string_view buffer);

  static void write(Level level, std::string_view buffer);

  template <typename... Args>
  static inline void write(const std::string_view format, Args &&...args) {
    write(std::vformat(format, std::make_format_args(args...)));
  }

  template <typename... Args>
  static inline void write(const Level level, const std::string_view format,
                           Args &&...args) {
    write(level, std::vformat(format, std::make_format_args(args...)));
  }

  template <typename... Args>
  static inline void info(const std::string_view format, Args &&...args) {
    write(Level::Info, std::vformat(format, std::make_format_args(args...)));
  }

  template <typename... Args>
  static inline void warn(const std::string_view format, Args &&...args) {
    write(Level::Warn, std::vformat(format, std::make_format_args(args...)));
  }

  template <typename... Args>
  static inline void error(const std::string_view format, Args &&...args) {
    write(Level::Error, std::vformat(format, std::make_format_args(args...)));
  }

  template <typename... Args>
  static inline void success(const std::string_view format, Args &&...args) {
    write(Level::Success, std::vformat(format, std::make_format_args(args...)));
  }
};
} // namespace dmadump
