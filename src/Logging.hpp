#pragma once
#include <string_view>
#include <format>

typedef void *HANDLE;

namespace dmadump {
#define LOG_WRITE(format, ...) Logger::get().write(format, __VA_ARGS__)
#define LOG_INFO(format, ...) Logger::get().info(format, __VA_ARGS__)
#define LOG_WARN(format, ...) Logger::get().warn(format, __VA_ARGS__)
#define LOG_ERROR(format, ...) Logger::get().error(format, __VA_ARGS__)
#define LOG_SUCCESS(format, ...) Logger::get().success(format, __VA_ARGS__)

class Logger {
public:
  static Logger &get();

  enum Level { Info, Warn, Error, Success, COUNT };

  void write(const std::string_view buffer) const;

  void write(const Level level, const std::string_view buffer) const;

  template <typename... arguments>
  inline void write(const std::string_view format, arguments &&...args) const {
    write(std::vformat(format, std::make_format_args(args...)));
  }

  template <typename... arguments>
  inline void write(const Level level, const std::string_view format,
                    arguments &&...args) const {
    write(level, std::vformat(format, std::make_format_args(args...)));
  }

  template <typename... arguments>
  inline void info(const std::string_view format, arguments &&...args) const {
    write(Level::Info, std::vformat(format, std::make_format_args(args...)));
  }

  template <typename... arguments>
  inline void warn(const std::string_view format, arguments &&...args) const {
    write(Level::Warn, std::vformat(format, std::make_format_args(args...)));
  }

  template <typename... arguments>
  inline void error(const std::string_view format, arguments &&...args) const {
    write(Level::Error, std::vformat(format, std::make_format_args(args...)));
  }

  template <typename... arguments>
  inline void success(const std::string_view format,
                      arguments &&...args) const {
    write(Level::Success, std::vformat(format, std::make_format_args(args...)));
  }

protected:
  HANDLE outputHandle{nullptr};

  Logger();
};
} // namespace dmadump
