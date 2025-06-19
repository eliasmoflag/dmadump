#pragma once
#include <cxxopts.hpp>
#include <optional>
#include <set>
#include <string>

namespace dmadump {
class CmdLine : protected cxxopts::Options {
public:
  CmdLine();

  bool load(int argc, const char *const argv[]);

  std::string help() const;

  std::optional<std::string> ProcessName;
  std::string ModuleName;
  std::set<std::string> IAT;
  std::string DeviceType;
  bool Debug{};
};
} // namespace dmadump
