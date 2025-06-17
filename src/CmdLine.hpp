#pragma once
#include <string>
#include <set>
#include <optional>
#include <cxxopts.hpp>

namespace dmadump {
class CmdLine : protected cxxopts::Options {
public:
  CmdLine();

  bool load(int argc, const char *const argv[]);

  std::string help() const;

  std::optional<std::string> ProcessName;
  std::string ModuleName;
  std::set<std::string> IAT;
  bool Debug{};
};
} // namespace dmadump
