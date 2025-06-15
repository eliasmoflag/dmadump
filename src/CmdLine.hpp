#pragma once
#include <string>
#include <set>
#include <optional>

namespace dmadump {
class CmdLine {
public:
  static std::optional<CmdLine> load(const int argc, const char *const argv[]);

  std::optional<std::string> ProcessName;
  std::string ModuleName;
  std::set<std::string> IAT;
  bool Debug;
};
} // namespace dmadump
