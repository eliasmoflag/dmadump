#pragma once
#include "ModuleInfo.hpp"
#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>

namespace dmadump {
class ModuleList {
public:
  ModuleList() = default;

  void addModule(ModuleInfo &&moduleInfo);
  void addModule(const ModuleInfo &moduleInfo);

  const std::unordered_map<std::string, std::unique_ptr<ModuleInfo>> &
  getModuleMap() const;

  const ModuleInfo *getModuleByName(std::string_view moduleName) const;
  const ModuleInfo *getModuleByAddress(std::uint64_t address) const;

private:
  std::unordered_map<std::string, std::unique_ptr<ModuleInfo>> moduleMap;
};
} // namespace dmadump
