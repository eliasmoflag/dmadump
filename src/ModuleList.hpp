#pragma once
#include <string>
#include <memory>
#include <vector>
#include <filesystem>
#include <unordered_map>

namespace dmadump {
class ModuleExportInfo {
public:
  std::string Name;

  std::uint32_t RVA{0};

  std::uint16_t Ordinal{0};
};

class ModuleInfo {
public:
  std::string Name;

  std::filesystem::path FilePath;

  std::uint64_t ImageBase{0};

  std::uint32_t ImageSize{0};

  std::vector<ModuleExportInfo> EAT;
};

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
  std::unordered_map<std::string, std::unique_ptr<ModuleInfo>> moduleInfoList;
};
} // namespace dmadump
