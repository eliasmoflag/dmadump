#include "ModuleList.hpp"
#include "Utils.hpp"
#include <ranges>

namespace dmadump {
void ModuleList::addModule(ModuleInfo &&moduleInfo) {

  const auto moduleID = simplifyLibraryName(moduleInfo.Name);

  moduleInfoList.try_emplace(
      moduleID, std::make_unique<ModuleInfo>(std::move(moduleInfo)));
}

void ModuleList::addModule(const ModuleInfo &moduleInfo) {

  const auto moduleID = simplifyLibraryName(moduleInfo.Name);

  moduleInfoList.try_emplace(simplifyLibraryName(moduleID),
                             std::make_unique<ModuleInfo>(moduleInfo));
}

const std::unordered_map<std::string, std::unique_ptr<ModuleInfo>> &
ModuleList::getModuleMap() const {
  return moduleInfoList;
}

const ModuleInfo *
ModuleList::getModuleByName(const std::string_view moduleName) const {

  const auto found = moduleInfoList.find(simplifyLibraryName(moduleName));
  if (found != moduleInfoList.end()) {

    return found->second.get();
  }

  return nullptr;
}

const ModuleInfo *
ModuleList::getModuleByAddress(const std::uint64_t address) const {

  for (const auto &mod : std::views::values(moduleInfoList)) {

    if (mod->ImageBase && mod->ImageSize && address >= mod->ImageBase &&
        address < mod->ImageBase + mod->ImageSize) {

      return mod.get();
    }
  }

  return nullptr;
}
} // namespace dmadump
