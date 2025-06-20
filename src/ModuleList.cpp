#include "ModuleList.hpp"
#include "Utils.hpp"
#include <ranges>

namespace dmadump {
void ModuleList::addModule(ModuleInfo &&moduleInfo) {
  if (const std::string moduleID = moduleInfo.getLibraryID();
      !moduleMap.contains(moduleID)) {
    moduleMap.emplace(moduleID,
                      std::make_unique<ModuleInfo>(std::move(moduleInfo)));
  }
}

void ModuleList::addModule(const ModuleInfo &moduleInfo) {
  if (const std::string &moduleID = moduleInfo.getLibraryID();
      !moduleMap.contains(moduleID)) {
    moduleMap.emplace(moduleID, std::make_unique<ModuleInfo>(moduleInfo));
  }
}

const std::unordered_map<std::string, std::unique_ptr<ModuleInfo>> &
ModuleList::getModuleMap() const {
  return moduleMap;
}

const ModuleInfo *
ModuleList::getModuleByName(const std::string_view moduleName) const {

  if (const auto found = moduleMap.find(simplifyLibraryName(moduleName));
      found != moduleMap.end()) {

    return found->second.get();
  }

  return nullptr;
}

const ModuleInfo *
ModuleList::getModuleByAddress(const std::uint64_t address) const {

  for (const auto &mod : std::views::values(moduleMap)) {

    if (mod->getImageBase() && mod->getImageSize() &&
        address >= mod->getImageBase() &&
        address < mod->getImageBase() + mod->getImageSize()) {

      return mod.get();
    }
  }

  return nullptr;
}
} // namespace dmadump
