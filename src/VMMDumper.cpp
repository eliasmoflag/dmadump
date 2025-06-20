#include "VMMDumper.hpp"
#include "PE.hpp"
#include "Utils.hpp"
#include "Logging.hpp"
#include <filesystem>
#include <format>

namespace dmadump {
VMMDumper::VMMDumper(VMM_HANDLE vmmHandle, const std::uint32_t processID)
    : vmmHandle(vmmHandle), processID(processID) {
  moduleList = std::make_unique<ModuleList>();
}

VMMDumper::~VMMDumper() { VMMDLL_Close(vmmHandle); }

bool VMMDumper::loadModuleInfo() {

  PVMMDLL_MAP_MODULE moduleMap;
  if (!VMMDLL_Map_GetModuleU(vmmHandle, processID, &moduleMap,
                             VMMDLL_MODULE_FLAG_NORMAL)) {
    return false;
  }

  for (std::uint32_t i = 0; i < moduleMap->cMap; i++) {
    const auto &moduleEntry = moduleMap->pMap[i];

    ModuleInfo moduleInfo(
        std::filesystem::path(moduleEntry.uszText).filename().string(),
        moduleEntry.uszFullName, moduleEntry.vaBase, moduleEntry.cbImageSize,
        {});

    if (!loadModuleEAT(moduleInfo)) {
      LOG_WARN("failed to load EAT for module: {}", moduleInfo.getName());
    }

    moduleList->addModule(std::move(moduleInfo));
  }

  VMMDLL_MemFree(moduleMap);

  return true;
}

ModuleList *VMMDumper::getModuleList() const { return moduleList.get(); }

bool VMMDumper::readMemory(const std::uint64_t va, void *buffer,
                           const std::uint32_t size,
                           std::uint32_t *bytesRead) {
  return VMMDLL_MemReadEx(vmmHandle, processID, va,
                          static_cast<PBYTE>(buffer), size,
                          reinterpret_cast<PDWORD>(bytesRead), 0);
}
} // namespace dmadump
