#include <dmadump/Dumper/VmmDumper.hpp>
#include <dmadump/PE.hpp>
#include <dmadump/Utils.hpp>
#include <dmadump/Logging.hpp>
#include <filesystem>
#include <format>

namespace dmadump {
VmmDumper::VmmDumper(VmmHandle vmmHandle, std::uint32_t processID)
    : vmmHandle(std::move(vmmHandle)), processID(processID) {
  moduleList = std::make_unique<ModuleList>();
}

VmmDumper::VmmDumper(std::shared_ptr<VmmHandle> vmmHandle,
                     std::uint32_t processID)
    : vmmHandle(std::move(vmmHandle)), processID(processID) {
  moduleList = std::make_unique<ModuleList>();
}

std::optional<std::uint32_t>
VmmDumper::findProcessByName(VMM_HANDLE vmmHandle, const char *processName) {
  DWORD processID;
  if (!VMMDLL_PidGetFromName(vmmHandle, processName, &processID)) {
    return std::nullopt;
  }

  return processID;
}

bool VmmDumper::loadModuleInfo() {

  PVMMDLL_MAP_MODULE moduleMap;
  if (!VMMDLL_Map_GetModuleU(getRawHandle(), processID, &moduleMap,
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

ModuleList *VmmDumper::getModuleList() const { return moduleList.get(); }

bool VmmDumper::readMemory(const std::uint64_t va, void *buffer,
                           const std::uint32_t size, std::uint32_t *bytesRead) {
  return VMMDLL_MemReadEx(getRawHandle(), processID, va,
                          static_cast<PBYTE>(buffer), size,
                          reinterpret_cast<PDWORD>(bytesRead), 0);
}

VMM_HANDLE VmmDumper::getRawHandle() const {
  switch (vmmHandle.index()) {
  case 0:
    return std::get<0>(vmmHandle);
  case 1:
    return *std::get<1>(vmmHandle);
  default:
    return nullptr;
  }
}
} // namespace dmadump
