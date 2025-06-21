#ifdef _WIN32
#include <dmadump/Dumper/Win32Dumper.hpp>
#include <dmadump/Logging.hpp>
#include <dmadump/Utils.hpp>
#include <TlHelp32.h>

namespace dmadump {
Win32Dumper::Win32Dumper(Win32Handle processHandle)
    : processHandle(std::move(processHandle)) {
  moduleList = std::make_unique<ModuleList>();
}

Win32Dumper::Win32Dumper(std::shared_ptr<Win32Handle> processHandle)
    : processHandle(std::move(processHandle)) {
  moduleList = std::make_unique<ModuleList>();
}

std::optional<std::uint32_t>
Win32Dumper::findProcessByName(std::string_view processName) {

  const HANDLE snapshotHandle{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
  if (snapshotHandle == INVALID_HANDLE_VALUE) {
    return std::nullopt;
  }

  PROCESSENTRY32W processEntry = {0};
  processEntry.dwSize = sizeof(processEntry);

  if (Process32FirstW(snapshotHandle, &processEntry)) {
    do {
      if (const auto fileName =
              std::filesystem::path(processEntry.szExeFile).filename();
          iequals(fileName.string(), processName)) {

        CloseHandle(snapshotHandle);
        return processEntry.th32ProcessID;
      }
    } while (Process32NextW(snapshotHandle, &processEntry));
  }

  CloseHandle(snapshotHandle);
  return std::nullopt;
}

bool Win32Dumper::loadModuleInfo() {

  const HANDLE snapshotHandle =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(getRawHandle()));
  if (snapshotHandle == INVALID_HANDLE_VALUE) {
    return false;
  }

  MODULEENTRY32W moduleEntry = {0};
  moduleEntry.dwSize = sizeof(moduleEntry);

  if (Module32FirstW(snapshotHandle, &moduleEntry)) {
    do {
      ModuleInfo moduleInfo(
          std::filesystem::path(moduleEntry.szModule).string(),
          moduleEntry.szExePath,
          reinterpret_cast<std::uint64_t>(moduleEntry.modBaseAddr),
          moduleEntry.modBaseSize, {});

      if (!loadModuleEAT(moduleInfo)) {
        LOG_WARN("failed to load EAT for module: {}", moduleInfo.getName());
      }

      moduleList->addModule(std::move(moduleInfo));
    } while (Module32NextW(snapshotHandle, &moduleEntry));
  }

  CloseHandle(snapshotHandle);

  return true;
}

ModuleList *Win32Dumper::getModuleList() const { return moduleList.get(); }

bool Win32Dumper::readMemory(std::uint64_t va, void *buffer, std::uint32_t size,
                             std::uint32_t *bytesRead) {

  SIZE_T read{0};
  if (!ReadProcessMemory(getRawHandle(), reinterpret_cast<LPCVOID>(va), buffer,
                         size, &read)) {
    return false;
  }

  if (bytesRead) {
    *bytesRead = read;
  }

  return true;
}

HANDLE Win32Dumper::getRawHandle() const {
  switch (processHandle.index()) {
  case 0:
    return std::get<0>(processHandle);
  case 1:
    return *std::get<1>(processHandle);
  default:
    return nullptr;
  }
}
} // namespace dmadump
#endif
