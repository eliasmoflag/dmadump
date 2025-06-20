#include "Utils.hpp"
#include <chrono>
#include <filesystem>
#include <thread>

#ifdef _WIN32
#include <Windows.h>
#endif

using namespace std::chrono_literals;

namespace dmadump {
std::expected<SharedVmmHandle, std::string>
createVmm(const std::vector<const char *> &argv) {

  PLC_CONFIG_ERRORINFO errorInfo;
  VMM_HANDLE vmmHandle = VMMDLL_InitializeEx(
      argv.size(), const_cast<LPCSTR *>(argv.data()), &errorInfo);

  if (!vmmHandle) {
    std::string errorMessage;
    if (errorInfo) {
      errorMessage =
          std::string(errorInfo->wszUserText,
                      errorInfo->wszUserText + errorInfo->cwszUserText);

      LcMemFree(errorInfo);
    }

    return std::unexpected(errorMessage);
  }

  if (!VMMDLL_InitializePlugins(vmmHandle)) {
    VMMDLL_Close(vmmHandle);
    return nullptr;
  }

  return SharedVmmHandle{vmmHandle, &VMMDLL_Close};
}

std::optional<std::uint32_t> findProcessByName(VMM_HANDLE vmmHandle,
                                               const char *processName) {

  DWORD processID;
  if (!VMMDLL_PidGetFromName(vmmHandle, processName, &processID)) {
    return std::nullopt;
  }

  return processID;
}

#ifdef _WIN32
bool enablePrivilege(const char *privilegeName) {

  LUID luid;
  if (!LookupPrivilegeValueA(nullptr, privilegeName, &luid)) {
    return false;
  }

  TOKEN_PRIVILEGES tp{0};
  tp.Privileges->Luid = luid;
  tp.Privileges->Attributes = SE_PRIVILEGE_ENABLED;
  tp.PrivilegeCount = 1;

  HANDLE tokenHandle{nullptr};
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle)) {
    return false;
  }

  if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tp, sizeof(tp), nullptr,
                             nullptr)) {
    CloseHandle(tokenHandle);
    return false;
  }

  CloseHandle(tokenHandle);
  return true;
}
#endif

void convertImageSectionsRawToVA(void *image) {
  const auto ntHeaders = pe::getNtHeaders(image);

  for (std::uint16_t i = 0; i < ntHeaders->getSectionCount(); i++) {
    const auto section = ntHeaders->getSectionHeader(i);

    section->PointerToRawData = section->VirtualAddress;
    section->SizeOfRawData = section->Misc.VirtualSize;
  }
}

pe::ImageSectionHeader *appendImageSectionHeader(void *image) {

  const auto ntHeaders = pe::getNtHeaders(image);

  const auto sectionHeader =
      ntHeaders->getSectionHeader(ntHeaders->FileHeader.NumberOfSections++);

  return sectionHeader;
}

std::string toLower(const std::string_view str) {
  std::string result;

  for (const auto &c : str) {
    result.push_back(static_cast<char>(std::tolower(c)));
  }

  return result;
}

bool iequals(const std::string_view lhs, const std::string_view rhs) {
  const auto pred = [](const char lhs, const char rhs) {
    return std::tolower(lhs) == std::tolower(rhs);
  };

  return lhs.size() == rhs.size() &&
         std::equal(lhs.begin(), lhs.end(), rhs.begin(), pred);
}

bool compareLibraryName(const std::string_view lhs,
                        const std::string_view rhs) {
  return iequals(lhs.substr(0, lhs.find_last_of('.')),
                 rhs.substr(0, rhs.find_last_of('.')));
}

std::string simplifyLibraryName(const std::string_view moduleName) {

  std::filesystem::path path(moduleName);
  path.replace_extension("");

  std::string result;
  for (const auto &c : path.string()) {
    result.push_back(static_cast<char>(std::tolower(c)));
  }

  return result;
}
} // namespace dmadump
