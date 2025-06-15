#include "Utils.hpp"
#include <chrono>
#include <thread>
#include <filesystem>

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

  DWORD processId;
  if (!VMMDLL_PidGetFromName(vmmHandle, processName, &processId)) {
    return std::nullopt;
  }

  return processId;
}

void convertImageSectionsRawToVA(void *image) {
  const auto ntHeaders = pe::getNtHeaders(image);

  for (std::uint16_t i = 0; i < ntHeaders->getSectionCount(); i++) {
    const auto section = ntHeaders->getSectionHeader(i);
    const auto sectionHeaderEnd = reinterpret_cast<std::uint8_t *>(section) +
                                  sizeof(pe::ImageSectionHeader);

    section->PointerToRawData = section->VirtualAddress;
    section->SizeOfRawData = section->Misc.VirtualSize;
  }
}

pe::ImageSectionHeader *appendImageSectionHeader(void *image) {

  const auto ntHeaders = pe::getNtHeaders(image);

  const auto sectionHeader =
      ntHeaders->getSectionHeader(ntHeaders->FileHeader.NumberOfSections++);

  std::memset(sectionHeader, 0x00, sizeof(sectionHeader));
  return sectionHeader;
}

std::string toLower(std::string_view str) {
  std::string result;

  for (const auto &c : str) {
    result.push_back(std::tolower(c));
  }

  return result;
}

bool iequals(std::string_view lhs, std::string_view rhs) {
  const auto pred = [](char lhs, char rhs) {
    return std::tolower(lhs) == std::tolower(rhs);
  };

  return lhs.size() == rhs.size() &&
         std::equal(lhs.begin(), lhs.end(), rhs.begin(), pred);
}

bool compareLibraryName(std::string_view lhs, std::string_view rhs) {
  return iequals(lhs.substr(0, lhs.find_last_of('.')),
                 rhs.substr(0, rhs.find_last_of('.')));
}
} // namespace dmadump
