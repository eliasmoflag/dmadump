#include <format>
#include <stdexcept>
#include <filesystem>
#include "Dumper.hpp"

namespace dmadump {
static std::string simplifyModuleName(const std::string &moduleName);

Dumper::Dumper(VMM_HANDLE vmmHandle, std::uint32_t processId)
    : vmmHandle(vmmHandle), processId(processId) {}

Dumper::~Dumper() { VMMDLL_Close(vmmHandle); }

bool Dumper::loadModuleInfo(bool loadEAT) {

  PVMMDLL_MAP_MODULE moduleMap;
  if (!VMMDLL_Map_GetModuleU(vmmHandle, processId, &moduleMap,
                             VMMDLL_MODULE_FLAG_NORMAL)) {
    return false;
  }

  for (std::uint32_t i = 0; i < moduleMap->cMap; i++) {
    const auto &moduleEntry = moduleMap->pMap[i];

    ModuleInfo moduleInfo;
    moduleInfo.Name = simplifyModuleName(
        std::filesystem::path(moduleEntry.uszText).filename().string());
    moduleInfo.FilePath = moduleEntry.uszFullName;
    moduleInfo.ImageBase = moduleEntry.vaBase;
    moduleInfo.ImageSize = moduleEntry.cbImageSize;

    if (loadEAT) {
      loadModuleEAT(moduleInfo);
    }

    imageInfo.insert({moduleInfo.Name, std::move(moduleInfo)});
  }

  VMMDLL_MemFree(moduleMap);

  return true;
}

const std::unordered_map<std::string, ModuleInfo> &
Dumper::getModuleInfo() const {
  return imageInfo;
}

const ModuleInfo *Dumper::getModuleInfo(const char *moduleName) const {
  const auto found = imageInfo.find(simplifyModuleName(moduleName));
  if (found != imageInfo.end()) {
    return &found->second;
  }

  return nullptr;
}

bool Dumper::readMemory(std::uint64_t va, void *buffer, std::uint32_t size,
                        std::uint32_t *bytesRead, bool forceUpdate) {

  if (va == 0 || size == 0) {
    return false;
  }

  const std::uint64_t startPageVA = va & ~0xfff;
  const std::uint64_t endVA = va + size;
  const std::uint64_t endPageVA = (endVA + 0xfff) & ~0xfff;

  std::size_t numBytesRead = 0;
  for (std::uint64_t page = startPageVA; page < endPageVA; page += 0x1000) {

    auto &cached = memoryCache[page];
    if (!cached || forceUpdate) {
      auto pageData = std::make_unique<std::uint8_t[]>(0x1000);

      DWORD pageBytesRead;
      if (!VMMDLL_MemReadEx(vmmHandle, processId, page, pageData.get(), 0x1000,
                            &pageBytesRead, 0)) {
        if (bytesRead) {
          *bytesRead = numBytesRead;
        }
        return false;
      }

      cached = std::move(pageData);
    }

    const std::uint32_t readOffset = std::max(va, page) - page;
    const std::uint32_t readSize =
        std::min<std::uint32_t>(0x1000 - readOffset, size - numBytesRead);

    std::copy_n(cached.get() + readOffset, readSize,
                reinterpret_cast<std::uint8_t *>(buffer) + numBytesRead);

    numBytesRead += readSize;
  }

  if (bytesRead) {
    *bytesRead = numBytesRead;
  }

  return true;
}

bool Dumper::readString(std::uint64_t va, std::string &readInto,
                        std::uint32_t maxRead, bool forceUpdate) {

  char buffer[16];
  for (std::uint32_t totalBytesRead = 0, bytesRead = 0;
       totalBytesRead < maxRead; totalBytesRead += bytesRead) {

    readMemory(va + totalBytesRead, buffer, sizeof(buffer), &bytesRead,
               forceUpdate);
    if (bytesRead == 0) {
      return totalBytesRead != 0;
    }

    for (std::uint32_t i = 0; i < bytesRead; i++) {
      if (buffer[i] == '\0') {
        readInto.insert(readInto.end(), buffer, buffer + i);
        return true;
      }
    }

    readInto.insert(readInto.end(), buffer, buffer + sizeof(buffer));
  }

  return true;
}

void Dumper::loadModuleEAT(ModuleInfo &moduleInfo) {

  std::uint8_t header[0x1000];
  if (!readMemory(moduleInfo.ImageBase, &header, sizeof(header), nullptr)) {
    return;
  }

  const auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(header);
  if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    return;
  }

  const auto ntHeaders =
      reinterpret_cast<const IMAGE_NT_HEADERS *>(header + dosHeader->e_lfanew);
  if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
    return;
  }

  if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
    return;
  }

  const auto &exportDirEntry =
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

  if (exportDirEntry.VirtualAddress == 0) {
    return;
  }

  IMAGE_EXPORT_DIRECTORY exportDir = {0};
  if (!readMemory(moduleInfo.ImageBase + exportDirEntry.VirtualAddress,
                  &exportDir, sizeof(exportDir), nullptr)) {
    return;
  }

  const std::uint64_t exportAddressTable =
      moduleInfo.ImageBase + exportDir.AddressOfFunctions;
  const std::uint64_t exportNameTable =
      moduleInfo.ImageBase + exportDir.AddressOfNames;
  const std::uint64_t exportNameOrdinalTable =
      moduleInfo.ImageBase + exportDir.AddressOfNameOrdinals;

  for (std::size_t i = 0; i < exportDir.NumberOfNames; i++) {

    std::uint32_t exportNameRVA;
    if (!readMemory(exportNameTable + i * sizeof(exportNameRVA), &exportNameRVA,
                    sizeof(exportNameRVA))) {
      continue;
    }

    std::uint16_t exportOrdinal;
    if (!readMemory(exportNameOrdinalTable + i * sizeof(exportOrdinal),
                    &exportOrdinal, sizeof(exportOrdinal))) {
      continue;
    }

    std::uint32_t exportFunctionRVA;
    if (!readMemory(exportAddressTable +
                        exportOrdinal * sizeof(exportFunctionRVA),
                    &exportFunctionRVA, sizeof(exportFunctionRVA))) {
      continue;
    }

    std::string exportName;
    if (!readString(moduleInfo.ImageBase + exportNameRVA, exportName, 250)) {
      continue;
    }

    ExportData exportData;
    exportData.Name = exportName;
    exportData.RVA = exportFunctionRVA;
    exportData.Ordinal = exportOrdinal;

    moduleInfo.EAT.push_back(exportData);
  }
}

std::string simplifyModuleName(const std::string &moduleName) {

  std::filesystem::path path(moduleName);
  path.replace_extension("");

  std::string result;
  for (const auto &c : path.string()) {
    result.push_back(std::tolower(c));
  }

  return result;
}
} // namespace dmadump
