#include "Dumper.hpp"
#include "ModuleInfo.hpp"
#include "PE.hpp"

namespace dmadump {
bool Dumper::readMemoryCached(std::uint64_t va, void *buffer,
                              std::uint32_t size, std::uint32_t *bytesRead,
                              bool forceUpdateCache) {
  if (va == 0 || size == 0) {
    return false;
  }

  const std::uint64_t startPageVA = va & ~0xfff;
  const std::uint64_t endVA = va + size;
  const std::uint64_t endPageVA = (endVA + 0xfff) & ~0xfff;

  std::size_t numBytesRead = 0;
  for (std::uint64_t page = startPageVA; page < endPageVA; page += 0x1000) {

    auto &cached = memoryCache[page];
    if (!cached || forceUpdateCache) {
      auto pageData = std::make_unique<std::uint8_t[]>(0x1000);

      std::uint32_t pageBytesRead;
      if (!readMemory(page, pageData.get(), 0x1000, &pageBytesRead)) {
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
                static_cast<std::uint8_t *>(buffer) + numBytesRead);

    numBytesRead += readSize;
  }

  if (bytesRead) {
    *bytesRead = numBytesRead;
  }

  return true;
}

bool Dumper::readString(std::uint64_t va, std::string &readInto,
                        std::uint32_t maxRead, bool forceUpdateCache) {
  char buffer[16];
  for (std::uint32_t totalBytesRead = 0, bytesRead = 0;
       totalBytesRead < maxRead; totalBytesRead += bytesRead) {

    readMemoryCached(va + totalBytesRead, buffer, sizeof(buffer), &bytesRead,
                     forceUpdateCache);
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

bool Dumper::loadModuleEAT(ModuleInfo &moduleInfo) {

  std::uint8_t header[0x1000];
  if (!readMemoryCached(moduleInfo.getImageBase(), &header, sizeof(header),
                        nullptr)) {
    return false;
  }

  const auto optionalHeader = pe::getOptionalHeader64(header);
  const auto &exportDirEntry = optionalHeader->ExportDirectory;

  if (exportDirEntry.VirtualAddress == 0 || exportDirEntry.Size == 0) {
    return true;
  }

  pe::ImageExportDirectory exportDir = {0};
  if (!readMemoryCached(moduleInfo.getImageBase() +
                            exportDirEntry.VirtualAddress,
                        &exportDir, sizeof(exportDir), nullptr)) {
    return false;
  }

  const std::uint64_t exportAddressTable =
      moduleInfo.getImageBase() + exportDir.AddressOfFunctions;
  const std::uint64_t exportNameTable =
      moduleInfo.getImageBase() + exportDir.AddressOfNames;
  const std::uint64_t exportNameOrdinalTable =
      moduleInfo.getImageBase() + exportDir.AddressOfNameOrdinals;

  for (std::size_t i = 0; i < exportDir.NumberOfNames; i++) {

    std::uint32_t exportNameRVA;
    if (!readMemoryCached(exportNameTable + i * sizeof(exportNameRVA),
                          &exportNameRVA, sizeof(exportNameRVA))) {
      return false;
    }

    std::uint16_t exportOrdinal;
    if (!readMemoryCached(exportNameOrdinalTable + i * sizeof(exportOrdinal),
                          &exportOrdinal, sizeof(exportOrdinal))) {
      return false;
    }

    std::uint32_t exportFunctionRVA;
    if (!readMemoryCached(exportAddressTable +
                              exportOrdinal * sizeof(exportFunctionRVA),
                          &exportFunctionRVA, sizeof(exportFunctionRVA))) {
      return false;
    }

    std::string exportName;
    if (!readString(moduleInfo.getImageBase() + exportNameRVA, exportName,
                          250)) {
      return false;
    }

    ModuleExportInfo exportInfo(exportName, exportOrdinal, exportFunctionRVA);
    moduleInfo.addExport(exportInfo);
  }
}
} // namespace dmadump
