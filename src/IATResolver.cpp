#include "Logging.hpp"
#include "Dumper.hpp"
#include "IATResolver.hpp"
#include "IATBuilder.hpp"
#include "Utils.hpp"
#include "PE.hpp"

namespace dmadump {
IATResolver::IATResolver(Dumper &dumper, std::uint64_t allocationBase)
    : dumper(dumper), allocationBase(allocationBase) {}

std::vector<std::uint32_t> IATResolver::findDirectCalls(
    const std::uint8_t *searchBegin, const std::uint8_t *searchEnd,
    std::uint32_t searchRVA, std::uint32_t functionPtrRVA) const {

  std::vector<std::uint32_t> result;

  for (auto it = searchBegin; it != searchEnd - 6; it++) {

    if (it[0] == 0xff && it[1] == 0x15) {
      const std::int32_t ripRelTarget =
          *reinterpret_cast<const std::int32_t *>(&it[2]);

      const std::uint64_t targetRVA =
          it - searchBegin + searchRVA + ripRelTarget + 6;

      if (targetRVA == functionPtrRVA) {
        result.push_back(it - searchBegin + searchRVA);
      }
    }
  }

  return result;
}

std::optional<std::pair<const ModuleInfo *, const ExportData *>>
IATResolver::findExportByVA(std::uint64_t va) const {

  for (const auto &[moduleName, moduleInfo] : dumper.getModuleInfo()) {
    for (const auto &exportData : moduleInfo.EAT) {
      if (moduleInfo.ImageBase + exportData.RVA == va) {
        return {{&moduleInfo, &exportData}};
      }
    }
  }

  return std::nullopt;
}

DirectIATResolver::DirectIATResolver(Dumper &dumper,
                                     std::uint64_t allocationBase)
    : IATResolver(dumper, allocationBase) {}

bool DirectIATResolver::resolve(const std::vector<std::uint8_t> &image) {
  const auto ntHeaders = pe::getNtHeaders(image.data());
  const auto &importDir = ntHeaders->OptionalHeader64.ImportDirectory;

  for (std::uint16_t i = 0; i < ntHeaders->getSectionCount(); i++) {
    const auto section = ntHeaders->getSectionHeader(i);

    if ((section->VirtualAddress & 0xfff) != 0 ||
        section->Misc.VirtualSize < 8) {
      continue;
    }

    const bool validCharacteristics =
        (section->Characteristics & IMAGE_SCN_MEM_READ) != 0 &&
        (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0;

    if (!validCharacteristics) {
      continue;
    }

    const auto sectionBegin = reinterpret_cast<const std::uint64_t *>(
        image.data() + section->VirtualAddress);

    const auto sectionEnd = reinterpret_cast<const std::uint64_t *>(
        image.data() + section->VirtualAddress + section->Misc.VirtualSize -
        section->Misc.VirtualSize % 8);

    for (auto it = sectionBegin; it != sectionEnd; ++it) {

      const std::uint32_t rva = static_cast<std::uint32_t>(
          reinterpret_cast<const std::uint8_t *>(it) - image.data());

      if (importDir.contains(rva)) {
        continue;
      }

      if (const auto match = findExportByVA(*it)) {
        const auto &[moduleInfo, exportData] = *match;

        ResolvedImport resolvedImport;
        resolvedImport.Library = moduleInfo->Name;
        resolvedImport.Function = exportData->Name;

        directImportsByRVA.insert({rva, resolvedImport});

        LOG_INFO("found import {}:{} at RVA 0x{:X}", moduleInfo->Name,
                 exportData->Name, rva);
      }
    }
  }

  if (directImportsByRVA.empty()) {
    LOG_INFO("resolved {} direct imports", directImportsByRVA.size());
  } else {
    LOG_SUCCESS("resolved {} direct imports", directImportsByRVA.size());
  }

  return true;
}

std::vector<ResolvedImport> DirectIATResolver::getImports() const {
  std::vector<ResolvedImport> deps;

  for (const auto &[rva, imp] : directImportsByRVA) {
    deps.push_back(imp);
  }

  return deps;
}

bool DirectIATResolver::applyPatches(IATBuilder &iatBuilder,
                                     std::uint8_t *imageData,
                                     SectionBuilder &scnBuilder) {

  const auto ntHeaders = pe::getNtHeaders(imageData);

  std::unordered_map<std::uint32_t, ResolvedImport> callSites;
  for (std::uint16_t i = 0; i < ntHeaders->getSectionCount(); i++) {
    const auto section = ntHeaders->getSectionHeader(i);

    if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
      continue;
    }

    const auto sectionBegin =
        reinterpret_cast<std::uint8_t *>(imageData) + section->VirtualAddress;
    const auto sectionEnd = sectionBegin + section->Misc.VirtualSize;

    for (const auto &[functionPtrRVA, resolvedImport] : directImportsByRVA) {

      for (const auto &callRVA :
           findDirectCalls(sectionBegin, sectionEnd, section->VirtualAddress,
                           functionPtrRVA)) {

        LOG_INFO("found direct call at RVA 0x{:X}", callRVA);

        callSites[callRVA] = resolvedImport;
      }
    }
  }

  const auto &importDir = ntHeaders->OptionalHeader64.ImportDirectory;

  for (const auto &[callSite, resolvedImport] : callSites) {

    auto importDesc = reinterpret_cast<const pe::ImageImportDescriptor *>(
        imageData + importDir.VirtualAddress);

    for (; importDesc->Name != 0; importDesc++) {

      const auto libraryName =
          reinterpret_cast<const char *>(imageData + importDesc->Name);

      if (!compareLibraryName(libraryName, resolvedImport.Library)) {
        continue;
      }

      auto originalFirstThunk = reinterpret_cast<const pe::ImageThunkData64 *>(
          imageData + importDesc->OriginalFirstThunk);
      auto firstThunk = reinterpret_cast<const pe::ImageThunkData64 *>(
          imageData + importDesc->FirstThunk);

      for (; originalFirstThunk->u1.AddressOfData != 0;
           ++originalFirstThunk, ++firstThunk) {

        const auto importByName =
            reinterpret_cast<const pe::ImageImportByName *>(
                imageData + originalFirstThunk->u1.AddressOfData);

        if (importByName->Name != resolvedImport.Function) {
          continue;
        }

        const auto addressOfDataRVA =
            *ntHeaders->fileOffsetToRVA(reinterpret_cast<const std::uint8_t *>(
                                            &firstThunk->u1.AddressOfData) -
                                        imageData);

        *reinterpret_cast<std::int32_t *>(imageData + callSite + 2) =
            addressOfDataRVA - (callSite + 6);
      }
    }
  }

  return true;
}

const std::unordered_map<std::uint32_t, ResolvedImport> &
DirectIATResolver::getDirectImports() const {
  return directImportsByRVA;
}
} // namespace dmadump
