#include <dmadump/iat/DynamicIATResolver.hpp>
#include <dmadump/Dumper.hpp>
#include <dmadump/ModuleList.hpp>
#include <dmadump/IATBuilder.hpp>
#include <dmadump/Logging.hpp>
#include <dmadump/Utils.hpp>

namespace dmadump {
DynamicIATResolver::DynamicIATResolver(IATBuilder &iatBuilder,
                                       const std::uint32_t requiredScnAttrs,
                                       const std::uint32_t allowedScnAttrs)
    : IATResolver(iatBuilder), requiredScnAttrs(requiredScnAttrs),
      allowedScnAttrs(allowedScnAttrs) {}

bool DynamicIATResolver::resolve(const std::vector<std::uint8_t> &image) {
  const auto ntHeaders = pe::getNtHeaders(image.data());
  const auto &importDir = ntHeaders->OptionalHeader64.ImportDirectory;

  const auto &moduleList = *iatBuilder.getDumper().getModuleList();
  const auto lowModStartAddr = getLowestModuleStartAddress();
  const auto highModEndAddr = getHighestModuleEndAddress();

  for (std::uint16_t i = 0; i < ntHeaders->getSectionCount(); ++i) {
    const auto section = ntHeaders->getSectionHeader(i);

    if ((section->VirtualAddress & 0xfff) != 0 ||
        section->Misc.VirtualSize < 8) {
      continue;
    }

    if ((section->Characteristics & requiredScnAttrs) != requiredScnAttrs ||
        (section->Characteristics & ~allowedScnAttrs) != 0) {
      continue;
    }

    const auto sectionBegin = reinterpret_cast<const std::uint64_t *>(
        image.data() + section->VirtualAddress);

    const auto sectionEnd = reinterpret_cast<const std::uint64_t *>(
        image.data() + section->VirtualAddress + section->Misc.VirtualSize -
        section->Misc.VirtualSize % 8);

    for (auto it = sectionBegin; it != sectionEnd; ++it) {
      const auto rva = static_cast<std::uint32_t>(
          reinterpret_cast<const std::uint8_t *>(it) - image.data());

      if (importDir.contains(rva)) {
        continue;
      }

      const std::uint64_t candidate = *it;
      if (candidate < lowModStartAddr || candidate >= highModEndAddr) {
        continue;
      }

      const auto moduleInfo = moduleList.getModuleByAddress(candidate);
      if (!moduleInfo) {
        continue;
      }

      const auto exportInfo = moduleInfo->getExportByVA(candidate);
      if (!exportInfo) {
        continue;
      }

      ResolvedImport resolvedImport;
      resolvedImport.Library = moduleInfo->getName();
      resolvedImport.Function = exportInfo->getName();

      resolvedImports.push_back(resolvedImport);
      resolvedImportsByRVAs.insert({rva, resolvedImport});

      LOG_INFO("found import {}:{} at RVA 0x{:X}", moduleInfo->getName(),
               exportInfo->getName(), rva);
    }
  }

  LOG_INFO("resolved {} dynamic imports.", resolvedImportsByRVAs.size());

  return true;
}

const std::vector<ResolvedImport> &DynamicIATResolver::getImports() const {
  return resolvedImports;
}

bool DynamicIATResolver::applyPatches(std::vector<std::uint8_t> &image,
                                      SectionBuilder &codeScn) {

  const auto ntHeaders = pe::getNtHeaders(image.data());
  const auto &importDir = ntHeaders->OptionalHeader64.ImportDirectory;

  LOG_INFO("redirecting dynamic IAT to stubs...");

  std::size_t iatPatchCount = 0;
  for (const auto &[functionPtrRVA, resolvedImport] : resolvedImportsByRVAs) {
    if (const auto importFunction = iatBuilder.findImportFunction(
            resolvedImport.Library, resolvedImport.Function)) {

      *reinterpret_cast<std::uint64_t *>(image.data() + functionPtrRVA) =
          iatBuilder.getModuleInfo()->getImageBase() +
          *importFunction->getRedirectStub();

      ++iatPatchCount;
    }
  }

  LOG_INFO("patched {} dynamic IAT entries.", iatPatchCount);

  LOG_INFO("searching for dynamic IAT calls...");

  std::unordered_map<std::uint32_t, ResolvedImport> callSites;
  for (std::uint16_t i = 0; i < ntHeaders->getSectionCount(); ++i) {
    const auto section = ntHeaders->getSectionHeader(i);

    if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
      continue;
    }

    const auto sectionBegin = reinterpret_cast<std::uint8_t *>(image.data()) +
                              section->VirtualAddress;
    const auto sectionEnd = sectionBegin + section->Misc.VirtualSize;

    for (const auto &[functionPtrRVA, resolvedImport] : resolvedImportsByRVAs) {

      for (const auto &callRVA :
           findDirectCalls(sectionBegin, sectionEnd, section->VirtualAddress,
                           functionPtrRVA)) {

        // LOG_INFO("found dynamic call at RVA 0x{:X}", callRVA);

        callSites[callRVA] = resolvedImport;
      }
    }
  }

  LOG_INFO("found {} dynamic IAT calls.", callSites.size());

  LOG_INFO("patching dynamic IAT calls...");

  std::size_t callPatchCount = 0;
  for (const auto &[callSite, resolvedImport] : callSites) {

    auto importDesc = reinterpret_cast<const pe::ImageImportDescriptor *>(
        image.data() + importDir.VirtualAddress);

    for (; importDesc->Name != 0; ++importDesc) {

      const auto libraryName =
          reinterpret_cast<const char *>(image.data() + importDesc->Name);

      if (!compareLibraryName(libraryName, resolvedImport.Library)) {
        continue;
      }

      auto originalFirstThunk = reinterpret_cast<const pe::ImageThunkData64 *>(
          image.data() + importDesc->OriginalFirstThunk);
      auto firstThunk = reinterpret_cast<const pe::ImageThunkData64 *>(
          image.data() + importDesc->FirstThunk);

      for (; originalFirstThunk->u1.AddressOfData != 0;
           ++originalFirstThunk, ++firstThunk) {

        const auto importByName =
            reinterpret_cast<const pe::ImageImportByName *>(
                image.data() + originalFirstThunk->u1.AddressOfData);

        if (importByName->Name != resolvedImport.Function) {
          continue;
        }

        const auto addressOfDataRVA =
            *ntHeaders->fileOffsetToRVA(reinterpret_cast<const std::uint8_t *>(
                                            &firstThunk->u1.AddressOfData) -
                                        image.data());

        *reinterpret_cast<std::int32_t *>(image.data() + callSite + 2) =
            static_cast<std::int32_t>(addressOfDataRVA - (callSite + 6));

        ++callPatchCount;
      }
    }
  }

  LOG_INFO("patched {} dynamic IAT calls", callPatchCount);

  return true;
}

const std::unordered_map<std::uint32_t, ResolvedImport> &
DynamicIATResolver::getResolvedImportsByRVAs() const {
  return resolvedImportsByRVAs;
}
} // namespace dmadump
