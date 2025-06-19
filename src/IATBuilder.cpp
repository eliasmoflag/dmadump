#include "IATBuilder.hpp"
#include "Dumper.hpp"
#include "IATResolverBase.hpp"
#include "Logging.hpp"
#include "PE.hpp"
#include "SectionBuilder.hpp"
#include "Utils.hpp"
#include <algorithm>
#include <numeric>

namespace dmadump {
IATBuilder::IATBuilder(Dumper &dumper, const ModuleInfo *moduleInfo)
    : dumper(dumper), moduleInfo(moduleInfo) {}

void IATBuilder::addImport(const std::string &libraryName,
                           const std::string &functionName) {

  for (auto &imp : imports) {
    if (compareLibraryName(imp.Library, libraryName)) {
      imp.addFunction(functionName);
      return;
    }
  }

  ImportFunction function;
  function.Name = functionName;

  ImportLibrary library;
  library.Library = libraryName;
  library.Functions = {function};

  imports.push_back(library);
}

Dumper &IATBuilder::getDumper() const { return dumper; }

const ModuleInfo *IATBuilder::getModuleInfo() const { return moduleInfo; }

bool IATBuilder::rebuild(std::vector<std::uint8_t> &image) {

  addOriginalImports(image);

  resolveImports(image);

  const auto originalImportDirVA =
      pe::getOptionalHeader64(image.data())->ImportDirectory.VirtualAddress;

  rebuildImportDir(image);

  applyPatches(image, originalImportDirVA);

  updateHeaders(image);

  return true;
}

void ImportLibrary::addFunction(const std::string &functionName) {
  for (const auto &func : Functions) {
    if (func.Name == functionName) {
      return;
    }
  }

  ImportFunction function;
  function.Name = functionName;
  Functions.push_back(function);
}

const std::vector<ImportLibrary> &IATBuilder::getImports() const {
  return imports;
}

ImportDirLayout IATBuilder::getImportDirLayout() const {

  ImportDirLayout layout{};
  std::uint32_t descriptorSize = 0;
  std::uint32_t thunkSize = 0;
  std::uint32_t libraryNameSize = 0;
  std::uint32_t functionNameSize = 0;

  std::size_t functionCount = 0;
  for (const auto &imp : imports) {
    libraryNameSize += imp.Library.size() + sizeof('\0');

    for (const auto &func : imp.Functions) {
      functionNameSize +=
          sizeof(std::uint16_t) + func.Name.size() + sizeof('\0');
    }

    thunkSize += sizeof(pe::ImageThunkData64) * (imp.Functions.size() + 1);
    functionCount += imp.Functions.size();
  }

  descriptorSize = sizeof(pe::ImageImportDescriptor) * (imports.size() + 1);

  layout.DescriptorOffset = 0;
  layout.FirstThunkOffset = layout.DescriptorOffset + descriptorSize;
  layout.OriginalFirstThunkOffset = layout.FirstThunkOffset + thunkSize;
  layout.LibraryNameOffset = layout.OriginalFirstThunkOffset + thunkSize;
  layout.FunctionNameOffset = layout.LibraryNameOffset + libraryNameSize;
  layout.Size = layout.FunctionNameOffset + functionNameSize;

  return layout;
}

const ImportFunction *
IATBuilder::findImportFunction(const std::string_view library,
                               const std::string_view function) const {

  for (const auto &imp : imports) {
    if (compareLibraryName(imp.Library, library)) {
      for (const auto &func : imp.Functions) {
        if (func.Name == function) {
          return &func;
        }
      }
    }
  }

  return nullptr;
}

ImportFunction *
IATBuilder::findImportFunction(const std::string_view library,
                               const std::string_view function) {

  for (auto &imp : imports) {
    if (compareLibraryName(imp.Library, library)) {
      for (auto &func : imp.Functions) {
        if (func.Name == function) {
          return &func;
        }
      }
    }
  }

  return nullptr;
}

void IATBuilder::addOriginalImports(const std::vector<std::uint8_t> &image) {

  const auto &importDir =
      pe::getOptionalHeader64(image.data())->ImportDirectory;

  if (importDir.VirtualAddress == 0 || importDir.Size == 0) {
    return;
  }

  auto importDesc = reinterpret_cast<const pe::ImageImportDescriptor *>(
      image.data() + importDir.VirtualAddress);

  for (; importDesc->Name != 0; importDesc++) {

    const auto libraryName =
        reinterpret_cast<const char *>(image.data() + importDesc->Name);

    auto originalFirstThunk = reinterpret_cast<const pe::ImageThunkData64 *>(
        image.data() + importDesc->OriginalFirstThunk);
    auto firstThunk = reinterpret_cast<const pe::ImageThunkData64 *>(
        image.data() + importDesc->FirstThunk);

    while (originalFirstThunk->u1.AddressOfData != 0) {

      const auto importByName = reinterpret_cast<const pe::ImageImportByName *>(
          image.data() + originalFirstThunk->u1.AddressOfData);

      addImport(libraryName, importByName->Name);

      ++originalFirstThunk;
      ++firstThunk;
    }
  }
}

void IATBuilder::resolveImports(const std::vector<std::uint8_t> &image) {
  if (!iatResolvers.empty()) {
    LOG_INFO("resolving imports...");
  }

  for (const auto &resolver : iatResolvers) {
    if (resolver->resolve(image)) {
      for (const auto &[library, function] : resolver->getImports()) {
        addImport(library, function);
      }
    }
  }

  LOG_WRITE("\n");
}

void IATBuilder::rebuildImportDir(std::vector<std::uint8_t> &image) {

  LOG_INFO("rebuilding import address table...");

  const auto optionalHeader = pe::getOptionalHeader64(image.data());
  const auto sectionAlignment = optionalHeader->SectionAlignment;
  const auto fileAlignment = optionalHeader->FileAlignment;

  SectionBuilder section(align<std::uint32_t>(image.size(), fileAlignment),
                         align<std::uint32_t>(image.size(), sectionAlignment),
                         sectionAlignment, fileAlignment);

  section.addCharacteristics(IMAGE_SCN_CNT_INITIALIZED_DATA |
                             IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

  constructImportDir(section);
  const auto importDirSize = section.getRawSize();

  const auto sectionHeader = appendImageSectionHeader(image.data());
  std::memcpy(sectionHeader->Name, ".dmp0\0\0", 8);
  sectionHeader->PointerToRawData = section.getOffset();
  sectionHeader->VirtualAddress = section.getRVA();
  sectionHeader->Misc.VirtualSize = section.getRawSize();
  sectionHeader->SizeOfRawData = section.getFileSize();
  sectionHeader->Characteristics = section.getCharacteristics();

  auto &importDir = optionalHeader->ImportDirectory;
  importDir.VirtualAddress = section.getRVA();
  importDir.Size = importDirSize;

  section.finalize();

  image.resize(section.getOffset());
  image.insert(image.end(), section.getData().begin(), section.getData().end());
}

void IATBuilder::applyPatches(std::vector<std::uint8_t> &image,
                              std::uint32_t originalImportDirVA) {

  const auto optionalHeader = pe::getOptionalHeader64(image.data());
  const auto sectionAlignment = optionalHeader->SectionAlignment;
  const auto fileAlignment = optionalHeader->FileAlignment;

  SectionBuilder section(align<std::uint32_t>(image.size(), fileAlignment),
                         align<std::uint32_t>(image.size(), sectionAlignment),
                         sectionAlignment, fileAlignment);

  section.addCharacteristics(IMAGE_SCN_CNT_INITIALIZED_DATA |
                             IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ |
                             IMAGE_SCN_MEM_EXECUTE);

  buildRedirectStubs(image, section);

  redirectOriginalIAT(image, section, originalImportDirVA);

  LOG_INFO("applying patches...");

  for (const auto &resolver : iatResolvers) {
    resolver->applyPatches(image.data(), section);
  }

  const auto sectionHeader = appendImageSectionHeader(image.data());
  std::memcpy(sectionHeader->Name, ".dmp1\0\0", 8);
  sectionHeader->PointerToRawData = section.getOffset();
  sectionHeader->VirtualAddress = section.getRVA();
  sectionHeader->Misc.VirtualSize = section.getRawSize();
  sectionHeader->SizeOfRawData = section.getFileSize();
  sectionHeader->Characteristics = section.getCharacteristics();

  section.finalize();

  image.resize(section.getOffset());
  image.insert(image.end(), section.getData().begin(), section.getData().end());
}

void IATBuilder::buildRedirectStubs(const std::vector<std::uint8_t> &image,
                                    SectionBuilder &scnBuilder) {

  const auto ntHeaders = pe::getNtHeaders(image.data());
  const auto &newImportDir = ntHeaders->OptionalHeader64.ImportDirectory;

  LOG_INFO("building IAT redirect stubs...");

  for (auto importDesc = reinterpret_cast<const pe::ImageImportDescriptor *>(
           image.data() +
           *ntHeaders->rvaToFileOffset(newImportDir.VirtualAddress));
       importDesc->Name != 0; importDesc++) {

    const auto libraryName = reinterpret_cast<const char *>(
        image.data() + *ntHeaders->rvaToFileOffset(importDesc->Name));

    auto originalFirstThunk = reinterpret_cast<const pe::ImageThunkData64 *>(
        image.data() +
        *ntHeaders->rvaToFileOffset(importDesc->OriginalFirstThunk));

    auto firstThunk = reinterpret_cast<const pe::ImageThunkData64 *>(
        image.data() + *ntHeaders->rvaToFileOffset(importDesc->FirstThunk));

    for (; originalFirstThunk->u1.AddressOfData != 0;
         ++originalFirstThunk, ++firstThunk) {

      const auto importByName = reinterpret_cast<const pe::ImageImportByName *>(
          image.data() +
          *ntHeaders->rvaToFileOffset(originalFirstThunk->u1.AddressOfData));

      // jmp    QWORD PTR [rip+offset]
      std::uint8_t stub[] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00};

      const auto stubRVA = scnBuilder.getRVA() + scnBuilder.getRawSize();

      const std::uint32_t addressOfDataRVA =
          *ntHeaders->fileOffsetToRVA(reinterpret_cast<const std::uint8_t *>(
                                          &firstThunk->u1.AddressOfData) -
                                      image.data());

      *reinterpret_cast<std::int32_t *>(&stub[2]) = static_cast<std::int32_t>(
          addressOfDataRVA - (stubRVA + sizeof(stub)));

      scnBuilder.append(stub);

      if (const auto importFunction =
              findImportFunction(libraryName, importByName->Name)) {

        importFunction->RedirectStubRVA = stubRVA;
      }
    }
  }
}

void IATBuilder::redirectOriginalIAT(std::vector<std::uint8_t> &image,
                                     SectionBuilder &scnBuilder,
                                     std::uint32_t originalImportDirVA) const {

  const auto ntHeaders = pe::getNtHeaders(image.data());
  const auto &newImportDir = ntHeaders->OptionalHeader64.ImportDirectory;

  LOG_INFO("redirecting original IAT...");

  for (auto importDesc = reinterpret_cast<pe::ImageImportDescriptor *>(
           image.data() + originalImportDirVA);
       importDesc->Name != 0; importDesc++) {

    const auto libraryName =
        reinterpret_cast<const char *>(image.data() + importDesc->Name);

    auto originalFirstThunk = reinterpret_cast<pe::ImageThunkData64 *>(
        image.data() + importDesc->OriginalFirstThunk);
    auto firstThunk = reinterpret_cast<pe::ImageThunkData64 *>(
        image.data() + importDesc->FirstThunk);

    for (; originalFirstThunk->u1.AddressOfData != 0;
         originalFirstThunk++, firstThunk++) {

      const auto importByName = reinterpret_cast<pe::ImageImportByName *>(
          image.data() +
          *ntHeaders->rvaToFileOffset(originalFirstThunk->u1.AddressOfData));

      if (const auto importFunction =
              findImportFunction(libraryName, importByName->Name)) {

        firstThunk->u1.Function =
            moduleInfo->ImageBase + importFunction->RedirectStubRVA;
      }
    }
  }
}

bool IATBuilder::constructImportDir(SectionBuilder &sectionBuilder) const {

  const auto importDirLayout = getImportDirLayout();

  const std::uint32_t importDirRVA =
      sectionBuilder.getRVA() + sectionBuilder.getRawSize();

  sectionBuilder.getMutableData().resize(
      static_cast<std::size_t>(sectionBuilder.getRawSize() +
                               importDirLayout.Size),
      0);

  std::uint8_t *importDirData = sectionBuilder.getMutableData().data() +
                                (importDirRVA - sectionBuilder.getRVA());

  std::size_t functionIdx = 0;
  std::size_t libraryNameOffset = importDirLayout.LibraryNameOffset;
  std::size_t functionNameOffset = importDirLayout.FunctionNameOffset;

  for (std::size_t i = 0; i < imports.size(); i++) {
    auto &imp = imports[i];

    const auto importDesc = reinterpret_cast<pe::ImageImportDescriptor *>(
        importDirData + importDirLayout.DescriptorOffset +
        sizeof(pe::ImageImportDescriptor) * i);

    importDesc->OriginalFirstThunk =
        importDirRVA + importDirLayout.OriginalFirstThunkOffset +
        sizeof(pe::ImageThunkData64) * (i + functionIdx);

    importDesc->ForwarderChain = 0;
    importDesc->Name = importDirRVA + libraryNameOffset;
    importDesc->FirstThunk = importDirRVA + importDirLayout.FirstThunkOffset +
                             sizeof(pe::ImageThunkData64) * (i + functionIdx);

    std::memcpy(importDirData + libraryNameOffset, imp.Library.data(),
                imp.Library.size() + sizeof('\0'));

    for (std::size_t j = 0; j < imp.Functions.size(); j++, functionIdx++) {
      auto &func = imp.Functions[j];

      const auto originalFirstThunk = reinterpret_cast<pe::ImageThunkData64 *>(
          importDirData + importDirLayout.OriginalFirstThunkOffset +
          sizeof(pe::ImageThunkData64) * (i + functionIdx));

      originalFirstThunk->u1.AddressOfData = importDirRVA + functionNameOffset;

      const auto importByName = reinterpret_cast<pe::ImageImportByName *>(
          importDirData + functionNameOffset);

      importByName->Hint = 0;
      std::memcpy(importByName->Name, func.Name.data(),
                  func.Name.size() + sizeof('\0'));

      functionNameOffset +=
          sizeof(std::uint16_t) + func.Name.size() + sizeof('\0');
    }

    libraryNameOffset += imports[i].Library.size() + sizeof('\0');
  }

  return true;
}

void IATBuilder::updateHeaders(std::vector<std::uint8_t> &image) {
  const auto ntHeaders = pe::getNtHeaders(image.data());
  const auto optionalHeader = &ntHeaders->OptionalHeader64;

  const std::uint32_t sectionHeaderOffset = [&] {
    return reinterpret_cast<std::uint8_t *>(
               ntHeaders->getSectionHeader(ntHeaders->getSectionCount() - 1)) -
           image.data();
  }();

  optionalHeader->SizeOfHeaders = std::max<std::uint32_t>(
      optionalHeader->SizeOfHeaders,
      align<std::uint32_t>(sectionHeaderOffset + sizeof(IMAGE_SECTION_HEADER),
                           optionalHeader->FileAlignment));

  optionalHeader->SizeOfImage =
      align<std::uint32_t>(image.size(), optionalHeader->SectionAlignment);
}
} // namespace dmadump
