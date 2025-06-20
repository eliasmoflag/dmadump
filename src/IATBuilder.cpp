#include <dmadump/IATBuilder.hpp>
#include <dmadump/Dumper.hpp>
#include <dmadump/ModuleList.hpp>
#include <dmadump/IATResolver.hpp>
#include <dmadump/Logging.hpp>
#include <dmadump/PE.hpp>
#include <dmadump/SectionBuilder.hpp>
#include <dmadump/Utils.hpp>
#include <algorithm>
#include <numeric>

namespace dmadump {
IATBuilder::IATBuilder(Dumper &dumper, const ModuleInfo *moduleInfo)
    : dumper(dumper), moduleInfo(moduleInfo) {}

void IATBuilder::addImport(const std::string &libraryName,
                           const ImportFunction &function) {

  for (auto &imp : imports) {
    if (compareLibraryName(imp.getName(), libraryName)) {
      imp.addFunction(function);
      return;
    }
  }

  imports.emplace_back(libraryName, std::vector{function});
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

IATBuilder::ImportFunction::ImportFunction(
    std::variant<std::string, std::uint16_t> name)
    : name(std::move(name)), redirectStubRVA(std::nullopt) {}

IATBuilder::ImportFunction
IATBuilder::ImportFunction::fromName(std::string name) {
  return ImportFunction(std::move(name));
}

IATBuilder::ImportFunction
IATBuilder::ImportFunction::fromOrdinal(const std::uint16_t ordinal) {
  return ImportFunction(ordinal);
}

const std::variant<std::string, std::uint16_t> &
IATBuilder::ImportFunction::getName() const {
  return name;
}

const std::optional<std::uint32_t> &
IATBuilder::ImportFunction::getRedirectStub() const {
  return redirectStubRVA;
}

void IATBuilder::ImportFunction::setRedirectStub(const std::uint32_t &rva) {
  redirectStubRVA = rva;
}

IATBuilder::ImportLibrary::ImportLibrary(std::string library,
                                         std::vector<ImportFunction> functions)
    : library(std::move(library)), functions(std::move(functions)) {}

const std::string &IATBuilder::ImportLibrary::getName() const {
  return library;
}

std::vector<IATBuilder::ImportFunction> &
IATBuilder::ImportLibrary::getFunctions() {
  return functions;
}

const std::vector<IATBuilder::ImportFunction> &
IATBuilder::ImportLibrary::getFunctions() const {
  return functions;
}

const IATBuilder::ImportFunction *
IATBuilder::ImportLibrary::getFunctionByName(std::string_view name) const {
  for (const auto &func : functions) {
    if (func.getName().index() == 0 && std::get<0>(func.getName()) == name) {
      return &func;
    }
  }
  return nullptr;
}

const IATBuilder::ImportFunction *
IATBuilder::ImportLibrary::getFunctionByOrdinal(std::uint16_t ordinal) const {
  for (const auto &func : functions) {
    if (func.getName().index() == 1 && std::get<1>(func.getName()) == ordinal) {
      return &func;
    }
  }
  return nullptr;
}

const IATBuilder::ImportFunction *IATBuilder::ImportLibrary::getFunctionByName(
    const std::variant<std::string, std::uint16_t> &name) const {
  for (const auto &func : functions) {
    if (func.getName() == name) {
      return &func;
    }
  }
  return nullptr;
}

void IATBuilder::ImportLibrary::addFunction(const ImportFunction &function) {
  for (const auto &func : functions) {
    if (func.getName() == function.getName()) {
      return;
    }
  }

  functions.emplace_back(function);
}

const std::vector<IATBuilder::ImportLibrary> &IATBuilder::getImports() const {
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
    libraryNameSize += imp.getName().size() + sizeof('\0');

    for (const auto &func : imp.getFunctions()) {
      if (func.getName().index() == 0) {
        functionNameSize += sizeof(std::uint16_t) +
                            std::get<0>(func.getName()).size() + sizeof('\0');
      }
    }

    thunkSize += sizeof(pe::ImageThunkData64) * (imp.getFunctions().size() + 1);
    functionCount += imp.getFunctions().size();
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

const IATBuilder::ImportFunction *IATBuilder::findImportFunction(
    const std::string_view library,
    const std::variant<std::string, std::uint16_t> &function) const {

  for (const auto &imp : imports) {
    if (compareLibraryName(imp.getName(), library)) {
      for (const auto &func : imp.getFunctions()) {
        if (func.getName() == function) {
          return &func;
        }
      }
    }
  }

  return nullptr;
}

IATBuilder::ImportFunction *IATBuilder::findImportFunction(
    const std::string_view library,
    const std::variant<std::string, std::uint16_t> &function) {

  for (auto &imp : imports) {
    if (compareLibraryName(imp.getName(), library)) {
      for (auto &func : imp.getFunctions()) {
        if (func.getName() == function) {
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

      if (IMAGE_SNAP_BY_ORDINAL64(originalFirstThunk->u1.Ordinal)) {
        addImport(libraryName, ImportFunction::fromOrdinal(IMAGE_ORDINAL64(
                                   originalFirstThunk->u1.Ordinal)));
      } else {
        const auto importByName =
            reinterpret_cast<const pe::ImageImportByName *>(
                image.data() + originalFirstThunk->u1.AddressOfData);

        addImport(libraryName, ImportFunction::fromName(importByName->Name));
      }

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
        addImport(library, ImportFunction::fromName(function));
      }
    }
  }

  LOG_WRITE("\n");
}

void IATBuilder::rebuildImportDir(std::vector<std::uint8_t> &image) const {

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
                              std::uint32_t origImportDirVA) {

  const auto optionalHeader = pe::getOptionalHeader64(image.data());
  const auto sectionAlignment = optionalHeader->SectionAlignment;
  const auto fileAlignment = optionalHeader->FileAlignment;

  SectionBuilder codeScn(align<std::uint32_t>(image.size(), fileAlignment),
                         align<std::uint32_t>(image.size(), sectionAlignment),
                         sectionAlignment, fileAlignment);

  codeScn.addCharacteristics(IMAGE_SCN_CNT_INITIALIZED_DATA |
                             IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ |
                             IMAGE_SCN_MEM_EXECUTE);

  buildRedirectStubs(image, codeScn);

  redirectOriginalIAT(image, origImportDirVA);

  LOG_INFO("applying patches...");

  for (const auto &resolver : iatResolvers) {
    resolver->applyPatches(image, codeScn);
  }

  const auto sectionHeader = appendImageSectionHeader(image.data());
  std::memcpy(sectionHeader->Name, ".dmp1\0\0", 8);
  sectionHeader->PointerToRawData = codeScn.getOffset();
  sectionHeader->VirtualAddress = codeScn.getRVA();
  sectionHeader->Misc.VirtualSize = codeScn.getRawSize();
  sectionHeader->SizeOfRawData = codeScn.getFileSize();
  sectionHeader->Characteristics = codeScn.getCharacteristics();

  codeScn.finalize();

  image.resize(codeScn.getOffset());
  image.insert(image.end(), codeScn.getData().begin(), codeScn.getData().end());
}

void IATBuilder::buildRedirectStubs(const std::vector<std::uint8_t> &image,
                                    SectionBuilder &codeScn) {

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

      // jmp    QWORD PTR [rip+offset]
      std::uint8_t stub[] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00};

      const auto stubRVA = codeScn.getRVA() + codeScn.getRawSize();

      const std::uint32_t addressOfDataRVA =
          *ntHeaders->fileOffsetToRVA(reinterpret_cast<const std::uint8_t *>(
                                          &firstThunk->u1.AddressOfData) -
                                      image.data());

      *reinterpret_cast<std::int32_t *>(&stub[2]) = static_cast<std::int32_t>(
          addressOfDataRVA - (stubRVA + sizeof(stub)));

      codeScn.append(stub);

      if (IMAGE_SNAP_BY_ORDINAL64(originalFirstThunk->u1.Ordinal)) {
        if (const auto importFunction = findImportFunction(
                libraryName, static_cast<std::uint16_t>(IMAGE_ORDINAL64(
                                 originalFirstThunk->u1.Ordinal)))) {

          importFunction->setRedirectStub(stubRVA);
        }
      } else {
        const auto importByName =
            reinterpret_cast<const pe::ImageImportByName *>(
                image.data() + *ntHeaders->rvaToFileOffset(
                                   originalFirstThunk->u1.AddressOfData));

        if (const auto importFunction =
                findImportFunction(libraryName, importByName->Name)) {

          importFunction->setRedirectStub(stubRVA);
        }
      }
    }
  }
}

void IATBuilder::redirectOriginalIAT(std::vector<std::uint8_t> &image,
                                     std::uint32_t origImportDirVA) const {

  const auto ntHeaders = pe::getNtHeaders(image.data());

  LOG_INFO("redirecting original IAT...");

  for (auto importDesc = reinterpret_cast<pe::ImageImportDescriptor *>(
           image.data() + origImportDirVA);
       importDesc->Name != 0; importDesc++) {

    const auto libraryName =
        reinterpret_cast<const char *>(image.data() + importDesc->Name);

    auto originalFirstThunk = reinterpret_cast<pe::ImageThunkData64 *>(
        image.data() + importDesc->OriginalFirstThunk);
    auto firstThunk = reinterpret_cast<pe::ImageThunkData64 *>(
        image.data() + importDesc->FirstThunk);

    for (; originalFirstThunk->u1.AddressOfData != 0;
         originalFirstThunk++, firstThunk++) {

      if (IMAGE_SNAP_BY_ORDINAL64(originalFirstThunk->u1.Ordinal)) {
        if (const auto importFunction = findImportFunction(
                libraryName, static_cast<std::uint16_t>(IMAGE_ORDINAL64(
                                 originalFirstThunk->u1.Ordinal)))) {

          firstThunk->u1.Function =
              moduleInfo->getImageBase() + *importFunction->getRedirectStub();
        }
      } else {
        const auto importByName = reinterpret_cast<pe::ImageImportByName *>(
            image.data() +
            *ntHeaders->rvaToFileOffset(originalFirstThunk->u1.AddressOfData));

        if (const auto importFunction =
                findImportFunction(libraryName, importByName->Name)) {

          firstThunk->u1.Function =
              moduleInfo->getImageBase() + *importFunction->getRedirectStub();
        }
      }
    }
  }
}

bool IATBuilder::constructImportDir(SectionBuilder &dataScn) const {

  const auto importDirLayout = getImportDirLayout();

  const std::uint32_t importDirRVA = dataScn.getRVA() + dataScn.getRawSize();

  dataScn.getMutableData().resize(
      static_cast<std::size_t>(dataScn.getRawSize()) + importDirLayout.Size, 0);

  std::uint8_t *importDirData =
      dataScn.getMutableData().data() + (importDirRVA - dataScn.getRVA());

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

    std::memcpy(importDirData + libraryNameOffset, imp.getName().data(),
                imp.getName().size() + sizeof('\0'));

    for (std::size_t j = 0; j < imp.getFunctions().size(); j++, functionIdx++) {
      const auto &func = imp.getFunctions()[j];

      const auto originalFirstThunk = reinterpret_cast<pe::ImageThunkData64 *>(
          importDirData + importDirLayout.OriginalFirstThunkOffset +
          sizeof(pe::ImageThunkData64) * (i + functionIdx));

      if (func.getName().index() == 0) {
        const auto &funcName = std::get<0>(func.getName());

        originalFirstThunk->u1.AddressOfData =
            importDirRVA + functionNameOffset;

        const auto importByName = reinterpret_cast<pe::ImageImportByName *>(
            importDirData + functionNameOffset);

        importByName->Hint = 0;

        std::memcpy(importByName->Name, funcName.data(),
                    funcName.size() + sizeof('\0'));

        functionNameOffset +=
            sizeof(std::uint16_t) + funcName.size() + sizeof('\0');
      } else if (func.getName().index() == 1) {
        originalFirstThunk->u1.Ordinal =
            static_cast<std::uint64_t>(std::get<1>(func.getName()));

        originalFirstThunk->u1.Ordinal |= IMAGE_ORDINAL_FLAG64;
      }
    }

    libraryNameOffset += imports[i].getName().size() + sizeof('\0');
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
