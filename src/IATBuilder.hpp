#pragma once
#include <memory>
#include <string>
#include <vector>

namespace dmadump {
class Dumper;
class ModuleInfo;
class IATResolverBase;
class SectionBuilder;

class RedirectStubInfo {
public:
  std::string Library;
  std::string Function;
  std::uint32_t RVA{0};
};

class ImportFunction {
public:
  std::string Name;
  std::uint32_t RedirectStubRVA{0};
};

class ImportLibrary {
public:
  std::string Library;
  std::vector<ImportFunction> Functions;

  void addFunction(const std::string &functionName);
};

class ImportDirLayout {
public:
  std::uint32_t Size;
  std::uint32_t DescriptorOffset;
  std::uint32_t FirstThunkOffset;
  std::uint32_t OriginalFirstThunkOffset;
  std::uint32_t LibraryNameOffset;
  std::uint32_t FunctionNameOffset;
};

class IATBuilder {
public:
  IATBuilder(Dumper &dumper, const ModuleInfo *moduleInfo);

  Dumper &getDumper() const;

  const ModuleInfo *getModuleInfo() const;

  void addImport(const std::string &libraryName,
                 const std::string &functionName);

  bool rebuild(std::vector<std::uint8_t> &image);

  template <typename T, typename... Args>
    requires std::is_base_of_v<IATResolverBase, T>
  inline IATBuilder &addResolver(Args &&...args) {
    iatResolvers.push_back(
        std::make_unique<T>(*this, std::forward<Args>(args)...));
    return *this;
  }

  const std::vector<ImportLibrary> &getImports() const;

  ImportDirLayout getImportDirLayout() const;

  const ImportFunction *findImportFunction(std::string_view library,
                                           std::string_view function) const;

  ImportFunction *findImportFunction(std::string_view library,
                                     std::string_view function);

protected:
  void addOriginalImports(const std::vector<std::uint8_t> &image);

  void resolveImports(const std::vector<std::uint8_t> &image);

  void rebuildImportDir(std::vector<std::uint8_t> &image) const;

  void applyPatches(std::vector<std::uint8_t> &image,
                    std::uint32_t originalImportDirVA);

  void buildRedirectStubs(const std::vector<std::uint8_t> &image,
                          SectionBuilder &scnBuilder);

  void redirectOriginalIAT(std::vector<std::uint8_t> &image,
                           SectionBuilder &scnBuilder,
                           std::uint32_t originalImportDirVA) const;

  bool constructImportDir(SectionBuilder &sectionBuilder) const;

  static void updateHeaders(std::vector<std::uint8_t> &image);

protected:
  Dumper &dumper;

  const ModuleInfo *moduleInfo;

  std::vector<std::unique_ptr<IATResolverBase>> iatResolvers;

  std::vector<ImportLibrary> imports;
};
} // namespace dmadump
