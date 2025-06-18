#pragma once
#include <vector>
#include <string>
#include <memory>
#include <unordered_set>

namespace dmadump {
class Dumper;
class ModuleInfo;
class IATResolver;
class SectionBuilder;

class ImportFunction {
public:
  std::string Name;
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
    requires std::is_base_of_v<IATResolver, T>
  inline IATBuilder &addResolver(Args &&...args) {
    iatResolvers.push_back(std::make_unique<T>(*this, std::forward<Args>(args)...));
    return *this;
  }

  const std::vector<ImportLibrary> &getImports() const;

  ImportDirLayout getImportDirLayout() const;

protected:
  void addOriginalImports(const std::vector<std::uint8_t> &image);

  void resolveImports(const std::vector<std::uint8_t> &image);

  void rebuildImportDir(std::vector<std::uint8_t> &image);

  static void updateHeaders(std::vector<std::uint8_t> &image);

  void applyPatches(std::vector<std::uint8_t> &image,
                    std::uint32_t originalImportDirVA);

  void redirectOriginalIAT(std::vector<std::uint8_t> &image,
                           SectionBuilder &scnBuilder,
                           std::uint32_t originalImportDirVA) const;

  bool constructImportDir(SectionBuilder &sectionBuilder) const;

protected:
  Dumper &dumper;

  const ModuleInfo *moduleInfo;

  std::vector<std::unique_ptr<IATResolver>> iatResolvers;

  std::vector<ImportLibrary> imports;
};
} // namespace dmadump
