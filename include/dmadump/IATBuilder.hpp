#pragma once
#include <memory>
#include <string>
#include <vector>
#include <variant>
#include <optional>
#include <dmadump/ImportDirLayout.hpp>

namespace dmadump {
class Dumper;
class ModuleInfo;
class IATResolver;
class SectionBuilder;

class IATBuilder {
public:
  class ImportFunction {
  public:
    explicit ImportFunction(std::variant<std::string, std::uint16_t> name);

    static ImportFunction fromName(std::string name);
    static ImportFunction fromOrdinal(std::uint16_t ordinal);

    const std::variant<std::string, std::uint16_t> &getName() const;
    const std::optional<std::uint32_t> &getRedirectStub() const;

    void setRedirectStub(const std::uint32_t &rva);

  private:
    std::variant<std::string, std::uint16_t> name;
    std::optional<std::uint32_t> redirectStubRVA;
  };

  class ImportLibrary {
  public:
    explicit ImportLibrary(std::string library,
                           std::vector<ImportFunction> functions);

    const std::string &getName() const;
    std::vector<ImportFunction> &getFunctions();
    const std::vector<ImportFunction> &getFunctions() const;

    const ImportFunction *getFunctionByName(std::string_view name) const;
    const ImportFunction *getFunctionByOrdinal(std::uint16_t ordinal) const;
    const ImportFunction *getFunctionByName(
        const std::variant<std::string, std::uint16_t> &name) const;

    void addFunction(const ImportFunction &function);

  private:
    std::string library;
    std::vector<ImportFunction> functions;
  };

  IATBuilder(Dumper &dumper, const ModuleInfo *moduleInfo);

  Dumper &getDumper() const;

  const ModuleInfo *getModuleInfo() const;

  void addImport(const std::string &libraryName,
                 const ImportFunction &function);

  bool rebuild(std::vector<std::uint8_t> &image);

  template <typename T, typename... Args>
    requires std::is_base_of_v<IATResolver, T>
  inline std::shared_ptr<T> addResolver(Args &&...args) {
    const auto resolver =
        std::make_shared<T>(*this, std::forward<Args>(args)...);
    iatResolvers.push_back(resolver);
    return resolver;
  }

  const std::vector<ImportLibrary> &getImports() const;

  ImportDirLayout getImportDirLayout() const;

  const ImportFunction *findImportFunction(
      std::string_view library,
      const std::variant<std::string, std::uint16_t> &function) const;

  ImportFunction *
  findImportFunction(std::string_view library,
                     const std::variant<std::string, std::uint16_t> &function);

protected:
  void addOriginalImports(const std::vector<std::uint8_t> &image);

  void resolveImports(const std::vector<std::uint8_t> &image);

  void rebuildImportDir(std::vector<std::uint8_t> &image) const;

  void applyPatches(std::vector<std::uint8_t> &image,
                    std::uint32_t origImportDirVA);

  void buildRedirectStubs(const std::vector<std::uint8_t> &image,
                          SectionBuilder &codeScn);

  void redirectOriginalIAT(std::vector<std::uint8_t> &image,
                           std::uint32_t origImportDirVA) const;

  bool constructImportDir(SectionBuilder &dataScn) const;

  static void updateHeaders(std::vector<std::uint8_t> &image);

protected:
  Dumper &dumper;
  const ModuleInfo *moduleInfo;
  std::vector<std::shared_ptr<IATResolver>> iatResolvers;
  std::vector<ImportLibrary> imports;
};
} // namespace dmadump
