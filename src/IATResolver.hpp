#pragma once
#include <string>
#include <optional>
#include <unordered_map>

namespace dmadump {
class Dumper;
class IATBuilder;
class SectionBuilder;
class ModuleInfo;
class ModuleExportInfo;

class ResolvedImport {
public:
  std::string Library;
  std::string Function;
};

class IATResolver {
public:
  IATResolver(IATBuilder &iatBuilder);

  virtual ~IATResolver() = default;

  virtual bool resolve(const std::vector<std::uint8_t> &image) = 0;

  virtual std::vector<ResolvedImport> getImports() const = 0;

  virtual bool applyPatches(std::uint8_t *imageData,
                            SectionBuilder &scnBuilder) = 0;

protected:
  static std::vector<std::uint32_t>
  findDirectCalls(const std::uint8_t *searchBegin,
                  const std::uint8_t *searchEnd, std::uint32_t searchRVA,
                  std::uint32_t functionPtrRVA) ;

  std::optional<std::pair<const ModuleInfo *, const ModuleExportInfo *>>
  findExportByVA(std::uint64_t va) const;

protected:
  IATBuilder &iatBuilder;
};

class DirectIATResolver : public IATResolver {
public:
  DirectIATResolver(IATBuilder &iatBuilder);

  ~DirectIATResolver() override = default;

  bool resolve(const std::vector<std::uint8_t> &image) override;

  std::vector<ResolvedImport> getImports() const override;

  bool applyPatches(std::uint8_t *imageData,
                    SectionBuilder &scnBuilder) override;

  const std::unordered_map<std::uint32_t, ResolvedImport> &
  getDirectImports() const;

protected:
  std::unordered_map<std::uint32_t, ResolvedImport> directImportsByRVA;
};
} // namespace dmadump
