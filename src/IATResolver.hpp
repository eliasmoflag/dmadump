#pragma once
#include <string>
#include <limits>
#include <optional>
#include <unordered_map>
#include "PE.hpp"

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

class IATResolverBase {
public:
  IATResolverBase(IATBuilder &iatBuilder);

  virtual ~IATResolverBase() = default;

  virtual bool resolve(const std::vector<std::uint8_t> &image) = 0;

  virtual std::vector<ResolvedImport> getImports() const = 0;

  virtual bool applyPatches(std::uint8_t *imageData,
                            SectionBuilder &scnBuilder) = 0;

protected:
  static std::vector<std::uint32_t>
  findDirectCalls(const std::uint8_t *searchBegin,
                  const std::uint8_t *searchEnd, std::uint32_t searchRVA,
                  std::uint32_t functionPtrRVA);

  std::optional<std::pair<const ModuleInfo *, const ModuleExportInfo *>>
  findExportByVA(std::uint64_t va) const;

protected:
  IATBuilder &iatBuilder;
};

class DirectIATResolver : public IATResolverBase {
public:
  static constexpr std::uint32_t DefaultRequiredScnAttrs =
      IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

  static constexpr std::uint32_t DefaultAllowedScnAttrs =
      std::numeric_limits<std::uint32_t>::max() & ~IMAGE_SCN_MEM_EXECUTE;

  DirectIATResolver(IATBuilder &iatBuilder,
                    std::uint32_t requiredScnAttrs = DefaultRequiredScnAttrs,
                    std::uint32_t allowedScnAttrs = DefaultAllowedScnAttrs);

  ~DirectIATResolver() override = default;

  bool resolve(const std::vector<std::uint8_t> &image) override;

  std::vector<ResolvedImport> getImports() const override;

  bool applyPatches(std::uint8_t *imageData,
                    SectionBuilder &scnBuilder) override;

  const std::unordered_map<std::uint32_t, ResolvedImport> &
  getDirectImports() const;

protected:
  std::uint32_t requiredScnAttrs;
  std::uint32_t allowedScnAttrs;

  std::unordered_map<std::uint32_t, ResolvedImport> directImportsByRVA;
};
} // namespace dmadump
