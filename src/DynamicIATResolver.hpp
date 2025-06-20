#pragma once
#include "IATResolver.hpp"
#include "PE.hpp"
#include <unordered_map>

namespace dmadump {
class DynamicIATResolver : public IATResolver {
public:
  static constexpr std::uint32_t DefaultRequiredScnAttrs =
      IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

  static constexpr std::uint32_t DefaultAllowedScnAttrs =
      ~IMAGE_SCN_MEM_EXECUTE;

  explicit DynamicIATResolver(
      IATBuilder &iatBuilder,
      std::uint32_t requiredScnAttrs = DefaultRequiredScnAttrs,
      std::uint32_t allowedScnAttrs = DefaultAllowedScnAttrs);

  ~DynamicIATResolver() override = default;

  bool resolve(const std::vector<std::uint8_t> &image) override;

  const std::vector<ResolvedImport> &getImports() const override;

  bool applyPatches(std::vector<std::uint8_t> &image,
                    SectionBuilder &scnBuilder) override;

  const std::unordered_map<std::uint32_t, ResolvedImport> &
  getResolvedImportsByRVAs() const;

protected:
  std::uint32_t requiredScnAttrs;
  std::uint32_t allowedScnAttrs;

  std::vector<ResolvedImport> resolvedImports;
  std::unordered_map<std::uint32_t, ResolvedImport> resolvedImportsByRVAs;
};
} // namespace dmadump
