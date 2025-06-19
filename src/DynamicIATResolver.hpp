#pragma once
#include "IATResolverBase.hpp"
#include <limits>
#include <unordered_map>

namespace dmadump {
class DynamicIATResolver : public IATResolverBase {
public:
  static constexpr std::uint32_t DefaultRequiredScnAttrs =
      IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

  static constexpr std::uint32_t DefaultAllowedScnAttrs =
      ~IMAGE_SCN_MEM_EXECUTE;

  DynamicIATResolver(IATBuilder &iatBuilder,
                     std::uint32_t requiredScnAttrs = DefaultRequiredScnAttrs,
                     std::uint32_t allowedScnAttrs = DefaultAllowedScnAttrs);

  ~DynamicIATResolver() override = default;

  bool resolve(const std::vector<std::uint8_t> &image) override;

  std::vector<ResolvedImport> getImports() const override;

  bool applyPatches(std::vector<std::uint8_t> &image,
                    SectionBuilder &scnBuilder) override;

  const std::unordered_map<std::uint32_t, ResolvedImport> &
  getResolvedImportsByRVAs() const;

protected:
  std::uint32_t requiredScnAttrs;
  std::uint32_t allowedScnAttrs;

  std::unordered_map<std::uint32_t, ResolvedImport> resolvedImportsByRVAs;
};
} // namespace dmadump
