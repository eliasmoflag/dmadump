#include "IATResolverBase.hpp"
#include "Dumper.hpp"
#include "IATBuilder.hpp"

namespace dmadump {
IATResolverBase::IATResolverBase(IATBuilder &iatBuilder)
    : iatBuilder(iatBuilder) {}

std::vector<std::uint32_t> IATResolverBase::findDirectCalls(
    const std::uint8_t *searchBegin, const std::uint8_t *searchEnd,
    const std::uint32_t searchRVA, const std::uint32_t functionPtrRVA) {

  std::vector<std::uint32_t> result;

  for (auto it = searchBegin; it != searchEnd - 6; ++it) {

    if (it[0] == 0xff && it[1] == 0x15) {
      const std::int32_t ripRelTarget =
          *reinterpret_cast<const std::int32_t *>(&it[2]);

      const std::uint64_t targetRVA =
          it - searchBegin + searchRVA + ripRelTarget + 6;

      if (targetRVA == functionPtrRVA) {
        result.push_back(it - searchBegin + searchRVA);
      }
    }
  }

  return result;
}

std::optional<std::pair<const ModuleInfo *, const ModuleExportInfo *>>
IATResolverBase::findExportByVA(std::uint64_t va) const {

  for (const auto &[moduleName, moduleInfo] :
       iatBuilder.getDumper().getModuleInfo()) {
    for (const auto &exportInfo : moduleInfo.EAT) {
      if (moduleInfo.ImageBase + exportInfo.RVA == va) {
        return {{&moduleInfo, &exportInfo}};
      }
    }
  }

  return std::nullopt;
}
} // namespace dmadump
