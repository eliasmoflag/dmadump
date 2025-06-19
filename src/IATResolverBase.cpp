#include "IATResolverBase.hpp"
#include "Dumper.hpp"
#include "IATBuilder.hpp"
#include <ranges>
#include <limits>

namespace dmadump {
IATResolverBase::IATResolverBase(IATBuilder &iatBuilder)
    : iatBuilder(iatBuilder) {}

std::uint64_t IATResolverBase::getLowestModuleStartAddress() const {
  std::uint64_t result = std::numeric_limits<std::uint64_t>::max();

  for (const auto &mod : std::views::values(
           iatBuilder.getDumper().getModuleList()->getModuleMap())) {
    result = std::min(result, mod->ImageBase);
  }

  return result;
}

std::uint64_t IATResolverBase::getHighestModuleEndAddress() const {
  std::uint64_t result = std::numeric_limits<std::uint64_t>::min();

  for (const auto &mod : std::views::values(
           iatBuilder.getDumper().getModuleList()->getModuleMap())) {
    result = std::max(result, mod->ImageBase + mod->ImageSize);
  }

  return result;
}

std::optional<std::pair<const ModuleInfo *, const ModuleExportInfo *>>
IATResolverBase::findExportByVA(std::uint64_t va) const {

  if (const auto moduleInfo =
          iatBuilder.getDumper().getModuleList()->getModuleByAddress(va)) {

    for (const auto &exportInfo : moduleInfo->EAT) {
      if (moduleInfo->ImageBase + exportInfo.RVA == va) {
        return {{moduleInfo, &exportInfo}};
      }
    }
  }

  return std::nullopt;
}

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
} // namespace dmadump
