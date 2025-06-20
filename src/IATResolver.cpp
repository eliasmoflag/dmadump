#include <dmadump/IATResolver.hpp>
#include <dmadump/Dumper.hpp>
#include <dmadump/ModuleList.hpp>
#include <dmadump/IATBuilder.hpp>
#include <limits>
#include <ranges>

namespace dmadump {
IATResolver::IATResolver(IATBuilder &iatBuilder)
    : iatBuilder(iatBuilder) {}

std::uint64_t IATResolver::getLowestModuleStartAddress() const {
  std::uint64_t result = std::numeric_limits<std::uint64_t>::max();

  for (const auto &moduleList = *iatBuilder.getDumper().getModuleList();
       const auto &mod : std::views::values(
           moduleList.getModuleMap())) {
    result = std::min(result, mod->getImageBase());
  }

  return result;
}

std::uint64_t IATResolver::getHighestModuleEndAddress() const {
  std::uint64_t result = std::numeric_limits<std::uint64_t>::min();

  for (const auto &moduleList = *iatBuilder.getDumper().getModuleList();
       const auto &mod : std::views::values(
           moduleList.getModuleMap())) {
    result = std::max(result, mod->getImageBase() + mod->getImageSize());
  }

  return result;
}

std::vector<std::uint32_t> IATResolver::findDirectCalls(
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
