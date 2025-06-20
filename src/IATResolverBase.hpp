#pragma once
#include <string>
#include <vector>

namespace dmadump {
class IATBuilder;
class SectionBuilder;

class ResolvedImport {
public:
  std::string Library;
  std::string Function;
};

class IATResolverBase {
public:
  explicit IATResolverBase(IATBuilder &iatBuilder);

  virtual ~IATResolverBase() = default;

  virtual bool resolve(const std::vector<std::uint8_t> &image) = 0;

  virtual const std::vector<ResolvedImport> &getImports() const = 0;

  virtual bool applyPatches(std::vector<std::uint8_t> &image,
                            SectionBuilder &scnBuilder) = 0;

protected:
  std::uint64_t getLowestModuleStartAddress() const;
  std::uint64_t getHighestModuleEndAddress() const;

  static std::vector<std::uint32_t>
  findDirectCalls(const std::uint8_t *searchBegin,
                  const std::uint8_t *searchEnd, std::uint32_t searchRVA,
                  std::uint32_t functionPtrRVA);

protected:
  IATBuilder &iatBuilder;
};
} // namespace dmadump
