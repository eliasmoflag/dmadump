#pragma once
#include <string>

namespace dmadump {
class ModuleExportInfo {
public:
  ModuleExportInfo(std::string name, std::uint16_t ordinal, std::uint32_t rva);

  const std::string &getName() const;
  std::uint16_t getOrdinal() const;
  std::uint32_t getRVA() const;

private:
  std::string name;
  std::uint16_t ordinal{0};
  std::uint32_t rva{0};
};
} // namespace dmadump
