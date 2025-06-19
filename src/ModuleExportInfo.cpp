#include "ModuleExportInfo.hpp"

namespace dmadump {
ModuleExportInfo::ModuleExportInfo(const std::string &name,
                                   std::uint16_t ordinal, std::uint32_t rva)
    : name(name), ordinal(ordinal), rva(rva) {}

const std::string &ModuleExportInfo::getName() const { return name; }

std::uint16_t ModuleExportInfo::getOrdinal() const { return ordinal; }

std::uint32_t ModuleExportInfo::getRVA() const { return rva; }
} // namespace dmadump
