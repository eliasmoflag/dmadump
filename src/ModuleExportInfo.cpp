#include "ModuleExportInfo.hpp"
#include <utility>

namespace dmadump {
ModuleExportInfo::ModuleExportInfo(std::string name,
                                   const std::uint16_t ordinal,
                                   const std::uint32_t rva)
    : name(std::move(name)), ordinal(ordinal), rva(rva) {}

const std::string &ModuleExportInfo::getName() const { return name; }

std::uint16_t ModuleExportInfo::getOrdinal() const { return ordinal; }

std::uint32_t ModuleExportInfo::getRVA() const { return rva; }
} // namespace dmadump
