#include "ModuleInfo.hpp"
#include "Utils.hpp"
#include <filesystem>
#include <vector>

namespace dmadump {
ModuleInfo::ModuleInfo(const std::string &name,
                       const std::filesystem::path filePath,
                       const std::uint64_t imageBase,
                       const std::uint32_t imageSize,
                       const std::vector<ModuleExportInfo> &exports)
    : name(name), libraryID(simplifyLibraryName(name)), filePath(filePath),
      imageBase(imageBase), imageSize(imageSize), exports(exports) {}

const std::string &ModuleInfo::getName() const { return name; }

const std::string &ModuleInfo::getLibraryID() const { return libraryID; }

const std::filesystem::path &ModuleInfo::getFilePath() const {
  return filePath;
}

std::uint64_t ModuleInfo::getImageBase() const { return imageBase; }

std::uint32_t ModuleInfo::getImageSize() const { return imageSize; }

const std::vector<ModuleExportInfo> &ModuleInfo::getExports() const {
  return exports;
}

void ModuleInfo::addExport(const ModuleExportInfo &exportInfo) {
  exports.push_back(exportInfo);
}

const ModuleExportInfo *
ModuleInfo::getExportByName(const std::string_view name) const {
  for (const auto &exp : exports) {
    if (exp.getName() == name) {
      return &exp;
    }
  }
  return nullptr;
}

const ModuleExportInfo *
ModuleInfo::getExportByOrdinal(const std::uint32_t ordinal) const {
  for (const auto &exp : exports) {
    if (exp.getOrdinal() == ordinal) {
      return &exp;
    }
  }
  return nullptr;
}

const ModuleExportInfo *
ModuleInfo::getExportByVA(const std::uint64_t va) const {
  for (const auto &exp : exports) {
    if (imageBase + exp.getRVA() == va) {
      return &exp;
    }
  }
  return nullptr;
}

const ModuleExportInfo *
ModuleInfo::getExportByRVA(const std::uint32_t rva) const {
  for (const auto &exp : exports) {
    if (exp.getRVA() == rva) {
      return &exp;
    }
  }
  return nullptr;
}
} // namespace dmadump
