#pragma once
#include "ModuleExportInfo.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace dmadump {
class ModuleInfo {
public:
  ModuleInfo(const std::string &name, const std::filesystem::path &filePath,
             std::uint64_t imageBase, std::uint32_t imageSize,
             const std::vector<ModuleExportInfo> &exports);

  const std::string &getName() const;
  const std::string &getLibraryID() const;
  const std::filesystem::path &getFilePath() const;
  std::uint64_t getImageBase() const;
  std::uint32_t getImageSize() const;

  const std::vector<ModuleExportInfo> &getExports() const;

  void addExport(const ModuleExportInfo &exportInfo);

  const ModuleExportInfo *getExportByName(std::string_view name) const;
  const ModuleExportInfo *getExportByOrdinal(std::uint32_t ordinal) const;
  const ModuleExportInfo *getExportByVA(std::uint64_t va) const;
  const ModuleExportInfo *getExportByRVA(std::uint32_t rva) const;

private:
  std::string name;
  std::string libraryID;
  std::filesystem::path filePath;
  std::uint64_t imageBase;
  std::uint32_t imageSize;
  std::vector<ModuleExportInfo> exports;
};
} // namespace dmadump
