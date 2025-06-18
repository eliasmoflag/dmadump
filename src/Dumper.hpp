#pragma once
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <filesystem>
#include <vmmdll.h>

namespace dmadump {
class ModuleExportInfo {
public:
  std::string Name;

  std::uint32_t RVA{0};

  std::uint16_t Ordinal{0};
};

class ModuleInfo {
public:
  std::string Name;

  std::filesystem::path FilePath;

  std::uint64_t ImageBase{0};

  std::uint32_t ImageSize{0};

  std::vector<ModuleExportInfo> EAT;
};

class Dumper {
public:
  Dumper(VMM_HANDLE vmmHandle, std::uint32_t processId);

  ~Dumper();

  bool loadModuleInfo(bool loadEAT);

  const std::unordered_map<std::string, ModuleInfo> &getModuleInfo() const;

  const ModuleInfo *getModuleInfo(const std::string &moduleName) const;

  bool readMemory(std::uint64_t va, void *buffer, std::uint32_t size,
                  std::uint32_t *bytesRead = nullptr, bool forceUpdate = false);

  bool readString(std::uint64_t va, std::string &readInto,
                  std::uint32_t maxRead, bool forceUpdate = false);

protected:
  void loadModuleEAT(ModuleInfo &moduleInfo);

protected:
  VMM_HANDLE vmmHandle;

  std::uint32_t processId;

  std::unordered_map<std::string, ModuleInfo> imageInfo;

  std::unordered_map<std::uint64_t, std::unique_ptr<std::uint8_t[]>>
      memoryCache;
};
} // namespace dmadump
