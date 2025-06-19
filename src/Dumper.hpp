#pragma once
#include <filesystem>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <vmmdll.h>
#include "ModuleList.hpp"

namespace dmadump {
class Dumper {
public:
  Dumper(VMM_HANDLE vmmHandle, std::uint32_t processId);

  ~Dumper();

  bool loadModuleInfo(bool loadEAT);

  const std::unique_ptr<ModuleList> &getModuleList() const;

  bool readMemory(std::uint64_t va, void *buffer, std::uint32_t size,
                  std::uint32_t *bytesRead = nullptr, bool forceUpdate = false);

  bool readString(std::uint64_t va, std::string &readInto,
                  std::uint32_t maxRead, bool forceUpdate = false);

protected:
  void loadModuleEAT(ModuleInfo &moduleInfo);

protected:
  VMM_HANDLE vmmHandle;

  std::uint32_t processId;

  std::unique_ptr<ModuleList> moduleList;

  std::unordered_map<std::uint64_t, std::unique_ptr<std::uint8_t[]>>
      memoryCache;
};
} // namespace dmadump
