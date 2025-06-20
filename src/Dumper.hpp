#pragma once
#include <memory>
#include <string>
#include <unordered_map>

namespace dmadump {
class ModuleList;
class ModuleInfo;

class Dumper {
public:
  virtual ~Dumper() = default;

  virtual bool loadModuleInfo() = 0;

  virtual ModuleList *getModuleList() const = 0;

  virtual bool readMemory(std::uint64_t va, void *buffer, std::uint32_t size,
                          std::uint32_t *bytesRead = nullptr) = 0;

  virtual bool readMemoryCached(std::uint64_t va, void *buffer,
                                std::uint32_t size,
                                std::uint32_t *bytesRead = nullptr,
                                bool forceUpdateCache = false);

  virtual bool readString(std::uint64_t va, std::string &readInto,
                          std::uint32_t maxRead, bool forceUpdateCache = false);

protected:
  virtual bool loadModuleEAT(ModuleInfo &moduleInfo);

protected:
  std::unordered_map<std::uint64_t, std::unique_ptr<std::uint8_t[]>>
      memoryCache;
};
} // namespace dmadump
