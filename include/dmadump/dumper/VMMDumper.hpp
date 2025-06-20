#pragma once
#include <dmadump/Dumper.hpp>
#include <dmadump/ModuleList.hpp>
#include <memory>
#include <vmmdll.h>

namespace dmadump {
class VMMDumper : public Dumper {
public:
  VMMDumper(VMM_HANDLE vmmHandle, std::uint32_t processID);

  ~VMMDumper() override;

  bool loadModuleInfo() override;

  ModuleList *getModuleList() const override;

  bool readMemory(std::uint64_t va, void *buffer, std::uint32_t size,
                  std::uint32_t *bytesRead = nullptr) override;

protected:
  VMM_HANDLE vmmHandle;
  std::uint32_t processID;
  std::unique_ptr<ModuleList> moduleList;
};
} // namespace dmadump
