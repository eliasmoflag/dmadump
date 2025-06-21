#pragma once
#include <dmadump/Dumper.hpp>
#include <dmadump/ModuleList.hpp>
#include <dmadump/Handle.hpp>
#include <variant>
#include <memory>
#include <vmmdll.h>

namespace dmadump {
class VmmDumper : public Dumper {
public:
  VmmDumper(VmmHandle vmmHandle, std::uint32_t processID);
  VmmDumper(std::shared_ptr<VmmHandle> vmmHandle, std::uint32_t processID);
  ~VmmDumper() override = default;

  static std::optional<std::uint32_t>
  findProcessByName(VMM_HANDLE vmmHandle, const char *processName);

  bool loadModuleInfo() override;
  ModuleList *getModuleList() const override;
  bool readMemory(std::uint64_t va, void *buffer, std::uint32_t size,
                  std::uint32_t *bytesRead = nullptr) override;

  VMM_HANDLE getRawHandle() const;

protected:
  std::variant<VmmHandle, std::shared_ptr<VmmHandle>> vmmHandle;
  std::uint32_t processID;
  std::unique_ptr<ModuleList> moduleList;
};
} // namespace dmadump
