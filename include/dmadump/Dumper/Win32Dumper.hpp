#pragma once
#ifdef _WIN32
#include <dmadump/Dumper.hpp>
#include <dmadump/ModuleList.hpp>
#include <dmadump/Handle.hpp>
#include <Windows.h>
#include <memory>
#include <variant>

namespace dmadump {
class Win32Dumper : public Dumper {
public:
  explicit Win32Dumper(Win32Handle processHandle);
  explicit Win32Dumper(std::shared_ptr<Win32Handle> processHandle);
  ~Win32Dumper() override = default;

  static std::optional<std::uint32_t>
  findProcessByName(std::string_view processName);

  bool loadModuleInfo() override;
  ModuleList *getModuleList() const override;
  bool readMemory(std::uint64_t va, void *buffer, std::uint32_t size,
                  std::uint32_t *bytesRead = nullptr) override;

  HANDLE getRawHandle() const;

protected:
  std::variant<Win32Handle, std::shared_ptr<Win32Handle>> processHandle;
  std::unique_ptr<ModuleList> moduleList;
};
} // namespace dmadump
#endif
