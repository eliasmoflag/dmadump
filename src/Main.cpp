#include <optional>
#include <expected>
#include <fstream>
#include <memory>

#include "CmdLine.hpp"
#include "Dumper.hpp"
#include "IATBuilder.hpp"
#include "IATResolver.hpp"
#include "Logging.hpp"
#include "Utils.hpp"

#include <iostream>

using namespace dmadump;

static int dumpModule(VMM_HANDLE vmmHandle,
                      const std::optional<std::string> &processName,
                      const std::string &moduleName,
                      const std::set<std::string> &resolveIAT = {});

int main(const int argc, const char *const argv[]) {

  CmdLine cmdLine;
  if (!cmdLine.load(argc, argv)) {
    std::cout << "invalid arguments specified.\n\n" << cmdLine.help() << std::endl;
    return 1;
  }

  Logger::init();

  LOG_INFO("initializing vmm...");

  std::vector vmmArgs{"-device", "fpga://algo=0"};
  if (cmdLine.Debug) {
    vmmArgs.insert(vmmArgs.end(), {"-v", "-printf"});
  }

  const auto vmmHandle = createVmm(vmmArgs);
  if (!vmmHandle) {
    if (vmmHandle.error().empty()) {
      LOG_ERROR("failed to initialize vmm, no error message provided.");
    } else {
      LOG_ERROR("failed to initialize vmm, error: {}.", vmmHandle.error());
    }
    return 1;
  }

  return dumpModule(vmmHandle->get(), cmdLine.ProcessName, cmdLine.ModuleName,
                    cmdLine.IAT);
}

int dumpModule(VMM_HANDLE vmmHandle,
               const std::optional<std::string> &processName,
               const std::string &moduleName,
               const std::set<std::string> &resolveIAT) {

  std::uint32_t processId;
  if (processName) {

    LOG_INFO("looking for process {}...", *processName);

    const auto found = findProcessByName(vmmHandle, processName->c_str());
    if (!found) {
      LOG_ERROR("failed to find process {}.", *processName);
      return 1;
    }

    processId = *found;
  } else {
    processId = 4;
  }

  Dumper dumper(vmmHandle, processId);

  LOG_INFO("loading module information...");

  if (const bool loadEAT = !resolveIAT.empty();
      !dumper.loadModuleInfo(loadEAT)) {
    LOG_ERROR("failed to load module info.");
    return 1;
  }

  LOG_INFO("looking for module {}...", moduleName);

  const auto moduleInfo = dumper.getModuleInfo(moduleName.c_str());
  if (!moduleInfo) {
    LOG_ERROR("failed to find module info for {}.", moduleName);
    return 1;
  }

  LOG_INFO("found {} at 0x{:X} (size: {}).", moduleName, moduleInfo->ImageBase,
           moduleInfo->ImageSize);

  LOG_INFO("reading image data...");

  std::vector<std::uint8_t> moduleData(moduleInfo->ImageSize);

  std::uint32_t bytesRead = 0;
  dumper.readMemory(moduleInfo->ImageBase, moduleData.data(), moduleData.size(),
                    &bytesRead);

  moduleData.resize(bytesRead);

  if (bytesRead == 0) {
    LOG_ERROR("failed to read module data.");
    return 1;
  }

  if (bytesRead != moduleInfo->ImageSize) {
    LOG_WARN("not all module bytes were read ({}/{}).", bytesRead,
             moduleInfo->ImageSize);
  }

  LOG_INFO("fixing image sections...");

  convertImageSectionsRawToVA(moduleData.data());

  const auto optionalHeader = pe::getOptionalHeader64(moduleData.data());
  optionalHeader->ImageBase = moduleInfo->ImageBase;

  if (!resolveIAT.empty()) {
    IATBuilder iatBuilder(dumper, moduleInfo->ImageBase);

    if (resolveIAT.contains("direct")) {
      iatBuilder.addResolver<DirectIATResolver>(dumper, moduleInfo->ImageBase);
    }

    if (!iatBuilder.rebuild(moduleData)) {
      LOG_WARN("failed to rebuild imports.");
    }
  }

  std::filesystem::path dstPath = std::filesystem::current_path() / moduleName;
  dstPath.replace_extension("dump" + dstPath.extension().string());

  LOG_INFO("saving dump...");

  std::ofstream file(dstPath,
                     std::ios::out | std::ios::binary | std::ios::trunc);
  if (!file) {
    LOG_ERROR("failed to open file {}.", dstPath.string());
    return 1;
  }

  file.write(reinterpret_cast<const char *>(moduleData.data()),
             static_cast<std::streamsize>(moduleData.size()));

  LOG_SUCCESS("dump has been written to {}.", dstPath.string());
  return 0;
}
