#include <expected>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <set>

#include <dmadump/dumper/VMMDumper.hpp>
#include <dmadump/iat/DynamicIATResolver.hpp>
#include <dmadump/IATBuilder.hpp>
#include <dmadump/Logging.hpp>
#include <dmadump/Utils.hpp>

#include <cxxopts.hpp>

using namespace dmadump;

static int dumpModule(VMM_HANDLE vmmHandle,
                      const std::optional<std::string> &processName,
                      const std::string &moduleName,
                      const std::set<std::string> &resolveIAT = {});

int main(const int argc, const char *const argv[]) {

  cxxopts::Options parser("dmadump");

  // clang-format off
  parser.add_options()
      ("p,process", "target process to dump", cxxopts::value<std::string>())
      ("m,module", "target module to dump", cxxopts::value<std::string>())
      ("iat", "type of IAT obfuscation to target", cxxopts::value<std::vector<std::string>>())
      ("device", "memory acquisition method", cxxopts::value<std::string>())
      ("debug", "show debug output", cxxopts::value<bool>());
  // clang-format on

  const auto options = parser.parse(argc, argv);

  std::string processName;
  std::string moduleName;
  std::string deviceType;
  std::set<std::string> iatTargets;
  bool debugMode;

  try {
    if (options["process"].count()) {
      processName = options["process"].as<std::string>();
    }

    moduleName = options["module"].as<std::string>();

    if (options["iat"].count()) {
      for (const auto &resolver :
           options["iat"].as<std::vector<std::string>>()) {
        iatTargets.insert(resolver);
      }
    }

    deviceType = options["device"].count() ? options["device"].as<std::string>()
                                           : "fpga";

    debugMode = options["debug"].count() != 0;

  } catch (const std::exception &e) {
    std::cout << e.what() << "\n\n" << parser.help() << std::endl;
    return 1;
  }

  Logger::init(&std::cout);

#ifdef _WIN32
  if (!enablePrivilege("SeDebugPrivilege")) {
    LOG_WARN("failed to enable SeDebugPrivilege.");
  }
#endif

  LOG_INFO("initializing vmm...");

  std::vector vmmArgs{"-device", deviceType.c_str()};
  if (debugMode) {
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

  return dumpModule(vmmHandle->get(), processName, moduleName, iatTargets);
}

int dumpModule(VMM_HANDLE vmmHandle,
               const std::optional<std::string> &processName,
               const std::string &moduleName,
               const std::set<std::string> &resolveIAT) {

  std::uint32_t processID;
  if (processName) {

    LOG_INFO("looking for process {}...", *processName);

    const auto found = findProcessByName(vmmHandle, processName->c_str());
    if (!found) {
      LOG_ERROR("failed to find process {}.", *processName);
      return 1;
    }

    processID = *found;
  } else {
    processID = 4;
  }

  VMMDumper dumper(vmmHandle, processID);

  LOG_INFO("loading module information...");

  if (!dumper.loadModuleInfo()) {
    LOG_ERROR("failed to load module info.");
    return 1;
  }

  LOG_INFO("looking for module {}...", moduleName);

  const auto moduleInfo = dumper.getModuleList()->getModuleByName(moduleName);
  if (!moduleInfo) {
    LOG_ERROR("failed to find module info for {}.", moduleName);
    return 1;
  }

  LOG_INFO("found {} at 0x{:X} (size: {}).", moduleName,
           moduleInfo->getImageBase(), moduleInfo->getImageSize());

  LOG_INFO("reading image data...");

  std::vector<std::uint8_t> moduleData(moduleInfo->getImageSize());

  std::uint32_t bytesRead = 0;
  dumper.readMemoryCached(moduleInfo->getImageBase(), moduleData.data(),
                          moduleData.size(), &bytesRead);

  moduleData.resize(bytesRead);

  if (bytesRead == 0) {
    LOG_ERROR("failed to read module data.");
    return 1;
  }

  if (bytesRead != moduleInfo->getImageSize()) {
    LOG_WARN("not all module bytes were read ({}/{}).", bytesRead,
             moduleInfo->getImageSize());
  }

  LOG_INFO("fixing image sections...");

  convertImageSectionsRawToVA(moduleData.data());

  const auto optionalHeader = pe::getOptionalHeader64(moduleData.data());
  optionalHeader->ImageBase = moduleInfo->getImageBase();

  if (!resolveIAT.empty()) {
    IATBuilder iatBuilder(dumper, moduleInfo);

    if (resolveIAT.contains("dynamic")) {
      iatBuilder.addResolver<DynamicIATResolver>();
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
