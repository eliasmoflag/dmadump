#include "CLI.hpp"
#include <iostream>
#include <fstream>
#include <dmadump/Logging.hpp>
#include <dmadump/Utils.hpp>
#include <dmadump/IATBuilder.hpp>
#include <dmadump/IAT/DynamicIATResolver.hpp>
#include <dmadump/Dumper/VmmDumper.hpp>
#include <dmadump/Dumper/Win32Dumper.hpp>
#include <cxxopts.hpp>

using namespace dmadump;

int main(const int argc, const char *const argv[]) {
  return CLI().run(argc, argv);
}

int CLI::run(const int argc, const char *const argv[]) {

  if (!parseOptions(argc, argv)) {
    return 1;
  }

  Logger::init(&std::cout);

#ifdef _WIN32
  if (!enablePrivilege("SeDebugPrivilege")) {
    LOG_WARN("failed to enable SeDebugPrivilege.");
  }

#endif

  dumper = selectDumper();
  if (!dumper) {
    return 1;
  }

  if (!dumpModule()) {
    return false;
  }

  return true;
}

bool CLI::parseOptions(const int argc, const char *const argv[]) {
  cxxopts::Options parser("dmadump");

  // clang-format off
  parser.add_options()
      ("p,process", "target process to dump", cxxopts::value<std::string>())
      ("m,module", "target module to dump", cxxopts::value<std::string>())
      ("iat", "type of IAT obfuscation to target", cxxopts::value<std::vector<std::string>>())
#ifdef _WIN32
      ("method", "memory acquisition method; defaults to platform API", cxxopts::value<std::string>())
#else
      ("method", "memory acquisition method (VMM)", cxxopts::value<std::string>())
#endif
      ("debug", "show debug output", cxxopts::value<bool>());
  // clang-format on

  try {
    const auto options = parser.parse(argc, argv);

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

    method =
        options["method"].count() ? options["method"].as<std::string>() : "";

    debugMode = options["debug"].count() != 0;

  } catch (const std::exception &e) {
    std::cout << e.what() << "\n\n" << parser.help() << std::endl;
    return false;
  }

  return true;
}

std::unique_ptr<Dumper> CLI::selectDumper() const {

#ifdef _WIN32
  if (method.empty() || method == "win32") {
    std::uint32_t processID;
    if (processName) {

      LOG_INFO("looking for process {}...", *processName);

      const auto found = Win32Dumper::findProcessByName(*processName);
      if (!found) {
        LOG_ERROR("failed to find process {}.", *processName);
        return nullptr;
      }

      processID = *found;
    } else {
      LOG_ERROR("kernel memory is inaccessible by the win32 dumper.");
      return nullptr;
    }

    const HANDLE processHandle =
        OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

    return std::make_unique<Win32Dumper>(Win32Handle(processHandle));
  }
#endif

  std::vector vmmArgs{"-device", method.c_str()};
  if (debugMode) {
    vmmArgs.insert(vmmArgs.end(), {"-v", "-printf"});
  }

  auto vmmHandle = createVmm(vmmArgs);
  if (!vmmHandle) {
    if (vmmHandle.error().empty()) {
      LOG_ERROR("failed to initialize vmm, no error message provided.");
    } else {
      LOG_ERROR("failed to initialize vmm, error: {}.", vmmHandle.error());
    }
    return nullptr;
  }

  std::uint32_t processID;
  if (processName) {

    LOG_INFO("looking for process {}...", *processName);

    const auto found =
        VmmDumper::findProcessByName(*vmmHandle, processName->c_str());
    if (!found) {
      LOG_ERROR("failed to find process {}.", *processName);
      return nullptr;
    }

    processID = *found;
  } else {
    processID = 4;
  }

  return std::make_unique<VmmDumper>(std::move(*vmmHandle), processID);
}

std::expected<VmmHandle, std::string>
CLI::createVmm(const std::vector<const char *> &argv) const {

  PLC_CONFIG_ERRORINFO errorInfo;
  VMM_HANDLE vmmHandle = VMMDLL_InitializeEx(
      argv.size(), const_cast<LPCSTR *>(argv.data()), &errorInfo);

  if (!vmmHandle) {
    std::string errorMessage;
    if (errorInfo) {
      errorMessage =
          std::string(errorInfo->wszUserText,
                      errorInfo->wszUserText + errorInfo->cwszUserText);

      LcMemFree(errorInfo);
    }

    return std::unexpected(errorMessage);
  }

  if (!VMMDLL_InitializePlugins(vmmHandle)) {
    VMMDLL_Close(vmmHandle);
    return nullptr;
  }

  return VmmHandle(vmmHandle);
}

bool CLI::dumpModule() const {

  LOG_INFO("loading module information...");

  if (!dumper->loadModuleInfo()) {
    LOG_ERROR("failed to load module info.");
    return 1;
  }

  LOG_INFO("looking for module {}...", moduleName);

  const auto moduleInfo = dumper->getModuleList()->getModuleByName(moduleName);
  if (!moduleInfo) {
    LOG_ERROR("failed to find module info for {}.", moduleName);
    return 1;
  }

  LOG_INFO("found {} at 0x{:X} (size: {}).", moduleName,
           moduleInfo->getImageBase(), moduleInfo->getImageSize());

  LOG_INFO("reading image data...");

  std::vector<std::uint8_t> moduleData(moduleInfo->getImageSize());

  std::uint32_t bytesRead = 0;
  dumper->readMemoryCached(moduleInfo->getImageBase(), moduleData.data(),
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

  if (!iatTargets.empty()) {
    IATBuilder iatBuilder(*dumper, moduleInfo);

    if (iatTargets.contains("dynamic")) {
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
