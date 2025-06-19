#include "CmdLine.hpp"
#include <vector>

namespace dmadump {
CmdLine::CmdLine() : Options("dmadump") {}

bool CmdLine::load(const int argc, const char *const argv[]) {

  // clang-format off
  add_options()
      ("p,process", "target process to dump", cxxopts::value<std::string>())
      ("m,module", "target module to dump", cxxopts::value<std::string>())
      ("iat", "type of IAT obfuscation to target", cxxopts::value<std::vector<std::string>>())
      ("device", "memory acquisition method", cxxopts::value<std::string>())
      ("debug", "show debug output", cxxopts::value<bool>());
  // clang-format on

  const auto options = parse(argc, argv);

  try {
    if (options["process"].count()) {
      ProcessName = options["process"].as<std::string>();
    }

    ModuleName = options["module"].as<std::string>();

    if (options["iat"].count()) {
      for (const auto &resolver :
           options["iat"].as<std::vector<std::string>>()) {
        IAT.insert(resolver);
      }
    }

    DeviceType = options["device"].count() ? options["device"].as<std::string>()
                                           : "fpga";

    Debug = options["debug"].count() != 0;

  } catch (const std::exception &) {
    return false;
  }

  return true;
}

std::string CmdLine::help() const { return Options::help(); }
} // namespace dmadump
