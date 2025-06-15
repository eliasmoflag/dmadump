#include "CmdLine.hpp"
#include <vector>
#include <cxxopts.hpp>

namespace dmadump {
std::optional<CmdLine> CmdLine::load(const int argc, const char *const argv[]) {

  CmdLine cmdLine;

  cxxopts::Options parser("dmadump");

  // clang-format off
  parser.add_options()
      ("p,process", "target process to dump", cxxopts::value<std::string>())
      ("m,module", "target module to dump", cxxopts::value<std::string>())
      ("iat", "type of IAT obfuscation to target", cxxopts::value<std::vector<std::string>>())
      ("debug", "show debug output", cxxopts::value<std::string>());
  // clang-format on

  const auto options = parser.parse(argc, argv);

  try {
    if (options["process"].count()) {
      cmdLine.ProcessName = options["process"].as<std::string>();
    }

    cmdLine.ModuleName = options["module"].as<std::string>();

    if (options["iat"].count()) {
      for (const auto &resolver :
           options["iat"].as<std::vector<std::string>>()) {
        cmdLine.IAT.insert(resolver);
      }
    }

    cmdLine.Debug = options["debug"].count() != 0;

  } catch (const std::exception &e) {
    std::printf("%s\n\n%s", e.what(), parser.help().c_str());
    return std::nullopt;
  }

  return cmdLine;
}
} // namespace dmadump
