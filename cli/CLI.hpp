#pragma once
#include <set>
#include <memory>
#include <string>
#include <optional>
#include <expected>

#include <dmadump/Dumper.hpp>
#include <dmadump/Handle.hpp>

class CLI {
public:
  int run(int argc, const char *const argv[]);

private:
  bool parseOptions(int argc, const char *const argv[]);

  std::unique_ptr<dmadump::Dumper> selectDumper() const;

  static std::expected<dmadump::VmmHandle, std::string>
  createVmm(const std::vector<const char *> &argv) ;

  bool dumpModule() const;

private:
  std::optional<std::string> processName;
  std::string moduleName;
  std::string method;
  std::set<std::string> iatTargets;
  bool debugMode{false};

  std::unique_ptr<dmadump::Dumper> dumper;
};
