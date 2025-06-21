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
  int run(const int argc, const char *const argv[]);

private:
  bool parseOptions(const int argc, const char *const argv[]);

  std::unique_ptr<dmadump::Dumper> selectDumper() const;

  std::expected<dmadump::VmmHandle, std::string>
  createVmm(const std::vector<const char *> &argv) const;

  bool dumpModule() const;

private:
  std::optional<std::string> processName;
  std::string moduleName;
  std::string method;
  std::set<std::string> iatTargets;
  bool debugMode{false};

  std::unique_ptr<dmadump::Dumper> dumper;
};
