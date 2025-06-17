#pragma once
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <expected>
#include <type_traits>
#include <vmmdll.h>
#include "PE.hpp"

namespace dmadump {
template <typename T>
static constexpr T align(T value, T alignment)
  requires std::is_integral_v<T>
{
  return (value + alignment - 1) & ~(alignment - 1);
}

using SharedVmmHandle = std::shared_ptr<std::remove_pointer_t<VMM_HANDLE>>;

std::expected<SharedVmmHandle, std::string>
createVmm(const std::vector<const char *> &argv);

std::optional<std::uint32_t> findProcessByName(VMM_HANDLE vmmHandle,
                                               const char *processName);

void convertImageSectionsRawToVA(void *image);

pe::ImageSectionHeader *appendImageSectionHeader(void *image);

std::string toLower(std::string_view str);

bool iequals(std::string_view lhs, std::string_view rhs);

bool compareLibraryName(std::string_view lhs, std::string_view rhs);

std::string simplifyLibraryName(const std::string &moduleName);
} // namespace dmadump
