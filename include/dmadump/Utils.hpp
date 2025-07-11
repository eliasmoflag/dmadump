#pragma once
#include <dmadump/PE.hpp>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>
#include <vmmdll.h>

namespace dmadump {
template <typename T>
static constexpr T align(T value, T alignment)
  requires std::is_integral_v<T>
{
  return (value + alignment - 1) & ~(alignment - 1);
}

#ifdef _WIN32
bool enablePrivilege(const char *privilegeName);
#endif

void convertImageSectionsRawToVA(void *image);

pe::ImageSectionHeader *appendImageSectionHeader(void *image);

std::string toLower(std::string_view str);

bool iequals(std::string_view lhs, std::string_view rhs);

bool compareLibraryName(std::string_view lhs, std::string_view rhs);

std::string simplifyLibraryName(std::string_view moduleName);
} // namespace dmadump
