#pragma once
#include <cstdint>

namespace dmadump {
class ImportDirLayout {
public:
  std::uint32_t Size;
  std::uint32_t DescriptorOffset;
  std::uint32_t FirstThunkOffset;
  std::uint32_t OriginalFirstThunkOffset;
  std::uint32_t LibraryNameOffset;
  std::uint32_t FunctionNameOffset;
};
}
