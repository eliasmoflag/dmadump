#include "SectionBuilder.hpp"
#include "Utils.hpp"

namespace dmadump {
SectionBuilder::SectionBuilder(const std::uint32_t sectionOffset,
                               const std::uint32_t sectionRVA,
                               const std::uint32_t sectionAlignment,
                               const std::uint32_t fileAlignment)
    : sectionOffset(sectionOffset), sectionRVA(sectionRVA),
      sectionAlignment(sectionAlignment), fileAlignment(fileAlignment),
      characteristics(0) {}

void SectionBuilder::finalize() { data.resize(getFileSize()); }

std::uint32_t SectionBuilder::getOffset() const { return sectionOffset; }

std::uint32_t SectionBuilder::getRVA() const { return sectionRVA; }

std::uint32_t SectionBuilder::getSectionAlignment() const {
  return sectionAlignment;
}

std::uint32_t SectionBuilder::getFileAlignment() const { return fileAlignment; }

const std::vector<std::uint8_t> &SectionBuilder::getData() const {
  return data;
}

std::vector<std::uint8_t> &SectionBuilder::getMutableData() { return data; }

void SectionBuilder::append(const std::uint8_t *buffer, std::size_t size) {
  data.insert(data.end(), buffer, buffer + size);
}

std::uint32_t SectionBuilder::getRawSize() const {
  return static_cast<std::uint32_t>(data.size());
}

std::uint32_t SectionBuilder::getVirtualSize() const {
  return align<std::uint32_t>(data.size(), sectionAlignment);
}

std::uint32_t SectionBuilder::getFileSize() const {
  return align<std::uint32_t>(data.size(), fileAlignment);
}

std::uint32_t SectionBuilder::getCharacteristics() const {
  return characteristics;
}

void SectionBuilder::addCharacteristics(std::uint32_t flags) {
  this->characteristics |= flags;
}
} // namespace dmadump
