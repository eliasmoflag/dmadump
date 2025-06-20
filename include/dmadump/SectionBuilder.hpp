#pragma once
#include <vector>

namespace dmadump {
class SectionBuilder {
public:
  SectionBuilder(std::uint32_t sectionOffset, std::uint32_t sectionRVA,
                 std::uint32_t sectionAlignment, std::uint32_t fileAlignment);

  void finalize();

  std::uint32_t getOffset() const;
  std::uint32_t getRVA() const;

  std::uint32_t getSectionAlignment() const;
  std::uint32_t getFileAlignment() const;

  const std::vector<std::uint8_t> &getData() const;
  std::vector<std::uint8_t> &getMutableData();

  void append(const std::uint8_t *buffer, std::size_t size);

  template <typename Container>
    requires std::input_iterator<typename Container::const_iterator>
  inline void append(const Container &container) {
    data.insert(data.end(), container.begin(), container.end());
  }

  template <typename T>
    requires std::is_trivially_copyable_v<T>
  inline void append(const T &value) {
    data.insert(data.end(), reinterpret_cast<const std::uint8_t *>(&value),
                reinterpret_cast<const std::uint8_t *>(&value + 1));
  }

  std::uint32_t getRawSize() const;
  std::uint32_t getVirtualSize() const;
  std::uint32_t getFileSize() const;

  std::uint32_t getCharacteristics() const;
  void addCharacteristics(std::uint32_t flags);

protected:
  std::uint32_t sectionOffset;
  std::uint32_t sectionRVA;

  std::uint32_t sectionAlignment;
  std::uint32_t fileAlignment;

  std::uint32_t characteristics;

  std::vector<std::uint8_t> data;
};
} // namespace dmadump
