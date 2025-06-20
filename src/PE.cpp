#include <dmadump/PE.hpp>
#include <algorithm>

namespace dmadump::pe {
ImageSectionHeader *ImageNtHeaders::getSectionHeader(const std::uint16_t i) {
  return &reinterpret_cast<ImageSectionHeader *>(
      reinterpret_cast<std::uintptr_t>(&FileHeader) + sizeof(ImageFileHeader) +
      FileHeader.SizeOfOptionalHeader)[i];
}

const ImageSectionHeader *
ImageNtHeaders::getSectionHeader(const std::uint16_t i) const {
  return &reinterpret_cast<const ImageSectionHeader *>(
      reinterpret_cast<std::uintptr_t>(&FileHeader) + sizeof(ImageFileHeader) +
      FileHeader.SizeOfOptionalHeader)[i];
}

std::uint16_t ImageNtHeaders::getSectionCount() const {
  return FileHeader.NumberOfSections;
}

std::optional<std::uint32_t>
ImageNtHeaders::fileOffsetToRVA(const std::uint32_t fileOffset) const {
  for (std::uint16_t i = 0; i < getSectionCount(); i++) {
    const auto section = getSectionHeader(i);

    if (fileOffset >= section->PointerToRawData) {

      const auto sectionFileOffset = fileOffset - section->PointerToRawData;
      if (sectionFileOffset < section->SizeOfRawData) {
        return section->VirtualAddress + sectionFileOffset;
      }
    }
  }

  return std::nullopt;
}

std::optional<std::uint32_t>
ImageNtHeaders::rvaToFileOffset(std::uint32_t rva) const {
  for (std::uint16_t i = 0; i < getSectionCount(); i++) {
    const auto section = getSectionHeader(i);

    if (rva >= section->VirtualAddress) {

      const auto sectionRva = rva - section->VirtualAddress;
      if (sectionRva < section->SizeOfRawData) {
        return section->PointerToRawData + sectionRva;
      }
    }
  }

  return std::nullopt;
}

std::uint64_t ImageNtHeaders::getSectionEndVA() const {
  std::uint64_t endVA = 0;

  for (std::uint16_t i = 0; i < getSectionCount(); i++) {
    const auto section = getSectionHeader(i);
    endVA =
        std::max(endVA, static_cast<std::uint64_t>(section->VirtualAddress) +
                            section->Misc.VirtualSize);
  }

  return endVA;
}

ImageNtHeaders *getNtHeaders(void *imageData) {
  return reinterpret_cast<ImageNtHeaders *>(
      static_cast<std::uint8_t *>(imageData) +
      static_cast<const ImageDosHeader *>(imageData)->e_lfanew);
}

const ImageNtHeaders *getNtHeaders(const void *imageData) {
  return reinterpret_cast<const ImageNtHeaders *>(
      static_cast<const std::uint8_t *>(imageData) +
      static_cast<const ImageDosHeader *>(imageData)->e_lfanew);
}

ImageFileHeader *getFileHeader(void *imageData) {
  return &getNtHeaders(imageData)->FileHeader;
}

const ImageFileHeader *getFileHeader(const void *imageData) {
  return &getNtHeaders(imageData)->FileHeader;
}

ImageOptionalHeader32 *getOptionalHeader32(void *imageData) {
  return &getNtHeaders(imageData)->OptionalHeader32;
}

const ImageOptionalHeader32 *getOptionalHeader32(const void *imageData) {
  return &getNtHeaders(imageData)->OptionalHeader32;
}

ImageOptionalHeader64 *getOptionalHeader64(void *imageData) {
  return &getNtHeaders(imageData)->OptionalHeader64;
}

const ImageOptionalHeader64 *getOptionalHeader64(const void *imageData) {
  return &getNtHeaders(imageData)->OptionalHeader64;
}
} // namespace dmadump::pe
