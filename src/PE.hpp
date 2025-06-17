#pragma once
#include <cstdint>
#include <cstddef>
#include <optional>

namespace dmadump::pe {
#define IMAGE_SIZEOF_SHORT_NAME 8

#define IMAGE_SIZEOF_SECTION_HEADER 40
#define IMAGE_SCN_TYPE_NO_PAD 0x00000008
#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_LNK_OTHER 0x00000100
#define IMAGE_SCN_LNK_INFO 0x00000200
#define IMAGE_SCN_LNK_REMOVE 0x00000800
#define IMAGE_SCN_LNK_COMDAT 0x00001000
#define IMAGE_SCN_NO_DEFER_SPEC_EXC 0x00004000
#define IMAGE_SCN_GPREL 0x00008000
#define IMAGE_SCN_MEM_FARDATA 0x00008000
#define IMAGE_SCN_MEM_PURGEABLE 0x00020000
#define IMAGE_SCN_MEM_16BIT 0x00020000
#define IMAGE_SCN_MEM_LOCKED 0x00040000
#define IMAGE_SCN_MEM_PRELOAD 0x00080000
#define IMAGE_SCN_ALIGN_1BYTES 0x00100000
#define IMAGE_SCN_ALIGN_2BYTES 0x00200000
#define IMAGE_SCN_ALIGN_4BYTES 0x00300000
#define IMAGE_SCN_ALIGN_8BYTES 0x00400000
#define IMAGE_SCN_ALIGN_16BYTES 0x00500000
#define IMAGE_SCN_ALIGN_32BYTES 0x00600000
#define IMAGE_SCN_ALIGN_64BYTES 0x00700000
#define IMAGE_SCN_ALIGN_128BYTES 0x00800000
#define IMAGE_SCN_ALIGN_256BYTES 0x00900000
#define IMAGE_SCN_ALIGN_512BYTES 0x00A00000
#define IMAGE_SCN_ALIGN_1024BYTES 0x00B00000
#define IMAGE_SCN_ALIGN_2048BYTES 0x00C00000
#define IMAGE_SCN_ALIGN_4096BYTES 0x00D00000
#define IMAGE_SCN_ALIGN_8192BYTES 0x00E00000
#define IMAGE_SCN_ALIGN_MASK 0x00F00000
#define IMAGE_SCN_LNK_NRELOC_OVFL 0x01000000
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED 0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED 0x08000000
#define IMAGE_SCN_MEM_SHARED 0x10000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000
#define IMAGE_SCN_SCALE_INDEX 0x00000001

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT 12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

struct ImageDosHeader {
  std::uint16_t e_magic;
  std::uint16_t e_cblp;
  std::uint16_t e_cp;
  std::uint16_t e_crlc;
  std::uint16_t e_cparhdr;
  std::uint16_t e_minalloc;
  std::uint16_t e_maxalloc;
  std::uint16_t e_ss;
  std::uint16_t e_sp;
  std::uint16_t e_csum;
  std::uint16_t e_ip;
  std::uint16_t e_cs;
  std::uint16_t e_lfarlc;
  std::uint16_t e_ovno;
  std::uint16_t e_res[4];
  std::uint16_t e_oemid;
  std::uint16_t e_oeminfo;
  std::uint16_t e_res2[10];
  std::int32_t e_lfanew;
};

struct ImageFileHeader {
  std::uint16_t Machine;
  std::uint16_t NumberOfSections;
  std::uint32_t TimeDateStamp;
  std::uint32_t PointerToSymbolTable;
  std::uint32_t NumberOfSymbols;
  std::uint16_t SizeOfOptionalHeader;
  std::uint16_t Characteristics;
};

struct ImageDataDirectory {
  std::uint32_t VirtualAddress;
  std::uint32_t Size;

  inline bool contains(std::uint32_t rva) const {
    return VirtualAddress && Size && rva >= VirtualAddress &&
           rva < VirtualAddress + Size;
  }
};

struct ImageOptionalHeader32 {
  std::uint16_t Magic;
  std::uint8_t  MajorLinkerVersion;
  std::uint8_t  MinorLinkerVersion;
  std::uint32_t SizeOfCode;
  std::uint32_t SizeOfInitializedData;
  std::uint32_t SizeOfUninitializedData;
  std::uint32_t AddressOfEntryPoint;
  std::uint32_t BaseOfCode;
  std::uint32_t BaseOfData;
  std::uint32_t ImageBase;
  std::uint32_t SectionAlignment;
  std::uint32_t FileAlignment;
  std::uint16_t MajorOperatingSystemVersion;
  std::uint16_t MinorOperatingSystemVersion;
  std::uint16_t MajorImageVersion;
  std::uint16_t MinorImageVersion;
  std::uint16_t MajorSubsystemVersion;
  std::uint16_t MinorSubsystemVersion;
  std::uint32_t Win32VersionValue;
  std::uint32_t SizeOfImage;
  std::uint32_t SizeOfHeaders;
  std::uint32_t CheckSum;
  std::uint16_t Subsystem;
  std::uint16_t DllCharacteristics;
  std::uint32_t SizeOfStackReserve;
  std::uint32_t SizeOfStackCommit;
  std::uint32_t SizeOfHeapReserve;
  std::uint32_t SizeOfHeapCommit;
  std::uint32_t LoaderFlags;
  std::uint32_t NumberOfRvaAndSizes;
  ImageDataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct ImageOptionalHeader64 {
  std::uint16_t Magic;
  std::uint8_t  MajorLinkerVersion;
  std::uint8_t  MinorLinkerVersion;
  std::uint32_t SizeOfCode;
  std::uint32_t SizeOfInitializedData;
  std::uint32_t SizeOfUninitializedData;
  std::uint32_t AddressOfEntryPoint;
  std::uint32_t BaseOfCode;
  std::uint64_t ImageBase;
  std::uint32_t SectionAlignment;
  std::uint32_t FileAlignment;
  std::uint16_t MajorOperatingSystemVersion;
  std::uint16_t MinorOperatingSystemVersion;
  std::uint16_t MajorImageVersion;
  std::uint16_t MinorImageVersion;
  std::uint16_t MajorSubsystemVersion;
  std::uint16_t MinorSubsystemVersion;
  std::uint32_t Win32VersionValue;
  std::uint32_t SizeOfImage;
  std::uint32_t SizeOfHeaders;
  std::uint32_t CheckSum;
  std::uint16_t Subsystem;
  std::uint16_t DllCharacteristics;
  std::uint64_t SizeOfStackReserve;
  std::uint64_t SizeOfStackCommit;
  std::uint64_t SizeOfHeapReserve;
  std::uint64_t SizeOfHeapCommit;
  std::uint32_t LoaderFlags;
  std::uint32_t NumberOfRvaAndSizes;

  union {
    ImageDataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    struct {
      ImageDataDirectory ExportDirectory;
      ImageDataDirectory ImportDirectory;
      ImageDataDirectory ResourceDirectory;
      ImageDataDirectory ExceptionDirectory;
      ImageDataDirectory SecurityDirectory;
      ImageDataDirectory BaseRelocDirectory;
      ImageDataDirectory DebugDirectory;
      ImageDataDirectory ArchitectureDirectory;
      ImageDataDirectory GlobalPtrDirectory;
      ImageDataDirectory TlsDirectory;
      ImageDataDirectory LoadConfigDirectory;
      ImageDataDirectory BoundImportDirectory;
      ImageDataDirectory IatDirectory;
      ImageDataDirectory DelayImportDirectory;
      ImageDataDirectory ComDescriptorDirectory;
    };
  };
};

struct ImageSectionHeader {
  std::uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    std::uint32_t PhysicalAddress;
    std::uint32_t VirtualSize;
  } Misc;
  std::uint32_t VirtualAddress;
  std::uint32_t SizeOfRawData;
  std::uint32_t PointerToRawData;
  std::uint32_t PointerToRelocations;
  std::uint32_t PointerToLinenumbers;
  std::uint16_t NumberOfRelocations;
  std::uint16_t NumberOfLinenumbers;
  std::uint32_t Characteristics;
};

struct ImageNtHeaders {
  std::uint32_t Signature;
  ImageFileHeader FileHeader;

  union {
    ImageOptionalHeader32 OptionalHeader32;
    ImageOptionalHeader64 OptionalHeader64;
  };

  ImageSectionHeader *getSectionHeader(std::uint16_t i);
  const ImageSectionHeader *getSectionHeader(std::uint16_t i) const;

  std::uint16_t getSectionCount() const;

  std::optional<std::uint32_t> fileOffsetToRVA(std::uint32_t fileOffset) const;
  std::optional<std::uint32_t> rvaToFileOffset(std::uint32_t rva) const;

  std::uint64_t getSectionEndVA() const;
};

struct ImageImportDescriptor {
  union {
    std::uint32_t Characteristics;
    std::uint32_t OriginalFirstThunk;
  };
  std::uint32_t TimeDateStamp;

  std::uint32_t ForwarderChain;
  std::uint32_t Name;
  std::uint32_t FirstThunk;
};

struct ImageThunkData64 {
  union {
    std::uint64_t ForwarderString;
    std::uint64_t Function;
    std::uint64_t Ordinal;
    std::uint64_t AddressOfData;
  } u1;
};

struct ImageThunkData32 {
  union {
    std::uint32_t ForwarderString;
    std::uint32_t Function;
    std::uint32_t Ordinal;
    std::uint32_t AddressOfData;
  } u1;
};

struct ImageImportByName {
  std::uint16_t Hint;
  char Name[1];
};

struct ImageExportDirectory {
    std::uint32_t   Characteristics;
    std::uint32_t   TimeDateStamp;
    std::uint16_t   MajorVersion;
    std::uint16_t   MinorVersion;
    std::uint32_t   Name;
    std::uint32_t   Base;
    std::uint32_t   NumberOfFunctions;
    std::uint32_t   NumberOfNames;
    std::uint32_t   AddressOfFunctions;
    std::uint32_t   AddressOfNames;
    std::uint32_t   AddressOfNameOrdinals;
};

ImageNtHeaders *getNtHeaders(void *imageData);
const ImageNtHeaders *getNtHeaders(const void *imageData);

ImageFileHeader *getFileHeader(void *imageData);
const ImageFileHeader *getFileHeader(const void *imageData);

ImageOptionalHeader32 *getOptionalHeader32(void *imageData);
const ImageOptionalHeader32 *getOptionalHeader32(const void *imageData);

ImageOptionalHeader64 *getOptionalHeader64(void *imageData);
const ImageOptionalHeader64 *getOptionalHeader64(const void *imageData);

} // namespace dmadump::pe
