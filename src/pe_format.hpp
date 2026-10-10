// pe_format.hpp — portable definitions of the PE/COFF structures used here.
//
// Field names and layouts match <winnt.h>, so code written against the
// Windows SDK compiles unchanged, but nothing here depends on Windows: the
// tool builds with MSVC, GCC and Clang and analyses PE files on any OS.
// Every structure is checked against its on-disk size below.

#pragma once

#include <cstddef>
#include <cstdint>

using BYTE      = std::uint8_t;
using WORD      = std::uint16_t;
using DWORD     = std::uint32_t;
using LONG      = std::int32_t;
using ULONGLONG = std::uint64_t;

constexpr WORD  IMAGE_DOS_SIGNATURE           = 0x5A4D;      // "MZ"
constexpr DWORD IMAGE_NT_SIGNATURE            = 0x00004550;  // "PE\0\0"
constexpr WORD  IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
constexpr WORD  IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

constexpr WORD IMAGE_FILE_MACHINE_I386  = 0x014c;
constexpr WORD IMAGE_FILE_MACHINE_ARM   = 0x01c0;
constexpr WORD IMAGE_FILE_MACHINE_IA64  = 0x0200;
constexpr WORD IMAGE_FILE_MACHINE_AMD64 = 0x8664;
constexpr WORD IMAGE_FILE_MACHINE_ARM64 = 0xAA64;

constexpr WORD IMAGE_SUBSYSTEM_NATIVE          = 1;
constexpr WORD IMAGE_SUBSYSTEM_WINDOWS_GUI     = 2;
constexpr WORD IMAGE_SUBSYSTEM_WINDOWS_CUI     = 3;
constexpr WORD IMAGE_SUBSYSTEM_EFI_APPLICATION = 10;

constexpr int IMAGE_DIRECTORY_ENTRY_EXPORT       = 0;
constexpr int IMAGE_DIRECTORY_ENTRY_IMPORT       = 1;
constexpr int IMAGE_NUMBEROF_DIRECTORY_ENTRIES   = 16;
constexpr int IMAGE_SIZEOF_SHORT_NAME            = 8;

constexpr DWORD IMAGE_SCN_MEM_EXECUTE = 0x20000000;

struct IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
};

struct IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    WORD  Magic;
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD  Subsystem;
    WORD  DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_OPTIONAL_HEADER64 {
    WORD      Magic;
    BYTE      MajorLinkerVersion;
    BYTE      MinorLinkerVersion;
    DWORD     SizeOfCode;
    DWORD     SizeOfInitializedData;
    DWORD     SizeOfUninitializedData;
    DWORD     AddressOfEntryPoint;
    DWORD     BaseOfCode;
    ULONGLONG ImageBase;
    DWORD     SectionAlignment;
    DWORD     FileAlignment;
    WORD      MajorOperatingSystemVersion;
    WORD      MinorOperatingSystemVersion;
    WORD      MajorImageVersion;
    WORD      MinorImageVersion;
    WORD      MajorSubsystemVersion;
    WORD      MinorSubsystemVersion;
    DWORD     Win32VersionValue;
    DWORD     SizeOfImage;
    DWORD     SizeOfHeaders;
    DWORD     CheckSum;
    WORD      Subsystem;
    WORD      DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD     LoaderFlags;
    DWORD     NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_NT_HEADERS64 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct IMAGE_SECTION_HEADER {
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
};

struct IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;  // RVA of the import lookup table
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;              // RVA of the import address table
};

struct IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
};

// The section table follows the optional header, whose size is recorded in
// the file header (it is not always sizeof(IMAGE_OPTIONAL_HEADER64)).
inline const IMAGE_SECTION_HEADER* image_first_section(const IMAGE_NT_HEADERS64* nt) {
    return reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const BYTE*>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
}
#define IMAGE_FIRST_SECTION(nt) image_first_section(nt)

// On-disk sizes and offsets from the PE/COFF specification.
static_assert(sizeof(IMAGE_DOS_HEADER) == 64, "IMAGE_DOS_HEADER");
static_assert(offsetof(IMAGE_DOS_HEADER, e_lfanew) == 0x3c, "e_lfanew");
static_assert(sizeof(IMAGE_FILE_HEADER) == 20, "IMAGE_FILE_HEADER");
static_assert(sizeof(IMAGE_OPTIONAL_HEADER32) == 224, "IMAGE_OPTIONAL_HEADER32");
static_assert(offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) == 96, "OptionalHeader32.DataDirectory");
static_assert(sizeof(IMAGE_OPTIONAL_HEADER64) == 240, "IMAGE_OPTIONAL_HEADER64");
static_assert(offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase) == 24, "OptionalHeader64.ImageBase");
static_assert(offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) == 112, "OptionalHeader64.DataDirectory");
static_assert(offsetof(IMAGE_NT_HEADERS64, OptionalHeader) == 24, "NT headers");
static_assert(sizeof(IMAGE_NT_HEADERS64) == 264, "IMAGE_NT_HEADERS64");
static_assert(sizeof(IMAGE_SECTION_HEADER) == 40, "IMAGE_SECTION_HEADER");
static_assert(sizeof(IMAGE_IMPORT_DESCRIPTOR) == 20, "IMAGE_IMPORT_DESCRIPTOR");
static_assert(sizeof(IMAGE_EXPORT_DIRECTORY) == 40, "IMAGE_EXPORT_DIRECTORY");
