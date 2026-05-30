#pragma once
#pragma pack(push, 1)

#include <stdint.h>
#include <stdio.h>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8



/*BYTE   — uint8_t
WORD   — uint16_t
DWORD  — uint32_t
QWORD  — uint64_t
BOOL   — int32_t
CHAR   — char
WCHAR  — wchar_t
HANDLE — void*
LPVOID — void*
PVOID  — void* */



typedef struct NT_Headers{
    uint32_t Sig;
}NT_Headers;


struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};


typedef struct DOSheader{
    uint16_t e_magic; // MZ
    uint8_t padding[58];
    uint32_t e_lfanew; // PE\0\0
}DOSheader;


typedef struct _IMAGE_OPTIONAL_HEADER {
  uint16_t                Magic;
  uint8_t                 MajorLinkerVersion;
  uint8_t                 MinorLinkerVersion;
  uint32_t                SizeOfCode;
  uint32_t                SizeOfInitializedData;
  uint32_t                SizeOfUninitializedData;
  uint32_t                AddressOfEntryPoint;
  uint32_t                BaseOfCode;
  uint32_t                BaseOfData;
  uint32_t                ImageBase;
  uint32_t                SectionAlignment;
  uint32_t                FileAlignment;
  uint16_t                MajorOperatingSystemVersion;
  uint16_t                MinorOperatingSystemVersion;
  uint16_t                MajorImageVersion;
  uint16_t                MinorImageVersion;
  uint16_t                MajorSubsystemVersion;
  uint16_t                MinorSubsystemVersion;
  uint32_t                Win32VersionValue;
  uint32_t                SizeOfImage;
  uint32_t                SizeOfHeaders;
  uint32_t                CheckSum;
  uint16_t                Subsystem;
  uint16_t                DllCharacteristics;
  uint32_t                SizeOfStackReserve;
  uint32_t                SizeOfStackCommit;
  uint32_t                SizeOfHeapReserve;
  uint32_t                SizeOfHeapCommit;
  uint32_t                LoaderFlags;
  uint32_t                NumberOfRvaAndSizes;
  struct DataDirectory DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;



typedef struct _IMAGE_OPTIONAL_HEADER64 {
  uint16_t               Magic;
  uint8_t                MajorLinkerVersion;
  uint8_t                MinorLinkerVersion;
  uint32_t               SizeOfCode;
  uint32_t               SizeOfInitializedData;
  uint32_t               SizeOfUninitializedData;
  uint32_t               AddressOfEntryPoint;
  uint32_t               BaseOfCode;
  uint64_t               ImageBase;
  uint32_t               SectionAlignment;
  uint32_t               FileAlignment;
  uint16_t               MajorOperatingSystemVersion;
  uint16_t               MinorOperatingSystemVersion;
  uint16_t               MajorImageVersion;
  uint16_t               MinorImageVersion;
  uint16_t               MajorSubsystemVersion;
  uint16_t               MinorSubsystemVersion;
  uint32_t               Win32VersionValue;
  uint32_t               SizeOfImage;
  uint32_t               SizeOfHeaders;
  uint32_t               CheckSum;
  uint16_t               Subsystem;
  uint16_t               DllCharacteristics;
  uint64_t               SizeOfStackReserve;
  uint64_t               SizeOfStackCommit;
  uint64_t               SizeOfHeapReserve;
  uint64_t               SizeOfHeapCommit;
  uint32_t               LoaderFlags;
  uint32_t               NumberOfRvaAndSizes;
  struct DataDirectory DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;



typedef struct FileHeader{
    uint16_t machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;

}FileHeader;


typedef struct section{
    uint8_t name[IMAGE_SIZEOF_SHORT_NAME];
    union{
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    }Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;


typedef struct {
    uint16_t Hint;
    char Name[1]; // variable length, null terminated
} IMAGE_IMPORT_BY_NAME;



typedef struct {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;



typedef enum {
 ARCH_32 = 0x10B,
 ARCH_64 = 0x20B
} ArchType;

#define MAX_SECTIONS 96

typedef struct {
    FILE* file;
    uint32_t arch;
    IMAGE_SECTION_HEADER sections[MAX_SECTIONS];
    uint16_t num_sections;
    long opt_header_offset;
    uint32_t entry_point;
    uint32_t import_rva;
} PE_Context;


#pragma pack(pop)