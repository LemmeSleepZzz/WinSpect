#include <stdio.h>
#include "parser.h"

#define FSEEK(f, offset, whence) if (fseek(f, offset, whence) != 0) return false
#define FREAD(dst, size, count, f) if (fread(dst, size, count, f) != count) return false

void read_path(char *path, int length)
{
    int c;
    int i;
    for (i = 0; i < length - 1 && ((c = getchar()) != EOF) && c != '\n'; i++) {
        path[i] = c;
    }
    path[i] = '\0';
}

static uint64_t ReadPtr(FILE *f, ArchType arch)
{
    if (arch == ARCH_32) {
        uint32_t val32 = 0;
        fread(&val32, sizeof(uint32_t), 1, f);
        return val32;
    }
    if (arch == ARCH_64) {
        uint64_t val64 = 0;
        fread(&val64, sizeof(uint64_t), 1, f);
        return val64;
    }
    return 0;
}

static long rvatoraw(uint32_t rva, IMAGE_SECTION_HEADER *section, uint16_t section_n)
{
    for (int i = 0; i < section_n; i++) {
        uint32_t size = section[i].Misc.VirtualSize;
        if (size == 0) size = section[i].SizeOfRawData;
        if (size == 0) continue;
        uint32_t section_end = section[i].VirtualAddress + size;
        if (section_end < section[i].VirtualAddress) continue;
        if (rva >= section[i].VirtualAddress && rva < section_end) {
            return (long)(section[i].PointerToRawData + (rva - section[i].VirtualAddress));
        }
    }
    return -1;
}

static void read_string(FILE *f, char *buf, int max_len)
{
    int i = 0;
    char c;
    while (i < max_len - 1 && fread(&c, 1, 1, f) == 1 && c != '\0') {
        buf[i++] = c;
    }
    buf[i] = '\0';
}

bool PE_ParserNtHeaders(FILE *f, PE_Context *pe)
{
    NT_Headers NT;
    DOSheader dos_header;
    FileHeader H;
    uint16_t magic;

    if (f == NULL || pe == NULL) return false;
    rewind(f);
    if (fread(&dos_header, sizeof(dos_header), 1, f) != 1) {
        printf("error occurred");
        return false;
    }
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) return false;

    FSEEK(f, 0, SEEK_END);
    long file_size = ftell(f);
    if (file_size == -1) return false;
    if (dos_header.e_lfanew < 0x40 || dos_header.e_lfanew >= file_size) return false;

    FSEEK(f, dos_header.e_lfanew, SEEK_SET);
    FREAD(&NT, sizeof(NT_Headers), 1, f);

    if (NT.Sig != IMAGE_NT_SIGNATURE) return false;

    FREAD(&H, sizeof(H), 1, f);
    pe->num_sections = H.NumberOfSections;
    if (pe->num_sections > MAX_SECTIONS) return false;

    long opt_h_offset = ftell(f);
    if (opt_h_offset == -1) return false;
    pe->opt_header_offset = opt_h_offset;
    FREAD(&magic, sizeof(magic), 1, f);

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        pe->arch = ARCH_32;
        printf("Program is x86 architecture (32 Bit)\n");
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        pe->arch = ARCH_64;
        printf("Program is x64 architecture (64 Bit)\n");
    } else {
        printf("Unknown Architecture");
        return false;
    }

    return true;
}

bool PE_ParserSection(FILE *f, PE_Context *pe)
{
    if (pe->arch == ARCH_32) {
        IMAGE_OPTIONAL_HEADER32 opt32;
        FSEEK(f, pe->opt_header_offset, SEEK_SET);
        FREAD(&opt32, sizeof(IMAGE_OPTIONAL_HEADER32), 1, f);

        pe->entry_point = opt32.AddressOfEntryPoint;
        pe->import_rva = opt32.DataDirectory[1].VirtualAddress;
        pe->export_rva = opt32.DataDirectory[0].VirtualAddress;
    } else if (pe->arch == ARCH_64) {
        IMAGE_OPTIONAL_HEADER64 opt64;
        FSEEK(f, pe->opt_header_offset, SEEK_SET);
        FREAD(&opt64, sizeof(IMAGE_OPTIONAL_HEADER64), 1, f);

        pe->entry_point = opt64.AddressOfEntryPoint;
        pe->import_rva = opt64.DataDirectory[1].VirtualAddress;
        pe->export_rva = opt64.DataDirectory[0].VirtualAddress;
    } else {
        return false;
    }

    printf("Address Of Entry Point: 0x%X\n", pe->entry_point);
    FREAD(pe->sections, sizeof(IMAGE_SECTION_HEADER), pe->num_sections, f);
    for (int i = 0; i < pe->num_sections; i++) {
        printf("Section: %.8s\n", pe->sections[i].Name);
    }
    return true;
}

bool PE_ParseImports(FILE *f, PE_Context *pe)
{
    IMAGE_IMPORT_DESCRIPTOR desc;
    char DLLNAME[256];
    char FUNCNAME[256];

    long import_offset = rvatoraw(pe->import_rva, pe->sections, pe->num_sections);
    if (import_offset == -1) return false;
    FSEEK(f, import_offset, SEEK_SET);

    if (fread(&desc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, f) != 1) return false;

    long desc_pos = import_offset + sizeof(desc);

    while (desc.Name != 0) {
        long name_offset = rvatoraw(desc.Name, pe->sections, pe->num_sections);
        if (name_offset != -1) {
            FSEEK(f, name_offset, SEEK_SET);
            read_string(f, DLLNAME, sizeof(DLLNAME));
            printf("DLL: %s\n", DLLNAME);
        } else {
            printf("DLL: UNKNOWN (Invalid RVA)\n");
        }

        uint32_t targetThunk = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        long thunkOffset = rvatoraw(targetThunk, pe->sections, pe->num_sections);

        if (thunkOffset != -1) {
            FSEEK(f, thunkOffset, SEEK_SET);
            uint64_t thunk = ReadPtr(f, (ArchType)pe->arch);
            long thunk_size = (pe->arch == ARCH_64) ? 8 : 4;
            long thunk_array_pos = thunkOffset + thunk_size;

            while (thunk) {
                if (thunk & (pe->arch == ARCH_64 ? 0x8000000000000000ULL : 0x80000000)) {
                    printf("  Ordinal: %llu\n", thunk & (pe->arch == ARCH_64 ? 0x7FFFFFFFFFFFFFFF : 0x7FFFFFFF));
                } else {
                    long func_name_off = rvatoraw((uint32_t)thunk, pe->sections, pe->num_sections);
                    if (func_name_off != -1) {
                        FSEEK(f, func_name_off + 2, SEEK_SET);
                        read_string(f, FUNCNAME, sizeof(FUNCNAME));
                        printf("  Function: %s\n", FUNCNAME);
                    }
                }

                FSEEK(f, thunk_array_pos, SEEK_SET);
                thunk = ReadPtr(f, (ArchType)pe->arch);
                thunk_array_pos += thunk_size;
            }
        }

        FSEEK(f, desc_pos, SEEK_SET);
        if (fread(&desc, sizeof(desc), 1, f) != 1) {
            break;
        }
        desc_pos += sizeof(desc);
    }

    return true;
}

bool PE_ParseExports(FILE *f, PE_Context *pe)
{
    IMAGE_EXPORT_DIRECTORY desc;
    long export_offset = rvatoraw(pe->export_rva, pe->sections, pe->num_sections);
    if (export_offset == -1) {
        printf("Export isn't found");
        return false;
    }

    FSEEK(f, export_offset, SEEK_SET);
    FREAD(&desc, sizeof(IMAGE_EXPORT_DIRECTORY), 1, f);

    long dll_name_offset = rvatoraw(desc.Name, pe->sections, pe->num_sections);
    long name_offset = rvatoraw(desc.AddressOfNames, pe->sections, pe->num_sections);
    long ordinal_offset = rvatoraw(desc.AddressOfNameOrdinals, pe->sections, pe->num_sections);

    if (name_offset == -1 || ordinal_offset == -1) return false;

    char DLLNAME[256];
    char FUNCNAME[256];

    if (dll_name_offset != -1) {
        FSEEK(f, dll_name_offset, SEEK_SET);
        read_string(f, DLLNAME, sizeof(DLLNAME));
        printf("Export DLL Name: %s\n", DLLNAME);
    }

    for (int i = 0; i < desc.NumberOfNames; i++) {
        uint32_t name_rva = 0;
        FSEEK(f, name_offset + i * sizeof(uint32_t), SEEK_SET);
        FREAD(&name_rva, sizeof(uint32_t), 1, f);

        uint16_t ordinal_rva = 0;
        FSEEK(f, ordinal_offset + i * sizeof(uint16_t), SEEK_SET);
        FREAD(&ordinal_rva, sizeof(uint16_t), 1, f);

        long func_name_off = rvatoraw(name_rva, pe->sections, pe->num_sections);
        if (func_name_off != -1) {
            FSEEK(f, func_name_off, SEEK_SET);
            read_string(f, FUNCNAME, sizeof(FUNCNAME));
            printf("  [%u] %s\n", desc.Base + ordinal_rva, FUNCNAME);
        }
    }

    return true;
}