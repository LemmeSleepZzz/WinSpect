#pragma once

#include "strt.h"

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B


void read_path(char *path, int lenght){
    int c;
    int i;
    for(i = 0; i < lenght - 1 && ((c = getchar()) != EOF) && c != '\n'; i++){
        path[i] = c;
    }
    path[i] = '\0';
}

uint64_t ReadPtr(FILE* f, ArchType arch){
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


long rvatoraw(uint32_t rva, IMAGE_SECTION_HEADER *section, uint16_t section_n){
    for(int i=0; i < section_n; i++){
        if(rva >= section[i].VirtualAddress && rva < section[i].VirtualAddress + section[i].SizeOfRawData){
            return (long)(section[i].PointerToRawData + (rva - section[i].VirtualAddress));
        }
    }
    return -1;
}


void read_string(FILE *f, char *buf, int max_len) {
    int i = 0;
    char c;
    while (i < max_len - 1 && fread(&c, 1, 1, f) == 1 && c != '\0') {
        buf[i++] = c;
    }
    buf[i] = '\0';
}


bool PE_ParserNtHeaders(FILE *f, PE_Context* pe){
    NT_Headers NT;
    DOSheader dos_header;
    FileHeader H;
    uint16_t magic;
    if(f == NULL || pe == NULL) return 0;
    rewind(f);
    if(fread(&dos_header,sizeof(dos_header), 1, f) != 1){
        printf("error occurred");
        return 0;
    }
    if(dos_header.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    // e_lfanew must be positive and within a sane range before seeking
    if(dos_header.e_lfanew <= 0 || dos_header.e_lfanew > 0x10000000) return 0;

    fseek(f, dos_header.e_lfanew, SEEK_SET);
    fread(&NT,sizeof(NT_Headers), 1, f);
    

    if(NT.Sig != IMAGE_NT_SIGNATURE) return false;
    
    
    fread(&H, sizeof(H), 1, f);
    pe->num_sections = H.NumberOfSections;
    // malformed PE can set this to anything, don't trust it
    if (pe->num_sections > MAX_SECTIONS) return false;


    long opt_h_offset = ftell(f);
    pe -> opt_header_offset = opt_h_offset;
    fread(&magic, sizeof(magic), 1, f);

    if(magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC){
        pe -> arch = ARCH_32;
        printf("Program is x86 architecture (32 Bit)\n");
    }
        else if(magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC){
            pe -> arch = ARCH_64;
            printf("Program is x64 architecture (64 Bit)\n");
        }
    else{ printf("Unknown Architecture"); return 0; } 
    return 1;

}

bool PE_ParserSection(FILE *f, PE_Context* pe){
    if(pe -> arch == ARCH_32){
        IMAGE_OPTIONAL_HEADER32 opt32;
        fseek(f, pe -> opt_header_offset, SEEK_SET);
        fread(&opt32, sizeof(IMAGE_OPTIONAL_HEADER32), 1 , f);

        pe -> entry_point = opt32.AddressOfEntryPoint;
        pe -> import_rva = opt32.DataDirectory[1].VirtualAddress;
    }

    else if(pe -> arch == ARCH_64){
        IMAGE_OPTIONAL_HEADER64 opt64;
        fseek(f, pe -> opt_header_offset, SEEK_SET);
        fread(&opt64, sizeof(IMAGE_OPTIONAL_HEADER64), 1 ,f);
    
        pe -> entry_point = opt64.AddressOfEntryPoint;
        pe -> import_rva = opt64.DataDirectory[1].VirtualAddress;
    } 
    else return 0;

    printf("Address Of Entry Point: 0x%X\n", pe -> entry_point);
    fread(pe->sections, sizeof(IMAGE_SECTION_HEADER), pe->num_sections, f);
    for(int i = 0; i < pe->num_sections; i++){
    printf("Section: %.8s\n", pe->sections[i].name);
    }
    return 1;
}


bool PE_ParseImports(FILE *f, PE_Context* pe){
    IMAGE_IMPORT_DESCRIPTOR desc;
    char DLLNAME[256];
    char FUNCNAME[256];

    long import_offset = rvatoraw(pe->import_rva, pe->sections, pe->num_sections);
    if(import_offset == -1) return 0;
    fseek(f, import_offset, SEEK_SET);
    
    if(fread(&desc, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1 , f) != 1) return 0;

    long desc_pos = import_offset + sizeof(desc);

    while(desc.Name != 0){
        long name_offset = rvatoraw(desc.Name, pe -> sections, pe -> num_sections);
        if(name_offset != -1){
            fseek(f, name_offset, SEEK_SET);
            read_string(f, DLLNAME, sizeof(DLLNAME));
            printf("DLL: %s\n", DLLNAME); 
        }
        else printf("DLL: UNKNOWN (Invalid RVA)\n");

        // fall back to FirstThunk if OriginalFirstThunk is absent (bound imports)
        uint32_t targetThunk = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        long thunkOffset = rvatoraw(targetThunk, pe -> sections, pe -> num_sections);

        
        
        if(thunkOffset != -1){
            fseek(f, thunkOffset, SEEK_SET);
            uint64_t thunk = ReadPtr(f, (ArchType)pe ->arch);
            long thunk_size = (pe->arch == ARCH_64) ? 8 : 4;
            long thunk_array_pos = thunkOffset + thunk_size;

            while(thunk){
                if(thunk & (pe->arch == ARCH_64 ? 0x8000000000000000ULL : 0x80000000)){
                    printf("  Ordinal: %llu\n", thunk & (pe->arch == ARCH_64 ? 0x7FFFFFFFFFFFFFFF : 0x7FFFFFFF));
                } else {
                    long func_name_off = rvatoraw((uint32_t)thunk, pe->sections, pe->num_sections);
                    if(func_name_off != -1){
                        // skip the Hint field (2 bytes) before the function name
                        fseek(f, func_name_off + 2, SEEK_SET);
                        read_string(f, FUNCNAME, sizeof(FUNCNAME));
                        printf("  Function: %s\n", FUNCNAME);
                    }
                }
                fseek(f, thunk_array_pos, SEEK_SET); // EOF check
                thunk = ReadPtr(f, (ArchType)pe->arch);
                thunk_array_pos += thunk_size;
                }
            }
        
                    fseek(f, desc_pos, SEEK_SET);
                    // THIS IS THE OUTER LOOP FIX: Break if we fail to read the next descriptor!
                    if (fread(&desc, sizeof(desc), 1, f) != 1) {
                    break; }
                    desc_pos += sizeof(desc);

    
    }
    return 1;

}