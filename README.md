# winspect
 
A parser for the PE (Portable Executable) format of executable files and dynamic libraries under Windows. It is able to parse DLL or EXE files, extract and produce information about the file, such as its architecture, entry point, sections, and entries found in its import table.
 
Written in pure C, designed to run cross-platform — analyze Windows binaries directly from a Linux environment.
 
---
 
## How it works
 
winspect walks the PE structure in three sequential stages:
 
### 1. Header Validation — `PE_ParserNtHeaders`
Reads and validates the DOS header, checks the `MZ` signature and bounds-checks
`e_lfanew` before seeking to the NT headers. Validates the `PE\0\0` signature,
reads `IMAGE_FILE_HEADER` to get section count, then detects architecture (x86/x64)
from the optional header magic field.
 
### 2. Section Table — `PE_ParserSection`
Reads the optional header (32 or 64 bit branch depending on arch) to extract
the entry point and import table RVA. Loads the full section table into memory
for use in RVA resolution downstream.
 
### 3. Import Table — `PE_ParseImports`
Resolves the import directory RVA to a raw file offset using the section table.
Walks each `IMAGE_IMPORT_DESCRIPTOR`, resolves DLL names, then walks the thunk
array for each DLL to extract imported function names and ordinals.
 
```
[ FILE* ] ──> [ PE_ParserNtHeaders ] ──> arch, num_sections, opt_header_offset
                      │
                      ├──> [ PE_ParserSection ] ──> entry_point, import_rva, sections[]
                      │
                      └──> [ PE_ParseImports ] ──> DLL names, function names, ordinals
```
 
---
 
## Hardening
 
Malformed or malicious PE files are a real input class. Several explicit validation steps guard against them:
 
- `e_lfanew` is bounds-checked before seeking — rejects offsets that point outside any real PE header range
- Section count is validated against `MAX_SECTIONS` before reading into a fixed buffer — prevents buffer overflow from attacker-controlled count fields
- String reading uses a custom `read_string` over `fscanf` — correct for binary data, bounded, stops on null terminator
---
 
## Build
 
```
gcc -o winspect main.c pe_parser.c -I.
```
 
## Usage
 
```
winspect <path to binary>
```
 
## Example Output
 
```
Program is x64 architecture (64 Bit)
Address Of Entry Point: 0x1234
Section: .text
Section: .rdata
Section: .data
DLL: KERNEL32.dll
  Function: VirtualAlloc
  Function: LoadLibraryA
DLL: ntdll.dll
  Function: NtQuerySystemInformation
```
 
---
 
## Roadmap
 
- [ ] Export Directory Table parsing
- [ ] IAT hook detection
- [ ] Base Relocation Block resolution (`.reloc`)
---
 
## References
 
- [Microsoft PE Format Documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [An In-Depth Look into the Win32 Portable Executable File Format — Matt Pietrek, MSDN Magazine](https://bytepointer.com/resources/pietrek_in_depth_look_into_pe_format_pt1.htm)
- [The C Programming Language — Kernighan & Ritchie](https://en.wikipedia.org/wiki/The_C_Programming_Language)
 
