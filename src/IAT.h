#pragma once
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include "parser.h"
#include "strt.h"

// process / module enumeration
LPVOID detect(DWORD pid);
int BuildModuleMap(HANDLE hProcess, ModuleInfo *mods, int maxMods);
bool GetProcessCreateTime(HANDLE proc, ULONGLONG *outCreateTime);

// memory reading helpers
uint64_t ReadPtrRuntime(HANDLE hProcess, LPVOID addr, ArchType arch);
void read_string_runtime(HANDLE hProcess, LPVOID addr, char *buf, int max_len);

// baseline store
IatBaseline* FindBaseline(DWORD pid, ULONGLONG createTime, LPVOID slotAddr);
IatBaseline* InsertBaseline(DWORD pid, ULONGLONG createTime, LPVOID iatSlot, uint64_t baseline);

// address legitimacy check
bool addr_leg(HANDLE proc, LPVOID addr, HMODULE modBase, SIZE_T modSize);

// main scan entry point
bool PE_RuntimeImportScanner(DWORD pid, PE_Context *pe);