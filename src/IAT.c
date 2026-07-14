#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>
#include <psapi.h>
#include "parser.h"
#include "strt.h"



#define MAX_BASELINE_ENTRIES 4096

static IatBaseline g_baselineStore[MAX_BASELINE_ENTRIES];
static size_t g_baselineCount = 0;

bool GetProcessCreateTime(HANDLE proc, ULONGLONG *outCreateTime){
    FILETIME creation, exit, kernelT, userT;
    if(!GetProcessTimes(proc, &creation, &exit, &kernelT, &userT))
        return false;
    ULARGE_INTEGER uli;
    uli.LowPart  = creation.dwLowDateTime;
    uli.HighPart = creation.dwHighDateTime;
    *outCreateTime = uli.QuadPart;
    return true;
}


int BuildModuleMap(HANDLE hProcess, ModuleInfo *mods, int maxMods) {
    HMODULE hMods[1024];
    DWORD needed;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &needed))
        return -1;

    int count = needed / sizeof(HMODULE);
    int n = 0;
    for (int i = 0; i < count && n < maxMods; i++) {
        MODULEINFO mi;
        char modName[MAX_PATH];
        if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi)) &&
            GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName))) {
            strncpy(mods[n].name, modName, MAX_PATH - 1);
            mods[n].name[MAX_PATH - 1] = '\0';
            mods[n].base = mi.lpBaseOfDll;
            mods[n].size = mi.SizeOfImage;
            n++;
        }
    }
    return n;
}

IatBaseline* FindBaseline(DWORD pid, ULONGLONG createTime, LPVOID slotAddr) {
    for (size_t i = 0; i < g_baselineCount; i++) {
        IatBaseline *e = &g_baselineStore[i];
        if (e->pid == pid && e->createTime == createTime && e->iatSlotAddr == slotAddr)
            return e;
    }
    return NULL;
}

IatBaseline* InsertBaseline(DWORD pid, ULONGLONG createTime, LPVOID iatSlot, uint64_t baseline){
    if (g_baselineCount >= MAX_BASELINE_ENTRIES) return NULL;
    IatBaseline *e = &g_baselineStore[g_baselineCount++];
    e->pid = pid;
    e->createTime = createTime;
    e->iatSlotAddr = iatSlot;
    e->baselineValue = baseline;
    return e;
}

LPVOID detect(DWORD pid){
    HMODULE HMod[256];
    DWORD cbNeeded;
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if(h == NULL) return NULL;
    if(!EnumProcessModules(h, HMod, sizeof(HMod), &cbNeeded)){
        CloseHandle(h);
        return NULL;
    }
    CloseHandle(h);
    return (LPVOID)HMod[0];
}

uint64_t ReadPtrRuntime(HANDLE hProcess, LPVOID addr, ArchType arch){
    if (arch == ARCH_32) {
        uint32_t val32 = 0;
        ReadProcessMemory(hProcess, addr, &val32, sizeof(uint32_t), NULL);
        return val32;
    }
    if (arch == ARCH_64) {
        uint64_t val64 = 0;
        ReadProcessMemory(hProcess, addr, &val64, sizeof(uint64_t), NULL);
        return val64;
    }
    return 0;
}

void read_string_runtime(HANDLE hProcess, LPVOID addr, char *buf, int max_len) {
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, addr, buf, max_len - 1, &bytesRead)) {
        if (max_len > 0) {
            buf[0] = '\0';
        }
        return;
    }

    for (int i = 0; i < (int)bytesRead; i++) {
        if (buf[i] == '\0') {
            return;
        }
    }

    buf[max_len - 1] = '\0';
}


bool addr_leg(HANDLE proc, LPVOID addr, HMODULE modBase, SIZE_T modSize){
    uintptr_t a = (uintptr_t)addr;
    uintptr_t b = (uintptr_t)modBase;
    if (!(a >= b && a < (b + modSize))) return false;

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(proc, addr, &mbi, sizeof(mbi))) return false;
    return mbi.Type == MEM_IMAGE;
}


bool PE_RuntimeImportScanner(DWORD pid, PE_Context *pe){
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_IMPORT_DESCRIPTOR desc;
    IMAGE_NT_HEADERS nt;
    LPVOID moduleBase = detect(pid);
    HANDLE f = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (f == NULL) return false;

    ULONGLONG createTime;
    if (!GetProcessCreateTime(f, &createTime)) { CloseHandle(f); return false; }

    ModuleInfo mods[256];
    int modCount = BuildModuleMap(f, mods, 256);

    char DLLNAME[256];
    char FUNCNAME[256];
    if(!ReadProcessMemory(f, moduleBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL)) return 0;
    if(!ReadProcessMemory(f, (BYTE*)moduleBase + dosHeader.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS), NULL)) return 0;

    DWORD importRVA = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    LPVOID descAddr = (BYTE*)moduleBase + importRVA;
    ReadProcessMemory(f, descAddr, &desc, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL);
    descAddr = (BYTE*)descAddr + sizeof(IMAGE_IMPORT_DESCRIPTOR);

    while (desc.Name != 0) {
        LPVOID nameAddr = (BYTE*)moduleBase + desc.Name;
        read_string_runtime(f, nameAddr, DLLNAME, sizeof(DLLNAME));

        ModuleInfo *expectedMod = NULL;
        for (int i = 0; i < modCount; i++)
            if (_stricmp(mods[i].name, DLLNAME) == 0) { expectedMod = &mods[i]; break; }

        bool hasINT = (desc.OriginalFirstThunk != 0);
        long thunk_size = (pe->arch == ARCH_64) ? 8 : 4;
        uint64_t ordMask = (pe->arch == ARCH_64) ? 0x8000000000000000ULL : 0x80000000;

        LPVOID intAddr = hasINT ? (BYTE*)moduleBase + desc.OriginalFirstThunk : NULL;
        LPVOID iatAddr = (BYTE*)moduleBase + desc.FirstThunk;
        uint64_t intEntry = hasINT ? ReadPtrRuntime(f, intAddr, (ArchType)pe->arch) : 0;
        uint64_t iatEntry = ReadPtrRuntime(f, iatAddr, (ArchType)pe->arch);

        while (hasINT ? intEntry != 0 : iatEntry != 0) {
            if (hasINT) {
                if (intEntry & ordMask)
                    snprintf(FUNCNAME, sizeof(FUNCNAME), "Ordinal_%llu", (unsigned long long)(intEntry & ~ordMask));
                else {
                    LPVOID fn = (BYTE*)moduleBase + (uint32_t)intEntry + 2;
                    read_string_runtime(f, fn, FUNCNAME, sizeof(FUNCNAME));
                }
            } else {
                strcpy(FUNCNAME, "<no INT>");
            }

            IatBaseline *b = FindBaseline(pid, createTime, iatAddr);
            if (b == NULL) {
                InsertBaseline(pid, createTime, iatAddr, iatEntry);

                bool strictOk = expectedMod && addr_leg(f, (LPVOID)iatEntry, (HMODULE)expectedMod->base, expectedMod->size);
                bool anyOk = strictOk;
                if (!strictOk)
                    for (int i = 0; i < modCount; i++)
                        if (addr_leg(f, (LPVOID)iatEntry, (HMODULE)mods[i].base, mods[i].size)) { anyOk = true; break; }

                if (!anyOk)
                    printf("  [BASELINE-FLAGGED] %s in %s -> 0x%llx outside all modules\n", FUNCNAME, DLLNAME, (unsigned long long)iatEntry);
                else if (!strictOk)
                    printf("  [BASELINE-CHECK] %s in %s resolved outside expected module\n", FUNCNAME, DLLNAME);

            } else if (b->baselineValue != iatEntry) {

                printf("  [HOOK DETECTED] %s in %s: 0x%llx -> 0x%llx\n",
                       FUNCNAME, DLLNAME, (unsigned long long)b->baselineValue, (unsigned long long)iatEntry);
                b->baselineValue = iatEntry;
            }

            if (hasINT) { intAddr = (BYTE*)intAddr + thunk_size; intEntry = ReadPtrRuntime(f, intAddr, (ArchType)pe->arch); }
            iatAddr = (BYTE*)iatAddr + thunk_size;
            iatEntry = ReadPtrRuntime(f, iatAddr, (ArchType)pe->arch);
        }

        if(!ReadProcessMemory(f, descAddr, &desc, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL)) return 0;
        descAddr = (BYTE*)descAddr + sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    CloseHandle(f);
    return true;
}