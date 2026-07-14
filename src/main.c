#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#include "parser.h"
#include "IAT.h"
#include "strt.h"

static DWORD GetPidByName(const char* name)
{
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return 0;
}

static DWORD ResolvePid(const char* input)
{
    char* end = NULL;
    unsigned long parsed = strtoul(input, &end, 10);
    if (end != input && *end == '\0')
        return (DWORD)parsed;

    return GetPidByName(input);
}

int main(int argc, char *argv[])
{
    char target[MAX_PATH] = {0};
    char path[MAX_PATH] = {0};
    PE_Context pe = {0};

    if (argc >= 2) {
        strncpy(target, argv[1], MAX_PATH - 1);
        target[MAX_PATH - 1] = '\0';
    } else {
        printf("Enter target process name or PID: ");
        fflush(stdout);
        read_path(target, MAX_PATH);
    }

    if (target[0] == '\0') {
        printf("No target process provided.\n");
        return 1;
    }

    if (argc >= 3) {
        strncpy(path, argv[2], MAX_PATH - 1);
        path[MAX_PATH - 1] = '\0';
    } else {
        printf("Enter PE file path: ");
        fflush(stdout);
        read_path(path, MAX_PATH);
    }

    if (path[0] == '\0') {
        printf("No file path provided. Please specify a valid PE file path.\n");
        return 1;
    }

    DWORD pid = ResolvePid(target);
    if (!pid) {
        printf("Process not found: %s\n", target);
        return 1;
    }

    printf("Target PID: %lu\n", (unsigned long)pid);

    pe.file = fopen(path, "rb");
    if (!pe.file) {
        printf("Error opening file '%s'.\n", path);
        return 1;
    }

    if (!PE_ParserNtHeaders(pe.file, &pe)) {
        printf("Invalid PE file.\n");
        fclose(pe.file);
        return 1;
    }

    if (!PE_ParserSection(pe.file, &pe)) {
        printf("Failed to parse sections.\n");
        fclose(pe.file);
        return 1;
    }

    PE_ParseImports(pe.file, &pe);
    PE_ParseExports(pe.file, &pe);

    if (!PE_RuntimeImportScanner(pid, &pe)) {
        printf("Runtime IAT scan failed.\n");
        fclose(pe.file);
        return 1;
    }

    fclose(pe.file);
    return 0;
}