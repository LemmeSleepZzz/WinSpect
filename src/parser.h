#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "strt.h"

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B

void read_path(char *path, int length);
bool PE_ParserNtHeaders(FILE *f, PE_Context *pe);
bool PE_ParserSection(FILE *f, PE_Context *pe);
bool PE_ParseImports(FILE *f, PE_Context *pe);
bool PE_ParseExports(FILE *f, PE_Context *pe);