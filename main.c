#include <stdio.h>
#include "parser.h"
#include <string.h>
#define MAX_PATH 1000





int main(int argc, char *argv[]){
    char path [MAX_PATH];
    PE_Context pe = {0};
    if(argc >= 2){
        strncpy(path, argv[1], MAX_PATH -1);
        path[MAX_PATH - 1] = '\0';
    } else read_path(path, MAX_PATH);
    
    
    pe.file = fopen(path, "rb");
    if(pe.file == NULL){ printf("Error opening file.\n"); return 1; }
    
    if(!PE_ParserNtHeaders(pe.file, &pe)){ printf("Invalid PE file.\n"); return 1; }
    if(!PE_ParserSection(pe.file, &pe)){ printf("Failed to parse sections.\n"); return 1; }
    PE_ParseImports(pe.file, &pe);
    
    fclose(pe.file);
    return 0;
}
