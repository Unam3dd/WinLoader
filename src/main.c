#include "loader.h"
#include <stdio.h>

int main(int argc, char **argv)
{
    // Check if arguments required is passed

    if (argc < 2) {
        fprintf(stderr, "usage : %s <binary>\n", argv[0]);
        return (1);
    }

    // Initialize file_info_t struct for read file
    file_info_t f;

    f.filename = argv[1];

    // Read file and map into the memory
    if (read_file(&f))
        fprintf(stderr, "[-] Error read file !\n");
    
    // get New Entry point of PE Loaded in memory (ImageBase + AOP)
    void *entry_point = LoadPE(f.ptr_data, 1);

    // If exist, we call it by our function pointer, which pointed to the entry_point of PE
    if (entry_point)
        ((void (*)(void)) entry_point)();
     
    return (0);
}