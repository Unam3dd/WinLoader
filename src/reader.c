#include "loader.h"
#include <stdio.h>
#include <stdlib.h>

uint8_t read_file(file_info_t *f)
{
    // Create File Pointer
    FILE *fp = fopen(f->filename, "rb");

    // Check if file exist
    if (!fp)
        return (1);
    
    // Get Size of file
    fseek(fp, 0L, SEEK_END);
    f->size_file = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    // Allocate the size of file in the heap memory
    f->ptr_data = (char *)malloc((sizeof(char) * f->size_file) + 1);
    
    /* Store bytes pointed by file pointer and write it to in ptr_data
    which point to the heap memory previous Allocated by malloc
    */

    if (fread(f->ptr_data, sizeof(char), f->size_file, fp) != f->size_file)
        return (1);
    
    // Close file pointer
    fclose(fp);

    return (0);
}