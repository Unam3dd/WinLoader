#pragma once
#include <sys/types.h>
#include <stdint.h>
#include <windows.h>

typedef struct file_info_t file_info_t;

struct file_info_t
{
    char *filename;
    char *ptr_data;
    size_t size_file;
};

// reader.c
uint8_t read_file(file_info_t *f);

// utils.c
void *memory_copy(void *dst, const void *src, size_t size);
void *memory_set(void *dst, char c, size_t size);

// loader.c
uint8_t check_file_format(WORD dos_sign, DWORD nt_sign);
void write_sections(char *ImageBase, char *ptr_data, PIMAGE_SECTION_HEADER sections, WORD nsections);
void write_imports(char *ImageBase, PIMAGE_IMPORT_DESCRIPTOR import_descriptor);
void write_relocations(char *ImageBase, PIMAGE_BASE_RELOCATION base_reloc, DWORD delta);
void write_protections(char *ImageBase, PIMAGE_SECTION_HEADER sections, WORD nsections, DWORD size_of_headers);
void *LoadPE(char *ptr_data);