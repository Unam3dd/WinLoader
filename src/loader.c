#include "loader.h"

/////////////////////////////////////////////////////////
//              LOADER (x86) PE File
////////////////////////////////////////////////////////

// check if file contain dos signature and nt signature
uint8_t check_file_format(WORD dos_sign, DWORD nt_sign)
{
    // 0x4D5A -> Little Endian (0x5A4D) (is 16 bits - 2 bytes (WORD))
    if (dos_sign != IMAGE_DOS_SIGNATURE)
        return (1);
    
    // NT SIGNATURE : PE\0\0 -> Little Endian 0x00004550
    if (nt_sign != IMAGE_NT_SIGNATURE)
        return (1);

    return (0);
}

// Write sections to the memory
void write_sections(char *ImageBase, char *ptr_data, PIMAGE_SECTION_HEADER sections, WORD nsections)
{
    char *addr = NULL;

    for (uint8_t i = 0; i < nsections; i++) {
        // sections[i].VirtualAddress is RVA
        addr = (ImageBase + sections[i].VirtualAddress);

        // sections[i].PointerToRawData is Physical Address to the raw data, See the docs
        if (sections[i].SizeOfRawData)
            memcpy(addr, ptr_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        else
            memset(addr, 0, sections[i].Misc.VirtualSize);
    }
}

void write_imports(char *ImageBase, PIMAGE_IMPORT_DESCRIPTOR import_descriptor)
{
    HMODULE lib = NULL;
    IMAGE_THUNK_DATA *lib_table = NULL, *addr_table = NULL;
    FARPROC function_handle = NULL;
    PIMAGE_IMPORT_BY_NAME by_name = NULL;
    DWORD function_addr = 0, i = 0;

    for (i = 0; import_descriptor[i].OriginalFirstThunk; i++) {

        // Load Library in the memory
        lib = LoadLibraryA((ImageBase + import_descriptor[i].Name));

        // This is the lookup table, its Import directory Table
        lib_table = (PIMAGE_THUNK_DATA) (ImageBase + import_descriptor[i].OriginalFirstThunk);

        // Here is the address table, we store ours address function in this struct pointers
        addr_table = (PIMAGE_THUNK_DATA) (ImageBase + import_descriptor[i].FirstThunk);

        // Write IAT table
        for (; lib_table[0].u1.AddressOfData; lib_table++, addr_table++) {
            
            // This is function address
            function_addr = lib_table[0].u1.AddressOfData;

            /*Check if function is ordinal
            see it (https://stackoverflow.com/questions/41581363/how-we-can-get-hint-in-image-import-by-name-struct-in-pe-file)
            */
            
            if (function_addr & IMAGE_ORDINAL_FLAG)
                function_handle = GetProcAddress(lib, (LPSTR)function_addr);
            else {
                // is not ordinal, so import it by name
                by_name = (PIMAGE_IMPORT_BY_NAME)(ImageBase + function_addr);
                function_handle = GetProcAddress(lib, (LPSTR)&by_name->Name);
            }

            // store the address of the function in IAT table
            addr_table[0].u1.Function = (DWORD) function_handle;
        }
    }
}

// We can see it https://stackoverflow.com/questions/31981929/what-is-the-base-relocation-table-in-the-pe-file-format
void write_relocations(char *ImageBase, PIMAGE_BASE_RELOCATION base_reloc, DWORD delta)
{
    DWORD size_blocks = 0, *patch_addr = NULL, i =0;

    while (base_reloc->VirtualAddress) {

        // Get size of blocks items
        size_blocks = ((base_reloc->SizeOfBlock) - sizeof(IMAGE_BASE_RELOCATION)) / 2;

        // get next blocks
        WORD *reloc = (WORD *)(base_reloc + 1);

        // for each items in blocks
        for (i = 0; i < size_blocks; i++) {
            // point to the items address by offset (12 last bits)
            patch_addr = (PDWORD) (ImageBase + base_reloc->VirtualAddress + (reloc[i] & 0xfff));

            // check type of items if needed to patch with delta
            if ((reloc[i] >> 12) == IMAGE_REL_BASED_HIGHLOW)
                *patch_addr += delta;
        }

        // switch to the next blocks
        base_reloc = (PIMAGE_BASE_RELOCATION) (((DWORD) base_reloc) + base_reloc->SizeOfBlock);
    }
}

// Write protections
void write_protections(char *ImageBase, PIMAGE_SECTION_HEADER sections, WORD nsections, DWORD size_of_headers)
{
    DWORD i = 0, old_prot = 0, new_prot = 0;
    char *addr = NULL;

    // Get Protections of the Headers
    VirtualProtect(ImageBase, size_of_headers, PAGE_READONLY, &old_prot);

    // for each sections, we can set the correct permissions
    for (i = 0; i < nsections; i++) {

        // address of each sections
        addr = (ImageBase + sections[i].VirtualAddress);

        // Check if sections is executable and if has write permissions
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            new_prot = ((sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ);
        else
            new_prot = ((sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY);
        
        // Set new protections in the address of each sections
        VirtualProtect(addr, sections[i].Misc.VirtualSize, new_prot, &old_prot);
    }
}

void *LoadPE(char *ptr_data, BOOL debug_mode)
{
    // We can see README.md to understand it
    PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER) ptr_data;
    PIMAGE_NT_HEADERS nt_hdr = (PIMAGE_NT_HEADERS) (((char *) dos_hdr) + dos_hdr->e_lfanew);
    PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER) (nt_hdr + 1);
    PIMAGE_DATA_DIRECTORY data_dir = (PIMAGE_DATA_DIRECTORY) (nt_hdr->OptionalHeader.DataDirectory);
    char *ImageBase = NULL;
    DWORD delta = 0;

    // Check file format
    if (check_file_format(dos_hdr->e_magic, nt_hdr->Signature))
        return (NULL);
    
    // Check if debug mode is enabled
    if (debug_mode)
        debug_info(dos_hdr, nt_hdr);
    
    /* Allocate Size of Image in the Heap memory
     to remind you, the VirtualAlloc is not the same as Malloc or HeapAlloc or GlobalAlloc
     VirtualAlloc Allocate Page Memory, Page memory size by default is 4k (4096) bytes (0x1000)
     Here we can allocate new page memory in the heap and reserve and commit it, with permissions read/write
    */
    ImageBase = (char *)VirtualAlloc(NULL, nt_hdr->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);


    // Write Headers in the Heap memory allocated by VirtualAlloc
    memcpy(ImageBase, ptr_data, nt_hdr->OptionalHeader.SizeOfHeaders);

    // Writing Sections
    write_sections(ImageBase, ptr_data, sections, nt_hdr->FileHeader.NumberOfSections);

    // Import descriptor Table & Write Imports (data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress is the RVA to the ImageBase)
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR) (ImageBase + data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Write Imports
    write_imports(ImageBase, import_descriptor);

    // calcul the n bytes displacement to the ImageBase
    delta = ((DWORD) ImageBase) - nt_hdr->OptionalHeader.ImageBase;

    if (data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress && delta) {
        PIMAGE_BASE_RELOCATION base_reloc = (PIMAGE_BASE_RELOCATION) (ImageBase + data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        // Writing relocations
        write_relocations(ImageBase, base_reloc, delta);
    }

    // Set sections permissions

    write_protections(ImageBase, sections, nt_hdr->FileHeader.NumberOfSections, nt_hdr->OptionalHeader.SizeOfHeaders);
    
    // return EntryPoint of PE loaded in to the memory
    return ((void *) (ImageBase + nt_hdr->OptionalHeader.AddressOfEntryPoint));
}