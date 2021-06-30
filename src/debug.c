#include "loader.h"
#include <time.h>
#include <stdio.h>

char *get_machine_type(WORD Machine)
{
    switch (Machine) {

        case IMAGE_FILE_MACHINE_I386:
            return ("Intel x86");
        
        case IMAGE_FILE_MACHINE_IA64:
            return ("Intel x64");
        
        case IMAGE_FILE_MACHINE_AMD64:
            return ("Amd x64");
        
        case IMAGE_FILE_MACHINE_UNKNOWN:
            return ("Unknown");

        default:
            return (NULL);
    }
}

char *get_timedatestamp(DWORD time)
{
    time_t t = (time_t)time;
    struct tm *gmt = gmtime(&t);
    return (asctime(gmt));
}

char *get_pe_format_type(WORD Magic)
{
    switch (Magic) {

        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            return ("PE32");
        
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return ("PE32+");

        default:
            return (NULL);
    }
}

void debug_info(PIMAGE_DOS_HEADER dos_hdr, PIMAGE_NT_HEADERS nt_hdr)
{
    printf("[+] Dos Signature : 0x%x\n", dos_hdr->e_magic);
    printf("[+] NT Signature : 0x%x\n", nt_hdr->Signature);
    printf("[+] NT Header (PE Header) : 0x%lx\n", dos_hdr->e_lfanew);
    printf("[+] Sections Headers : 0x%lx\n", dos_hdr->e_lfanew + 1);
    printf("[+] Machine Type : %s\n", get_machine_type(nt_hdr->FileHeader.Machine));
    printf("[+] Number of sections : 0x%x\n", nt_hdr->FileHeader.NumberOfSections);
    printf("[+] TimeDateStamp : %s", get_timedatestamp(nt_hdr->FileHeader.TimeDateStamp));
    printf("[+] Size of Optional Header : 0x%x\n", nt_hdr->FileHeader.SizeOfOptionalHeader);
    printf("[+] Address of EntryPoint : 0x%x\n", nt_hdr->OptionalHeader.AddressOfEntryPoint);
    printf("[+] Magic Number : 0x%x (%s)\n", nt_hdr->OptionalHeader.Magic, get_pe_format_type(nt_hdr->OptionalHeader.Magic));
    printf("[+] Base Code (RVA to the ImageBase) : 0x%x\n", nt_hdr->OptionalHeader.BaseOfCode);
    printf("[+] Image Base : 0x%x\n", nt_hdr->OptionalHeader.ImageBase);
    printf("[+] Size of Image : 0x%x\n", nt_hdr->OptionalHeader.SizeOfImage);
    printf("[+] Size of Headers : 0x%x\n", nt_hdr->OptionalHeader.SizeOfHeaders);
    printf("[+] Size of Code : 0x%x\n", nt_hdr->OptionalHeader.SizeOfCode);
    printf("[+] Size of Initialized data : 0x%x\n", nt_hdr->OptionalHeader.SizeOfInitializedData);
    printf("[+] Size of UnInitialized data : 0x%x\n", nt_hdr->OptionalHeader.SizeOfUninitializedData);
    printf("[+] Section alignement : 0x%x\n", nt_hdr->OptionalHeader.SectionAlignment);
    printf("[+] File alignement : 0x%x\n", nt_hdr->OptionalHeader.FileAlignment);
    printf("[+] Subsystem : 0x%x\n", nt_hdr->OptionalHeader.Subsystem);
}