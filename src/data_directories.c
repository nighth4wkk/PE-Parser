#include "pe.h"
#include "data_directories.h"
#include "headers.h"
#include "reader.h"
#include "json.h"

uint32_t rva_to_raw(uint32_t rva) {
    if (rva == 0) {
        return 0;
    }
    for (size_t i = 0; i < sections.count; ++i) {
        Section* s = &sections.SectionsList[i];
        if (rva >= s->r_virtual_address && rva <= s->r_virtual_address + s->virtual_size) {
            return rva - s->r_virtual_address + s->pointer_to_raw;
        }
    }
    return 0;
}

void find_for_table_entry(const unsigned char* buf) {
    uint32_t export_raw = rva_to_raw(DataDirs.export_rva);
    if (export_raw != 0) { // Export Table
        printf("\n[+] Export table found at 0x%X\n", export_raw);
        uint32_t addr_of_names_rva = u32_read(buf, export_raw + 32);
        uint32_t num_of_names = u32_read(buf, export_raw + 24);
        uint32_t names_raw = rva_to_raw(addr_of_names_rva);

        if (names_raw != 0) {
            printf("Exported functions:\n");
            for (uint32_t i = 0; i < num_of_names; ++i) {
                uint32_t name_rva = u32_read(buf, names_raw + 4*i);
                uint32_t name_raw = rva_to_raw(name_rva);
                
                if (name_raw != 0) {
                    Exports.names[i] = (char*)(buf + name_raw);
                    Exports.rva[i] = u32_read(buf, names_raw + 4*i);
                    Exports.count += 1;
                    printf("\t[%d] %s\n", i, (buf + name_raw));
                }
            }
            printf("\n");
        }
    } else {
        printf("[-] Export table not found\n");
    }

    uint32_t import_raw = rva_to_raw(DataDirs.import_rva);
    if (import_raw != 0) { // Import Table
        printf("\n[+] Import table found at 0x%X\n", import_raw);
        uint32_t current_raw = import_raw;
        int id = 0;
        while (1) {
            Import_Element* imp_elem = &Imports.elements[id++];
            uint32_t name_rva = u32_read(buf, current_raw + 12);
            uint32_t ilt_rva = u32_read(buf, current_raw);
            uint32_t iat_rva = u32_read(buf, current_raw + 16);
            if (name_rva == 0 && ilt_rva == 0 && iat_rva == 0) {
                break;
            }
            uint32_t name_raw = rva_to_raw(name_rva);
            if (name_raw != 0) {
                printf("DLL:\t %s\n", (char*)(buf + name_raw));
                imp_elem->dllname = (char*)(buf + name_raw);
                Imports.count += 1;
            }
            uint32_t table_rva = (ilt_rva != 0 ? ilt_rva : iat_rva);
            uint32_t ilt_raw = rva_to_raw(table_rva);

            if (Header.magic == PE32_MAGIC) {
                uint32_t current_ilt = ilt_raw;
                int idx = 0;
                while (1) {
                    uint32_t elem = u32_read(buf, current_ilt);
                    if (elem == 0) {
                        break;
                    }
                    if ((elem & 0x80000000) == 0) {
                        uint32_t hint_name = rva_to_raw(elem);
                        if (hint_name != 0) {
                            imp_elem->names[idx] = (char*)(buf + hint_name + 2);
                            printf("\t[%d] %s\n", idx++, (char*)(buf + hint_name + 2));
                        }
                    }
                    current_ilt += 4;
                }
            } else if (Header.magic == PE32P_MAGIC) {
                uint32_t current_ilt = ilt_raw;
                int idx = 0;
                while (1) {
                    uint64_t elem = u64_read(buf, current_ilt);
                    if (elem == 0) {
                        break;
                    }
                    if ((elem & 0x8000000000000000) == 0) {
                        uint32_t hint_name = rva_to_raw((uint32_t)elem);
                        if (hint_name != 0) {
                            imp_elem->names[idx] = (char*)(buf + hint_name + 2);
                            printf("\t[%d] %s\n", idx++, (char*)(buf + hint_name + 2));
                        }
                    }
                    current_ilt += 8;
                }
            }
            current_raw += 20;
        }
    } else {
        printf("[-] Import table not found\n");
    }
}