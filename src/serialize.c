#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "serialize.h"
#include "json.h"
#include "pe.h"

static const char *machine_name(uint16_t machine) {
    switch (machine) {
        case 0x014c: return "I386";
        case 0x8664: return "AMD64";
        case 0x01c0: return "ARM";
        case 0x01c4: return "ARMNT";
        case 0xaa64: return "ARM64";
        case 0x0200: return "IA64";
        case 0x0166: return "MIPS";
        case 0x01f0: return "POWERPC";
        case 0x0ebc: return "EBC";
        case 0x5032: return "RISCV32";
        case 0x5064: return "RISCV64";
        case 0x5128: return "RISCV128";
        default:     return "UNKNOWN";
    }
}

static const char *subsystem_name(uint16_t s) {
    switch (s) {
        case 0:  return "UNKNOWN";
        case 1:  return "NATIVE";
        case 2:  return "WINDOWS_GUI";
        case 3:  return "WINDOWS_CUI";
        case 5:  return "OS2_CUI";
        case 7:  return "POSIX_CUI";
        case 8:  return "NATIVE_WINDOWS";
        case 9:  return "WINDOWS_CE_GUI";
        case 10: return "EFI_APPLICATION";
        case 11: return "EFI_BOOT_SERVICE_DRIVER";
        case 12: return "EFI_RUNTIME_DRIVER";
        case 13: return "EFI_ROM";
        case 14: return "XBOX";
        case 16: return "WINDOWS_BOOT_APPLICATION";
        default: return "UNKNOWN";
    }
}

static void section_flags_to_json(FILE *f, uint32_t c) {
    static const struct {
        uint32_t    bit;
        const char *name;
    } FLAGS[] = {
        {0x00000008, "TYPE_NO_PAD"},
        {0x00000020, "CNT_CODE"},
        {0x00000040, "CNT_INITIALIZED_DATA"},
        {0x00000080, "CNT_UNINITIALIZED_DATA"},
        {0x00000100, "LNK_OTHER"},
        {0x00000200, "LNK_INFO"},
        {0x00000800, "LNK_REMOVE"},
        {0x00001000, "LNK_COMDAT"},
        {0x00008000, "GPREL"},
        {0x00020000, "MEM_PURGEABLE"},
        {0x00040000, "MEM_LOCKED"},
        {0x00080000, "MEM_PRELOAD"},
        {0x00100000, "ALIGN_1BYTES"},
        {0x00200000, "ALIGN_2BYTES"},
        {0x00300000, "ALIGN_4BYTES"},
        {0x00400000, "ALIGN_8BYTES"},
        {0x00500000, "ALIGN_16BYTES"},
        {0x00600000, "ALIGN_32BYTES"},
        {0x00700000, "ALIGN_64BYTES"},
        {0x00800000, "ALIGN_128BYTES"},
        {0x00900000, "ALIGN_256BYTES"},
        {0x00A00000, "ALIGN_512BYTES"},
        {0x00B00000, "ALIGN_1024BYTES"},
        {0x00C00000, "ALIGN_2048BYTES"},
        {0x00D00000, "ALIGN_4096BYTES"},
        {0x00E00000, "ALIGN_8192BYTES"},
        {0x01000000, "LNK_NRELOC_OVFL"},
        {0x02000000, "MEM_DISCARDABLE"},
        {0x04000000, "MEM_NOT_CACHED"},
        {0x08000000, "MEM_NOT_PAGED"},
        {0x10000000, "MEM_SHARED"},
        {0x20000000, "MEM_EXECUTE"},
        {0x40000000, "MEM_READ"},
        {0x80000000, "MEM_WRITE"},
    };

    fputs("[", f);
    bool first = true;
    for (size_t i = 0; i < sizeof(FLAGS)/sizeof(FLAGS[0]); ++i) {
        if (c & FLAGS[i].bit) {
            if (!first) fputs(", ", f);
            fputc('"', f);
            fputs(FLAGS[i].name, f);
            fputc('"', f);
            first = false;
        }
    }
    fputs("]", f);
}

void file_to_json(FILE* f) {
	fprintf(f, "\"file\": {");
    json_kv_str(f, "path", File.path); json_comma(f); 
    json_kv_u32(f, "size", File.size); json_comma(f);
    json_kv_str(f, "type", (File.type == PE32_MAGIC ? "PE32" : "PE32+")); json_comma(f);
    json_kv_str(f, "machine", machine_name(File.machine)); json_comma(f);
    json_kv_str(f, "subsystem", subsystem_name(File.subsystem)); json_comma(f);
    json_kv_u32(f, "timestamp_raw", File.timestamp);
    fprintf(f, "\n\t},\n");
}

void hashes_to_json(FILE* f) {
    fprintf(f, "\"hashes\": {");
    json_kv_str(f, "md5", Hashes.md5); json_comma(f);
    json_kv_str(f, "sha256", Hashes.sha256);
    fprintf(f, "\n\t},\n");
}

void headers_to_json(FILE* f) {
    fprintf(f, "\"headers\": {");
    json_kv_str(f, "nt_signature", Header.signature); json_comma(f);
    json_kv_hex(f, "nt_signature_raw", (uint64_t)Header.signature_raw); json_comma(f);
    json_kv_hex(f, "entry_point_rva", Header.entrypoint); json_comma(f);
    json_kv_hex(f, "image_base", Header.imagebase); json_comma(f);
    json_kv_hex(f, "num_of_sections", Header.numofsections); json_comma(f);
    json_kv_hex(f, "section_alignment", Header.sectionalignment); json_comma(f);
    json_kv_hex(f, "file_alignment", Header.filealignment); json_comma(f);
    json_kv_hex(f, "major_subsystem_version", Header.majorsubversion); json_comma(f);
    json_kv_hex(f, "minor_subsystem_version", Header.minorsubversion); json_comma(f);
    json_kv_hex(f, "number_of_rva", Header.numofrvaandsizes);
    fprintf(f, "\n\t},\n");
}

void sections_to_json(FILE* f) {
    fprintf(f, "\"sections\": [");
    for (size_t i = 0; i < sections.count; ++i) {
        Section* s = &sections.SectionsList[i];
        fprintf(f, "\n\t{");
        json_kv_str(f, "name", s->name); json_comma(f);
        json_kv_hex(f, "rva", s->r_virtual_address); json_comma(f);
        json_kv_u32(f, "virtual_size", s->virtual_size); json_comma(f);
        json_kv_u32(f, "raw_size", s->raw_size); json_comma(f);
        json_kv_hex(f, "raw_offset", s->pointer_to_raw); json_comma(f);
        json_key(f, "characteristics");
        section_flags_to_json(f, s->characteristics);

        if (i != sections.count - 1) {
            fprintf(f, "\n\t},");
        } else {
            fprintf(f, "\n\t}\n\t],\n");
        }
    }
}

void exports_to_json(FILE* f) {
    if (Exports.count != 0) {
        fprintf(f, "\"exports\": {");
        json_kv_u32(f, "count", Exports.count); json_comma(f);
        fprintf(f, "\n\t\"functions\": [");
        for (size_t i = 0; i < Exports.count; ++i) {
            fprintf(f, "\n\t{");
            json_kv_str(f, "name", Exports.names[i]); json_comma(f);
            json_kv_hex(f, "rva", Exports.rva[i]);
            if (i != Exports.count - 1) {
                fprintf(f, "\n\t},");
            } else {
                fprintf(f, "\n\t}\n\t]");
            }
        }
        fprintf(f, "\n\t},\n");
    }
}

void imports_to_json(FILE* f) {
    if (Imports.count != 0) {
        fprintf(f, "\"imports\": [");
        for (size_t i = 0; i < Imports.count; ++i) {
            Import_Element* imp_elem = &Imports.elements[i];
            fprintf(f, "\n\t{");
            json_kv_str(f, "name", imp_elem->dllname); json_comma(f);
            fprintf(f, "\n\t\"functions\": [");
            int idx = 0;
            if (imp_elem->names[idx] == 0) {
                fprintf(f, "]");
            } else {
                while (imp_elem->names[idx] != 0) {
                    fprintf(f, "\n\t{");
                    json_kv_str(f, "name", imp_elem->names[idx++]);
                    if (imp_elem->names[idx] != 0) {
                        fprintf(f, "\n\t},");
                    } else {
                        fprintf(f, "\n\t}\n\t]");
                    }
                }
                if (i == Imports.count - 1) {
                    fprintf(f, "\n\t}\n\t]");
                } else {
                    fprintf(f, "\n\t},\n\t");
                }
            }
        }
    }
}