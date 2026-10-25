#pragma once
#include <stdint.h>
#include <stddef.h>

#define PE32_MAGIC 0x10b
#define PE32P_MAGIC 0x20b
#define PE32_OPTSIZE 0xE0
#define PE32P_OPTSIZE 0xF0
#define MAX_SECTIONS 96

typedef struct {
	char name[9];
	uint32_t r_virtual_address;
	uint32_t virtual_size;
	uint32_t raw_size;
    uint32_t pointer_to_raw;
    uint32_t characteristics;
} Section;

typedef struct {
	Section SectionsList[MAX_SECTIONS];
	size_t count;
} Sections;

typedef struct {
	char* signature;
    uint64_t signature_raw;
    uint32_t e_lfanew;
    uint16_t machine;
	uint32_t numofsections;
    uint32_t timedatestamp;
	uint16_t sizeofoptheader;
    uint16_t characteristic;
	uint16_t magic;
	uint64_t entrypoint;
	uint64_t imagebase;
	uint32_t numofrvaandsizes;
    uint32_t optbase;
    size_t size;
    size_t SectionTableBase;
    uint16_t subsystem;
    uint32_t sectionalignment;
    uint32_t filealignment;
    uint16_t majorsubversion;
    uint16_t minorsubversion;
    uint16_t dll_characteristics;
} HeadersInfo;

typedef struct {
    char* path;
    size_t size;
    uint16_t type;
    uint16_t machine;
    uint32_t timestamp;
    uint16_t subsystem;
} FileJson;

typedef struct {
    char* sha256;
    char* md5;
} HashJson;

typedef struct {
    uint32_t export_rva;
	uint32_t export_size;
	uint32_t import_rva;
	uint32_t import_size;
	uint32_t resource_rva;
	uint32_t resource_size;
} DataDirectories;

typedef struct {
    char* names[64];
    uint32_t rva[64];
    size_t count;
} Export;

typedef struct {
    char* dllname;
    char* names[256];
} Import_Element;

typedef struct {
    Import_Element elements[128];
    size_t count;
} Import;

extern FileJson File;
extern HashJson Hashes;
extern HeadersInfo Header;
extern Sections sections;
extern DataDirectories DataDirs;
extern Export Exports;
extern Import_Element imp_elem;
extern Import Imports;