#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include "pe.h"
#include "reader.h"
#include "headers.h"
#include "serialize.h"
#include "json.h"
#include "data_directories.h"

HeadersInfo Header = {0};
Sections sections = {0};
FileJson File = {0};
HashJson Hashes = {0};
DataDirectories DataDirs = {0};
Export Exports = {0};
Import Imports = {0};
Import_Element imp_elem = {0};

void pe_info() {
	printf("Signature: %s\n", Header.signature);
	printf("Number of sections: %d\n", Header.numofsections);
	printf("SizeOfOptionalHeader 0x%X\n", Header.sizeofoptheader);
	printf("Magic: 0x%X (%s)\n", Header.magic, (Header.magic == PE32_MAGIC ? "PE32" : "PE32+"));
	printf("AddressOfEntryPoint: 0x%lX\n", Header.entrypoint);
	printf("ImageBase: 0x%lX\n", Header.imagebase);
	printf("NumberOfRvaAndSizes: 0x%X\n\n", Header.numofrvaandsizes);
	printf("SHA256: %s\n", Hashes.sha256);
	printf("MD5: %s\n\n", Hashes.md5);
	printf("Export Table: RVA-0x%X, Size-0x%X\n", DataDirs.export_rva, DataDirs.export_size);
	printf("Import Table: RVA-0x%X, Size-0x%X\n", DataDirs.import_rva, DataDirs.import_size);
	printf("Resources Table: RVA-0x%X, Size-0x%X\n\n", DataDirs.resource_rva, DataDirs.resource_size);
	printf("Sections:\n");
	for (uint32_t i = 0; i < Header.numofsections; ++i) {
		Section* s = &sections.SectionsList[i];
		printf("\t[%d] %s\n", i, s->name);
		printf("\t\tRawSize: 0x%X\n", s->raw_size);
		printf("\t\tVirtualSize: 0x%X\n", s->virtual_size);
		printf("\t\tPointerToRawData: 0x%X\n", s->pointer_to_raw);
		printf("\t\tRVA: 0x%X\n", s->r_virtual_address);
		printf("\t\tEnthropy: %f\n", s->enthropy);	
	}
}

void pack_data(char* arg) {
	File.path = arg;
	File.size = Header.size;
	File.type = Header.magic;
	File.machine = Header.machine;
	File.timestamp = Header.timedatestamp;
	File.subsystem = Header.subsystem;
}

int main(int argc, char* argv[]) {
	int mode = 1;
	if (argc == 1 || argc > 3) {
		fprintf(stderr, "Usage: ./parser <file.exe> [-json]\n\nArguments:\n\t<file.exe>\tPath to the executable file to parse.\nOptions:\n\t-json\t\tOutput results in JSON format instead of plain text.\n");
		return 1;
	}
	if (argc == 3) {
		if (!strcmp(argv[2], "-json")) {
			mode = 0;
		} else {
			fprintf(stderr, "Usage: ./parser <file.exe> [-json]\n\nArguments:\n\t<file.exe>\tPath to the executable file to parse.\nOptions:\n\t-json\t\tOutput results in JSON format instead of plain text.\n");
			return 1;
		}
	}

	unsigned char* buf = file_read(argv[1]);
	char outBuf_sha256[65];
	char outBuf_md5[33];

	if (buf[0]!='M' || buf[1]!='Z') {
		fprintf(stderr, "Unsupported file format or broken DOS header\n");
		free(buf);
		return 1;
	}
	if (Header.size < 0x40) {
		fprintf(stderr, "Malformed file size\n");	
		free(buf);
		return 1;
	}
	Header.e_lfanew = u32_read(buf, 0x3c);
	if (Header.e_lfanew > Header.size - 24) {
		fprintf(stderr, "Malformed e_lfanew\n");
		free(buf);
		return 1;
	}
	if (u32_read(buf, Header.e_lfanew) != 0x00004550) {
		fprintf(stderr, "Malformed PE-signature (not PE)\n");
		free(buf);
		return 1;
	}

	Header.optbase = Header.e_lfanew + 24;
	pe_header(buf);
	if (optional_header(buf) == 1) {
		free(buf);
		return 1;
	};
	data_directories(buf);
	sha256(buf, outBuf_sha256);
	md5(buf, outBuf_md5);
	section_table(buf);
	pack_data(argv[1]);
	if (mode) {
		pe_info();
	}
	find_for_table_entry(buf, mode);	
	if (mode == 0 && json_output() != 0) {
		fprintf(stderr, "Error opening output.json\n");
		free(buf);
		return 1;
	}
	free(buf);
	return 0;
}	
