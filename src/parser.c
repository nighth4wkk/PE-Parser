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


HeadersInfo Header = {0};
Sections sections = {0};
FileJson File = {0};
HashJson Hashes = {0};
DataDirectoriesJson DataDirs = {0};


void print_debug_info() {
	printf("\n");
	printf("Signature: %s\n", Header.signature);
	printf("Number of sections: %d\n", Header.numofsections);
	printf("SizeOfOptionalHeader 0x%X\n", Header.sizeofoptheader);

	printf("Magic: 0x%X (%s)\n", Header.magic, (Header.magic == PE32_MAGIC ? "PE32" : "PE32+"));
	printf("AddressOfEntryPoint: 0x%lX\n", Header.entrypoint);
	printf("ImageBase: 0x%lX\n", Header.imagebase);
	printf("NumberOfRvaAndSizes: 0x%X\n", Header.numofrvaandsizes);

	printf("SHA256: %s\n", Hashes.sha256);
	printf("MD5: %s\n", Hashes.md5);

	printf("Export Table: RVA-0x%X, Size-0x%X\n", DataDirs.export_rva, DataDirs.export_size);
	printf("Import Table: RVA-0x%X, Size-0x%X\n", DataDirs.import_rva, DataDirs.import_size);
	printf("Resources Table: RVA-0x%X, Size-0x%X\n", DataDirs.resource_rva, DataDirs.resource_size);

}


void print_hexdump(const unsigned char* buf) {
	printf("\n\n");
	for (size_t i = 0; i < sections.count; ++i) {
		Section* s = &sections.SectionsList[i];
		for (uint32_t j = 0; j < s->raw_size; ++j) {
			uint8_t c = buf[s->pointer_to_raw + j];
			putchar((c >= 0x20 && c <= 0x7e) ? c : '.');
		}
	}
	printf("\n\n");
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
	if (argc == 1) {
		printf("Usage: ./parser <file.exe> [-json]\n\nArguments:\n\t<file.exe>\tPath to the executable file to parse.\nOptions:\n\t-json\t\tOutput results in JSON format instead of plain text.\n");
		exit(0);
	}

	unsigned char* buf = file_read(argv[1]);
	char outBuf_sha256[65];
	char outBuf_md5[33];
	
	if (buf[0]!='M' || buf[1]!='Z') {
		printf("Unsupported file format or broken DOS header\n");
		return 0;
	}

	if (Header.size < 0x40) {return 1;}
	Header.e_lfanew = u32_read(buf, 0x3c);
	if (Header.e_lfanew > Header.size - 24) {return 1;}
	Header.optbase = Header.e_lfanew + 24;

	pe_header(buf);
	optional_header(buf);
	data_directories(buf);
	sha256(buf, outBuf_sha256);
	md5(buf, outBuf_md5);
	print_debug_info();
	section_table(buf);
	pack_data(argv[1]);
	int a = 0;
	if (argc == 3) {if (!strcmp(argv[2], "-json")) {a = json_output();}}
	if (a == 1) {printf("Error with opening an output.json\n");}
	return 0;
}	
