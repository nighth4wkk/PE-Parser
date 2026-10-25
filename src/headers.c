#include <stdio.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "pe.h"
#include "headers.h"
#include <sys/stat.h>

unsigned char* file_read(const char* file) {
	int fd = open(file, O_RDONLY);
	if (fd < 0) {
		printf("Incorrect input file\n");
		exit(1);
	}
	struct stat st;
	if (fstat(fd, &st) == -1) {
		close(fd);
		exit(1);
	}
	size_t size = (size_t)st.st_size;
	unsigned char* buf = calloc(size, sizeof(char));
	if (!buf) {
		perror("calloc");
		close(fd);
		free(buf);
		exit(1);
	}
	size_t off = 0;
	while (off < size) {
		int n = read(fd, buf+off, size-off);
		if (n<0) {
			perror("read");
			close(fd);
			free(buf);
			exit(1);
		}
		off += (size_t)n;
	}
	Header.size = size;
	close(fd);
	return buf;
}

void sha256(const unsigned char* buffer, char outputBuffer[65]) {
	size_t n = Header.size;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int output_len = 0;
	EVP_MD_CTX* context = EVP_MD_CTX_new();
	if (context == NULL) {
		printf("[-] SHA256 error\n");
	} else {
		EVP_DigestInit_ex(context, EVP_sha256(), NULL);
		EVP_DigestUpdate(context, buffer, n);
		EVP_DigestFinal_ex(context, hash, &output_len);
		EVP_MD_CTX_free(context);
		for (unsigned int i=0; i<output_len; ++i) {
			sprintf((char*)(outputBuffer+(i*2)), "%02x", hash[i]);
		}
		outputBuffer[64] = 0;
		Hashes.sha256 = outputBuffer;
	}
}

void md5(const unsigned char* buffer, char outputBuffer[33]) {
	size_t n = Header.size;
	unsigned char hash[16];
	unsigned int output_len = 0;
	EVP_MD_CTX* context = EVP_MD_CTX_new();
	if (context == NULL) {
		printf("[-] MD5 error\n");
	} else {
		EVP_DigestInit_ex(context, EVP_md5(), NULL);
		EVP_DigestUpdate(context, buffer, n);
		EVP_DigestFinal_ex(context, hash, &output_len);
		EVP_MD_CTX_free(context);
		for (unsigned int i=0; i<output_len; ++i) {
			sprintf((char*)(outputBuffer+(i*2)), "%02x", hash[i]);
		}
		outputBuffer[32] = 0;
		Hashes.md5 = outputBuffer;
	}
}

void pe_header(const unsigned char* buf) {
	uint16_t SizeOfOptionalHeader = u16_read(buf, Header.e_lfanew+20);
	if (SizeOfOptionalHeader > Header.size - (Header.e_lfanew + 24)) {
		printf("Malformed OptionalHeader - uncorrect size 0x%X\n", SizeOfOptionalHeader);
	}
	Header.sizeofoptheader = SizeOfOptionalHeader;
	Header.signature = (char*)&buf[Header.e_lfanew];
	Header.signature_raw = u32_read(buf, Header.e_lfanew);
	Header.numofsections = u16_read(buf, Header.e_lfanew+6);
	Header.machine = u16_read(buf, Header.e_lfanew + 4);
	Header.characteristic = u16_read(buf, Header.e_lfanew + 22);
	Header.timedatestamp = u32_read(buf, Header.e_lfanew + 8);
}

void optional_header(const unsigned char* buf) {
	uint32_t opt_Base = Header.e_lfanew+24;
	uint16_t magic = (uint16_t)buf[opt_Base] | ((uint16_t)buf[opt_Base+1] << 8);
	Header.magic = magic;
	Header.optbase = opt_Base;
	Header.subsystem = u16_read(buf, opt_Base + 68);
	Header.sectionalignment = u32_read(buf, opt_Base + 32);
	Header.filealignment = u32_read(buf, opt_Base + 36);
	Header.majorsubversion = u16_read(buf, opt_Base + 48);
	Header.minorsubversion = u16_read(buf, opt_Base + 50);
	Header.dll_characteristics = u16_read(buf, opt_Base + 70);
	if (magic == PE32_MAGIC) { 
		uint32_t EntryPoint_addr = u32_read(buf, Header.optbase+16);
		uint32_t ImageBase = u32_read(buf, Header.optbase+28);
		uint32_t NumberOfRvaAndSizes = u32_read(buf, Header.optbase+92);
		Header.numofrvaandsizes = NumberOfRvaAndSizes;
		Header.entrypoint = (uint64_t)EntryPoint_addr;
		Header.imagebase = (uint64_t)ImageBase;
	} else if (magic == PE32P_MAGIC) {
		uint32_t EntryPoint_addr = u32_read(buf, Header.optbase+16);
		uint64_t ImageBase = u64_read(buf, Header.optbase+24);
		uint32_t NumberOfRvaAndSizes = u32_read(buf, Header.optbase+108);
		Header.numofrvaandsizes = NumberOfRvaAndSizes;
		Header.entrypoint = (uint64_t)EntryPoint_addr;
		Header.imagebase = (uint64_t)ImageBase;
	}
}


void data_directories(const unsigned char* buf) {
	if (Header.numofrvaandsizes == 0) {
		printf("No Data Directories section\n");
	} else {
		uint32_t export_rva = 0;
		uint32_t export_size = 0;
		uint32_t import_rva = 0;
		uint32_t import_size = 0;
		uint32_t resource_rva = 0;
		uint32_t resource_size = 0;
		if (Header.magic == PE32_MAGIC) { 
			export_rva = u32_read(buf, Header.optbase+96);
			export_size = u32_read(buf, Header.optbase+96+4);
			import_rva = u32_read(buf, Header.optbase+104);
			import_size = u32_read(buf, Header.optbase+104+4);
			resource_rva = u32_read(buf, Header.optbase+112);
			resource_size = u32_read(buf, Header.optbase+112+4);
		} else if (Header.magic == PE32P_MAGIC) {
			export_rva = u32_read(buf, Header.optbase+112);
			export_size = u32_read(buf, Header.optbase+112+4);
			import_rva = u32_read(buf, Header.optbase+120);
			import_size = u32_read(buf, Header.optbase+120+4);
			resource_rva = u32_read(buf, Header.optbase+128);
			resource_size = u32_read(buf, Header.optbase+128+4);
		} else {
			printf("Malformed Header magic (not PE32 or PE32+)\n");
		}
		DataDirs.export_rva = export_rva;
		DataDirs.export_size = export_size;
		DataDirs.import_rva = import_rva;
		DataDirs.import_size = import_size;
		DataDirs.resource_rva = resource_rva;
		DataDirs.resource_size = resource_size;
	}
}

void section_table(const unsigned char* buf) {
	uint32_t table_off = Header.optbase + Header.sizeofoptheader;
	Header.optbase = table_off;
	uint32_t n = Header.numofsections;
	if (n > MAX_SECTIONS) {n = MAX_SECTIONS;}
	if ((uint64_t)table_off + (uint64_t)n * 40 > Header.size) {
		printf("Section table out of bounds\n");
	}
	for (uint32_t i = 0; i < n; ++i) {
		uint32_t offset = table_off + 40*i;
		Section* s = &sections.SectionsList[i];
		memcpy(s->name, buf+offset, 8);
		s->name[8] = '\0';
		s->virtual_size = u32_read(buf, offset+8);
		s->r_virtual_address = u32_read(buf, offset+12);
		s->raw_size = u32_read(buf, offset+16);
		s->pointer_to_raw = u32_read(buf, offset+20);
		s->characteristics = u32_read(buf, offset+36);
		sections.count += 1;
	}	
}

// 1366311264