#include <stdio.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <sys/stat.h>
#include "pe.h"
#include "headers.h"
#include "detect.h"

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

double entropy_calc(const unsigned char* buf, uint32_t raw_size, uint32_t pointer_to_raw) {
	if (raw_size == 0) {
		return 0.0;
	}
	uint32_t m[256] = {0};
	for (uint32_t i = 0; i < raw_size; ++i) {
		uint32_t elem = buf[pointer_to_raw + i];
		m[elem] += 1;
	}
	float prob = 0.0;
	float enth = 0.0;
	for (int i = 0; i < 256; ++i) {
		if (m[i] != 0) {
			prob = (float)m[i] / (float)raw_size;
			enth = enth - prob * log2(prob);
		}
	}
	return enth;
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

int pe_header(const unsigned char* buf) {
	uint16_t SizeOfOptionalHeader = u16_read(buf, Header.e_lfanew+20);
	if (SizeOfOptionalHeader > Header.size - (Header.e_lfanew + 24)) {
		fprintf(stderr, "Malformed OptionalHeader - uncorrect size 0x%X\n", SizeOfOptionalHeader);
		return 1;
	}
	Header.sizeofoptheader = SizeOfOptionalHeader;
	Header.signature = (char*)&buf[Header.e_lfanew];
	Header.signature_raw = u32_read(buf, Header.e_lfanew);
	Header.numofsections = u16_read(buf, Header.e_lfanew+6);
	Header.machine = u16_read(buf, Header.e_lfanew + 4);
	Header.characteristic = u16_read(buf, Header.e_lfanew + 22);
	Header.timedatestamp = u32_read(buf, Header.e_lfanew + 8);
	return 0;
}

int optional_header(const unsigned char* buf) {
	uint32_t opt_Base = Header.e_lfanew+24;
	size_t opt_size = Header.sizeofoptheader;
	
	if (opt_size < 2) {
		fprintf(stderr, "Optional header is too small for magic\n");
		return 1;
	}

	uint16_t magic = u16_read(buf, opt_Base);
	size_t minimum_size;

	if (magic == PE32_MAGIC) {
		minimum_size = 96;
	} else if (magic == PE32P_MAGIC) {
		minimum_size = 112;
	} else {
		fprintf(stderr, "Unknown Optional Header magic: 0x%X\n", magic);
		return 1;
	}

	if (opt_size < minimum_size) {
		fprintf(stderr, "Optional Header is too small\n");
		return 1;
	}

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
		return 0;
	} else if (magic == PE32P_MAGIC) {
		uint32_t EntryPoint_addr = u32_read(buf, Header.optbase+16);
		uint64_t ImageBase = u64_read(buf, Header.optbase+24);
		uint32_t NumberOfRvaAndSizes = u32_read(buf, Header.optbase+108);
		Header.numofrvaandsizes = NumberOfRvaAndSizes;
		Header.entrypoint = (uint64_t)EntryPoint_addr;
		Header.imagebase = (uint64_t)ImageBase;
		return 0;
	}
	fprintf(stderr, "Unknown Optional Header magic\n");
	return 1;
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

int section_table(const unsigned char* buf) {
	uint32_t table_off = Header.optbase + Header.sizeofoptheader;
	Header.optbase = table_off;
	uint32_t n = Header.numofsections;

	if (n > MAX_SECTIONS) {
		n = MAX_SECTIONS;
	}
	if ((uint64_t)table_off + (uint64_t)n * 40 > Header.size) {
		fprintf(stderr, "Section table out of bounds\n");
		return 1;
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
		if (s->raw_size !=0 && (s->pointer_to_raw > Header.size || s->raw_size > Header.size - s->pointer_to_raw)) {
			fprintf(stderr, "Section data out of bounds\n");
			return 1;
		}
		s->entropy = entropy_calc(buf, s->raw_size, s->pointer_to_raw); 
		
		// ================== last section struct ========================
		last_sec.last_sec_pointer = s->pointer_to_raw;
		last_sec.last_sec_size = s->raw_size;
		// ==============================================================

		sections.count += 1;
	}
	return 0;
}