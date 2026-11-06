#pragma once
#include "reader.h"

double entropy_calc(const unsigned char* buf, uint32_t raw_size, uint32_t pointer_to_raw);
void sha256(const unsigned char* buffer, char outputBuffer[65]);
void md5(const unsigned char* buffer, char outputBuffer[33]);
void pe_header(const unsigned char* buf);
int optional_header(const unsigned char* buf);
void data_directories(const unsigned char* buf);
int section_table(const unsigned char* buf);
unsigned char* file_read(const char* file);

