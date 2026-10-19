#pragma once
#include "reader.h"

void sha256(const unsigned char* buffer, char outputBuffer[65]);

void md5(const unsigned char* buffer, char outputBuffer[33]);

unsigned char* file_read(const char* file);

void pe_header(const unsigned char* buf);

void optional_header(const unsigned char* buf);

void data_directories(const unsigned char* buf);

void section_table(const unsigned char* buf);