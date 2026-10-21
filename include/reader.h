#pragma once
#include <stdint.h>
#include <stddef.h>

static inline uint16_t u16_read(const unsigned char* buf, size_t offset) {
	return ((uint16_t)buf[offset] | ((uint16_t)buf[offset+1] << 8));
}

static inline uint32_t u32_read(const unsigned char* buf, size_t offset) {
	return ((uint32_t)buf[offset] | ((uint32_t)buf[offset+1] << 8) | ((uint32_t)buf[offset+2] << 16) | ((uint32_t)buf[offset+3] << 24));
}

static inline uint64_t u64_read(const unsigned char* buf, size_t offset) {
	return ((uint64_t)buf[offset] | ((uint64_t)buf[offset+1] << 8) | ((uint64_t)buf[offset+2] << 16) | ((uint64_t)buf[offset+3] << 24) | ((uint64_t)buf[offset+4] << 32) | ((uint64_t)buf[offset+5] << 40) | ((uint64_t)buf[offset+6] << 48) | ((uint64_t)buf[offset+7] << 56));
}