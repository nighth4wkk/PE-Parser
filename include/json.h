#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

void json_comma(FILE* f);
void json_escape(FILE* f, const char* s);
void json_key(FILE* f, const char* k);
void json_kv_str(FILE* f, const char* k, const char* v);
void json_kv_u32(FILE* f, const char* k, uint32_t v);
void json_kv_u64(FILE* f, const char* k, uint64_t v);
void json_kv_hex(FILE* f, const char* k, uint64_t v);
void json_kv_bool(FILE *f, const char *k, bool v);
void json_kv_double(FILE *f, const char *k, double v, int prec);
void json_kv_null(FILE *f, const char *k);
int json_output();