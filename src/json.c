#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "json.h"
#include "serialize.h"

void json_comma(FILE* f) {
	fprintf(f, ", ");
}

void json_key(FILE* f, const char* k) {
    fprintf(f, "\n\t\"%s\": ", k);
}

void json_escape(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char*)s; *p; ++p) {
        switch (*p) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n",  f); break;
            case '\r': fputs("\\r",  f); break;
            case '\t': fputs("\\t",  f); break;
            case '\b': fputs("\\b",  f); break;
            case '\f': fputs("\\f",  f); break;
            default:
                if (*p < 0x20) fprintf(f, "\\u%04x", *p);
                else fputc(*p, f);
        }
    }
    fputc('"', f);
}

void json_kv_str(FILE* f, const char* k, const char* v) {
    fputs("\n\t", f);
    json_escape(f, k);
    fputs(": ", f);
    json_escape(f, v);
}

void json_kv_u32(FILE* f, const char* k, uint32_t v) {
    fprintf(f, "\n\t\"%s\": %d", k, v);
}

void json_kv_u64(FILE* f, const char* k, uint64_t v) {
    fprintf(f, "\n\t\"%s\": %ld", k, v);
}

void json_kv_hex(FILE* f, const char* k, uint64_t v) {
    fprintf(f, "\n\t\"%s\": \"0x%llX\"", k, (unsigned long long)v);
}

int json_output() {
	FILE* f = fopen("output.json", "w");
	if (!f) {return 1;};
	fprintf(f, "{\n");
	file_to_json(f);
	hashes_to_json(f);
	headers_to_json(f);
	sections_to_json(f);
	fprintf(f, "\n}\n");
	fclose(f);
    return 0;
}
