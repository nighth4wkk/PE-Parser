#pragma once
#include <stdio.h>

void export_table(FILE* f);
void import_table(FILE* f);
void find_for_table_entry(const unsigned char* buf);
void imports_for_json(FILE* f);
void exports_for_json(FILE* f);