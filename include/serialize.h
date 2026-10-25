#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "pe.h"

void file_to_json(FILE* f);
void hashes_to_json(FILE* f);
void headers_to_json(FILE* f);
void sections_to_json(FILE* f);
void imports_to_json(FILE* f);
void exports_to_json(FILE* f);