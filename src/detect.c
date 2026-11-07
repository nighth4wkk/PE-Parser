#include <stdio.h>
#include "pe.h"
#include "detect.h"
#include "reader.h"


void check_overlay() {
    uint32_t overlay_off = last_sec.last_sec_pointer + last_sec.last_sec_size;
    if (overlay_off < File.size) {
        printf("Overlay detected (0x%X)\n", overlay_off);
    }   
}