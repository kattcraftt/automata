/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_SIGNATURES_H
#define AUTOMATA_SIGNATURES_H
#include "automata/identify.h"

static const signature_t builtin_signatures[] = {
    {"SquashFS LE", (const unsigned char *)"hsqs", 4, 1.0},
    {"SquashFS BE", (const unsigned char *)"sqsh", 4, 1.0},
    {"SquashFS LZMA", (const unsigned char *)"\x71\x6c\x7a\x73", 4, 1.0},
    {"JFFS2 LE", (const unsigned char *)"\x85\x19", 2, 1.0},
    {"JFFS2 BE", (const unsigned char *)"\x19\x85", 2, 1.0},
    {"U-Boot", (const unsigned char *)"\x27\x05\x19\x56", 4, 1.0},
    {"gzip", (const unsigned char *)"\x1f\x8b", 2, 1.0},
    {"LZMA", (const unsigned char *)"\x5d\x00\x00", 3, 1.0},
    {"XZ", (const unsigned char *)"\xfd\x37\x7a\x58\x5a\x00", 6, 1.0},
    {"Bzip2", (const unsigned char *)"BZh", 3, 1.0},
    {"ELF", (const unsigned char *)"\x7f""ELF", 4, 1.0},
    {"CramFS", (const unsigned char *)"\x45\x3d\xcd\x28", 4, 1.0},
    {"UBIFS", (const unsigned char *)"\x31\x18\x10\x06", 4, 1.0},
    {"Android boot", (const unsigned char *)"ANDROID!", 8, 1.0},
    {"Certificate", (const unsigned char *)"-----BEGIN", 10, 1.0},
    {"DTB", (const unsigned char *)"\xd0\x0d\xfe\xed", 4, 1.0},
    {"cpio newc", (const unsigned char *)"070701", 6, 1.0},
    {"PE/MZ", (const unsigned char *)"MZ", 2, 1.0},
    {"Realtek", (const unsigned char *)"CSYS", 4, 1.0},
    {"YAFFS", (const unsigned char *)"\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff", 10, 1.0}
};

static const size_t num_builtin_signatures = sizeof(builtin_signatures) / sizeof(builtin_signatures[0]);

#endif
