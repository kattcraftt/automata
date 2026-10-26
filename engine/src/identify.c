/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/identify.h"
#include <string.h>

const signature_t builtin_signatures[] = {
    { (const uint8_t *)"\x7f" "ELF", 4, "ELF Binary" },
    { (const uint8_t *)"PK\x03\x04", 4, "ZIP Archive" },
    { (const uint8_t *)"\x1f\x8b", 2, "GZIP Archive" },
    { (const uint8_t *)"\xfd" "7zXZ\x00", 6, "XZ Archive" },
    { (const uint8_t *)"sqsh", 4, "SquashFS (BE)" },
    { (const uint8_t *)"hsqs", 4, "SquashFS (LE)" },
    { (const uint8_t *)"\x71\x6c\x7a\x73", 4, "SquashFS (LZMA)" },
    { (const uint8_t *)"\x85\x19", 2, "JFFS2 (LE)" },
    { (const uint8_t *)"\x19\x85", 2, "JFFS2 (BE)" },
    { (const uint8_t *)"\x27\x05\x19\x56", 4, "U-Boot Image" },
    { (const uint8_t *)"\x5d\x00\x00", 3, "LZMA" },
    { (const uint8_t *)"BZh", 3, "Bzip2" },
    { (const uint8_t *)"\x45\x3d\xcd\x28", 4, "CramFS" },
    { (const uint8_t *)"\x31\x18\x10\x06", 4, "UBIFS" },
    { (const uint8_t *)"ANDROID!", 8, "Android Boot" },
    { (const uint8_t *)"-----BEGIN", 10, "PEM Certificate" },
    { (const uint8_t *)"\xd0\x0d\xfe\xed", 4, "Device Tree Blob" },
    { (const uint8_t *)"070701", 6, "cpio (newc)" },
    { (const uint8_t *)"MZ", 2, "PE/COFF" },
    { (const uint8_t *)"7z\xbc\xaf\x27\x1c", 6, "7-Zip" },
    { (const uint8_t *)"\x28\xb5\x2f\xfd", 4, "Zstandard" },
    { (const uint8_t *)"\x04\x22\x4d\x18", 4, "LZ4 Frame" }
};

const size_t num_builtin_signatures = sizeof(builtin_signatures) / sizeof(signature_t);

int identify_scan(const uint8_t *data, size_t size, finding_t *out_findings, size_t max_findings, size_t *out_count) {
    if (data == NULL || out_findings == NULL || out_count == NULL) return -1;
    size_t count = 0;
    for (size_t i = 0; i < size && count < max_findings; i++) {
        for (size_t j = 0; j < num_builtin_signatures; j++) {
            size_t p_len = builtin_signatures[j].pattern_len;
            if (i + p_len <= size) {
                int match = 1;
                for (size_t k = 0; k < p_len; k++) {
                    if (data[i + k] != builtin_signatures[j].pattern[k]) {
                        match = 0;
                        break;
                    }
                }
                if (match) {
                    out_findings[count].offset = i;
                    out_findings[count].label = builtin_signatures[j].label;
                    if (p_len >= 4) out_findings[count].confidence = 1.0f;
                    else if (p_len == 3) out_findings[count].confidence = 0.7f;
                    else if (p_len == 2) out_findings[count].confidence = 0.5f;
                    else out_findings[count].confidence = 0.1f;
                    count++;
                    if (count >= max_findings) break;
                }
            }
        }
    }
    *out_count = count;
    return 0;
}
