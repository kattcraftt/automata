/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/identify.h"
#include <string.h>

const signature_t builtin_signatures[] = {
    { (const uint8_t *)"\x7f""ELF", 4, "ELF Binary" },
    { (const uint8_t *)"PK\x03\x04", 4, "ZIP Archive" },
    { (const uint8_t *)"\x1f\x8b", 2, "GZIP Archive" },
    { (const uint8_t *)"\xfd""7zXZ\x00", 6, "XZ Archive" },
    { (const uint8_t *)"sqsh", 4, "SquashFS" },
    { (const uint8_t *)"hsqs", 4, "SquashFS (LE)" }
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
