/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/strings.h"
#include <ctype.h>

int string_extract(const uint8_t *data, size_t size, size_t min_len, extracted_string_t *out_strings, size_t max_strings, size_t *out_count) {
    if (data == NULL || out_strings == NULL || out_count == NULL) return -1;
    size_t count = 0;
    size_t i = 0;
    while (i < size && count < max_strings) {
        if (isprint(data[i])) {
            size_t start = i;
            while (i < size && isprint(data[i])) {
                i++;
            }
            size_t len = i - start;
            if (len >= min_len) {
                out_strings[count].offset = start;
                out_strings[count].length = len;
                size_t copy_len = len < 255 ? len : 255;
                for (size_t j = 0; j < copy_len; j++) {
                    out_strings[count].value[j] = (char)data[start + j];
                }
                out_strings[count].value[copy_len] = '\0';
                count++;
            }
        } else {
            i++;
        }
    }
    *out_count = count;
    return 0;
}
