/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_STRINGS_H
#define AUTOMATA_STRINGS_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    size_t offset;
    char value[256];
    size_t length;
} extracted_string_t;

int string_extract(const uint8_t *data, size_t size, size_t min_len, extracted_string_t *out_strings, size_t max_strings, size_t *out_count);

#endif /* AUTOMATA_STRINGS_H */
