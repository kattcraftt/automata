/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_IDENTIFY_H
#define AUTOMATA_IDENTIFY_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    const uint8_t *pattern;
    size_t pattern_len;
    const char *label;
} signature_t;

typedef struct {
    size_t offset;
    const char *label;
    float confidence;
} finding_t;

extern const signature_t builtin_signatures[];
extern const size_t num_builtin_signatures;

int identify_scan(const uint8_t *data, size_t size, finding_t *out_findings, size_t max_findings, size_t *out_count);

#endif /* AUTOMATA_IDENTIFY_H */
