/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_SBOM_H
#define AUTOMATA_SBOM_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char name[128];
    char version[64];
    char source[32];   /* "string", "elf", "config" */
    char location[256]; /* file inside an extracted tree where first seen; empty = raw image */
} component_t;

/* Scan firmware data for known component version strings.
 * Returns 0 on success. */
int sbom_scan(const uint8_t *data, size_t size, component_t *out, size_t max, size_t *out_count);

#endif /* AUTOMATA_SBOM_H */
