/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_FWHDR_H
#define AUTOMATA_FWHDR_H

#include <stdint.h>
#include <stddef.h>

#define FWHDR_MAX_PARTS 4

/* A vendor/container image header found in a firmware file, with integrity verification where the
 * format defines a checksum. Supported: Netgear CHK ("*#$^"), Broadcom TRX ("HDR0" v1/v2), U-Boot uImage. */
typedef struct {
    size_t offset;
    char format[24];            /* "NETGEAR CHK", "TRX v1", "uImage" */
    char summary[200];          /* human-readable header fields */
    size_t length;              /* payload bytes covered by the header, 0 = unknown */
    int integrity;              /* -1 not checked, 0 mismatch, 1 all checks passed */
    char checks[160];           /* e.g. "image checksum OK, header checksum OK" */
    size_t num_parts;
    char part_name[FWHDR_MAX_PARTS][12];
    size_t part_offset[FWHDR_MAX_PARTS];   /* absolute offsets in the file */
    size_t part_length[FWHDR_MAX_PARTS];
} fwhdr_t;

/* Netgear's image checksum: Fletcher-style sums c0 (bytes) and c1 (running c0), each folded to 16 bits,
 * returned as (c1 << 16) | c0. Verified against a real R7000 image. */
uint32_t fwhdr_netgear_checksum(const uint8_t *data, size_t size);

int fwhdr_analyze(const uint8_t *data, size_t size, fwhdr_t *out, size_t max, size_t *out_count);

#endif /* AUTOMATA_FWHDR_H */
