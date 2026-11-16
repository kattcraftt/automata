/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_SECRETS_H
#define AUTOMATA_SECRETS_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    PRIVATE_KEY,
    CERTIFICATE,
    PASSWORD,
    API_KEY,
    SSH_KEY,
    AWS_KEY,
    GENERIC_TOKEN,
    HARDCODED_CRED
} secret_type_t;

typedef struct {
    size_t offset;
    secret_type_t type;
    char description[128];
    char context[256];
    float confidence;
    char source[256];   /* file inside an extracted tree; empty = raw image */
} secret_finding_t;

/* Flags for secrets_scan_ex */
#define SECRETS_F_BINARY      0x1   /* input is a compiled binary: skip keyword patterns (variable names, format strings) */
#define SECRETS_F_AUTODETECT  0x2   /* treat input as binary if it has a NUL in its first 4 KB */
#define SECRETS_F_WEBUI       0x4   /* web UI page/script or UI string table: variable names and labels, skip keyword patterns */

int secrets_scan_ex(const uint8_t *data, size_t size, secret_finding_t *out_findings, size_t max_findings, size_t *out_count, unsigned flags);

int secrets_scan(const uint8_t *data, size_t size, secret_finding_t *out_findings, size_t max_findings, size_t *out_count);
const char *secret_type_string(secret_type_t type);

#endif /* AUTOMATA_SECRETS_H */
