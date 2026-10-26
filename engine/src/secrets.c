/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/secrets.h"
#include <string.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>

const char *secret_type_string(secret_type_t type) {
    switch (type) {
        case PRIVATE_KEY: return "PRIVATE_KEY";
        case CERTIFICATE: return "CERTIFICATE";
        case PASSWORD: return "PASSWORD";
        case API_KEY: return "API_KEY";
        case SSH_KEY: return "SSH_KEY";
        case AWS_KEY: return "AWS_KEY";
        case GENERIC_TOKEN: return "GENERIC_TOKEN";
        case HARDCODED_CRED: return "HARDCODED_CRED";
        default: return "UNKNOWN";
    }
}

typedef struct {
    const char *pattern;
    size_t len;
    secret_type_t type;
    float confidence;
    const char *description;
    int case_insensitive;    /* 1 = use tolower comparison */
    int needs_alnum_check;   /* 1 = verify N alnum chars follow (for AKIA) */
    int alnum_count;         /* how many alnum chars to verify */
} secret_pattern_t;

static const secret_pattern_t patterns[] = {
    { "-----BEGIN RSA PRIVATE KEY-----", 31, PRIVATE_KEY, 1.0f, "RSA Private Key", 0, 0, 0 },
    { "-----BEGIN EC PRIVATE KEY-----", 30, PRIVATE_KEY, 1.0f, "EC Private Key", 0, 0, 0 },
    { "-----BEGIN PRIVATE KEY-----", 27, PRIVATE_KEY, 1.0f, "PEM Private Key", 0, 0, 0 },
    { "-----BEGIN DSA PRIVATE KEY-----", 31, PRIVATE_KEY, 1.0f, "DSA Private Key", 0, 0, 0 },
    { "-----BEGIN CERTIFICATE-----", 27, CERTIFICATE, 0.9f, "X.509 Certificate", 0, 0, 0 },
    { "-----BEGIN SSH", 14, SSH_KEY, 1.0f, "SSH Key", 0, 0, 0 },
    { "ssh-rsa AAAA", 12, SSH_KEY, 0.9f, "SSH RSA Public Key", 0, 0, 0 },
    { "ssh-ed25519 AAAA", 16, SSH_KEY, 0.9f, "SSH Ed25519 Public Key", 0, 0, 0 },
    { "AKIA", 4, AWS_KEY, 0.8f, "AWS Access Key", 0, 1, 16 },
    { "password=", 9, PASSWORD, 0.6f, "Hardcoded password", 1, 0, 0 },
    { "passwd=", 7, PASSWORD, 0.6f, "Hardcoded password", 1, 0, 0 },
    { "secret_key=", 11, GENERIC_TOKEN, 0.7f, "Secret key assignment", 0, 0, 0 },
    { "api_key=", 8, API_KEY, 0.7f, "API key assignment", 0, 0, 0 },
    { "token=", 6, GENERIC_TOKEN, 0.5f, "Token assignment", 0, 0, 0 },
    { "Authorization: Bearer ", 22, GENERIC_TOKEN, 0.7f, "Bearer token", 0, 0, 0 },
    { "root:$", 6, HARDCODED_CRED, 0.9f, "Root shadow entry", 0, 0, 0 },
    { "admin:", 6, HARDCODED_CRED, 0.5f, "Admin credential", 0, 0, 0 }
};

static const size_t num_patterns = sizeof(patterns) / sizeof(patterns[0]);

int secrets_scan(const uint8_t *data, size_t size, secret_finding_t *out_findings, size_t max_findings, size_t *out_count) {
    if (data == NULL || out_findings == NULL || out_count == NULL) return -1;
    size_t count = 0;

    for (size_t i = 0; i < size && count < max_findings; ) {
        int matched = 0;
        size_t match_len = 0;

        for (size_t p = 0; p < num_patterns; p++) {
            const secret_pattern_t *pat = &patterns[p];
            if (size - i >= pat->len) {
                int match = 1;
                if (pat->case_insensitive) {
                    for (size_t k = 0; k < pat->len; k++) {
                        if (tolower((unsigned char)data[i + k]) != tolower((unsigned char)pat->pattern[k])) {
                            match = 0;
                            break;
                        }
                    }
                } else {
                    if (memcmp(data + i, pat->pattern, pat->len) != 0) {
                        match = 0;
                    }
                }

                if (match) {
                    if (pat->needs_alnum_check) {
                        if (size - i - pat->len < (size_t)pat->alnum_count) {
                            continue;
                        }
                        int alnum_ok = 1;
                        for (int k = 0; k < pat->alnum_count; k++) {
                            if (!isalnum((unsigned char)data[i + pat->len + k])) {
                                alnum_ok = 0;
                                break;
                            }
                        }
                        if (!alnum_ok) {
                            continue;
                        }
                    }

                    out_findings[count].offset = i;
                    out_findings[count].type = pat->type;
                    out_findings[count].confidence = pat->confidence;
                    strncpy(out_findings[count].description, pat->description, sizeof(out_findings[count].description) - 1);
                    out_findings[count].description[sizeof(out_findings[count].description) - 1] = '\0';

                    size_t ctx_start = (i >= 32) ? (i - 32) : 0;
                    size_t ctx_end = (i + 32 <= size) ? (i + 32) : size;
                    size_t ctx_len = ctx_end - ctx_start;
                    if (ctx_len >= sizeof(out_findings[count].context)) {
                        ctx_len = sizeof(out_findings[count].context) - 1;
                    }
                    for (size_t c = 0; c < ctx_len; c++) {
                        uint8_t byte = data[ctx_start + c];
                        out_findings[count].context[c] = (byte < 0x20 || byte > 0x7e) ? '.' : (char)byte;
                    }
                    out_findings[count].context[ctx_len] = '\0';

                    count++;
                    matched = 1;
                    match_len = pat->len;
                    break;
                }
            }
        }

        if (matched) {
            i += match_len;
        } else {
            i++;
        }
    }

    *out_count = count;
    return 0;
}
