/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "automata/secrets.h"

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

int secrets_scan(const uint8_t *data, size_t size, secret_finding_t *out_findings, size_t max_findings, size_t *out_count) {
    size_t count = 0;
    
    for (size_t i = 0; i + 32 < size && count < max_findings; i++) {
        if (memcmp(data + i, "-----BEGIN PRIVATE KEY-----", 27) == 0) {
            out_findings[count].offset = i;
            out_findings[count].type = PRIVATE_KEY;
            out_findings[count].confidence = 1.0f;
            strncpy(out_findings[count].description, "PEM Private Key found", sizeof(out_findings[count].description) - 1);
            strncpy(out_findings[count].context, "-----BEGIN PRIVATE KEY-----", sizeof(out_findings[count].context) - 1);
            count++;
            i += 27;
        } else if (memcmp(data + i, "password=", 9) == 0) {
            out_findings[count].offset = i;
            out_findings[count].type = PASSWORD;
            out_findings[count].confidence = 0.8f;
            strncpy(out_findings[count].description, "Hardcoded password assignment", sizeof(out_findings[count].description) - 1);
            strncpy(out_findings[count].context, "password=", sizeof(out_findings[count].context) - 1);
            count++;
            i += 9;
        }
    }
    
    if (out_count) *out_count = count;
    return 0;
}
