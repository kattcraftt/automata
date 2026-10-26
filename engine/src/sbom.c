/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/sbom.h"
#include "automata/util.h"
#include <string.h>
#include <stdlib.h>

typedef struct {
    const char *prefix;     /* string to search for */
    size_t prefix_len;
    const char *comp_name;  /* normalized component name */
    int version_follows;    /* 1 = version comes right after prefix */
} comp_pattern_t;

static const comp_pattern_t patterns[] = {
    { "OpenSSL ",        8,  "openssl",      1 },
    { "BusyBox v",       9,  "busybox",      1 },
    { "dropbear_",       9,  "dropbear",     1 },
    { "Dropbear v",      10, "dropbear",     1 },
    { "lighttpd/",       9,  "lighttpd",     1 },
    { "Linux version ",  14, "linux-kernel", 1 },
    { "dnsmasq-",        8,  "dnsmasq",      1 },
    { "iptables v",      10, "iptables",     1 },
    { "uClibc ",         7,  "uclibc",       1 },
    { "musl libc ",      10, "musl",         1 },
    { "mini_httpd/",     11, "mini_httpd",   1 },
    { "sshd: ",          6,  "openssh",      1 },
    { "OpenSSH_",        8,  "openssh",      1 },
    { "curl ",           5,  "curl",         1 },
    { "nginx/",          6,  "nginx",        1 }
};

static const size_t num_patterns = sizeof(patterns) / sizeof(patterns[0]);

static int is_version_char(char c) {
    if ((c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' ||
        (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
        return 1;
    }
    return 0;
}

int sbom_scan(const uint8_t *data, size_t size, component_t *out, size_t max, size_t *out_count) {
    if (data == NULL || out_count == NULL) {
        return -1;
    }
    if (out == NULL && max > 0) {
        return -1;
    }

    *out_count = 0;
    if (size == 0) {
        return 0;
    }

    size_t count = 0;

    for (size_t i = 0; i < size; i++) {
        for (size_t p = 0; p < num_patterns; p++) {
            const comp_pattern_t *pat = &patterns[p];
            if (data[i] != (uint8_t)pat->prefix[0]) {
                continue;
            }
            if (size - i < pat->prefix_len) {
                continue;
            }
            if (memcmp(data + i, pat->prefix, pat->prefix_len) != 0) {
                continue;
            }

            size_t vstart = i + pat->prefix_len;
            while (vstart < size && data[vstart] == ' ') {
                vstart++;
            }

            if (vstart < size && (data[vstart] == 'v' || data[vstart] == 'V')) {
                if (vstart + 1 < size && data[vstart + 1] >= '0' && data[vstart + 1] <= '9') {
                    vstart++;
                }
            }

            /* Version must start with a digit */
            if (vstart >= size || data[vstart] < '0' || data[vstart] > '9') {
                continue;
            }

            char version[64];
            size_t vlen = 0;
            while (vlen < sizeof(version) - 1 && vstart + vlen < size) {
                char c = (char)data[vstart + vlen];
                if (!is_version_char(c)) {
                    break;
                }
                version[vlen++] = c;
            }
            version[vlen] = '\0';

            /* Trim trailing punctuation */
            while (vlen > 0 && (version[vlen - 1] == '.' || version[vlen - 1] == '-' || version[vlen - 1] == '_')) {
                version[--vlen] = '\0';
            }

            if (vlen == 0) {
                continue;
            }

            /* Check deduplication */
            int duplicate = 0;
            for (size_t k = 0; k < count; k++) {
                if (k < max) {
                    if (strcmp(out[k].name, pat->comp_name) == 0 &&
                        strcmp(out[k].version, version) == 0) {
                        duplicate = 1;
                        break;
                    }
                }
            }

            if (!duplicate) {
                if (count < max && out != NULL) {
                    safe_strncpy(out[count].name, pat->comp_name, sizeof(out[count].name));
                    safe_strncpy(out[count].version, version, sizeof(out[count].version));
                    safe_strncpy(out[count].source, "string", sizeof(out[count].source));
                }
                count++;
            }

            /* Advance index past this pattern and version */
            if (pat->prefix_len + vlen > 1) {
                i += (pat->prefix_len + vlen - 1);
            }
            break;
        }
    }

    *out_count = count;
    return 0;
}
