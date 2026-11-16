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
    { "nginx/",          6,  "nginx",        1 },
    { "mbed TLS ",       9,  "mbedtls",      1 },
    { "MiniUPnPd/",      10, "miniupnpd",    1 },
    { "miniupnpd/",      10, "miniupnpd",    1 }
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

    uint8_t is_first[256];
    memset(is_first, 0, sizeof(is_first));
    for (size_t p = 0; p < num_patterns; p++) is_first[(uint8_t)patterns[p].prefix[0]] = 1;

    for (size_t i = 0; i < size; i++) {
        if (!is_first[data[i]]) continue;
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

    *out_count = (count > max) ? max : count;   /* never report more than was stored */
    return 0;
}


/* ── OpenWrt/opkg package database ──
 * /usr/lib/opkg/status lists every installed package with its exact version, which is a
 * far better SBOM source than guessing from strings in binaries. */
typedef struct { const char *opkg_name; const char *canonical; } opkg_alias_t;

static const opkg_alias_t opkg_aliases[] = {
    { "kernel",        "linux-kernel" },
    { "libopenssl",    "openssl" },
    { "libcurl",       "curl" },
    { "libmbedtls",    "mbedtls" },
    { "libnettle",     "nettle" },
    { "libjson-c",     "json-c" },
    { "libuci",        "uci" },
    { "libubox",       "libubox" },
    { "dnsmasq-full",  "dnsmasq" },
    { "dnsmasq-dhcpv6","dnsmasq" },
    { "wpad-mini",     "wpad" },
    { "wpad-basic",    "wpad" }
};

static void opkg_clean_version(const char *in, char *out, size_t out_sz) {
    /* "2.1-1" -> "2.1", "4.9.152-1-abc123" -> "4.9.152": the part after the first '-' is the package release */
    size_t n = 0;
    while (in[n] && in[n] != '-' && in[n] != ' ' && n < out_sz - 1) { out[n] = in[n]; n++; }
    out[n] = '\0';
}

int sbom_parse_opkg_status(const uint8_t *data, size_t size, component_t *out, size_t max, size_t *out_count) {
    if (data == NULL || out == NULL || out_count == NULL) return -1;
    size_t count = 0;
    char name[128] = "";

    size_t i = 0;
    while (i < size) {
        size_t ls = i;
        while (i < size && data[i] != '\n') i++;
        size_t len = i - ls;
        if (i < size) i++;                      /* skip newline */

        if (len > 9 && memcmp(data + ls, "Package: ", 9) == 0) {
            size_t n = len - 9;
            if (n >= sizeof(name)) n = sizeof(name) - 1;
            memcpy(name, data + ls + 9, n);
            name[n] = '\0';
            while (n > 0 && (name[n - 1] == '\r' || name[n - 1] == ' ')) name[--n] = '\0';
        } else if (len > 9 && memcmp(data + ls, "Version: ", 9) == 0 && name[0]) {
            char raw[128];
            size_t n = len - 9;
            if (n >= sizeof(raw)) n = sizeof(raw) - 1;
            memcpy(raw, data + ls + 9, n);
            raw[n] = '\0';
            while (n > 0 && (raw[n - 1] == '\r' || raw[n - 1] == ' ')) raw[--n] = '\0';

            char ver[64];
            opkg_clean_version(raw, ver, sizeof(ver));

            const char *canon = name;
            for (size_t a = 0; a < sizeof(opkg_aliases) / sizeof(opkg_aliases[0]); a++) {
                if (strcmp(name, opkg_aliases[a].opkg_name) == 0) { canon = opkg_aliases[a].canonical; break; }
            }

            if (ver[0] && count < max) {
                safe_strncpy(out[count].name, canon, sizeof(out[count].name));
                safe_strncpy(out[count].version, ver, sizeof(out[count].version));
                safe_strncpy(out[count].source, "opkg", sizeof(out[count].source));
                out[count].location[0] = '\0';
                count++;
            }
            name[0] = '\0';
        }
    }
    *out_count = count;
    return 0;
}
