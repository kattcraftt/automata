/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/fwhdr.h"
#include "automata/util.h"
#include <stdio.h>
#include <string.h>
#include <zlib.h>

uint32_t fwhdr_netgear_checksum(const uint8_t *data, size_t size) {
    uint32_t c0 = 0, c1 = 0;
    for (size_t i = 0; i < size; i++) {
        c0 += data[i];
        c1 += c0;
    }
    while (c0 >> 16) c0 = (c0 & 0xffff) + (c0 >> 16);
    while (c1 >> 16) c1 = (c1 & 0xffff) + (c1 >> 16);
    return (c1 << 16) | c0;
}

static uint32_t be32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static uint32_t le32(const uint8_t *p) { return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | p[0]; }
static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static void add_part(fwhdr_t *h, const char *name, size_t off, size_t len) {
    if (h->num_parts >= FWHDR_MAX_PARTS) return;
    safe_strncpy(h->part_name[h->num_parts], name, sizeof(h->part_name[0]));
    h->part_offset[h->num_parts] = off;
    h->part_length[h->num_parts] = len;
    h->num_parts++;
}

static void add_check(fwhdr_t *h, const char *what, int ok) {
    size_t n = strlen(h->checks);
    snprintf(h->checks + n, sizeof(h->checks) - n, "%s%s %s", n ? ", " : "", what, ok ? "OK" : "MISMATCH");
    if (!ok) h->integrity = 0;
    else if (h->integrity < 0) h->integrity = 1;
}

/* ── Netgear CHK ── */
static int parse_chk(const uint8_t *d, size_t size, size_t off, fwhdr_t *h) {
    const uint8_t *p = d + off;
    size_t n = size - off;
    if (n < 0x30) return 0;
    uint32_t hl = be32(p + 4);
    if (hl < 0x2c || hl > 0x100 || hl > n) return 0;

    /* board id: printable text between 0x28 and the end of the header */
    char board[48] = "";
    size_t bl = 0;
    for (size_t i = 0x28; i < hl && bl < sizeof(board) - 1; i++) {
        if (p[i] == 0) break;
        if (p[i] < 0x20 || p[i] > 0x7e) return 0;
        board[bl++] = (char)p[i];
    }
    board[bl] = '\0';
    if (bl < 4) return 0;

    uint32_t kchk = be32(p + 0x10), rchk = be32(p + 0x14), klen = be32(p + 0x18), rlen = be32(p + 0x1c);
    uint32_t ichk = be32(p + 0x20), hchk = be32(p + 0x24);
    (void)kchk; (void)rchk;

    memset(h, 0, sizeof(*h));
    h->integrity = -1;
    h->offset = off;
    safe_strncpy(h->format, "NETGEAR CHK", sizeof(h->format));
    h->length = (size_t)klen + (size_t)rlen;

    /* bytes 8..15 carry the firmware version, e.g. 01 | 01 00 09 40 | 0a 02 40 = V1.0.9.64_10.2.64 */
    snprintf(h->summary, sizeof(h->summary), "board %s, version %u.%u.%u.%u_%u.%u.%u (decoded from header bytes), kernel %u bytes, rootfs %u bytes",
             board, p[9], p[10], p[11], p[12], p[13], p[14], p[15], klen, rlen);

    uint8_t hdr[0x100];
    memcpy(hdr, p, hl);
    memset(hdr + 0x24, 0, 4);
    add_check(h, "header checksum", fwhdr_netgear_checksum(hdr, hl) == hchk);

    if ((size_t)hl + h->length <= n && h->length > 0) {
        add_check(h, "image checksum", fwhdr_netgear_checksum(p + hl, h->length) == ichk);
    } else if (h->length > 0) {
        snprintf(h->checks + strlen(h->checks), sizeof(h->checks) - strlen(h->checks), "%simage truncated (%zu of %zu payload bytes present)",
                 h->checks[0] ? ", " : "", n - hl, h->length);
        h->integrity = 0;
    }
    if (rlen == 0) {
        if (klen) add_part(h, "payload", off + hl, klen);            /* single image (usually a TRX): kernel_len holds its whole length */
    } else {
        if (klen) add_part(h, "kernel", off + hl, klen);
        add_part(h, "rootfs", off + hl + klen, rlen);
    }
    return 1;
}

/* ── Broadcom TRX ── */
static int parse_trx(const uint8_t *d, size_t size, size_t off, fwhdr_t *h) {
    const uint8_t *p = d + off;
    size_t n = size - off;
    if (n < 28) return 0;
    uint32_t len = le32(p + 4), crc = le32(p + 8);
    uint16_t flags = le16(p + 12), ver = le16(p + 14);
    if (ver != 1 && ver != 2) return 0;
    size_t hsize = (ver == 1) ? 28 : 32;
    if (len < hsize || n < hsize) return 0;

    size_t nofs = (ver == 1) ? 3 : 4;
    uint32_t offs[4] = {0, 0, 0, 0};
    for (size_t i = 0; i < nofs; i++) {
        offs[i] = le32(p + 16 + 4 * i);
        if (offs[i] != 0 && (offs[i] < hsize || offs[i] >= len)) return 0;
    }
    if (offs[0] == 0 && offs[1] == 0) return 0;

    memset(h, 0, sizeof(*h));
    h->integrity = -1;
    h->offset = off;
    snprintf(h->format, sizeof(h->format), "TRX v%u", ver);
    h->length = len;
    snprintf(h->summary, sizeof(h->summary), "%u bytes, flags 0x%04x", len, flags);

    if (len <= n) {
        /* Broadcom's CRC32 is the raw CRC (init 0xFFFFFFFF, no final inversion) over everything after the crc field */
        uint32_t calc = ~(uint32_t)crc32(0L, p + 12, (uInt)(len - 12));
        add_check(h, "CRC32", calc == crc);
    } else {
        snprintf(h->checks, sizeof(h->checks), "image truncated (%zu of %u bytes present)", n, len);
        h->integrity = 0;
    }

    static const char *names[4] = { "kernel", "rootfs", "part3", "part4" };
    for (size_t i = 0; i < nofs; i++) {
        if (offs[i] == 0) continue;
        uint32_t end = len;
        for (size_t j = i + 1; j < nofs; j++) if (offs[j] > offs[i]) { end = offs[j]; break; }
        add_part(h, names[i], off + offs[i], end - offs[i]);
    }
    return 1;
}

/* ── U-Boot legacy uImage ── */
static const char *uimage_os(uint8_t v) {
    switch (v) { case 5: return "Linux"; case 17: return "U-Boot"; case 3: return "NetBSD"; case 2: return "OpenBSD"; case 14: return "VxWorks"; default: return "OS?"; }
}
static const char *uimage_arch(uint8_t v) {
    switch (v) { case 2: return "ARM"; case 3: return "x86"; case 5: return "MIPS"; case 6: return "MIPS64"; case 7: return "PowerPC"; case 9: return "SuperH";
                 case 22: return "AArch64"; case 24: return "RISC-V"; default: return "arch?"; }
}
static const char *uimage_type(uint8_t v) {
    switch (v) { case 2: return "kernel"; case 3: return "ramdisk"; case 4: return "multi-image"; case 5: return "firmware"; case 6: return "script";
                 case 8: return "filesystem"; case 14: return "flat device tree"; default: return "image"; }
}
static const char *uimage_comp(uint8_t v) {
    switch (v) { case 0: return "uncompressed"; case 1: return "gzip"; case 2: return "bzip2"; case 3: return "lzma"; case 4: return "lzo"; case 5: return "lz4"; case 6: return "zstd"; default: return "comp?"; }
}

static int parse_uimage(const uint8_t *d, size_t size, size_t off, fwhdr_t *h) {
    const uint8_t *p = d + off;
    size_t n = size - off;
    if (n < 64) return 0;
    uint32_t hcrc = be32(p + 4), dsize = be32(p + 12), load = be32(p + 16), entry = be32(p + 20), dcrc = be32(p + 24);

    uint8_t hdr[64];
    memcpy(hdr, p, 64);
    memset(hdr + 4, 0, 4);
    if ((uint32_t)crc32(0L, hdr, 64) != hcrc) return 0;     /* only report headers whose own CRC is valid */

    char name[33];
    memcpy(name, p + 32, 32);
    name[32] = '\0';
    for (int i = 0; i < 32 && name[i]; i++) if (name[i] < 0x20 || name[i] > 0x7e) name[i] = '?';

    memset(h, 0, sizeof(*h));
    h->integrity = -1;
    h->offset = off;
    safe_strncpy(h->format, "uImage", sizeof(h->format));
    h->length = dsize;
    snprintf(h->summary, sizeof(h->summary), "\"%s\", %s %s %s, %s, load 0x%08x, entry 0x%08x, %u bytes",
             name, uimage_arch(p[29]), uimage_os(p[28]), uimage_type(p[30]), uimage_comp(p[31]), load, entry, dsize);
    add_check(h, "header CRC", 1);
    if ((size_t)dsize + 64 <= n) {
        add_check(h, "data CRC", (uint32_t)crc32(0L, p + 64, (uInt)dsize) == dcrc);
    } else {
        snprintf(h->checks + strlen(h->checks), sizeof(h->checks) - strlen(h->checks), ", data truncated");
        h->integrity = 0;
    }
    add_part(h, uimage_type(p[30]), off + 64, dsize);
    return 1;
}

int fwhdr_analyze(const uint8_t *data, size_t size, fwhdr_t *out, size_t max, size_t *out_count) {
    if (!data || !out || !out_count) return -1;
    size_t count = 0;
    for (size_t i = 0; i + 4 <= size && count < max; i++) {
        uint8_t c = data[i];
        if (c != '*' && c != 'H' && c != 0x27) continue;
        fwhdr_t h;
        int ok = 0;
        if (c == '*' && memcmp(data + i, "*#$^", 4) == 0) ok = parse_chk(data, size, i, &h);
        else if (c == 'H' && memcmp(data + i, "HDR0", 4) == 0) ok = parse_trx(data, size, i, &h);
        else if (c == 0x27 && data[i + 1] == 0x05 && data[i + 2] == 0x19 && data[i + 3] == 0x56) ok = parse_uimage(data, size, i, &h);
        if (ok) out[count++] = h;
    }
    *out_count = count;
    return 0;
}
