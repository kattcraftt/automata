/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/identify.h"
#include "automata/elf.h"
#include "automata/squashfs.h"
#include "automata/util.h"
#include <string.h>
#include <zlib.h>

/* ── Header validators ──
 * A 2-byte magic matches by chance roughly once per 64 KB of compressed data,
 * so every short or collision-prone signature checks real header fields. */

static float v_elf(const uint8_t *p, size_t n) {
    return elf_header_valid(p, n) ? 1.0f : 0.0f;
}

static float v_gzip(const uint8_t *p, size_t n) {
    if (n < 10) return 0.0f;
    if (p[2] != 8) return 0.0f;                 /* CM must be deflate */
    if (p[3] & 0xE0) return 0.0f;               /* reserved FLG bits */
    if (p[8] != 0 && p[8] != 2 && p[8] != 4) return 0.0f;   /* XFL */
    if (p[9] > 13 && p[9] != 255) return 0.0f;  /* OS */
    return 0.9f;
}

static float v_xz(const uint8_t *p, size_t n) {
    if (n < 12) return 0.0f;
    if (p[6] != 0) return 0.0f;                 /* stream flags, byte 1 */
    if (p[7] != 0x00 && p[7] != 0x01 && p[7] != 0x04 && p[7] != 0x0A) return 0.0f; /* check type */
    return 1.0f;
}

static float v_squashfs(const uint8_t *p, size_t n) {
    if (squashfs_superblock_size(p, n, 0) != 0) return 1.0f;
    return 0.3f;    /* magic only: kernel strings, legacy v3 images, truncated dumps */
}

static float v_squashfs_lzma(const uint8_t *p, size_t n) {
    (void)p; (void)n;
    return 0.3f;    /* unvalidated vendor variant */
}

static float v_jffs2_common(const uint8_t *p, size_t n, int be) {
    if (n < 12) return 0.0f;
    uint16_t type = be ? read_u16_be(p, n, 2) : read_u16_le(p, n, 2);
    uint32_t totlen = be ? read_u32_be(p, n, 4) : read_u32_le(p, n, 4);
    uint32_t hdr_crc = be ? read_u32_be(p, n, 8) : read_u32_le(p, n, 8);
    switch (type) {
        case 0xE001: case 0xE002: case 0xE003: case 0xE008: case 0xE009:
        case 0x2004: case 0x2006:
            break;
        default:
            return 0.0f;
    }
    if (totlen < 12 || totlen > (1u << 22)) return 0.0f;
    /* JFFS2 uses a raw CRC32 (init 0, no final xor); zlib's crc32 inverts both ends. */
    uint32_t crc = ~(uint32_t)crc32(0xFFFFFFFFUL, p, 8);
    return (crc == hdr_crc) ? 1.0f : 0.4f;
}
static float v_jffs2_le(const uint8_t *p, size_t n) { return v_jffs2_common(p, n, 0); }
static float v_jffs2_be(const uint8_t *p, size_t n) { return v_jffs2_common(p, n, 1); }

static float v_uboot(const uint8_t *p, size_t n) {
    if (n < 64) return 0.4f;
    uint8_t hdr[64];
    memcpy(hdr, p, 64);
    uint32_t want = read_u32_be(p, n, 4);
    memset(hdr + 4, 0, 4);
    uint32_t got = (uint32_t)crc32(0L, hdr, 64);
    return (got == want) ? 1.0f : 0.4f;
}

static float v_lzma(const uint8_t *p, size_t n) {
    if (n < 14) return 0.0f;
    if (p[0] != 0x5d) return 0.0f;
    uint32_t dict = read_u32_le(p, n, 1);
    if (dict < 4096 || dict > (1u << 30)) return 0.0f;
    uint32_t low = dict & (dict - 1);
    /* dictionary sizes are 2^n or 2^n + 2^(n-1) */
    if (low != 0 && (low & (low - 1)) != 0) return 0.0f;
    uint64_t usize = read_u64_le(p, n, 5);
    if (usize != UINT64_MAX && usize > (1ULL << 31)) return 0.0f;
    if (p[13] != 0) return 0.0f;                /* range coder always starts with 0x00 */
    return 0.9f;
}

static float v_bzip2(const uint8_t *p, size_t n) {
    static const uint8_t blk[6] = { 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 };
    if (n < 10) return 0.0f;
    if (p[3] < '1' || p[3] > '9') return 0.0f;
    return memcmp(p + 4, blk, 6) == 0 ? 1.0f : 0.0f;
}

static float v_cramfs(const uint8_t *p, size_t n) {
    if (n < 32) return 0.0f;
    return memcmp(p + 16, "Compressed ROMFS", 16) == 0 ? 1.0f : 0.0f;
}

static float v_dtb(const uint8_t *p, size_t n) {
    if (n < 40) return 0.0f;
    uint32_t total = read_u32_be(p, n, 4);
    uint32_t off_struct = read_u32_be(p, n, 8);
    uint32_t off_strings = read_u32_be(p, n, 12);
    uint32_t version = read_u32_be(p, n, 20);
    uint32_t last_comp = read_u32_be(p, n, 24);
    if (total < 40 || total > n || total > (1u << 24)) return 0.0f;
    if (version < 1 || version > 17 || last_comp > version) return 0.0f;
    if (off_struct >= total || off_strings >= total) return 0.0f;
    return 1.0f;
}

static float v_cpio(const uint8_t *p, size_t n) {
    if (n < 110) return 0.0f;
    for (size_t i = 6; i < 110; i++) {
        uint8_t c = p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return 0.0f;
    }
    return 1.0f;
}

static float v_pe(const uint8_t *p, size_t n) {
    if (n < 0x40) return 0.0f;
    uint32_t off = read_u32_le(p, n, 0x3c);
    if (off < 0x40 || off > 0x1000 || (size_t)off + 4 > n) return 0.0f;
    return memcmp(p + off, "PE\0\0", 4) == 0 ? 1.0f : 0.0f;
}

const signature_t builtin_signatures[] = {
    { (const uint8_t *)"\x7f" "ELF",        4,  "ELF Binary",       SIG_ELF,           v_elf },
    { (const uint8_t *)"PK\x03\x04",        4,  "ZIP Archive",      SIG_ZIP,           NULL },
    { (const uint8_t *)"\x1f\x8b",          2,  "GZIP Archive",     SIG_GZIP,          v_gzip },
    { (const uint8_t *)"\xfd" "7zXZ\x00",   6,  "XZ Archive",       SIG_XZ,            v_xz },
    { (const uint8_t *)"sqsh",              4,  "SquashFS (BE)",    SIG_SQUASHFS_BE,   v_squashfs },
    { (const uint8_t *)"hsqs",              4,  "SquashFS (LE)",    SIG_SQUASHFS_LE,   v_squashfs },
    { (const uint8_t *)"\x71\x6c\x7a\x73",  4,  "SquashFS (LZMA)",  SIG_SQUASHFS_LZMA, v_squashfs_lzma },
    { (const uint8_t *)"\x85\x19",          2,  "JFFS2 (LE)",       SIG_JFFS2_LE,      v_jffs2_le },
    { (const uint8_t *)"\x19\x85",          2,  "JFFS2 (BE)",       SIG_JFFS2_BE,      v_jffs2_be },
    { (const uint8_t *)"\x27\x05\x19\x56",  4,  "U-Boot Image",     SIG_UBOOT,         v_uboot },
    { (const uint8_t *)"\x5d\x00\x00",      3,  "LZMA",             SIG_LZMA,          v_lzma },
    { (const uint8_t *)"BZh",               3,  "Bzip2",            SIG_BZIP2,         v_bzip2 },
    { (const uint8_t *)"\x45\x3d\xcd\x28",  4,  "CramFS",           SIG_CRAMFS,        v_cramfs },
    { (const uint8_t *)"\x31\x18\x10\x06",  4,  "UBIFS",            SIG_UBIFS,         NULL },
    { (const uint8_t *)"ANDROID!",          8,  "Android Boot",     SIG_ANDROID_BOOT,  NULL },
    { (const uint8_t *)"-----BEGIN",        10, "PEM Certificate",  SIG_PEM,           NULL },
    { (const uint8_t *)"\xd0\x0d\xfe\xed",  4,  "Device Tree Blob", SIG_DTB,           v_dtb },
    { (const uint8_t *)"070701",            6,  "cpio (newc)",      SIG_CPIO,          v_cpio },
    { (const uint8_t *)"MZ",                2,  "PE/COFF",          SIG_PE,            v_pe },
    { (const uint8_t *)"7z\xbc\xaf\x27\x1c",6,  "7-Zip",            SIG_7Z,            NULL },
    { (const uint8_t *)"\x28\xb5\x2f\xfd",  4,  "Zstandard",        SIG_ZSTD,          NULL },
    { (const uint8_t *)"\x04\x22\x4d\x18",  4,  "LZ4 Frame",        SIG_LZ4,           NULL }
};

const size_t num_builtin_signatures = sizeof(builtin_signatures) / sizeof(signature_t);

#define MAX_SIGS 32

static float default_confidence(size_t p_len) {
    if (p_len >= 4) return 1.0f;
    if (p_len == 3) return 0.7f;
    if (p_len == 2) return 0.5f;
    return 0.1f;
}

int identify_scan(const uint8_t *data, size_t size, finding_t *out_findings, size_t max_findings, size_t *out_count) {
    if (data == NULL || out_findings == NULL || out_count == NULL) return -1;
    if (num_builtin_signatures > MAX_SIGS) return -1;

    /* Bucket signatures by first byte so each position costs one table lookup. */
    uint8_t by_first[256][MAX_SIGS];
    uint8_t n_first[256];
    memset(n_first, 0, sizeof(n_first));
    for (size_t j = 0; j < num_builtin_signatures; j++) {
        uint8_t b = builtin_signatures[j].pattern[0];
        by_first[b][n_first[b]++] = (uint8_t)j;
    }

    size_t count = 0;
    for (size_t i = 0; i < size && count < max_findings; i++) {
        uint8_t b = data[i];
        for (uint8_t s = 0; s < n_first[b]; s++) {
            const signature_t *sig = &builtin_signatures[by_first[b][s]];
            size_t p_len = sig->pattern_len;
            if (i + p_len > size) continue;
            if (memcmp(data + i, sig->pattern, p_len) != 0) continue;

            float conf = sig->validate ? sig->validate(data + i, size - i)
                                       : default_confidence(p_len);
            if (conf <= 0.0f) continue;

            out_findings[count].offset = i;
            out_findings[count].label = sig->label;
            out_findings[count].confidence = conf;
            out_findings[count].type = sig->type;
            count++;
            if (count >= max_findings) break;
        }
    }
    *out_count = count;
    return 0;
}

int identify_header(const uint8_t *data, size_t size, finding_t *out) {
    if (data == NULL || out == NULL) return 0;
    float best = 0.0f;
    int found = 0;
    for (size_t j = 0; j < num_builtin_signatures; j++) {
        const signature_t *sig = &builtin_signatures[j];
        if (sig->pattern_len > size || memcmp(data, sig->pattern, sig->pattern_len) != 0) continue;
        float conf = sig->validate ? sig->validate(data, size) : default_confidence(sig->pattern_len);
        if (conf < IDENTIFY_MIN_CONFIDENCE || conf <= best) continue;
        best = conf;
        out->offset = 0;
        out->label = sig->label;
        out->confidence = conf;
        out->type = sig->type;
        found = 1;
    }
    return found;
}
