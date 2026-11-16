/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#define _GNU_SOURCE
#include "automata/automata.h"
#include "automata/sbom.h"
#include "automata/cve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <zlib.h>
#include "test_fixtures.h"
#ifdef HAVE_BZIP2
#include <bzlib.h>
#endif
#ifdef HAVE_ZSTD
#include <zstd.h>
#endif
#ifdef HAVE_LZ4
#include <lz4frame.h>
#endif
#include <unistd.h>
#include <ftw.h>
#include <sys/stat.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(fn) do { \
    tests_run++; \
    if (fn() == 0) { tests_passed++; } \
} while(0)

/* ── Entropy tests ── */
static int test_entropy_zeros(void) {
    uint8_t zeros[256] = {0};
    double e = entropy_calculate(zeros, 256);
    if (e != 0.0) {
        printf("FAIL: test_entropy_zeros (got %.4f, expected 0.0)\n", e);
        return 1;
    }
    printf("PASS: test_entropy_zeros\n");
    return 0;
}

static int test_entropy_uniform(void) {
    uint8_t all[256];
    for (int i = 0; i < 256; i++) all[i] = (uint8_t)i;
    double e = entropy_calculate(all, 256);
    if (e < 7.99) {
        printf("FAIL: test_entropy_uniform (got %.4f, expected ~8.0)\n", e);
        return 1;
    }
    printf("PASS: test_entropy_uniform\n");
    return 0;
}

static int test_entropy_histogram(void) {
    uint8_t data[] = {0, 0, 0, 1, 1, 2};
    size_t counts[256] = {0};
    entropy_byte_histogram(data, sizeof(data), counts);
    if (counts[0] != 3 || counts[1] != 2 || counts[2] != 1) {
        printf("FAIL: test_entropy_histogram\n");
        return 1;
    }
    printf("PASS: test_entropy_histogram\n");
    return 0;
}

/* ── String extraction tests ── */
static int test_string_extract(void) {
    uint8_t buf[] = "test1234\x00\x01hello_world\x02\x03" "ab";
    extracted_string_t strings[16];
    size_t count = 0;
    string_extract(buf, sizeof(buf) - 1, 4, strings, 16, &count);
    /* "test1234" (8 chars) and "hello_world" (11 chars) should match, "ab" (2 chars) too short */
    if (count < 2) {
        printf("FAIL: test_string_extract (found %zu, expected >= 2)\n", count);
        return 1;
    }
    printf("PASS: test_string_extract\n");
    return 0;
}

/* Build a minimal but valid 32-bit little-endian ARM ELF header. */
static void make_elf_header(uint8_t *p) {
    memset(p, 0, 64);
    p[0] = 0x7f; p[1] = 'E'; p[2] = 'L'; p[3] = 'F';
    p[4] = 1; p[5] = 1; p[6] = 1;       /* 32-bit, little endian, version 1 */
    p[16] = 2;                          /* ET_EXEC */
    p[18] = 40;                         /* EM_ARM */
    p[20] = 1;                          /* e_version */
    p[42] = 32;                         /* e_phentsize */
}

/* ── Identify (signature scan) tests ── */
static int test_identify_scan(void) {
    uint8_t buf[256] = {0};
    /* Valid gzip header at offset 10 (method 8, XFL 0, OS unix) */
    buf[10] = 0x1f; buf[11] = 0x8b; buf[12] = 0x08; buf[19] = 0x03;
    /* Valid ELF header at offset 30 */
    make_elf_header(buf + 30);
    /* U-Boot magic \x27\x05\x19\x56 at offset 100 */
    buf[100] = 0x27; buf[101] = 0x05; buf[102] = 0x19; buf[103] = 0x56;

    finding_t findings[32];
    size_t num_findings = 0;
    identify_scan(buf, sizeof(buf), findings, 32, &num_findings);

    int found_gzip = 0, found_elf = 0, found_uboot = 0;
    for (size_t i = 0; i < num_findings; i++) {
        if (findings[i].offset == 10 && findings[i].type == SIG_GZIP) found_gzip = 1;
        if (findings[i].offset == 30 && findings[i].type == SIG_ELF) found_elf = 1;
        if (findings[i].offset == 100 && findings[i].type == SIG_UBOOT) found_uboot = 1;
    }
    if (!found_gzip || !found_elf || !found_uboot) {
        printf("FAIL: test_identify_scan (gzip=%d elf=%d uboot=%d, %zu findings)\n",
               found_gzip, found_elf, found_uboot, num_findings);
        for (size_t i = 0; i < num_findings; i++)
            printf("  [%zu] offset=%zu label='%s' conf=%.2f\n", i, findings[i].offset, findings[i].label, findings[i].confidence);
        return 1;
    }
    printf("PASS: test_identify_scan\n");
    return 0;
}

/* Bare 2-3 byte magics in noise must not be reported: this is what produced
 * ~700 junk findings on a 33 MB firmware image. */
static int test_identify_rejects_noise(void) {
    uint8_t buf[512];
    memset(buf, 0xAA, sizeof(buf));
    buf[10] = 0x1f; buf[11] = 0x8b;                     /* gzip magic, bad header */
    buf[40] = 'M';  buf[41] = 'Z';                      /* MZ, no PE header */
    buf[80] = 0x85; buf[81] = 0x19;                     /* JFFS2 magic, bad node */
    buf[120] = 0x7f; buf[121] = 'E'; buf[122] = 'L'; buf[123] = 'F'; /* ELF magic only */
    buf[200] = 0x5d;                                    /* LZMA-ish props, bad header */

    finding_t findings[32];
    size_t n = 0;
    identify_scan(buf, sizeof(buf), findings, 32, &n);
    if (n != 0) {
        printf("FAIL: test_identify_rejects_noise (%zu bogus findings)\n", n);
        for (size_t i = 0; i < n; i++)
            printf("  offset=%zu label='%s' conf=%.2f\n", findings[i].offset, findings[i].label, findings[i].confidence);
        return 1;
    }
    printf("PASS: test_identify_rejects_noise\n");
    return 0;
}

static int test_identify_jffs2_crc(void) {
    uint8_t buf[64];
    memset(buf, 0xFF, sizeof(buf));
    uint8_t *n = buf + 8;
    n[0] = 0x85; n[1] = 0x19;                           /* magic (LE) */
    n[2] = 0x01; n[3] = 0xE0;                           /* nodetype 0xE001 dirent */
    n[4] = 0x0c; n[5] = 0; n[6] = 0; n[7] = 0;          /* totlen 12 */
    uint32_t crc = ~(uint32_t)crc32(0xFFFFFFFFUL, n, 8);
    n[8] = crc & 0xff; n[9] = (crc >> 8) & 0xff; n[10] = (crc >> 16) & 0xff; n[11] = (crc >> 24) & 0xff;

    finding_t f[8];
    size_t cnt = 0;
    identify_scan(buf, sizeof(buf), f, 8, &cnt);
    for (size_t i = 0; i < cnt; i++) {
        if (f[i].offset == 8 && f[i].type == SIG_JFFS2_LE && f[i].confidence >= 0.99f) {
            printf("PASS: test_identify_jffs2_crc\n");
            return 0;
        }
    }
    printf("FAIL: test_identify_jffs2_crc (%zu findings)\n", cnt);
    return 1;
}

static void make_squashfs_sb(uint8_t *p, uint64_t used) {
    memset(p, 0, 96);
    memcpy(p, "hsqs", 4);
    p[12] = 0x00; p[13] = 0x00; p[14] = 0x02; p[15] = 0x00;   /* block_size 131072 */
    p[20] = 4;                                                /* xz */
    p[22] = 17;                                               /* block_log */
    p[28] = 4;                                                /* major */
    for (int i = 0; i < 8; i++) p[40 + i] = (uint8_t)(used >> (8 * i));
}

static int test_squashfs_validation(void) {
    uint8_t buf[256] = {0};
    make_squashfs_sb(buf + 16, 200);
    size_t used = squashfs_superblock_size(buf, sizeof(buf), 16);
    if (used != 200) {
        printf("FAIL: test_squashfs_validation (valid superblock gave %zu)\n", used);
        return 1;
    }
    /* A bare magic string (e.g. in kernel code) must be rejected */
    uint8_t junk[256] = {0};
    memcpy(junk + 16, "hsqs", 4);
    if (squashfs_superblock_size(junk, sizeof(junk), 16) != 0) {
        printf("FAIL: test_squashfs_validation (bare magic accepted)\n");
        return 1;
    }
    /* bytes_used larger than the buffer must be rejected */
    make_squashfs_sb(buf + 16, 100000);
    if (squashfs_superblock_size(buf, sizeof(buf), 16) != 0) {
        printf("FAIL: test_squashfs_validation (oversized bytes_used accepted)\n");
        return 1;
    }
    printf("PASS: test_squashfs_validation\n");
    return 0;
}

static int test_elf_validation(void) {
    elf_info_t info;
    uint8_t fake[128];
    memset(fake, 0xAA, sizeof(fake));
    memcpy(fake, "\x7f" "ELF", 4);
    if (elf_parse_buf(fake, sizeof(fake), &info) == 0) {
        printf("FAIL: test_elf_validation (bare magic accepted)\n");
        return 1;
    }
    uint8_t good[128];
    memset(good, 0, sizeof(good));
    make_elf_header(good);
    if (elf_parse_buf(good, sizeof(good), &info) != 0 || info.e_machine != 40 ||
        strcmp(elf_arch_string(info.e_machine), "ARM") != 0) {
        printf("FAIL: test_elf_validation (valid ARM header rejected or misreported)\n");
        return 1;
    }
    printf("PASS: test_elf_validation\n");
    return 0;
}

static int test_extract_gzip_roundtrip(void) {
    const char *msg = "root:$1$abc$hash:0:0:root:/root:/bin/ash\nhello firmware\n";
    uint8_t gz[512];
    z_stream z;
    memset(&z, 0, sizeof(z));
    if (deflateInit2(&z, 9, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        printf("FAIL: test_extract_gzip_roundtrip (deflateInit2)\n");
        return 1;
    }
    z.next_in = (Bytef *)msg;
    z.avail_in = (uInt)strlen(msg);
    z.next_out = gz;
    z.avail_out = sizeof(gz);
    deflate(&z, Z_FINISH);
    size_t gz_len = sizeof(gz) - z.avail_out;
    deflateEnd(&z);

    uint8_t image[2048];
    memset(image, 0xAA, sizeof(image));
    memcpy(image + 300, gz, gz_len);

    char dir[] = "/tmp/automata_test_XXXXXX";
    if (mkdtemp(dir) == NULL) {
        printf("FAIL: test_extract_gzip_roundtrip (mkdtemp)\n");
        return 1;
    }
    extract_result_t res[8];
    size_t n = 0;
    extract_all(image, sizeof(image), dir, res, 8, &n);

    int ok = (n == 1 && res[0].offset == 300 && strcmp(res[0].type, "gzip") == 0 &&
              res[0].decompressed == strlen(msg));
    for (size_t i = 0; i < n; i++) unlink(res[i].path);
    rmdir(dir);
    if (!ok) {
        printf("FAIL: test_extract_gzip_roundtrip (n=%zu)\n", n);
        return 1;
    }
    printf("PASS: test_extract_gzip_roundtrip\n");
    return 0;
}

/* ── Secrets scan tests ── */
static int test_secrets_scan(void) {
    uint8_t buf[512] = {0};
    const char *key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n-----END RSA PRIVATE KEY-----\n";
    uint8_t buf2[512] = {0};
    memcpy(buf2 + 50, key, strlen(key));
    memcpy(buf, buf2, sizeof(buf) < sizeof(buf2) ? sizeof(buf) : sizeof(buf2));

    secret_finding_t findings[16];
    size_t num_findings = 0;
    secrets_scan(buf, sizeof(buf), findings, 16, &num_findings);

    if (num_findings < 1) {
        printf("FAIL: test_secrets_scan (found %zu, expected >= 1)\n", num_findings);
        return 1;
    }
    if (findings[0].offset != 50 || findings[0].type != PRIVATE_KEY) {
        printf("FAIL: test_secrets_scan (wrong offset or type)\n");
        return 1;
    }
    printf("PASS: test_secrets_scan\n");
    return 0;
}

/* ── Hash FNV-1a tests ── */
static int test_hash_fnv1a(void) {
    /* Known FNV-1a test vector: empty string */
    uint64_t h = hash_fnv1a((const uint8_t *)"", 0);
    /* FNV-1a 32-bit offset basis = 2166136261, 64-bit = 14695981039346656037 */
    if (h != 2166136261ULL && h != 14695981039346656037ULL) {
        printf("FAIL: test_hash_fnv1a (empty string hash = %llu)\n", (unsigned long long)h);
        return 1;
    }
    /* Non-empty: "a" */
    h = hash_fnv1a((const uint8_t *)"a", 1);
    if (h == 0) {
        printf("FAIL: test_hash_fnv1a (hash of 'a' should not be 0)\n");
        return 1;
    }
    printf("PASS: test_hash_fnv1a\n");
    return 0;
}

/* ── Bounds-checked reader tests ── */
static int test_bounds_readers(void) {
    uint8_t buf[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    /* Normal reads — signature is (data, size, offset) */
    uint16_t v16le = read_u16_le(buf, sizeof(buf), 0);
    if (v16le != 0x0201) {
        printf("FAIL: test_bounds_readers (u16_le got 0x%04x, expected 0x0201)\n", v16le);
        return 1;
    }
    uint16_t v16be = read_u16_be(buf, sizeof(buf), 0);
    if (v16be != 0x0102) {
        printf("FAIL: test_bounds_readers (u16_be got 0x%04x, expected 0x0102)\n", v16be);
        return 1;
    }

    /* OOB reads should return 0 */
    uint32_t oob = read_u32_le(buf, sizeof(buf), 7);
    if (oob != 0) {
        printf("FAIL: test_bounds_readers (OOB read should return 0)\n");
        return 1;
    }

    printf("PASS: test_bounds_readers\n");
    return 0;
}

/* ── SHA-256 test ── */
static int test_sha256(void) {
    /* SHA-256 of empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    uint8_t hash[32];
    sha256_hash((const uint8_t *)"", 0, hash);
    if (hash[0] != 0xe3 || hash[1] != 0xb0 || hash[2] != 0xc4) {
        printf("FAIL: test_sha256 (empty string hash mismatch)\n");
        return 1;
    }
    printf("PASS: test_sha256\n");
    return 0;
}

/* ── SBOM scan test ── */
static int test_sbom_scan(void) {
    uint8_t buf[128] = {0};
    const char *text = "Some prefix data BusyBox v1.30.1 multi-call binary";
    memcpy(buf, text, strlen(text));

    component_t components[16];
    size_t count = 0;
    int rc = sbom_scan(buf, strlen(text), components, 16, &count);
    if (rc != 0 || count == 0) {
        printf("FAIL: test_sbom_scan (rc=%d, count=%zu)\n", rc, count);
        return 1;
    }

    int found_busybox = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcasecmp(components[i].name, "busybox") == 0 &&
            strcmp(components[i].version, "1.30.1") == 0) {
            found_busybox = 1;
            break;
        }
    }

    if (!found_busybox) {
        printf("FAIL: test_sbom_scan (busybox v1.30.1 not found among %zu components)\n", count);
        for (size_t i = 0; i < count; i++) {
            printf("  [%zu] %s %s\n", i, components[i].name, components[i].version);
        }
        return 1;
    }

    printf("PASS: test_sbom_scan\n");
    return 0;
}

/* ── CVE correlation test ── */
static int test_cve_check(void) {
    component_t comp;
    memset(&comp, 0, sizeof(comp));
    strncpy(comp.name, "openssl", sizeof(comp.name) - 1);
    strncpy(comp.version, "1.0.1f", sizeof(comp.version) - 1);
    strncpy(comp.source, "string", sizeof(comp.source) - 1);

    cve_entry_t cves[32];
    size_t count = 0;
    int rc = cve_check(&comp, 1, cves, 32, &count);
    if (rc != 0 || count == 0) {
        printf("FAIL: test_cve_check (rc=%d, count=%zu)\n", rc, count);
        return 1;
    }

    int found_heartbleed = 0;
    for (size_t i = 0; i < count; i++) {
        if (strstr(cves[i].cve_id, "CVE-2014-0160") != NULL ||
            strcasestr(cves[i].description, "Heartbleed") != NULL) {
            found_heartbleed = 1;
            break;
        }
    }

    if (!found_heartbleed) {
        printf("FAIL: test_cve_check (Heartbleed / CVE-2014-0160 not found among %zu CVEs)\n", count);
        for (size_t i = 0; i < count; i++) {
            printf("  [%zu] %s %s: %s\n", i, cves[i].cve_id, cves[i].severity, cves[i].description);
        }
        return 1;
    }

    printf("PASS: test_cve_check\n");
    return 0;
}

static int cve_has(const char *name, const char *version, const char *cve_id) {
    component_t comp;
    memset(&comp, 0, sizeof(comp));
    strncpy(comp.name, name, sizeof(comp.name) - 1);
    strncpy(comp.version, version, sizeof(comp.version) - 1);
    strncpy(comp.source, "string", sizeof(comp.source) - 1);
    cve_entry_t cves[64];
    size_t count = 0;
    cve_check(&comp, 1, cves, 64, &count);
    for (size_t i = 0; i < count; i++)
        if (strcmp(cves[i].cve_id, cve_id) == 0) return 1;
    return 0;
}

/* Regression: IoTGoat's Linux 4.9.152 used to report Dirty Pipe (affects 5.8+)
 * and a sudo CVE filed under the kernel. */
static int test_cve_no_false_positives(void) {
    struct { const char *n, *v, *id; const char *why; } neg[] = {
        { "linux-kernel", "4.9.152",  "CVE-2022-0847", "Dirty Pipe needs >= 5.8" },
        { "linux-kernel", "4.9.152",  "CVE-2021-3156", "sudo bug is not a kernel CVE" },
        { "linux-kernel", "5.10.150", "CVE-2022-0847", "fixed in 5.10.102" },
        { "linux-kernel", "5.15.30",  "CVE-2022-0847", "fixed in 5.15.25" },
        { "linux-kernel", "4.9.190",  "CVE-2019-11477", "fixed in 4.9.182" },
        { "openssl",      "1.0.1g",   "CVE-2014-0160", "fixed in 1.0.1g" },
        { "openssl",      "0.9.8zh",  "CVE-2014-0160", "Heartbleed starts at 1.0.1" },
        { "openssl",      "0.9.8zh",  "CVE-2014-0224", "fixed in 0.9.8za" },
        { "openssl",      "1.0.1u",   "CVE-2016-2107", "fixed in 1.0.1t" },
        { "nginx",        "1.14.2",   "CVE-2018-16843", "fixed in 1.14.1" },
        { "openssh",      "7.4",      "CVE-2024-6387", "regreSSHion starts at 8.5" },
    };
    for (size_t i = 0; i < sizeof(neg) / sizeof(neg[0]); i++) {
        if (cve_has(neg[i].n, neg[i].v, neg[i].id)) {
            printf("FAIL: test_cve_no_false_positives (%s %s matched %s: %s)\n", neg[i].n, neg[i].v, neg[i].id, neg[i].why);
            return 1;
        }
    }
    printf("PASS: test_cve_no_false_positives\n");
    return 0;
}

static int test_cve_true_positives(void) {
    struct { const char *n, *v, *id; } pos[] = {
        { "linux-kernel", "4.9.152", "CVE-2019-11477" },
        { "linux-kernel", "5.10.50", "CVE-2022-0847" },
        { "linux-kernel", "5.15.10", "CVE-2022-0847" },
        { "linux-kernel", "5.16.5",  "CVE-2022-0847" },
        { "openssl",      "1.0.1f",  "CVE-2014-0160" },
        { "openssl",      "1.0.1g",  "CVE-2014-0224" },
        { "nginx",        "1.15.0",  "CVE-2018-16843" },
        { "openssh",      "9.7p1",   "CVE-2024-6387" },
    };
    for (size_t i = 0; i < sizeof(pos) / sizeof(pos[0]); i++) {
        if (!cve_has(pos[i].n, pos[i].v, pos[i].id)) {
            printf("FAIL: test_cve_true_positives (%s %s did not match %s)\n", pos[i].n, pos[i].v, pos[i].id);
            return 1;
        }
    }
    printf("PASS: test_cve_true_positives\n");
    return 0;
}

/* ── Extracted-tree scanning tests ── */
static int rm_cb(const char *p, const struct stat *sb, int flag, struct FTW *ftw) {
    (void)sb; (void)flag; (void)ftw;
    return remove(p);
}
static void rm_rf(const char *dir) { nftw(dir, rm_cb, 16, FTW_DEPTH | FTW_PHYS); }

static void put_file(const char *dir, const char *rel, const void *data, size_t len) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, rel);
    char parent[512];
    snprintf(parent, sizeof(parent), "%s", path);
    char *slash = strrchr(parent, '/');
    if (slash) { *slash = '\0'; mkdirp(parent); }
    FILE *f = fopen(path, "wb");
    if (f) { fwrite(data, 1, len, f); fclose(f); }
}

static size_t make_gzip(const char *msg, uint8_t *out, size_t cap) {
    z_stream z;
    memset(&z, 0, sizeof(z));
    if (deflateInit2(&z, 9, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return 0;
    z.next_in = (Bytef *)msg;
    z.avail_in = (uInt)strlen(msg);
    z.next_out = out;
    z.avail_out = (uInt)cap;
    deflate(&z, Z_FINISH);
    size_t n = cap - z.avail_out;
    deflateEnd(&z);
    return n;
}

static int test_tree_scan(void) {
    char root[] = "/tmp/automata_tree_XXXXXX";
    if (mkdtemp(root) == NULL) { printf("FAIL: test_tree_scan (mkdtemp)\n"); return 1; }

    const char *pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n-----END RSA PRIVATE KEY-----\n";
    put_file(root, "etc/key.pem", pem, strlen(pem));
    const char *bb = "xx BusyBox v1.30.1 multi-call binary";
    put_file(root, "bin/busybox", bb, strlen(bb));
    uint8_t elf[128];
    memset(elf, 0, sizeof(elf));
    make_elf_header(elf);
    put_file(root, "bin/app", elf, sizeof(elf));
    uint8_t gz[512];
    size_t gzlen = make_gzip("junk BusyBox v1.29.0 multi-call binary junk", gz, sizeof(gz));
    put_file(root, "data/blob.gz", gz, gzlen);
    /* A symlink to a host file must never be read */
    char link[512];
    snprintf(link, sizeof(link), "%s/etc/hostpasswd", root);
    if (symlink("/etc/passwd", link) != 0) { /* ignore: test still checks counts */ }

    elf_info_t elfs[16];
    secret_finding_t secrets[16];
    component_t comps[16];
    int rc = 1;

    /* 1. non-recursive */
    tree_limits_t lim;
    tree_limits_default(&lim);
    tree_results_t tr;
    memset(&tr, 0, sizeof(tr));
    tr.elfs = elfs; tr.max_elfs = 16;
    tr.secrets = secrets; tr.max_secrets = 16;
    tr.components = comps; tr.max_components = 16;
    tree_scan(root, root, &lim, &tr);

    if (tr.files_scanned != 4) {
        printf("FAIL: test_tree_scan (scanned %zu files, expected 4: symlink must be skipped)\n", tr.files_scanned);
        goto done;
    }
    if (tr.num_elfs != 1 || strcmp(elfs[0].path, "bin/app") != 0 || strcmp(elf_arch_string(elfs[0].e_machine), "ARM") != 0) {
        printf("FAIL: test_tree_scan (ELF: n=%zu path='%s')\n", tr.num_elfs, tr.num_elfs ? elfs[0].path : "");
        goto done;
    }
    int key_ok = 0;
    for (size_t i = 0; i < tr.num_secrets; i++)
        if (secrets[i].type == PRIVATE_KEY && strcmp(secrets[i].source, "etc/key.pem") == 0) key_ok = 1;
    if (!key_ok) { printf("FAIL: test_tree_scan (private key not attributed to etc/key.pem)\n"); goto done; }
    if (tr.num_components != 1 || strcasecmp(comps[0].name, "busybox") != 0 ||
        strcmp(comps[0].version, "1.30.1") != 0 || strcmp(comps[0].location, "bin/busybox") != 0) {
        printf("FAIL: test_tree_scan (non-recursive components: n=%zu)\n", tr.num_components);
        goto done;
    }

    /* 2. recursive: the gzip's contents (BusyBox 1.29.0) become visible */
    lim.recursive = 1;
    memset(&tr, 0, sizeof(tr));
    tr.elfs = elfs; tr.max_elfs = 16;
    tr.secrets = secrets; tr.max_secrets = 16;
    tr.components = comps; tr.max_components = 16;
    tree_scan(root, root, &lim, &tr);

    int nested_ok = 0;
    for (size_t i = 0; i < tr.num_components; i++)
        if (strcmp(comps[i].version, "1.29.0") == 0 && strstr(comps[i].location, ".nested") != NULL) nested_ok = 1;
    if (!nested_ok || tr.nested_extractions < 1) {
        printf("FAIL: test_tree_scan (recursive: nested component missing, components=%zu nested=%zu)\n",
               tr.num_components, tr.nested_extractions);
        goto done;
    }
    printf("PASS: test_tree_scan\n");
    rc = 0;
done:
    rm_rf(root);
    return rc;
}

/* Paths come from firmware and are attacker-controlled: terminal and JSON output must be safe. */
static int test_report_escaping(void) {
    char *buf = NULL;
    size_t blen = 0;
    FILE *f = open_memstream(&buf, &blen);
    if (!f) { printf("FAIL: test_report_escaping (open_memstream)\n"); return 1; }
    report_json_string(f, "a\"b\\c\n\x1b[31m");
    report_print_safe(f, "x\x1b[2Jy");
    fclose(f);
    int ok = buf && strstr(buf, "\\\"") && strstr(buf, "\\n") && strstr(buf, "\\u001b") &&
             !strchr(buf, '\x1b') && strstr(buf, "x?[2Jy");
    free(buf);
    if (!ok) { printf("FAIL: test_report_escaping\n"); return 1; }
    printf("PASS: test_report_escaping\n");
    return 0;
}

/* ── Secrets: false-positive regressions from the IoTGoat scan ── */
static int count_secrets(const char *text, unsigned flags, secret_type_t type) {
    secret_finding_t f[16];
    size_t n = 0;
    secrets_scan_ex((const uint8_t *)text, strlen(text), f, 16, &n, flags);
    int c = 0;
    for (size_t i = 0; i < n; i++) if (f[i].type == type) c++;
    return c;
}

static int test_secrets_false_positives(void) {
    /* a PEM header with nothing after it is a parser constant (mbedTLS), not a key */
    if (count_secrets("-----BEGIN RSA PRIVATE KEY-----", 0, PRIVATE_KEY) != 0 ||
        count_secrets("-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n", 0, PRIVATE_KEY) != 0 ||
        count_secrets("-----BEGIN CERTIFICATE-----", 0, CERTIFICATE) != 0) {
        printf("FAIL: test_secrets_false_positives (header-only PEM accepted)\n");
        return 1;
    }
    /* variable references and format strings are not hard-coded passwords */
    if (count_secrets("password=$PASSWORD\n", 0, PASSWORD) != 0 ||
        count_secrets("password=%s&user=x", 0, PASSWORD) != 0 ||
        count_secrets("password=\n", 0, PASSWORD) != 0) {
        printf("FAIL: test_secrets_false_positives (password reference accepted)\n");
        return 1;
    }
    /* keyword patterns do not apply to compiled binaries */
    if (count_secrets("password=hunter2hunter2", SECRETS_F_BINARY, PASSWORD) != 0) {
        printf("FAIL: test_secrets_false_positives (keyword matched inside a binary)\n");
        return 1;
    }
    /* true positives still found */
    if (count_secrets("wifi password=hunter2hunter2\n", 0, PASSWORD) != 1 ||
        count_secrets("root:$1$xyz$abcdefghijklmnopqrstuv:0:0:root:/root:/bin/ash\n", 0, HARDCODED_CRED) != 1 ||
        count_secrets("-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123\n\nMHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLUvVthYWkMSz6/Q9HEAXToAoGCCqGSM49AwEHoUQDQgAE\n-----END EC PRIVATE KEY-----\n", 0, PRIVATE_KEY) != 1) {
        printf("FAIL: test_secrets_false_positives (real secret missed)\n");
        return 1;
    }
    printf("PASS: test_secrets_false_positives\n");
    return 0;
}

/* ── ELF kinds: kernel modules and libraries must not get meaningless NX/PIE verdicts ── */
static void make_elf_ph(uint8_t *p, uint16_t e_type, uint32_t ph_type, uint32_t ph_flags) {
    memset(p, 0, 128);
    make_elf_header(p);
    p[16] = (uint8_t)e_type;
    p[28] = 52;                 /* e_phoff */
    p[44] = 1;                  /* e_phnum */
    p[42] = 32;                 /* e_phentsize */
    for (int k = 0; k < 4; k++) p[52 + k] = (uint8_t)(ph_type >> (8 * k));
    p[52 + 24] = (uint8_t)ph_flags;
}

static int test_elf_kinds(void) {
    uint8_t b[128];
    elf_info_t e;

    memset(b, 0, sizeof(b));
    make_elf_header(b);
    b[16] = 1;                                           /* ET_REL, e.g. a kernel module */
    if (elf_parse_buf(b, sizeof(b), &e) != 0 || e.kind != ELF_KIND_RELOCATABLE ||
        strcmp(elf_nx_string(&e), "n/a") != 0 || strcmp(elf_pie_string(&e), "n/a") != 0 ||
        strcmp(elf_relro_string(&e), "n/a") != 0) {
        printf("FAIL: test_elf_kinds (relocatable object gets NX/PIE/RELRO verdicts)\n");
        return 1;
    }

    make_elf_ph(b, 3, 6 /* PT_PHDR: no GNU_STACK, no INTERP */, 0);
    if (elf_parse_buf(b, sizeof(b), &e) != 0 || e.kind != ELF_KIND_SHARED || e.is_pie ||
        strcmp(elf_pie_string(&e), "n/a") != 0 || strcmp(elf_nx_string(&e), "unknown") != 0) {
        printf("FAIL: test_elf_kinds (shared object misreported: kind=%d)\n", e.kind);
        return 1;
    }

    make_elf_ph(b, 3, 3 /* PT_INTERP */, 0);
    if (elf_parse_buf(b, sizeof(b), &e) != 0 || e.kind != ELF_KIND_PIE || !e.is_pie) {
        printf("FAIL: test_elf_kinds (PIE executable not recognised)\n");
        return 1;
    }

    make_elf_ph(b, 2, 0x6474e551 /* PT_GNU_STACK */, 7 /* RWE */);
    if (elf_parse_buf(b, sizeof(b), &e) != 0 || e.kind != ELF_KIND_EXEC || !e.has_gnu_stack || e.has_nx ||
        strcmp(elf_nx_string(&e), "no") != 0 || strcmp(elf_pie_string(&e), "no") != 0) {
        printf("FAIL: test_elf_kinds (RWE stack not reported as NX off)\n");
        return 1;
    }

    make_elf_ph(b, 2, 0x6474e551, 6 /* RW */);
    if (elf_parse_buf(b, sizeof(b), &e) != 0 || !e.has_nx || strcmp(elf_nx_string(&e), "yes") != 0) {
        printf("FAIL: test_elf_kinds (RW stack not reported as NX on)\n");
        return 1;
    }
    printf("PASS: test_elf_kinds\n");
    return 0;
}

/* ── SBOM: OpenWrt opkg package database ── */
static int test_sbom_opkg(void) {
    const char *status =
        "Package: miniupnpd\nVersion: 2.1-1\nDepends: libc, iptables\nStatus: install user installed\n\n"
        "Package: kernel\nVersion: 4.9.152-1-1fd2f1d8d1e1ff0e0b1e5d5c1d1c6a5a\nStatus: install user installed\n\n"
        "Package: libopenssl\nVersion: 1.0.2q-1\nStatus: install user installed\n\n"
        "Package: base-files\nVersion: 194-r7676-cddd7b4c77\nStatus: install user installed\n";
    component_t c[16];
    size_t n = 0;
    if (sbom_parse_opkg_status((const uint8_t *)status, strlen(status), c, 16, &n) != 0 || n != 4) {
        printf("FAIL: test_sbom_opkg (parsed %zu packages)\n", n);
        return 1;
    }
    int mini = 0, kern = 0, ssl = 0;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(c[i].name, "miniupnpd") == 0 && strcmp(c[i].version, "2.1") == 0) mini = 1;
        if (strcmp(c[i].name, "linux-kernel") == 0 && strcmp(c[i].version, "4.9.152") == 0) kern = 1;
        if (strcmp(c[i].name, "openssl") == 0 && strcmp(c[i].version, "1.0.2q") == 0) ssl = 1;
    }
    if (!mini || !kern || !ssl) {
        printf("FAIL: test_sbom_opkg (miniupnpd=%d kernel=%d openssl=%d)\n", mini, kern, ssl);
        return 1;
    }

    /* and through the tree scanner: usr/lib/opkg/status inside an extracted rootfs */
    char root[] = "/tmp/automata_opkg_XXXXXX";
    if (mkdtemp(root) == NULL) { printf("FAIL: test_sbom_opkg (mkdtemp)\n"); return 1; }
    put_file(root, "usr/lib/opkg/status", status, strlen(status));
    component_t comps[16];
    tree_results_t tr;
    memset(&tr, 0, sizeof(tr));
    tr.components = comps; tr.max_components = 16;
    tree_scan(root, root, NULL, &tr);
    int ok = 0;
    for (size_t i = 0; i < tr.num_components; i++)
        if (strcmp(comps[i].name, "miniupnpd") == 0 && strcmp(comps[i].source, "opkg") == 0 &&
            strstr(comps[i].location, "opkg/status") != NULL) ok = 1;
    rm_rf(root);
    if (!ok || tr.num_components != 4) {
        printf("FAIL: test_sbom_opkg (tree scan produced %zu components)\n", tr.num_components);
        return 1;
    }
    printf("PASS: test_sbom_opkg\n");
    return 0;
}

/* ── CVE ranges validated against NVD/OSV/JFrog data for the IoTGoat image ── */
static int test_cve_iotgoat_ranges(void) {
    struct { const char *n, *v, *id; int want; const char *why; } t[] = {
        /* busybox 1.28.4 (IoTGoat) */
        { "busybox", "1.28.4", "CVE-2021-42373", 0, "man applet: only 1.33.0-1.33.1" },
        { "busybox", "1.28.4", "CVE-2021-42383", 0, "awk evaluate: only 1.33.1" },
        { "busybox", "1.28.4", "CVE-2021-42375", 0, "ash: only 1.33.1" },
        { "busybox", "1.28.4", "CVE-2021-42374", 1, "unlzma: 1.27.0-1.33.1" },
        { "busybox", "1.28.4", "CVE-2021-42380", 1, "awk clrvar: 1.28-1.33.1" },
        { "busybox", "1.28.4", "CVE-2021-42386", 1, "awk nvalloc: 1.16-1.33.1" },
        { "busybox", "1.28.4", "CVE-2021-42376", 1, "hush: 1.16-1.31.1" },
        { "busybox", "1.27.2", "CVE-2021-42380", 0, "awk clrvar starts at 1.28" },
        { "busybox", "1.33.1", "CVE-2021-42373", 1, "man applet affected" },
        { "busybox", "1.33.1", "CVE-2021-42383", 1, "awk evaluate affected" },
        { "busybox", "1.34.0", "CVE-2021-42386", 0, "fixed in 1.34.0" },
        /* dnsmasq 2.73 (IoTGoat) */
        { "dnsmasq", "2.73", "CVE-2017-14491", 1, "fixed in 2.78" },
        { "dnsmasq", "2.73", "CVE-2017-14493", 1, "fixed in 2.78" },
        { "dnsmasq", "2.78", "CVE-2017-14491", 0, "fixed in 2.78" },
        { "dnsmasq", "2.73", "CVE-2020-25681", 1, "fixed in 2.83" },
        /* miniupnpd 2.1 (IoTGoat) */
        { "miniupnpd", "2.1", "CVE-2019-12110", 1, "through 2.1" },
        { "miniupnpd", "2.0", "CVE-2019-12111", 1, "through 2.1" },
        { "miniupnpd", "2.2", "CVE-2019-12110", 0, "after 2.1" },
        /* openssl 1.0.2h (Netgear R7000) and the 22 Sep 2016 advisory */
        { "openssl", "1.0.2h", "CVE-2016-6304", 1, "fixed in 1.0.2i" },
        { "openssl", "1.0.2h", "CVE-2016-2183", 1, "fixed in 1.0.2i" },
        { "openssl", "1.0.2h", "CVE-2016-2182", 1, "fixed in 1.0.2i" },
        { "openssl", "1.0.2i", "CVE-2016-6304", 0, "fixed in 1.0.2i" },
        { "openssl", "1.0.2k", "CVE-2016-2182", 0, "later 1.0.2" },
        { "openssl", "1.0.1t", "CVE-2016-6304", 1, "fixed in 1.0.1u" },
        { "openssl", "1.0.1u", "CVE-2016-6304", 0, "fixed in 1.0.1u" },
        { "openssl", "1.1.0a", "CVE-2016-6304", 0, "1.1.0 branch not covered here" },
        /* kernel 4.9.152 (IoTGoat) */
        { "linux-kernel", "4.9.152", "CVE-2019-11477", 1, "fixed in 4.9.182" },
        { "linux-kernel", "4.9.152", "CVE-2019-11478", 1, "fixed in 4.9.182" },
        { "linux-kernel", "3.16.70", "CVE-2019-11477", 0, "fixed in 3.16.69" },
        { "linux-kernel", "3.16.60", "CVE-2019-11477", 1, "before 3.16.69" },
        { "linux-kernel", "4.14.95", "CVE-2019-11477", 1, "fixed in 4.14.127" },
        { "linux-kernel", "4.14.200", "CVE-2019-11477", 0, "fixed in 4.14.127" },
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        int got = cve_has(t[i].n, t[i].v, t[i].id);
        if (got != t[i].want) {
            printf("FAIL: test_cve_iotgoat_ranges (%s %s %s: got %d, want %d; %s)\n",
                   t[i].n, t[i].v, t[i].id, got, t[i].want, t[i].why);
            return 1;
        }
    }
    /* conditions are carried through so the report can say "only if the awk applet is built in" */
    component_t comp;
    memset(&comp, 0, sizeof(comp));
    strcpy(comp.name, "busybox"); strcpy(comp.version, "1.28.4"); strcpy(comp.source, "string");
    cve_entry_t out[64];
    size_t n = 0;
    cve_check(&comp, 1, out, 64, &n);
    int cond_ok = 0;
    for (size_t i = 0; i < n; i++)
        if (strcmp(out[i].cve_id, "CVE-2021-42386") == 0 && strcmp(out[i].condition, "awk applet") == 0) cond_ok = 1;
    if (!cond_ok) { printf("FAIL: test_cve_iotgoat_ranges (condition not carried)\n"); return 1; }
    printf("PASS: test_cve_iotgoat_ranges\n");
    return 0;
}

/* The caller indexes its arrays with the reported count: it must never exceed what fits. */
static int test_counts_are_clamped(void) {
    char text[2048];
    text[0] = '\0';
    for (int i = 0; i < 30; i++) {
        char one[64];
        snprintf(one, sizeof(one), "BusyBox v1.%d.0 multi-call binary\n", i);
        strcat(text, one);
    }
    component_t c[4];
    size_t n = 0;
    sbom_scan((const uint8_t *)text, strlen(text), c, 4, &n);
    if (n > 4) { printf("FAIL: test_counts_are_clamped (sbom reported %zu for 4 slots)\n", n); return 1; }

    component_t many[40];
    memset(many, 0, sizeof(many));
    for (int i = 0; i < 40; i++) {
        strcpy(many[i].name, "busybox");
        snprintf(many[i].version, sizeof(many[i].version), "1.%d.0", i + 1);
    }
    cve_entry_t out[2];
    size_t cn = 0;
    cve_check(many, 40, out, 2, &cn);
    if (cn > 2) { printf("FAIL: test_counts_are_clamped (cve_check reported %zu for 2 slots)\n", cn); return 1; }
    printf("PASS: test_counts_are_clamped\n");
    return 0;
}

/* ── mkdirp: long paths and failures ── */
static int test_mkdirp(void) {
    char base[] = "/tmp/automata_mk_XXXXXX";
    if (mkdtemp(base) == NULL) { printf("FAIL: test_mkdirp (mkdtemp)\n"); return 1; }
    char deep[1024];
    snprintf(deep, sizeof(deep), "%s", base);
    for (int i = 0; i < 8; i++) strcat(deep, "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    int rc = mkdirp(deep);
    struct stat st;
    int created = (rc == 0 && stat(deep, &st) == 0 && S_ISDIR(st.st_mode));
    /* a regular file in the way must be an error, not silent success */
    char file[600];
    snprintf(file, sizeof(file), "%s/afile", base);
    put_file(base, "afile", "x", 1);
    char blocked[700];
    snprintf(blocked, sizeof(blocked), "%s/sub", file);
    int blocked_rc = mkdirp(blocked);
    rm_rf(base);
    if (strlen(deep) < 300 || !created) { printf("FAIL: test_mkdirp (long path not created, rc=%d)\n", rc); return 1; }
    if (blocked_rc == 0) { printf("FAIL: test_mkdirp (failure reported as success)\n"); return 1; }
    printf("PASS: test_mkdirp\n");
    return 0;
}

/* ── Report: fold container internals, group runs, keep untrusted strings safe ── */
static int test_report_findings_layout(void) {
    finding_t fs[32];
    size_t n = 0;
    memset(fs, 0, sizeof(fs));
    for (int i = 0; i < 6; i++) {                       /* 6 DTBs in a row */
        fs[n].offset = 0x1000 + (size_t)i * 0x800; fs[n].label = "Device Tree Blob"; fs[n].confidence = 1.0f; fs[n].type = SIG_DTB; n++;
    }
    fs[n].offset = 0x100000; fs[n].label = "SquashFS (LE)"; fs[n].confidence = 1.0f; fs[n].type = SIG_SQUASHFS_LE; fs[n].length = 0x50000; n++;
    for (int i = 0; i < 5; i++) {                       /* XZ blocks inside the SquashFS */
        fs[n].offset = 0x100100 + (size_t)i * 0x100; fs[n].label = "XZ Archive"; fs[n].confidence = 1.0f; fs[n].type = SIG_XZ; n++;
    }
    fs[n].offset = 0x200000; fs[n].label = "GZIP Archive"; fs[n].confidence = 0.9f; fs[n].type = SIG_GZIP; n++;
    fs[n].offset = 0x300000; fs[n].label = "SquashFS (LE)"; fs[n].confidence = 0.3f; fs[n].type = SIG_SQUASHFS_LE; n++;

    analysis_result_t res;
    memset(&res, 0, sizeof(res));
    snprintf(res.filename, sizeof(res.filename), "evil\x1b[2Jname.bin");
    res.findings = fs;
    res.num_findings = n;

    char path[] = "/tmp/automata_report_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { printf("FAIL: test_report_findings_layout (mkstemp)\n"); return 1; }
    close(fd);
    report_human(&res, path);
    char buf[8192] = {0};
    FILE *f = fopen(path, "r");
    size_t got = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;
    if (f) fclose(f);
    unlink(path);
    buf[got] = '\0';

    int ok = strstr(buf, "x6") != NULL &&                         /* DTB run grouped */
             strstr(buf, "5 more findings inside this region hidden") != NULL &&
             strstr(buf, "XZ Archive") == NULL &&                 /* internals folded away */
             strstr(buf, "1 low-confidence findings hidden") != NULL &&
             strstr(buf, "GZIP Archive") != NULL;
    if (!ok) { printf("FAIL: test_report_findings_layout\n%s\n", buf); return 1; }

    res.show_all_findings = 1;
    f = fopen(path, "w"); if (f) fclose(f);
    report_human(&res, path);
    memset(buf, 0, sizeof(buf));
    f = fopen(path, "r");
    got = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;
    if (f) fclose(f);
    unlink(path);
    if (strstr(buf, "XZ Archive") == NULL || strstr(buf, "conf: 0.30") == NULL) {
        printf("FAIL: test_report_findings_layout (-v must show everything)\n");
        return 1;
    }
    printf("PASS: test_report_findings_layout\n");
    return 0;
}

/* ── Image headers: Netgear CHK, Broadcom TRX, U-Boot uImage ── */
static int test_fwhdr_netgear_known_answer(void) {
    /* The 58-byte CHK header of Netgear R7000 V1.0.9.64_10.2.64 (header checksum 0x520a0ce8 over the header with that field zeroed) */
    static const uint8_t real[58] = {
        0x2a,0x23,0x24,0x5e,0x00,0x00,0x00,0x3a,0x01,0x01,0x00,0x09,0x40,0x0a,0x02,0x40,
        0x4d,0x68,0xfa,0xca,0x00,0x00,0x00,0x00,0x01,0xe3,0xc0,0x00,0x00,0x00,0x00,0x00,
        0x4d,0x68,0xfa,0xca,0x52,0x0a,0x0c,0xe8,0x55,0x31,0x32,0x48,0x32,0x37,0x30,0x54,
        0x30,0x30,0x5f,0x4e,0x45,0x54,0x47,0x45,0x41,0x52 };
    uint8_t h[58];
    memcpy(h, real, sizeof(h));
    memset(h + 0x24, 0, 4);
    uint32_t got = fwhdr_netgear_checksum(h, sizeof(h));
    if (got != 0x520a0ce8u) {
        printf("FAIL: test_fwhdr_netgear_known_answer (header checksum %08x, want 520a0ce8)\n", got);
        return 1;
    }
    /* the header alone is truncated (payload missing): reported as an integrity problem, not crashed on */
    fwhdr_t out[4];
    size_t n = 0;
    fwhdr_analyze(real, sizeof(real), out, 4, &n);
    if (n != 1 || strcmp(out[0].format, "NETGEAR CHK") != 0 || out[0].integrity != 0 ||
        strstr(out[0].summary, "U12H270T00_NETGEAR") == NULL || strstr(out[0].summary, "1.0.9.64_10.2.64") == NULL ||
        strstr(out[0].checks, "header checksum OK") == NULL) {
        printf("FAIL: test_fwhdr_netgear_known_answer (n=%zu, checks='%s')\n", n, n ? out[0].checks : "");
        return 1;
    }
    printf("PASS: test_fwhdr_netgear_known_answer\n");
    return 0;
}

static void put_le32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static void put_be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

static int test_fwhdr_chk_trx(void) {
    enum { KLEN = 400, RLEN = 600, TRX_LEN = 28 + KLEN + RLEN, CHK_LEN = 58 };
    static uint8_t img[CHK_LEN + TRX_LEN];
    memset(img, 0, sizeof(img));
    uint8_t *trx = img + CHK_LEN;
    memcpy(trx, "HDR0", 4);
    put_le32(trx + 4, TRX_LEN);
    trx[14] = 1;                                            /* version 1 */
    put_le32(trx + 16, 28);                                 /* kernel */
    put_le32(trx + 20, 28 + KLEN);                          /* rootfs */
    for (size_t i = 28; i < TRX_LEN; i++) trx[i] = (uint8_t)(i * 7 + 3);
    put_le32(trx + 8, ~(uint32_t)crc32(0L, trx + 12, TRX_LEN - 12));

    uint8_t *chk = img;
    memcpy(chk, "*#$^", 4);
    put_be32(chk + 4, CHK_LEN);
    chk[9] = 1; chk[10] = 0; chk[11] = 9; chk[12] = 64; chk[13] = 10; chk[14] = 2; chk[15] = 64;
    put_be32(chk + 0x18, TRX_LEN);
    uint32_t ichk = fwhdr_netgear_checksum(trx, TRX_LEN);
    put_be32(chk + 0x10, ichk);
    put_be32(chk + 0x20, ichk);
    memcpy(chk + 0x28, "TEST123_NETGEAR", 15);
    uint8_t hc[CHK_LEN];
    memcpy(hc, chk, CHK_LEN);
    memset(hc + 0x24, 0, 4);
    put_be32(chk + 0x24, fwhdr_netgear_checksum(hc, CHK_LEN));

    fwhdr_t out[4];
    size_t n = 0;
    fwhdr_analyze(img, sizeof(img), out, 4, &n);
    if (n != 2 || strcmp(out[0].format, "NETGEAR CHK") != 0 || strcmp(out[1].format, "TRX v1") != 0 ||
        out[0].integrity != 1 || out[1].integrity != 1 || out[1].num_parts != 2 ||
        out[1].part_offset[0] != CHK_LEN + 28 || out[1].part_length[0] != KLEN ||
        out[1].part_offset[1] != CHK_LEN + 28 + KLEN || out[1].part_length[1] != RLEN) {
        printf("FAIL: test_fwhdr_chk_trx (n=%zu chk='%s' trx='%s')\n", n, n > 0 ? out[0].checks : "", n > 1 ? out[1].checks : "");
        return 1;
    }
    /* one flipped payload byte breaks both checksums */
    img[CHK_LEN + 28 + 100] ^= 0xff;
    n = 0;
    fwhdr_analyze(img, sizeof(img), out, 4, &n);
    if (n != 2 || out[0].integrity != 0 || out[1].integrity != 0 ||
        strstr(out[0].checks, "image checksum MISMATCH") == NULL || strstr(out[1].checks, "CRC32 MISMATCH") == NULL) {
        printf("FAIL: test_fwhdr_chk_trx (corruption not detected)\n");
        return 1;
    }
    printf("PASS: test_fwhdr_chk_trx\n");
    return 0;
}

static int test_fwhdr_uimage(void) {
    uint8_t img[64 + 200];
    memset(img, 0, sizeof(img));
    for (int i = 64; i < 264; i++) img[i] = (uint8_t)(i ^ 0x5a);
    put_be32(img, 0x27051956);
    put_be32(img + 12, 200);
    put_be32(img + 16, 0x80008000);
    put_be32(img + 20, 0x80008000);
    put_be32(img + 24, (uint32_t)crc32(0L, img + 64, 200));
    img[28] = 5; img[29] = 2; img[30] = 2; img[31] = 1;                 /* Linux, ARM, kernel, gzip */
    memcpy(img + 32, "Linux-2.6.36", 12);
    uint8_t hc[64];
    memcpy(hc, img, 64);
    memset(hc + 4, 0, 4);
    put_be32(img + 4, (uint32_t)crc32(0L, hc, 64));

    fwhdr_t out[2];
    size_t n = 0;
    fwhdr_analyze(img, sizeof(img), out, 2, &n);
    if (n != 1 || strcmp(out[0].format, "uImage") != 0 || out[0].integrity != 1 ||
        strstr(out[0].summary, "Linux-2.6.36") == NULL || strstr(out[0].summary, "ARM Linux kernel, gzip") == NULL ||
        strstr(out[0].checks, "data CRC OK") == NULL) {
        printf("FAIL: test_fwhdr_uimage (n=%zu '%s')\n", n, n ? out[0].summary : "");
        return 1;
    }
    img[100] ^= 1;
    n = 0;
    fwhdr_analyze(img, sizeof(img), out, 2, &n);
    if (n != 1 || out[0].integrity != 0 || strstr(out[0].checks, "data CRC MISMATCH") == NULL) {
        printf("FAIL: test_fwhdr_uimage (data corruption not detected)\n");
        return 1;
    }
    /* a stray magic with no valid header CRC is not reported */
    uint8_t junk[128];
    memset(junk, 0xAA, sizeof(junk));
    put_be32(junk + 10, 0x27051956);
    n = 99;
    fwhdr_analyze(junk, sizeof(junk), out, 2, &n);
    if (n != 0) { printf("FAIL: test_fwhdr_uimage (stray magic reported)\n"); return 1; }
    printf("PASS: test_fwhdr_uimage\n");
    return 0;
}

/* ── Binary review: imports decide what an executable can do ── */
static size_t build_elf_imports(uint8_t *b, size_t cap, int is64, const char *const *names, size_t n, size_t pad_to, uint16_t e_type) {
    memset(b, 0, cap);
    uint8_t strtab[512];
    size_t sl = 1;
    strtab[0] = 0;
    for (size_t i = 0; i < n; i++) { size_t l = strlen(names[i]); memcpy(strtab + sl, names[i], l + 1); sl += l + 1; }

    size_t dyn_off = is64 ? 256 : 128, str_off = is64 ? 320 : 160;
    size_t total = str_off + sl;
    if (pad_to > total) total = pad_to;
    if (total > cap) return 0;
    uint64_t base = 0x400000;

    b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[4] = is64 ? 2 : 1; b[5] = 1; b[6] = 1;
    b[16] = (uint8_t)e_type; b[17] = (uint8_t)(e_type >> 8);
    b[18] = is64 ? 62 : 40;
    b[20] = 1;
    memcpy(b + str_off, strtab, sl);
    if (is64) {
        b[32] = 64;                                         /* e_phoff */
        b[54] = 56; b[56] = 2;                              /* phentsize, phnum */
        uint8_t *p = b + 64;
        put_le32(p, 1); put_le32(p + 4, 5);                 /* PT_LOAD, R+X */
        put_le32(p + 16, (uint32_t)base); put_le32(p + 32, (uint32_t)total);
        p += 56;
        put_le32(p, 2);                                     /* PT_DYNAMIC */
        put_le32(p + 8, (uint32_t)dyn_off); put_le32(p + 16, (uint32_t)(base + dyn_off)); put_le32(p + 32, 48);
        uint8_t *d = b + dyn_off;
        put_le32(d, 5);  put_le32(d + 8, (uint32_t)(base + str_off));      /* DT_STRTAB */
        put_le32(d + 16, 10); put_le32(d + 24, (uint32_t)sl);              /* DT_STRSZ */
    } else {
        b[28] = 52;
        b[42] = 32; b[44] = 2;
        uint8_t *p = b + 52;
        put_le32(p, 1); put_le32(p + 8, (uint32_t)base); put_le32(p + 16, (uint32_t)total); put_le32(p + 24, 5);
        p += 32;
        put_le32(p, 2); put_le32(p + 4, (uint32_t)dyn_off); put_le32(p + 8, (uint32_t)(base + dyn_off)); put_le32(p + 16, 24);
        uint8_t *d = b + dyn_off;
        put_le32(d, 5);  put_le32(d + 4, (uint32_t)(base + str_off));
        put_le32(d + 8, 10); put_le32(d + 12, (uint32_t)sl);
    }
    return total;
}

static int review(const char *path, int is64, const char *const *names, size_t n, size_t pad, uint16_t etype, elf_info_t *info) {
    static uint8_t buf[300 * 1024];
    size_t len = build_elf_imports(buf, sizeof(buf), is64, names, n, pad, etype);
    if (len == 0 || elf_parse_buf(buf, len, info) != 0) return -1;
    snprintf(info->path, sizeof(info->path), "%s", path);
    elf_review(buf, len, info);
    return 0;
}

static int test_binary_review(void) {
    static const char *const shell[] = { "socket", "bind", "listen", "accept", "dup2", "execl", "puts" };
    static const char *const cmdsrv[] = { "socket", "bind", "listen", "accept", "system" };
    static const char *const benign[] = { "puts", "printf" };
    static const char *const sysonly[] = { "puts", "system" };
    elf_info_t e;

    if (review("usr/bin/shellback", 1, shell, 7, 0, 2, &e) != 0 || e.risk != 3 || strstr(e.risk_note, "bind-shell") == NULL) {
        printf("FAIL: test_binary_review (bind shell not HIGH: risk=%d)\n", e.risk); return 1;
    }
    if (review("usr/bin/shellback", 0, shell, 7, 0, 2, &e) != 0 || e.risk != 3) {
        printf("FAIL: test_binary_review (32-bit bind shell not HIGH: risk=%d)\n", e.risk); return 1;
    }
    if (review("usr/sbin/dropbear", 1, shell, 7, 0, 2, &e) != 0 || e.risk != 2 || strstr(e.risk_note, "remote access service") == NULL) {
        printf("FAIL: test_binary_review (known service not MEDIUM)\n"); return 1;
    }
    if (review("usr/sbin/bigdaemon", 1, shell, 7, 200 * 1024, 2, &e) != 0 || e.risk >= 3) {
        printf("FAIL: test_binary_review (full-size daemon flagged as bind shell)\n"); return 1;
    }
    if (review("bin/wget", 1, shell, 7, 0, 2, &e) != 0 || e.risk != 0) {
        printf("FAIL: test_binary_review (client flagged)\n"); return 1;
    }
    if (review("usr/sbin/httpd", 1, cmdsrv, 5, 0, 2, &e) != 0 || e.risk != 2 || strstr(e.risk_note, "command-injection") == NULL) {
        printf("FAIL: test_binary_review (system() server not MEDIUM)\n"); return 1;
    }
    if (review("usr/bin/hello", 1, benign, 2, 0, 2, &e) != 0 || e.risk != 0 || e.caps != 0) {
        printf("FAIL: test_binary_review (benign flagged)\n"); return 1;
    }
    if (review("usr/bin/tool", 1, sysonly, 2, 0, 2, &e) != 0 || e.risk != 1) {
        printf("FAIL: test_binary_review (system() not LOW)\n"); return 1;
    }
    if (review("bin/busybox", 1, shell, 7, 0, 2, &e) != 0 || e.risk != 0) {
        printf("FAIL: test_binary_review (busybox flagged)\n"); return 1;
    }
    if (review("lib/libc.so", 1, shell, 7, 0, 3, &e) != 0 || e.risk != 0 || e.caps != 0) {
        printf("FAIL: test_binary_review (shared object reviewed)\n"); return 1;
    }
    printf("PASS: test_binary_review\n");
    return 0;
}

/* ── Secrets: false positives seen in the Netgear R7000 and IoTGoat scans ── */
static int test_secrets_netgear_regressions(void) {
    /* JS member access and UI label text */
    if (count_secrets("var password=cf.sysDNSPassword_Netgear.value;", 0, PASSWORD) != 0 ||
        count_secrets("parent.l2tp_password=cf.l2tp_passwd.value;", 0, PASSWORD) != 0 ||
        count_secrets("bh_new_password=\"Nuova password\"\n", 0, PASSWORD) != 0 ||
        count_secrets("password=getPassword()\n", 0, PASSWORD) != 0) {
        printf("FAIL: test_secrets_netgear_regressions (code or label treated as a password)\n"); return 1;
    }
    /* web UI files skip keyword patterns entirely */
    if (count_secrets("password=hunter2hunter2", SECRETS_F_WEBUI, PASSWORD) != 0) {
        printf("FAIL: test_secrets_netgear_regressions (keyword matched in web UI file)\n"); return 1;
    }
    /* MD5 of "password" is a default credential, not just "a password" */
    secret_finding_t f[4];
    size_t n = 0;
    const char *amule = "ECPort=4712\nECPassword=5f4dcc3b5aa765d61d8327deb882cf99\nUPnP=0\n";
    secrets_scan_ex((const uint8_t *)amule, strlen(amule), f, 4, &n, 0);
    if (n != 1 || f[0].type != HARDCODED_CRED || f[0].confidence < 0.9f || strstr(f[0].description, "MD5 of \"password\"") == NULL) {
        printf("FAIL: test_secrets_netgear_regressions (default MD5 hash not recognised, n=%zu)\n", n); return 1;
    }
    const char *other = "password=0123456789abcdef0123456789abcdef\n";
    secrets_scan_ex((const uint8_t *)other, strlen(other), f, 4, &n, 0);
    if (n != 1 || strstr(f[0].description, "Unsalted MD5") == NULL) {
        printf("FAIL: test_secrets_netgear_regressions (generic MD5 hash not recognised)\n"); return 1;
    }
    /* AWS key ids sit on word boundaries: this one is inside a word list in libunistring */
    if (count_secrets("IMMUINGWAZININGUINSECTINSIDEISAKIAISSHARITALICIYANNAJOINED", 0, AWS_KEY) != 0 ||
        count_secrets("key=AKIAIOSFODNN7EXAMPLE\n", 0, AWS_KEY) != 1 ||
        count_secrets("key=AKIAIOSFODNN7EXAMPLE\n", SECRETS_F_BINARY, AWS_KEY) != 0) {
        printf("FAIL: test_secrets_netgear_regressions (AWS key boundaries)\n"); return 1;
    }
    /* group/passwd entries are not credentials; a hash or a literal password is */
    if (count_secrets("admin:x:0:\nadmin:*:1:2\nadmin::3\n", 0, HARDCODED_CRED) != 0 ||
        count_secrets("admin:$1$abc$0123456789abcdefghijkl:0:0\n", 0, HARDCODED_CRED) != 1 ||
        count_secrets("curl -u admin:hunter2pw http://x\n", 0, HARDCODED_CRED) != 1) {
        printf("FAIL: test_secrets_netgear_regressions (admin entries)\n"); return 1;
    }
    printf("PASS: test_secrets_netgear_regressions\n");
    return 0;
}

/* ── Filesystems: JFFS2 (native), CramFS, UBI, and the optional codecs ── */
static int file_is(const char *dir, const char *rel, const void *want, size_t n) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, rel);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    uint8_t buf[4096];
    size_t got = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    return got == n && memcmp(buf, want, n) == 0;
}

static int check_jffs2_fixture(const char *name, const uint8_t *img, size_t len, int be) {
    uint8_t buf[2048];
    memset(buf, 0xAA, 50);
    memcpy(buf + 50, img, len);
    memset(buf + 50 + len, 0xFF, 200);
    size_t total = 50 + len + 200;

    finding_t fs[8];
    size_t nf = 0;
    identify_scan(buf, total, fs, 8, &nf);
    int found = 0;
    for (size_t i = 0; i < nf; i++)
        if (fs[i].offset == 50 && fs[i].type == (be ? SIG_JFFS2_BE : SIG_JFFS2_LE) && fs[i].confidence >= 0.99f) found = 1;
    if (!found) { printf("FAIL: test_jffs2_extract (%s: real node not recognised, CRC rule wrong?)\n", name); return 1; }

    char base[] = "/tmp/automata_jffs2_XXXXXX";
    if (mkdtemp(base) == NULL) return 1;
    char out[600];
    snprintf(out, sizeof(out), "%s/out", base);
    size_t span = 0, files = 0, unsup = 99;
    int rc = jffs2_extract(buf, total, 50, be, out, &span, &files, &unsup);

    char motd[30 * 25 + 1] = "";
    for (int i = 0; i < 30; i++) strcat(motd, "automata jffs2 test line\n");
    const char *passwd = "root:x:0:0:root:/root:/bin/ash\n";
    int ok = rc == 0 && files == 4 && unsup == 0 && span > 0 &&
             file_is(out, "etc/passwd", passwd, strlen(passwd)) &&
             file_is(out, "etc/motd", motd, strlen(motd));
    char linkpath[700], target[64] = "";
    snprintf(linkpath, sizeof(linkpath), "%s/bin/sh", out);
    ssize_t tl = readlink(linkpath, target, sizeof(target) - 1);
    if (tl > 0) target[tl] = '\0';
    ok = ok && strcmp(target, "/bin/ash") == 0;
    struct stat st;
    char blob[700];
    snprintf(blob, sizeof(blob), "%s/bin/blob.bin", out);
    ok = ok && stat(blob, &st) == 0 && st.st_size == 200;
    rm_rf(base);
    if (!ok) { printf("FAIL: test_jffs2_extract (%s: rc=%d files=%zu unsupported=%zu)\n", name, rc, files, unsup); return 1; }
    return 0;
}

static int test_jffs2_extract(void) {
    if (check_jffs2_fixture("LE zlib+none", fx_jffs2_le, sizeof(fx_jffs2_le), 0)) return 1;
    if (check_jffs2_fixture("BE zlib+none", fx_jffs2_be, sizeof(fx_jffs2_be), 1)) return 1;
    if (check_jffs2_fixture("LE rtime", fx_jffs2_rtime, sizeof(fx_jffs2_rtime), 0)) return 1;
    printf("PASS: test_jffs2_extract\n");
    return 0;
}

static uint32_t jt_crc(const uint8_t *p, size_t n) { return ~(uint32_t)crc32(0xFFFFFFFFUL, p, (uInt)n); }
static size_t jt_dirent(uint8_t *b, uint32_t pino, uint32_t ino, uint32_t ver, uint8_t type, const char *name) {
    size_t nl = strlen(name), tot = 40 + nl;
    memset(b, 0, (tot + 3) & ~3u);
    b[0] = 0x85; b[1] = 0x19; b[2] = 0x01; b[3] = 0xE0;
    put_le32(b + 4, (uint32_t)tot);
    put_le32(b + 8, jt_crc(b, 8));
    put_le32(b + 12, pino); put_le32(b + 16, ver); put_le32(b + 20, ino);
    b[28] = (uint8_t)nl; b[29] = type;
    memcpy(b + 40, name, nl);
    put_le32(b + 32, jt_crc(b, 32));
    put_le32(b + 36, jt_crc(b + 40, nl));
    return (tot + 3) & ~3u;
}
static size_t jt_inode(uint8_t *b, uint32_t ino, uint32_t ver, uint32_t mode, const char *data) {
    size_t dl = strlen(data), tot = 68 + dl;
    memset(b, 0, (tot + 3) & ~3u);
    b[0] = 0x85; b[1] = 0x19; b[2] = 0x02; b[3] = 0xE0;
    put_le32(b + 4, (uint32_t)tot);
    put_le32(b + 8, jt_crc(b, 8));
    put_le32(b + 12, ino); put_le32(b + 16, ver); put_le32(b + 20, mode);
    put_le32(b + 28, (uint32_t)dl); put_le32(b + 48, (uint32_t)dl); put_le32(b + 52, (uint32_t)dl);
    memcpy(b + 68, data, dl);
    put_le32(b + 60, jt_crc(b + 68, dl));
    put_le32(b + 64, jt_crc(b, 60));
    return (tot + 3) & ~3u;
}

/* A hostile image must not write outside the output directory, neither through ".." and "/" in names
 * nor through a symlink that a later entry claims as its parent directory. */
static int test_jffs2_hostile(void) {
    char base[] = "/tmp/automata_jhost_XXXXXX";
    if (mkdtemp(base) == NULL) return 1;
    char target[700], out[700], evil[700];
    snprintf(target, sizeof(target), "%s/target", base);
    snprintf(out, sizeof(out), "%s/out", base);
    snprintf(evil, sizeof(evil), "%s/evil", base);
    mkdir(target, 0755);

    static uint8_t img[4096];
    size_t p = 0;
    p += jt_dirent(img + p, 1, 2, 1, 8, "../evil");     p += jt_inode(img + p, 2, 1, 0100644, "EVIL");
    p += jt_dirent(img + p, 1, 3, 1, 8, "a/b");         p += jt_inode(img + p, 3, 1, 0100644, "EVIL2");
    p += jt_dirent(img + p, 1, 4, 1, 10, "lnk");        p += jt_inode(img + p, 4, 1, 0120777, target);
    p += jt_dirent(img + p, 4, 5, 1, 8, "pwned");       p += jt_inode(img + p, 5, 1, 0100644, "EVIL3");
    p += jt_dirent(img + p, 1, 6, 1, 8, "ok");          p += jt_inode(img + p, 6, 1, 0100644, "fine");

    size_t span = 0, files = 0, unsup = 0;
    int rc = jffs2_extract(img, p, 0, 0, out, &span, &files, &unsup);
    char tp[800], okp[800];
    snprintf(tp, sizeof(tp), "%s/pwned", target);
    snprintf(okp, sizeof(okp), "%s/ok", out);
    struct stat st;
    int escaped = stat(evil, &st) == 0 || stat(tp, &st) == 0;
    int ok_written = file_is(out, "ok", "fine", 4);
    (void)okp;
    rm_rf(base);
    if (rc != 0 || escaped || !ok_written) {
        printf("FAIL: test_jffs2_hostile (rc=%d escaped=%d ok_written=%d)\n", rc, escaped, ok_written);
        return 1;
    }
    printf("PASS: test_jffs2_hostile\n");
    return 0;
}

static int test_cramfs(void) {
    uint8_t buf[8192];
    memset(buf, 0xAA, 100);
    memset(buf + 100, 0, 4096);
    memcpy(buf + 100, fx_cramfs, sizeof(fx_cramfs));
    memset(buf + 100 + 4096, 0xAA, 64);
    size_t total = 100 + 4096 + 64;

    if (cramfs_size(buf, total, 100) != 4096) { printf("FAIL: test_cramfs (size from header)\n"); return 1; }
    finding_t fs[4];
    size_t nf = 0;
    identify_scan(buf, total, fs, 4, &nf);
    if (nf != 1 || fs[0].type != SIG_CRAMFS || fs[0].offset != 100 || fs[0].length != 4096) {
        printf("FAIL: test_cramfs (identify: n=%zu)\n", nf);
        return 1;
    }
    if (!cramfs_available()) { printf("PASS: test_cramfs (extraction skipped: fsck.cramfs not installed)\n"); return 0; }

    char base[] = "/tmp/automata_cramfs_XXXXXX";
    if (mkdtemp(base) == NULL) return 1;
    char out[600];
    snprintf(out, sizeof(out), "%s/out", base);
    int rc = cramfs_extract(buf, total, 100, out);
    int ok = rc == 0 && file_is(out, "etc/passwd", "cramfs test passwd\n", 19);
    rm_rf(base);
    if (!ok) { printf("FAIL: test_cramfs (extract rc=%d)\n", rc); return 1; }
    printf("PASS: test_cramfs\n");
    return 0;
}

static int test_ubi_header(void) {
    uint8_t buf[256];
    memset(buf, 0xFF, sizeof(buf));
    memcpy(buf + 32, fx_ubi_ec, 64);                    /* first 64 bytes of a real ubinize image */
    finding_t fs[4];
    size_t nf = 0;
    identify_scan(buf, sizeof(buf), fs, 4, &nf);
    if (nf != 1 || fs[0].type != SIG_UBI || fs[0].confidence < 0.99f || fs[0].offset != 32) {
        printf("FAIL: test_ubi_header (n=%zu)\n", nf);
        return 1;
    }
    buf[32 + 20] ^= 1;                                  /* corrupt data_offset: header CRC no longer matches */
    nf = 0;
    identify_scan(buf, sizeof(buf), fs, 4, &nf);
    for (size_t i = 0; i < nf; i++)
        if (fs[i].type == SIG_UBI && fs[i].confidence >= IDENTIFY_MIN_CONFIDENCE) {
            printf("FAIL: test_ubi_header (corrupt header accepted)\n");
            return 1;
        }
    printf("PASS: test_ubi_header\n");
    return 0;
}

static int extract_roundtrip(const char *label, const uint8_t *comp, size_t clen, const char *want_type, const char *plain, size_t plen) {
    uint8_t img[4096];
    memset(img, 0xAA, sizeof(img));
    if (300 + clen + 100 > sizeof(img)) return 1;
    memcpy(img + 300, comp, clen);
    char dir[] = "/tmp/automata_codec_XXXXXX";
    if (mkdtemp(dir) == NULL) return 1;
    extract_result_t res[4];
    size_t n = 0;
    extract_all(img, 300 + clen + 100, dir, res, 4, &n);
    int ok = n == 1 && res[0].offset == 300 && strcmp(res[0].type, want_type) == 0 && res[0].decompressed == plen;
    if (ok) {
        FILE *f = fopen(res[0].path, "rb");
        uint8_t back[2048] = {0};
        size_t got = f ? fread(back, 1, sizeof(back), f) : 0;
        if (f) fclose(f);
        ok = got == plen && memcmp(back, plain, plen) == 0;
        unlink(res[0].path);
    }
    rmdir(dir);
    if (!ok) { printf("FAIL: test_codecs (%s: n=%zu)\n", label, n); return 1; }
    return 0;
}

static int test_codecs(void) {
    char plain[1200];
    for (size_t i = 0; i < sizeof(plain); i++) plain[i] = "root:x:0:0 password=SuperSecret123\n"[i % 35];
    int tested = 0;
#ifdef HAVE_BZIP2
    {
        uint8_t c[2048];
        unsigned int cl = sizeof(c);
        if (BZ2_bzBuffToBuffCompress((char *)c, &cl, plain, sizeof(plain), 9, 0, 30) != BZ_OK ||
            extract_roundtrip("bzip2", c, cl, "bzip2", plain, sizeof(plain))) return 1;
        tested++;
    }
#endif
#ifdef HAVE_ZSTD
    {
        uint8_t c[2048];
        size_t cl = ZSTD_compress(c, sizeof(c), plain, sizeof(plain), 3);
        if (ZSTD_isError(cl) || extract_roundtrip("zstd", c, cl, "zstd", plain, sizeof(plain))) return 1;
        tested++;
    }
#endif
#ifdef HAVE_LZ4
    {
        uint8_t c[2048];
        size_t cl = LZ4F_compressFrame(c, sizeof(c), plain, sizeof(plain), NULL);
        if (LZ4F_isError(cl) || extract_roundtrip("lz4", c, cl, "lz4", plain, sizeof(plain))) return 1;
        tested++;
    }
#endif
    printf("PASS: test_codecs (%d of 3 optional codecs compiled in)\n", tested);
    return 0;
}

int run_all_tests(void) {
    tests_run = 0;
    tests_passed = 0;
    printf("=== automata engine tests ===\n\n");

    RUN_TEST(test_entropy_zeros);
    RUN_TEST(test_entropy_uniform);
    RUN_TEST(test_entropy_histogram);
    RUN_TEST(test_string_extract);
    RUN_TEST(test_identify_scan);
    RUN_TEST(test_identify_rejects_noise);
    RUN_TEST(test_identify_jffs2_crc);
    RUN_TEST(test_squashfs_validation);
    RUN_TEST(test_elf_validation);
    RUN_TEST(test_extract_gzip_roundtrip);
    RUN_TEST(test_tree_scan);
    RUN_TEST(test_report_escaping);
    RUN_TEST(test_secrets_scan);
    RUN_TEST(test_hash_fnv1a);
    RUN_TEST(test_bounds_readers);
    RUN_TEST(test_sha256);
    RUN_TEST(test_sbom_scan);
    RUN_TEST(test_cve_check);
    RUN_TEST(test_cve_no_false_positives);
    RUN_TEST(test_cve_true_positives);
    RUN_TEST(test_cve_iotgoat_ranges);
    RUN_TEST(test_secrets_false_positives);
    RUN_TEST(test_elf_kinds);
    RUN_TEST(test_sbom_opkg);
    RUN_TEST(test_counts_are_clamped);
    RUN_TEST(test_mkdirp);
    RUN_TEST(test_report_findings_layout);
    RUN_TEST(test_fwhdr_netgear_known_answer);
    RUN_TEST(test_fwhdr_chk_trx);
    RUN_TEST(test_fwhdr_uimage);
    RUN_TEST(test_binary_review);
    RUN_TEST(test_secrets_netgear_regressions);
    RUN_TEST(test_jffs2_extract);
    RUN_TEST(test_jffs2_hostile);
    RUN_TEST(test_cramfs);
    RUN_TEST(test_ubi_header);
    RUN_TEST(test_codecs);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
