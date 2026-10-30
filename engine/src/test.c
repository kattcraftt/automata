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
#include <unistd.h>
#include <ftw.h>
#include <sys/stat.h>

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
    uint8_t buf[256] = {0};
    const char *key = "-----BEGIN RSA PRIVATE KEY-----";
    memcpy(buf + 50, key, strlen(key));

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

    const char *pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----\n";
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

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
