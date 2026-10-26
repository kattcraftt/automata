/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#define _GNU_SOURCE
#include "automata/automata.h"
#include "automata/sbom.h"
#include "automata/cve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

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
    uint8_t buf[] = "test1234\x00\x01hello_world\x02\x03ab";
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

/* ── Identify (signature scan) tests ── */
static int test_identify_scan(void) {
    uint8_t buf[100] = {0};
    /* Place gzip magic at offset 10 */
    buf[10] = 0x1f;
    buf[11] = 0x8b;
    /* Place ELF magic at offset 50 */
    buf[50] = 0x7f;
    buf[51] = 'E';
    buf[52] = 'L';
    buf[53] = 'F';
    /* Place U-Boot magic \x27\x05\x19\x56 at offset 60 */
    buf[60] = 0x27;
    buf[61] = 0x05;
    buf[62] = 0x19;
    buf[63] = 0x56;

    finding_t findings[32];
    size_t num_findings = 0;
    identify_scan(buf, sizeof(buf), findings, 32, &num_findings);

    if (num_findings < 3) {
        printf("FAIL: test_identify_scan (found %zu, expected >= 3)\n", num_findings);
        return 1;
    }

    int found_gzip = 0;
    int found_uboot = 0;
    for (size_t i = 0; i < num_findings; i++) {
        if (findings[i].offset == 10) {
            const char *l = findings[i].label;
            if (strcasestr(l, "gzip") != NULL || strcasestr(l, "gz") != NULL) {
                found_gzip = 1;
            }
        }
        if (findings[i].offset == 60) {
            const char *l = findings[i].label;
            if (strcasestr(l, "u-boot") != NULL || strcasestr(l, "uboot") != NULL) {
                found_uboot = 1;
            }
        }
    }

    if (!found_gzip) {
        printf("FAIL: test_identify_scan (gzip not found at offset 10, got %zu findings)\n", num_findings);
        for (size_t i = 0; i < num_findings; i++) {
            printf("  [%zu] offset=%zu label='%s'\n", i, findings[i].offset, findings[i].label);
        }
        return 1;
    }
    if (!found_uboot) {
        printf("FAIL: test_identify_scan (U-Boot not found at offset 60, got %zu findings)\n", num_findings);
        for (size_t i = 0; i < num_findings; i++) {
            printf("  [%zu] offset=%zu label='%s'\n", i, findings[i].offset, findings[i].label);
        }
        return 1;
    }

    printf("PASS: test_identify_scan\n");
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

int run_all_tests(void) {
    tests_run = 0;
    tests_passed = 0;
    printf("=== automata engine tests ===\n\n");

    RUN_TEST(test_entropy_zeros);
    RUN_TEST(test_entropy_uniform);
    RUN_TEST(test_entropy_histogram);
    RUN_TEST(test_string_extract);
    RUN_TEST(test_identify_scan);
    RUN_TEST(test_secrets_scan);
    RUN_TEST(test_hash_fnv1a);
    RUN_TEST(test_bounds_readers);
    RUN_TEST(test_sha256);
    RUN_TEST(test_sbom_scan);
    RUN_TEST(test_cve_check);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
