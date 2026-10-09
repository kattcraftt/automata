/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#define _GNU_SOURCE
#include "automata/automata.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_banner(void) {
    printf("   ___         __                  __\n");
    printf("  / _ | __ __ / /_ ___  __ _  ___ / /_ ___ _\n");
    printf(" / __ |/ // // __// _ \\/  ' \\/ _ `/ __// _ `/\n");
    printf("/_/ |_|\\_,_/ \\__/ \\___/_/_/_/\\_,_/\\__/ \\_,_/\n");
    printf("   firmware analysis engine v%s\n\n", AUTOMATA_VERSION);
}

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS] <file>\n\n", prog);
    printf("Options:\n");
    printf("  -j          JSON output\n");
    printf("  -e          Extract found compressed regions\n");
    printf("  -v          Verbose output\n");
    printf("  -o DIR      Output directory (default: <file>.extracted/)\n");
    printf("  --version   Print version and exit\n");
    printf("  --help      Print this help and exit\n");
}

int main(int argc, char **argv) {
    int json_mode = 0;
    int extract_mode = 0;
    int verbose = 0;
    const char *outdir = NULL;
    const char *input_file = NULL;

    /* ── Parse CLI arguments ── */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("automata v%s\n", AUTOMATA_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-j") == 0) {
            json_mode = 1;
        } else if (strcmp(argv[i], "-e") == 0) {
            extract_mode = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outdir = argv[++i];
        } else if (argv[i][0] != '-') {
            input_file = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (!input_file) {
        fprintf(stderr, "Error: no input file specified.\n\n");
        print_usage(argv[0]);
        return 2;
    }

    if (!json_mode) {
        print_banner();
    }

    /* ── Start timing ── */
    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    /* ── Map input file ── */
    mapped_file_t mf;
    if (map_file(input_file, &mf) != 0) {
        fprintf(stderr, "Error: failed to open '%s'\n", input_file);
        return 1;
    }

    if (verbose) {
        fprintf(stderr, "[*] Loaded %s (%zu bytes)\n", input_file, mf.size);
    }

    /* ── Initialize result struct ── */
    analysis_result_t res;
    memset(&res, 0, sizeof(res));
    safe_strncpy(res.filename, input_file, sizeof(res.filename));
    res.file_size = mf.size;

    /* ── SHA-256 ── */
    sha256_hash(mf.data, mf.size, res.sha256);

    /* ── Overall entropy ── */
    res.overall_entropy = entropy_calculate(mf.data, mf.size);

    if (verbose) {
        fprintf(stderr, "[*] Entropy: %.4f\n", res.overall_entropy);
    }

    /* ── Signature identification ── */
    finding_t findings[4096];
    size_t num_findings = 0;
    identify_scan(mf.data, mf.size, findings, 4096, &num_findings);
    res.findings = findings;
    res.num_findings = num_findings;

    if (verbose) {
        fprintf(stderr, "[*] Found %zu signatures\n", num_findings);
    }

    /* ── Extraction (if -e) ── */
    extract_result_t extractions[256];
    size_t num_extractions = 0;
    if (extract_mode) {
        /* Build default outdir if not specified */
        char default_outdir[512];
        if (!outdir) {
            snprintf(default_outdir, sizeof(default_outdir), "%s.extracted", input_file);
            outdir = default_outdir;
        }
        extract_all(mf.data, mf.size, outdir, extractions, 256, &num_extractions);
        res.extractions = extractions;
        res.num_extractions = num_extractions;

        if (verbose) {
            fprintf(stderr, "[*] Extracted %zu regions to %s\n", num_extractions, outdir);
        }
    }

    /* ── ELF binary detection ── */
    elf_info_t elfs[256];
    size_t num_elfs = 0;
    if (mf.size >= 4) {
        for (size_t i = 0; i <= mf.size - 4 && num_elfs < 256; i++) {
            if (mf.data[i] == 0x7f && mf.data[i+1] == 'E' &&
                mf.data[i+2] == 'L' && mf.data[i+3] == 'F') {
                if (elf_parse_buf(mf.data + i, mf.size - i, &elfs[num_elfs]) == 0) {
                    num_elfs++;
                }
            }
        }
    }
    res.elfs = elfs;
    res.num_elfs = num_elfs;

    if (verbose) {
        fprintf(stderr, "[*] Found %zu ELF binaries\n", num_elfs);
    }

    /* ── Secrets scan ── */
    secret_finding_t secrets[1024];
    size_t num_secrets = 0;
    secrets_scan(mf.data, mf.size, secrets, 1024, &num_secrets);
    res.secrets = secrets;
    res.num_secrets = num_secrets;

    if (verbose) {
        fprintf(stderr, "[*] Found %zu potential secrets\n", num_secrets);
    }

    /* ── String extraction (count only) ── */
    extracted_string_t str_buf[128];
    size_t str_count = 0;
    string_extract(mf.data, mf.size, 4, str_buf, 128, &str_count);
    /* str_count here is capped at 128; for real count we'd need a larger buffer
       or a counting-only pass. For now this gives a lower bound. */
    res.num_strings = str_count;

    /* ── Finalize timing ── */
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    res.analysis_time_secs = (double)(ts_end.tv_sec - ts_start.tv_sec) +
                             (double)(ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;

    /* ── Output ── */
    if (json_mode) {
        report_json(&res, NULL);   /* NULL = write to stdout */
    } else {
        report_human(&res, NULL);  /* NULL = write to stdout */
    }

    /* ── Cleanup ── */
    unmap_file(&mf);
    return 0;
}
