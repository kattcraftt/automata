/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#define _GNU_SOURCE
#include "automata/automata.h"
#include "automata/squashfs.h"
#include "automata/sbom.h"
#include "automata/cve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern int run_all_tests(void);

static void print_banner(void) {
    printf("   ___         __                   __\n");
    printf("  / _ | __ __ / /_ ___  __ _  ___  / /_ ___ _\n");
    printf(" / __ |/ // // __// _ \\/  ' \\/ _ `/ __// _ `/\n");
    printf("/_/ |_|\\_,_/ \\__/ \\___/_/_/_/\\_,_/\\__/ \\_,_/\n");
    printf("   firmware analysis engine v%s\n\n", AUTOMATA_VERSION);
}

static void print_usage(const char *prog) {
    printf("Usage: %s <subcommand> [options] [arguments]\n\n", prog);
    printf("Subcommands:\n");
    printf("  scan <file> [-j] [-e] [-r] [-v] [-o DIR]   Full analysis\n");
    printf("  test                                       Run self-tests\n");
    printf("  extract <file> [-o DIR] [-r]               Extract only\n");
    printf("  info <file>                                Quick file info\n");
    printf("  version                                    Version\n");
    printf("  help                                       Help\n\n");
    printf("Options:\n");
    printf("  -j          JSON output\n");
    printf("  -e          Extract found compressed regions\n");
    printf("  -r          Recursive extraction (TODO)\n");
    printf("  -v          Verbose output\n");
    printf("  -o DIR      Output directory (default: <file>.extracted/)\n");
}

static void print_entropy_sparkline(const entropy_map_t *map) {
    if (!map || map->count == 0 || !map->values) return;
    static const char *sparks[] = {" ", " ", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
    printf("Entropy Sparkline: ");
    size_t step = (map->count > 64) ? (map->count / 64) : 1;
    for (size_t i = 0; i < map->count; i += step) {
        double v = map->values[i];
        int idx = (int)((v / 8.0) * 8.0);
        if (idx < 0) idx = 0;
        if (idx > 8) idx = 8;
        printf("%s", sparks[idx]);
    }
    printf("\n");
}

static int cmd_scan(int argc, char **argv) {
    int json_mode = 0;
    int extract_mode = 0;
    int recursive_mode = 0;
    int verbose = 0;
    const char *outdir = NULL;
    const char *input_file = NULL;

    /* ── Parse CLI arguments ── */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-j") == 0) {
            json_mode = 1;
        } else if (strcmp(argv[i], "-e") == 0) {
            extract_mode = 1;
        } else if (strcmp(argv[i], "-r") == 0) {
            recursive_mode = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outdir = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            input_file = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 2;
        }
    }

    if (!input_file) {
        fprintf(stderr, "Error: no input file specified for scan.\n\n");
        print_usage(argv[0]);
        return 2;
    }
    (void)recursive_mode;

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

    /* ── Entropy sliding map ── */
    entropy_map_t emap;
    memset(&emap, 0, sizeof(emap));
    size_t win = (mf.size > 2048) ? (mf.size / 64) : (mf.size > 64 ? 64 : mf.size);
    if (win == 0) win = 1;
    entropy_sliding_map(mf.data, mf.size, win, win, &emap);

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
    res.num_strings = str_count;

    /* ── SBOM component detection ── */
    component_t components[256];
    size_t num_components = 0;
    sbom_scan(mf.data, mf.size, components, 256, &num_components);

    /* ── CVE correlation ── */
    cve_entry_t cves[256];
    size_t num_cves = 0;
    if (num_components > 0) {
        cve_check(components, num_components, cves, 256, &num_cves);
    }

    /* ── Finalize timing ── */
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    res.analysis_time_secs = (double)(ts_end.tv_sec - ts_start.tv_sec) +
                             (double)(ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;

    /* ── Output ── */
    if (json_mode) {
        report_json(&res, NULL);
        printf("{\n  \"components\": [\n");
        for (size_t i = 0; i < num_components; i++) {
            printf("    { \"name\": \"%s\", \"version\": \"%s\", \"source\": \"%s\" }%s\n",
                   components[i].name, components[i].version, components[i].source,
                   (i + 1 < num_components) ? "," : "");
        }
        printf("  ],\n  \"cves\": [\n");
        for (size_t i = 0; i < num_cves; i++) {
            printf("    { \"cve_id\": \"%s\", \"severity\": \"%s\", \"component\": \"%s\", \"description\": \"%s\" }%s\n",
                   cves[i].cve_id, cves[i].severity, cves[i].component, cves[i].description,
                   (i + 1 < num_cves) ? "," : "");
        }
        printf("  ]\n}\n");
    } else {
        report_human(&res, NULL);
        print_entropy_sparkline(&emap);

        printf("\n--- Components (SBOM) ---\n");
        if (num_components == 0) {
            printf("  None detected\n");
        } else {
            for (size_t i = 0; i < num_components; i++) {
                printf("  %-20s %s (%s)\n", components[i].name, components[i].version, components[i].source);
            }
        }

        printf("\n--- CVE Matches ---\n");
        if (num_cves == 0) {
            printf("  None detected\n");
        } else {
            for (size_t i = 0; i < num_cves; i++) {
                printf("  [%s] %-16s %-12s: %s\n",
                       cves[i].severity, cves[i].cve_id, cves[i].component, cves[i].description);
            }
        }
    }

    entropy_map_free(&emap);
    unmap_file(&mf);
    return 0;
}

static int cmd_test(int argc, char **argv) {
    (void)argc;
    (void)argv;
    return run_all_tests();
}

static int cmd_extract(int argc, char **argv) {
    const char *input_file = NULL;
    const char *outdir = NULL;
    int recursive_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) {
            recursive_mode = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outdir = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: automata extract <file> [-o DIR] [-r]\n");
            return 0;
        } else if (argv[i][0] != '-') {
            input_file = argv[i];
        } else {
            fprintf(stderr, "Unknown extract option: %s\n", argv[i]);
            return 2;
        }
    }

    if (!input_file) {
        fprintf(stderr, "Error: no input file specified for extract.\n");
        return 2;
    }
    (void)recursive_mode;

    mapped_file_t mf;
    if (map_file(input_file, &mf) != 0) {
        fprintf(stderr, "Error: failed to open '%s'\n", input_file);
        return 1;
    }

    finding_t findings[4096];
    size_t num_findings = 0;
    identify_scan(mf.data, mf.size, findings, 4096, &num_findings);

    char default_outdir[512];
    if (!outdir) {
        snprintf(default_outdir, sizeof(default_outdir), "%s.extracted", input_file);
        outdir = default_outdir;
    }

    extract_result_t extractions[256];
    size_t num_extractions = 0;
    extract_all(mf.data, mf.size, outdir, extractions, 256, &num_extractions);

    printf("Extracted %zu regions to %s\n", num_extractions, outdir);
    for (size_t i = 0; i < num_extractions; i++) {
        printf("  [0x%08zx] %-16s -> %s (%zu bytes)\n",
               extractions[i].offset, extractions[i].type, extractions[i].path, extractions[i].decompressed);
    }

    unmap_file(&mf);
    return 0;
}

static int cmd_info(int argc, char **argv) {
    const char *input_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: automata info <file>\n");
            return 0;
        } else if (argv[i][0] != '-') {
            input_file = argv[i];
        } else {
            fprintf(stderr, "Unknown info option: %s\n", argv[i]);
            return 2;
        }
    }

    if (!input_file) {
        fprintf(stderr, "Error: no input file specified for info.\n");
        return 2;
    }

    mapped_file_t mf;
    if (map_file(input_file, &mf) != 0) {
        fprintf(stderr, "Error: failed to open '%s'\n", input_file);
        return 1;
    }

    uint8_t sha[32];
    sha256_hash(mf.data, mf.size, sha);

    double ent = entropy_calculate(mf.data, mf.size);

    finding_t findings[4096];
    size_t num_findings = 0;
    identify_scan(mf.data, mf.size, findings, 4096, &num_findings);

    printf("File:            %s\n", input_file);
    printf("Size:            %zu bytes\n", mf.size);
    printf("SHA-256:         ");
    for (int i = 0; i < 32; i++) printf("%02x", sha[i]);
    printf("\n");
    printf("Entropy:         %.4f\n", ent);
    printf("Signatures:      %zu\n", num_findings);

    unmap_file(&mf);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_banner();
        print_usage(argv[0]);
        return 2;
    }

    const char *subcmd = argv[1];

    if (strcmp(subcmd, "scan") == 0) {
        return cmd_scan(argc - 1, argv + 1);
    } else if (strcmp(subcmd, "test") == 0) {
        return cmd_test(argc - 1, argv + 1);
    } else if (strcmp(subcmd, "extract") == 0) {
        return cmd_extract(argc - 1, argv + 1);
    } else if (strcmp(subcmd, "info") == 0) {
        return cmd_info(argc - 1, argv + 1);
    } else if (strcmp(subcmd, "version") == 0 || strcmp(subcmd, "--version") == 0) {
        printf("automata v%s\n", AUTOMATA_VERSION);
        return 0;
    } else if (strcmp(subcmd, "help") == 0 || strcmp(subcmd, "--help") == 0 || strcmp(subcmd, "-h") == 0) {
        print_banner();
        print_usage(argv[0]);
        return 0;
    } else {
        fprintf(stderr, "Unknown subcommand: %s\n\n", subcmd);
        print_usage(argv[0]);
        return 2;
    }
}
