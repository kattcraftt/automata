/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_REPORT_H
#define AUTOMATA_REPORT_H

#include <stdio.h>
#include "automata/elf.h"
#include "automata/identify.h"
#include "automata/extract.h"
#include "automata/secrets.h"
#include "automata/sbom.h"
#include "automata/cve.h"
typedef struct {
    char filename[256];
    size_t file_size;
    uint8_t sha256[32];
    double overall_entropy;
    
    finding_t *findings;
    size_t num_findings;
    
    extract_result_t *extractions;
    size_t num_extractions;
    int extraction_ran;        /* 1 if -e was given; 0 means "not run", not "found nothing" */
    int show_all_findings;     /* 1 = print low-confidence findings too (-v) */
    size_t tree_files_scanned; /* files read from extracted trees */
    size_t tree_files_skipped;
    size_t nested_extractions; /* archives unpacked inside extracted trees (-r) */
    int tree_truncated;        /* a limit was hit: extracted-tree results are incomplete */
    
    elf_info_t *elfs;
    size_t num_elfs;
    
    secret_finding_t *secrets;
    size_t num_secrets;
    
    component_t *components;   /* SBOM, included in JSON output */
    size_t num_components;
    cve_entry_t *cves;
    size_t num_cves;

    size_t num_strings;
    double analysis_time_secs;
} analysis_result_t;

/* Untrusted strings (paths from firmware) must never reach the terminal or JSON raw. */
void report_print_safe(FILE *f, const char *s);   /* control chars -> '?' */
void report_json_string(FILE *f, const char *s);  /* quoted, escaped JSON string */

void report_json(const analysis_result_t *result, const char *out_path);
void report_human(const analysis_result_t *result, const char *out_path);

#endif /* AUTOMATA_REPORT_H */
