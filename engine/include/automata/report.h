/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_REPORT_H
#define AUTOMATA_REPORT_H

#include "automata/elf.h"
#include "automata/identify.h"
#include "automata/extract.h"
#include "automata/secrets.h"

typedef struct {
    char filename[256];
    size_t file_size;
    uint8_t sha256[32];
    double overall_entropy;
    
    finding_t *findings;
    size_t num_findings;
    
    extract_result_t *extractions;
    size_t num_extractions;
    
    elf_info_t *elfs;
    size_t num_elfs;
    
    secret_finding_t *secrets;
    size_t num_secrets;
    
    size_t num_strings;
    double analysis_time_secs;
} analysis_result_t;

void report_json(const analysis_result_t *result, const char *out_path);
void report_human(const analysis_result_t *result, const char *out_path);

#endif /* AUTOMATA_REPORT_H */
