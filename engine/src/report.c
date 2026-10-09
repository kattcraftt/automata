/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "automata/identify.h"
#include "automata/extract.h"
#include "automata/secrets.h"
#include "automata/elf.h"
#include "automata/report.h"

void report_json(const analysis_result_t *result, const char *out_path) {
    FILE *f = stdout;
    if (out_path) {
        f = fopen(out_path, "w");
        if (!f) return;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"filename\": \"%s\",\n", result->filename);
    fprintf(f, "  \"file_size\": %zu,\n", result->file_size);
    fprintf(f, "  \"analysis_time_secs\": %f,\n", result->analysis_time_secs);
    fprintf(f, "  \"overall_entropy\": %f,\n", result->overall_entropy);
    fprintf(f, "  \"num_strings\": %zu,\n", result->num_strings);
    
    fprintf(f, "  \"sha256\": \"");
    for (size_t i = 0; i < 32; i++) {
        fprintf(f, "%02x", result->sha256[i]);
    }
    fprintf(f, "\",\n");

    fprintf(f, "  \"findings\": [\n");
    for (size_t i = 0; i < result->num_findings; i++) {
        fprintf(f, "    { \"offset\": %zu, \"label\": \"%s\", \"confidence\": %f }%s\n",
                result->findings[i].offset, result->findings[i].label, result->findings[i].confidence,
                (i + 1 < result->num_findings) ? "," : "");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"extractions\": [\n");
    for (size_t i = 0; i < result->num_extractions; i++) {
        fprintf(f, "    { \"offset\": %zu, \"type\": \"%s\", \"path\": \"%s\", \"compressed\": %zu, \"decompressed\": %zu }%s\n",
                result->extractions[i].offset, result->extractions[i].type, result->extractions[i].path,
                result->extractions[i].compressed, result->extractions[i].decompressed,
                (i + 1 < result->num_extractions) ? "," : "");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"elfs\": [\n");
    for (size_t i = 0; i < result->num_elfs; i++) {
        fprintf(f, "    { \"ei_class\": %u, \"ei_data\": %u, \"arch\": \"%s\", \"is_pie\": %d, \"has_nx\": %d, \"has_relro\": %d, \"is_stripped\": %d }%s\n",
                result->elfs[i].ei_class, result->elfs[i].ei_data, elf_arch_string(result->elfs[i].e_machine),
                result->elfs[i].is_pie, result->elfs[i].has_nx, result->elfs[i].has_relro, result->elfs[i].is_stripped,
                (i + 1 < result->num_elfs) ? "," : "");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"secrets\": [\n");
    for (size_t i = 0; i < result->num_secrets; i++) {
        fprintf(f, "    { \"offset\": %zu, \"type\": \"%s\", \"description\": \"%s\", \"confidence\": %f }%s\n",
                result->secrets[i].offset, secret_type_string(result->secrets[i].type), result->secrets[i].description, result->secrets[i].confidence,
                (i + 1 < result->num_secrets) ? "," : "");
    }
    fprintf(f, "  ]\n");

    fprintf(f, "}\n");

    if (f != stdout) fclose(f);
}

void report_human(const analysis_result_t *result, const char *out_path) {
    FILE *f = stdout;
    if (out_path) {
        f = fopen(out_path, "w");
        if (!f) return;
    }

    fprintf(f, "Analysis Report: %s\n", result->filename);
    fprintf(f, "Size: %zu bytes\n", result->file_size);
    
    fprintf(f, "SHA256: ");
    for (size_t i = 0; i < 32; i++) {
        fprintf(f, "%02x", result->sha256[i]);
    }
    fprintf(f, "\n");
    
    fprintf(f, "Entropy: %.4f\n", result->overall_entropy);
    fprintf(f, "Time: %.2fs\n", result->analysis_time_secs);
    fprintf(f, "Strings: %zu\n", result->num_strings);
    fprintf(f, "\n");

    fprintf(f, "--- Findings (%zu) ---\n", result->num_findings);
    for (size_t i = 0; i < result->num_findings; i++) {
        fprintf(f, "  0x%zx : %s (conf: %.2f)\n", result->findings[i].offset, result->findings[i].label, result->findings[i].confidence);
    }
    fprintf(f, "\n");

    fprintf(f, "--- Extractions (%zu) ---\n", result->num_extractions);
    for (size_t i = 0; i < result->num_extractions; i++) {
        fprintf(f, "  0x%zx : %s -> %s (compressed: %zu, decompressed: %zu)\n",
                result->extractions[i].offset, result->extractions[i].type, result->extractions[i].path,
                result->extractions[i].compressed, result->extractions[i].decompressed);
    }
    fprintf(f, "\n");

    fprintf(f, "--- ELFs (%zu) ---\n", result->num_elfs);
    for (size_t i = 0; i < result->num_elfs; i++) {
        fprintf(f, "  Arch: %s, Class: %d-bit, Endian: %s, PIE: %d, NX: %d, RELRO: %d, Stripped: %d\n",
                elf_arch_string(result->elfs[i].e_machine),
                result->elfs[i].ei_class == 2 ? 64 : 32,
                result->elfs[i].ei_data == 2 ? "Big" : "Little",
                result->elfs[i].is_pie, result->elfs[i].has_nx, result->elfs[i].has_relro, result->elfs[i].is_stripped);
    }
    fprintf(f, "\n");

    fprintf(f, "--- Secrets (%zu) ---\n", result->num_secrets);
    for (size_t i = 0; i < result->num_secrets; i++) {
        fprintf(f, "  0x%zx : %s [%s] (conf: %.2f)\n",
                result->secrets[i].offset, secret_type_string(result->secrets[i].type), result->secrets[i].description, result->secrets[i].confidence);
    }

    if (f != stdout) fclose(f);
}
