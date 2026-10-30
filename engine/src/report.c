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

void report_print_safe(FILE *f, const char *s) {
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        fputc((c < 0x20 || c == 0x7f) ? '?' : c, f);
    }
}

void report_json_string(FILE *f, const char *s) {
    fputc('"', f);
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n", f); break;
            case '\r': fputs("\\r", f); break;
            case '\t': fputs("\\t", f); break;
            default:
                if (c < 0x20 || c == 0x7f) fprintf(f, "\\u%04x", c);
                else fputc(c, f);
        }
    }
    fputc('"', f);
}

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

    fprintf(f, "  \"extraction_ran\": %s,\n", result->extraction_ran ? "true" : "false");
    fprintf(f, "  \"tree\": { \"files_scanned\": %zu, \"files_skipped\": %zu, \"nested_extractions\": %zu, \"truncated\": %s },\n",
            result->tree_files_scanned, result->tree_files_skipped, result->nested_extractions,
            result->tree_truncated ? "true" : "false");
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
        fprintf(f, "    { \"path\": ");
        report_json_string(f, result->elfs[i].path);
        fprintf(f, ", \"ei_class\": %u, \"ei_data\": %u, \"arch\": \"%s\", \"is_pie\": %d, \"has_nx\": %d, \"has_relro\": %d, \"has_bind_now\": %d, \"is_stripped\": %d }%s\n",
                result->elfs[i].ei_class, result->elfs[i].ei_data, elf_arch_string(result->elfs[i].e_machine),
                result->elfs[i].is_pie, result->elfs[i].has_nx, result->elfs[i].has_relro, result->elfs[i].has_bind_now, result->elfs[i].is_stripped,
                (i + 1 < result->num_elfs) ? "," : "");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"secrets\": [\n");
    for (size_t i = 0; i < result->num_secrets; i++) {
        fprintf(f, "    { \"source\": ");
        report_json_string(f, result->secrets[i].source);
        fprintf(f, ", \"offset\": %zu, \"type\": \"%s\", \"description\": \"%s\", \"confidence\": %f }%s\n",
                result->secrets[i].offset, secret_type_string(result->secrets[i].type), result->secrets[i].description, result->secrets[i].confidence,
                (i + 1 < result->num_secrets) ? "," : "");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"components\": [\n");
    for (size_t i = 0; i < result->num_components; i++) {
        fprintf(f, "    { \"name\": ");
        report_json_string(f, result->components[i].name);
        fprintf(f, ", \"version\": ");
        report_json_string(f, result->components[i].version);
        fprintf(f, ", \"source\": ");
        report_json_string(f, result->components[i].source);
        fprintf(f, ", \"location\": ");
        report_json_string(f, result->components[i].location);
        fprintf(f, " }%s\n", (i + 1 < result->num_components) ? "," : "");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"cves\": [\n");
    for (size_t i = 0; i < result->num_cves; i++) {
        fprintf(f, "    { \"cve_id\": ");
        report_json_string(f, result->cves[i].cve_id);
        fprintf(f, ", \"severity\": ");
        report_json_string(f, result->cves[i].severity);
        fprintf(f, ", \"component\": ");
        report_json_string(f, result->cves[i].component);
        fprintf(f, ", \"description\": ");
        report_json_string(f, result->cves[i].description);
        fprintf(f, " }%s\n", (i + 1 < result->num_cves) ? "," : "");
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

    size_t shown = 0, hidden = 0;
    for (size_t i = 0; i < result->num_findings; i++) {
        if (result->findings[i].confidence < IDENTIFY_MIN_CONFIDENCE && !result->show_all_findings) { hidden++; continue; }
        shown++;
    }
    fprintf(f, "--- Findings (%zu) ---\n", shown);
    for (size_t i = 0; i < result->num_findings; i++) {
        if (result->findings[i].confidence < IDENTIFY_MIN_CONFIDENCE && !result->show_all_findings) continue;
        fprintf(f, "  0x%zx : %s (conf: %.2f)\n", result->findings[i].offset, result->findings[i].label, result->findings[i].confidence);
    }
    if (hidden > 0) fprintf(f, "  (%zu low-confidence findings hidden, use -v to show)\n", hidden);
    fprintf(f, "\n");

    if (result->extraction_ran) {
        fprintf(f, "--- Extractions (%zu) ---\n", result->num_extractions);
        for (size_t i = 0; i < result->num_extractions; i++) {
            fprintf(f, "  0x%zx : %s -> %s (compressed: %zu, decompressed: %zu)\n",
                    result->extractions[i].offset, result->extractions[i].type, result->extractions[i].path,
                    result->extractions[i].compressed, result->extractions[i].decompressed);
        }
        if (result->tree_files_scanned + result->tree_files_skipped > 0) {
            fprintf(f, "  Scanned %zu extracted files (%zu skipped, %zu nested archives unpacked)\n",
                    result->tree_files_scanned, result->tree_files_skipped, result->nested_extractions);
        }
        if (result->tree_truncated) {
            fprintf(f, "  WARNING: scan limits reached, extracted-tree results are incomplete\n");
        }
    } else {
        fprintf(f, "--- Extractions: not run (use -e) ---\n");
    }
    fprintf(f, "\n");

    fprintf(f, "--- ELFs (%zu) ---\n", result->num_elfs);
    for (size_t i = 0; i < result->num_elfs; i++) {
        if (result->elfs[i].path[0]) { fprintf(f, "  "); report_print_safe(f, result->elfs[i].path); fprintf(f, "\n  "); }
        fprintf(f, "  Arch: %s, Class: %d-bit, Endian: %s, PIE: %d, NX: %d, RELRO: %s, Stripped: %d\n",
                elf_arch_string(result->elfs[i].e_machine),
                result->elfs[i].ei_class == 2 ? 64 : 32,
                result->elfs[i].ei_data == 2 ? "Big" : "Little",
                result->elfs[i].is_pie, result->elfs[i].has_nx, elf_relro_string(&result->elfs[i]), result->elfs[i].is_stripped);
    }
    fprintf(f, "\n");

    fprintf(f, "--- Secrets (%zu) ---\n", result->num_secrets);
    for (size_t i = 0; i < result->num_secrets; i++) {
        fprintf(f, "  0x%zx : %s [%s] (conf: %.2f)",
                result->secrets[i].offset, secret_type_string(result->secrets[i].type), result->secrets[i].description, result->secrets[i].confidence);
        if (result->secrets[i].source[0]) { fprintf(f, " in "); report_print_safe(f, result->secrets[i].source); }
        fprintf(f, "\n");
    }

    if (f != stdout) fclose(f);
}
