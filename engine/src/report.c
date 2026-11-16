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
    fprintf(f, "  \"filename\": ");
    report_json_string(f, result->filename);
    fprintf(f, ",\n");
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
        fprintf(f, "    { \"offset\": %zu, \"label\": \"%s\", \"confidence\": %f, \"length\": %zu }%s\n",
                result->findings[i].offset, result->findings[i].label, result->findings[i].confidence, result->findings[i].length,
                (i + 1 < result->num_findings) ? "," : "");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"extraction_ran\": %s,\n", result->extraction_ran ? "true" : "false");
    fprintf(f, "  \"tree\": { \"files_scanned\": %zu, \"files_skipped\": %zu, \"nested_extractions\": %zu, \"truncated\": %s },\n",
            result->tree_files_scanned, result->tree_files_skipped, result->nested_extractions,
            result->tree_truncated ? "true" : "false");
    fprintf(f, "  \"image_headers\": [\n");
    for (size_t i = 0; i < result->num_headers; i++) {
        const fwhdr_t *h = &result->headers[i];
        fprintf(f, "    { \"offset\": %zu, \"format\": ", h->offset);
        report_json_string(f, h->format);
        fprintf(f, ", \"summary\": ");
        report_json_string(f, h->summary);
        fprintf(f, ", \"length\": %zu, \"integrity\": %d, \"checks\": ", h->length, h->integrity);
        report_json_string(f, h->checks);
        fprintf(f, ", \"partitions\": [");
        for (size_t k = 0; k < h->num_parts; k++) {
            fprintf(f, "%s{ \"name\": ", k ? ", " : "");
            report_json_string(f, h->part_name[k]);
            fprintf(f, ", \"offset\": %zu, \"length\": %zu }", h->part_offset[k], h->part_length[k]);
        }
        fprintf(f, "] }%s\n", (i + 1 < result->num_headers) ? "," : "");
    }
    fprintf(f, "  ],\n");
    fprintf(f, "  \"extractions\": [\n");
    for (size_t i = 0; i < result->num_extractions; i++) {
        fprintf(f, "    { \"offset\": %zu, \"type\": \"%s\", \"path\": ", result->extractions[i].offset, result->extractions[i].type);
        report_json_string(f, result->extractions[i].path);
        fprintf(f, ", \"compressed\": %zu, \"decompressed\": %zu }%s\n",
                result->extractions[i].compressed, result->extractions[i].decompressed,
                (i + 1 < result->num_extractions) ? "," : "");
    }
    fprintf(f, "  ],\n");

    fprintf(f, "  \"elfs\": [\n");
    for (size_t i = 0; i < result->num_elfs; i++) {
        fprintf(f, "    { \"path\": ");
        report_json_string(f, result->elfs[i].path);
        fprintf(f, ", \"ei_class\": %u, \"ei_data\": %u, \"arch\": \"%s\", \"is_pie\": %d, \"has_nx\": %d, \"has_relro\": %d, \"has_bind_now\": %d, \"is_stripped\": %d, \"kind\": \"%s\", \"pie\": \"%s\", \"nx\": \"%s\", \"relro\": \"%s\", \"caps\": %u, \"risk\": \"%s\", \"risk_note\": ",
                result->elfs[i].ei_class, result->elfs[i].ei_data, elf_arch_string(result->elfs[i].e_machine),
                result->elfs[i].is_pie, result->elfs[i].has_nx, result->elfs[i].has_relro, result->elfs[i].has_bind_now, result->elfs[i].is_stripped,
                elf_kind_string(&result->elfs[i]), elf_pie_string(&result->elfs[i]), elf_nx_string(&result->elfs[i]), elf_relro_string(&result->elfs[i]),
                result->elfs[i].caps, elf_risk_string(result->elfs[i].risk));
        report_json_string(f, result->elfs[i].risk_note);
        fprintf(f, " }%s\n", (i + 1 < result->num_elfs) ? "," : "");
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
        fprintf(f, ", \"condition\": ");
        report_json_string(f, result->cves[i].condition);
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

    if (result->num_headers > 0) {
        fprintf(f, "--- Image headers (%zu) ---\n", result->num_headers);
        for (size_t i = 0; i < result->num_headers; i++) {
            const fwhdr_t *h = &result->headers[i];
            fprintf(f, "  0x%zx : %s, %s\n", h->offset, h->format, h->summary);
            if (h->checks[0])
                fprintf(f, "      %s%s\n", h->checks, h->integrity == 0 ? "   <-- integrity problem" : "");
            for (size_t k = 0; k < h->num_parts; k++)
                fprintf(f, "      %s @0x%zx (%zu bytes)\n", h->part_name[k], h->part_offset[k], h->part_length[k]);
        }
        fprintf(f, "\n");
    }

    /* Findings: hide low confidence, fold what lies inside a validated container
     * (e.g. the ~60 XZ blocks of a SquashFS), and group long runs of the same type. */
    size_t nf = result->num_findings;
    size_t *vis = malloc((nf + 1) * sizeof(size_t));
    size_t *inside = calloc(nf + 1, sizeof(size_t));
    size_t nvis = 0, hidden = 0;
    if (vis && inside) {
        size_t cover_end = 0, cover_vis = (size_t)-1;
        for (size_t i = 0; i < nf; i++) {
            const finding_t *fd = &result->findings[i];
            if (!result->show_all_findings && fd->confidence < IDENTIFY_MIN_CONFIDENCE) { hidden++; continue; }
            if (!result->show_all_findings && cover_vis != (size_t)-1 && fd->offset < cover_end) { inside[cover_vis]++; continue; }
            vis[nvis] = i;
            if (fd->length > 0 && fd->confidence >= 0.9f) { cover_end = fd->offset + fd->length; cover_vis = nvis; }
            nvis++;
        }
    }
    fprintf(f, "--- Findings (%zu) ---\n", nvis);
    for (size_t a2 = 0; a2 < nvis; ) {
        const finding_t *fd = &result->findings[vis[a2]];
        size_t b2 = a2 + 1;
        if (!result->show_all_findings && fd->length == 0 && inside[a2] == 0) {
            while (b2 < nvis && result->findings[vis[b2]].type == fd->type && fd->type != SIG_UNKNOWN &&
                   result->findings[vis[b2]].length == 0 && inside[b2] == 0) b2++;
        }
        if (b2 - a2 >= 4) {
            fprintf(f, "  0x%zx .. 0x%zx : %s x%zu (conf: %.2f)\n", fd->offset, result->findings[vis[b2 - 1]].offset,
                    fd->label, b2 - a2, fd->confidence);
        } else {
            b2 = a2 + 1;
            fprintf(f, "  0x%zx : %s (conf: %.2f)", fd->offset, fd->label, fd->confidence);
            if (fd->length > 0) fprintf(f, " [%zu bytes]", fd->length);
            fprintf(f, "\n");
            if (inside[a2] > 0) fprintf(f, "    (%zu more findings inside this region hidden, use -v)\n", inside[a2]);
        }
        a2 = b2;
    }
    free(vis);
    free(inside);
    if (hidden > 0) fprintf(f, "  (%zu low-confidence findings hidden, use -v to show)\n", hidden);
    fprintf(f, "\n");

    if (result->extraction_ran) {
        fprintf(f, "--- Extractions (%zu) ---\n", result->num_extractions);
        for (size_t i = 0; i < result->num_extractions; i++) {
            fprintf(f, "  0x%zx : %s -> ", result->extractions[i].offset, result->extractions[i].type);
            report_print_safe(f, result->extractions[i].path);
            if (result->extractions[i].decompressed > 0)
                fprintf(f, " (compressed: %zu, decompressed: %zu)\n", result->extractions[i].compressed, result->extractions[i].decompressed);
            else
                fprintf(f, " (%zu bytes of image unpacked)\n", result->extractions[i].compressed);
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
    {
        size_t n_exec = 0, n_pie = 0, n_shared = 0, n_rel = 0, nx_off = 0, nx_unknown = 0, pie_off = 0;
        size_t rel_none = 0, rel_partial = 0, rel_full = 0;
        for (size_t i = 0; i < result->num_elfs; i++) {
            const elf_info_t *e = &result->elfs[i];
            if (e->kind == ELF_KIND_EXEC) { n_exec++; pie_off++; }
            else if (e->kind == ELF_KIND_PIE) n_pie++;
            else if (e->kind == ELF_KIND_SHARED) n_shared++;
            else if (e->kind == ELF_KIND_RELOCATABLE) n_rel++;
            if (e->kind == ELF_KIND_EXEC || e->kind == ELF_KIND_PIE || e->kind == ELF_KIND_SHARED) {
                if (e->has_gnu_stack && !e->has_nx) nx_off++;
                else if (!e->has_gnu_stack) nx_unknown++;
                const char *rs = elf_relro_string(e);
                if (strcmp(rs, "Full") == 0) rel_full++; else if (strcmp(rs, "Partial") == 0) rel_partial++; else rel_none++;
            }
        }
        if (result->num_elfs > 0 && result->elfs[0].path[0]) {
            fprintf(f, "  Summary: %zu executables, %zu PIE executables, %zu shared objects, %zu relocatable objects\n", n_exec, n_pie, n_shared, n_rel);
            fprintf(f, "  Hardening: stack executable (NX off): %zu, NX unknown: %zu, non-PIE executables: %zu, RELRO none/partial/full: %zu/%zu/%zu\n",
                    nx_off, nx_unknown, pie_off, rel_none, rel_partial, rel_full);
            if (nx_off > 0) {
                fprintf(f, "  NX disabled:");
                size_t listed = 0;
                for (size_t i = 0; i < result->num_elfs && listed < 10; i++) {
                    const elf_info_t *e = &result->elfs[i];
                    if ((e->kind == ELF_KIND_EXEC || e->kind == ELF_KIND_PIE || e->kind == ELF_KIND_SHARED) && e->has_gnu_stack && !e->has_nx) {
                        fprintf(f, "%s ", listed ? "," : ""); report_print_safe(f, e->path); listed++;
                    }
                }
                if (nx_off > listed) fprintf(f, ", ... (%zu more)", nx_off - listed);
                fprintf(f, "\n");
            }
        }
        size_t skipped_rel = 0;
        for (size_t i = 0; i < result->num_elfs; i++) {
            const elf_info_t *e = &result->elfs[i];
            if (e->kind == ELF_KIND_RELOCATABLE && !result->show_all_findings) { skipped_rel++; continue; }
            if (e->path[0]) { fprintf(f, "  "); report_print_safe(f, e->path); fprintf(f, "\n  "); }
            fprintf(f, "  Type: %s, Arch: %s, Class: %d-bit, Endian: %s, PIE: %s, NX: %s, RELRO: %s, Stripped: %s\n",
                    elf_kind_string(e), elf_arch_string(e->e_machine),
                    e->ei_class == 2 ? 64 : 32,
                    e->ei_data == 2 ? "Big" : "Little",
                    elf_pie_string(e), elf_nx_string(e), elf_relro_string(e), e->is_stripped ? "yes" : "no");
        }
        if (skipped_rel > 0) fprintf(f, "  (%zu relocatable objects such as kernel modules not listed, use -v)\n", skipped_rel);
    }
    fprintf(f, "\n");

    /* Binary review: what the executables can do, judged from their imports */
    {
        size_t n_exec = 0, n_sys = 0, n_srv = 0, flagged = 0;
        for (size_t i = 0; i < result->num_elfs; i++) {
            const elf_info_t *e = &result->elfs[i];
            if (e->kind != ELF_KIND_EXEC && e->kind != ELF_KIND_PIE) continue;
            n_exec++;
            if (e->caps & ELFCAP_SYSTEM) n_sys++;
            if ((e->caps & ELFCAP_LISTEN) && (e->caps & ELFCAP_ACCEPT)) n_srv++;
            if (e->risk >= 2) flagged++;
        }
        if (flagged > 0 || n_sys > 0 || n_srv > 0) {
            fprintf(f, "--- Binary review (%zu flagged) ---\n", flagged);
            fprintf(f, "  %zu of %zu executables import system()/popen(); %zu listen for network connections\n", n_sys, n_exec, n_srv);
            size_t listed = 0;
            for (int level = 3; level >= 2; level--) {
                for (size_t i = 0; i < result->num_elfs; i++) {
                    const elf_info_t *e = &result->elfs[i];
                    if (e->risk != level) continue;
                    if (listed >= 30 && !result->show_all_findings) continue;
                    fprintf(f, "  [%s] ", elf_risk_string(e->risk));
                    report_print_safe(f, e->path);
                    fprintf(f, "\n      %s\n", e->risk_note);
                    listed++;
                }
            }
            if (flagged > listed) fprintf(f, "  (%zu more flagged binaries, use -v)\n", flagged - listed);
            fprintf(f, "\n");
        }
    }

    /* Secrets: group repeats per file; public certificates are listed separately, they are not secrets */
    {
        size_t ns = result->num_secrets;
        char *done = calloc(ns + 1, 1);
        size_t shown = 0, certs = 0;
        for (size_t i = 0; i < ns; i++) { if (result->secrets[i].type == CERTIFICATE) certs++; else shown++; }
        fprintf(f, "--- Secrets (%zu) ---\n", shown);
        for (size_t i = 0; done && i < ns; i++) {
            const secret_finding_t *s = &result->secrets[i];
            if (s->type == CERTIFICATE || done[i]) continue;
            size_t same = 1;
            for (size_t j = i + 1; j < ns; j++) {
                const secret_finding_t *t = &result->secrets[j];
                if (!done[j] && t->type == s->type && strcmp(t->description, s->description) == 0 && strcmp(t->source, s->source) == 0) { done[j] = 1; same++; }
            }
            if (same > 1) fprintf(f, "  %s [%s] x%zu (first at 0x%zx, conf: %.2f)", secret_type_string(s->type), s->description, same, s->offset, s->confidence);
            else fprintf(f, "  0x%zx : %s [%s] (conf: %.2f)", s->offset, secret_type_string(s->type), s->description, s->confidence);
            if (s->source[0]) { fprintf(f, " in "); report_print_safe(f, s->source); }
            fprintf(f, "\n");
        }
        if (certs > 0) {
            fprintf(f, "\n--- Embedded certificates (%zu) ---\n", certs);
            for (size_t i = 0; done && i < ns; i++) {
                const secret_finding_t *s = &result->secrets[i];
                if (s->type != CERTIFICATE || done[i]) continue;
                size_t same = 1;
                for (size_t j = i + 1; j < ns; j++) {
                    const secret_finding_t *t = &result->secrets[j];
                    if (!done[j] && t->type == CERTIFICATE && strcmp(t->source, s->source) == 0) { done[j] = 1; same++; }
                }
                fprintf(f, "  %zu in ", same);
                report_print_safe(f, s->source[0] ? s->source : "(raw image)");
                fprintf(f, "\n");
            }
        }
        free(done);
    }

    if (f != stdout) fclose(f);
}
