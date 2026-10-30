/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_TREE_H
#define AUTOMATA_TREE_H

#include <stdint.h>
#include <stddef.h>
#include "automata/elf.h"
#include "automata/secrets.h"
#include "automata/sbom.h"

/* Limits protect against decompression bombs and pathological images. */
typedef struct {
    int analyze;               /* 1 = run ELF/secrets/SBOM on each file; 0 = unpack only */
    int recursive;             /* 1 = unpack archives found inside the tree (gzip, xz, lzma, squashfs at offset 0) */
    int max_depth;             /* nested archive depth, default 4 */
    size_t max_file_size;      /* files larger than this are skipped, default 64 MiB */
    size_t max_files;          /* default 200000 */
    uint64_t max_total_bytes;  /* scanned + decompressed budget, default 4 GiB */
} tree_limits_t;

/* The caller owns the result arrays. tree_scan appends to them and updates the
 * counts, so one struct can accumulate results over several tree_scan calls. */
typedef struct {
    elf_info_t *elfs;               size_t max_elfs;        size_t num_elfs;
    secret_finding_t *secrets;      size_t max_secrets;     size_t num_secrets;
    component_t *components;        size_t max_components;  size_t num_components;  /* de-duplicated by name+version */

    size_t files_scanned;
    size_t files_skipped;           /* too large, unreadable, or over budget */
    size_t nested_extractions;      /* archives unpacked inside the tree */
    uint64_t bytes_total;
    int truncated;                  /* a limit or result array was hit: results are incomplete */
} tree_results_t;

void tree_limits_default(tree_limits_t *lim);

/* Scan a file or directory produced by extraction.
 * label_base is stripped from paths in results (usually the extraction output directory).
 * Only regular files are read. Symlinks, devices and sockets are never followed. */
int tree_scan(const char *label_base, const char *path, const tree_limits_t *lim, tree_results_t *out);

#endif /* AUTOMATA_TREE_H */
