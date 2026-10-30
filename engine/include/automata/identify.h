/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_IDENTIFY_H
#define AUTOMATA_IDENTIFY_H

#include <stdint.h>
#include <stddef.h>

/* Stable type IDs so callers (extract, report, Python bridge) never have to
 * string-compare labels. */
typedef enum {
    SIG_UNKNOWN = 0,
    SIG_ELF, SIG_ZIP, SIG_GZIP, SIG_XZ,
    SIG_SQUASHFS_BE, SIG_SQUASHFS_LE, SIG_SQUASHFS_LZMA,
    SIG_JFFS2_LE, SIG_JFFS2_BE, SIG_UBOOT, SIG_LZMA, SIG_BZIP2,
    SIG_CRAMFS, SIG_UBIFS, SIG_ANDROID_BOOT, SIG_PEM, SIG_DTB,
    SIG_CPIO, SIG_PE, SIG_7Z, SIG_ZSTD, SIG_LZ4
} sig_type_t;

/* Optional header validator. p points at the magic, remaining is the number of
 * bytes left in the buffer. Returns a confidence in (0,1], or 0 to reject the
 * match (random bytes that merely look like a magic number). */
typedef float (*sig_validate_fn)(const uint8_t *p, size_t remaining);

typedef struct {
    const uint8_t *pattern;
    size_t pattern_len;
    const char *label;
    sig_type_t type;
    sig_validate_fn validate;   /* NULL = confidence from magic length only */
} signature_t;

typedef struct {
    size_t offset;
    const char *label;
    float confidence;
    sig_type_t type;   
} finding_t;

extern const signature_t builtin_signatures[];
extern const size_t num_builtin_signatures;

/* Findings below this are treated as noise by extraction and the default report. */
#define IDENTIFY_MIN_CONFIDENCE 0.5f

/* Match signatures at offset 0 only (cheap container check for a whole file).
 * Returns 1 and fills *out when a signature with confidence >= IDENTIFY_MIN_CONFIDENCE matches. */
int identify_header(const uint8_t *data, size_t size, finding_t *out);

int identify_scan(const uint8_t *data, size_t size, finding_t *out_findings, size_t max_findings, size_t *out_count);

#endif /* AUTOMATA_IDENTIFY_H */
