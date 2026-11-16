/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_FSEXTRACT_H
#define AUTOMATA_FSEXTRACT_H

#include <stdint.h>
#include <stddef.h>

/* JFFS2: parsed natively (nodes are CRC-checked; zlib, rtime and uncompressed data are supported;
 * LZO and dynrubin nodes are skipped and counted). Returns 0 on success and sets *out_span to the
 * number of bytes from `offset` covered by valid nodes, *out_files to the number of files written. */
int jffs2_extract(const uint8_t *data, size_t size, size_t offset, int big_endian, const char *out_dir,
                  size_t *out_span, size_t *out_files, size_t *out_unsupported);

/* CramFS: size from the header (0 if not a valid header); extraction runs util-linux fsck.cramfs. */
size_t cramfs_size(const uint8_t *data, size_t size, size_t offset);
int cramfs_extract(const uint8_t *data, size_t size, size_t offset, const char *out_dir);
int cramfs_available(void);

/* UBI / UBIFS: runs ubireader_extract_files (pip package ubi_reader) on the data from offset to the end. */
int ubi_extract(const uint8_t *data, size_t size, size_t offset, const char *out_dir);
int ubi_available(void);

#endif /* AUTOMATA_FSEXTRACT_H */
