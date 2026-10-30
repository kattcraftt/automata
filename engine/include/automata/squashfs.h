/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_SQUASHFS_H
#define AUTOMATA_SQUASHFS_H

#include <stdint.h>
#include <stddef.h>

/* Validate a SquashFS v4 superblock at data+offset (version, block size /
 * block log, compression id, bytes_used within the buffer).
 * Returns bytes_used on success, 0 if this is not a plausible v4 image. */
size_t squashfs_superblock_size(const uint8_t *data, size_t size, size_t offset);

/* Extract a SquashFS image found at data+offset to out_dir.
 * Shells out to system unsquashfs.
 * Returns 0 on success, -1 on error (unsquashfs not found, etc.) */
int squashfs_extract(const uint8_t *data, size_t size, size_t offset, const char *out_dir);

/* Check if unsquashfs is available on the system */
int squashfs_available(void);

#endif /* AUTOMATA_SQUASHFS_H */
