/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_SQUASHFS_H
#define AUTOMATA_SQUASHFS_H

#include <stdint.h>
#include <stddef.h>

/* Extract a SquashFS image found at data+offset to out_dir.
 * Shells out to system unsquashfs.
 * Returns 0 on success, -1 on error (unsquashfs not found, etc.) */
int squashfs_extract(const uint8_t *data, size_t size, size_t offset, const char *out_dir);

/* Check if unsquashfs is available on the system */
int squashfs_available(void);

#endif /* AUTOMATA_SQUASHFS_H */
