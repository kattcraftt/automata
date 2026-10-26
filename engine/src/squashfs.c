/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/squashfs.h"
#include "automata/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int squashfs_available(void) {
    FILE *fp = popen("which unsquashfs 2>/dev/null", "r");
    if (fp == NULL) {
        return 0;
    }
    char buf[256];
    char *res = fgets(buf, sizeof(buf), fp);
    int status = pclose(fp);
    if (res != NULL && status == 0 && strlen(buf) > 0) {
        return 1;
    }
    return 0;
}

int squashfs_extract(const uint8_t *data, size_t size, size_t offset, const char *out_dir) {
    if (data == NULL || out_dir == NULL) {
        return -1;
    }
    if (offset >= size) {
        return -1;
    }
    if (!squashfs_available()) {
        return -1;
    }

    /* SquashFS superblock is at least 48 bytes up through bytes_used */
    if (size - offset < 48) {
        return -1;
    }

    const uint8_t *sb = data + offset;
    int is_le = 0;
    if (memcmp(sb, "hsqs", 4) == 0) {
        is_le = 1;
    } else if (memcmp(sb, "sqsh", 4) == 0) {
        is_le = 0;
    } else {
        return -1;
    }

    /* Read filesystem size from bytes_used at offset+40 */
    uint64_t bytes_used = 0;
    if (is_le) {
        bytes_used = read_u64_le(data, size, offset + 40);
    } else {
        bytes_used = read_u64_be(data, size, offset + 40);
        if (bytes_used == 0) {
            bytes_used = read_u64_le(data, size, offset + 40);
        }
    }

    if (bytes_used == 0 || bytes_used > (uint64_t)(size - offset)) {
        return -1;
    }

    size_t sqfs_size = (size_t)bytes_used;

    /* Write to temp file */
    char tmpfile[] = "/tmp/automata_sqfs_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        return -1;
    }

    const uint8_t *src = data + offset;
    size_t written = 0;
    int write_err = 0;
    while (written < sqfs_size) {
        ssize_t n = write(fd, src + written, sqfs_size - written);
        if (n <= 0) {
            write_err = 1;
            break;
        }
        written += (size_t)n;
    }
    close(fd);

    if (write_err) {
        unlink(tmpfile);
        return -1;
    }

    /* Ensure out_dir exists */
    mkdirp(out_dir);

    /* Run unsquashfs */
    char cmd[1024];
    int ncmd = snprintf(cmd, sizeof(cmd), "unsquashfs -f -d \"%s\" \"%s\" >/dev/null 2>&1", out_dir, tmpfile);
    if (ncmd < 0 || (size_t)ncmd >= sizeof(cmd)) {
        unlink(tmpfile);
        return -1;
    }

    int ret = system(cmd);

    /* Remove temp file */
    unlink(tmpfile);

    if (ret != 0) {
        return -1;
    }
    return 0;
}
