/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/squashfs.h"
#include "automata/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define SQFS_SUPERBLOCK_SIZE 96

size_t squashfs_superblock_size(const uint8_t *data, size_t size, size_t offset) {
    if (data == NULL || offset >= size || size - offset < SQFS_SUPERBLOCK_SIZE) return 0;
    const uint8_t *sb = data + offset;
    size_t n = size - offset;

    int be;
    if (memcmp(sb, "hsqs", 4) == 0) be = 0;
    else if (memcmp(sb, "sqsh", 4) == 0) be = 1;
    else return 0;

    uint32_t block_size = be ? read_u32_be(sb, n, 12) : read_u32_le(sb, n, 12);
    uint16_t comp = be ? read_u16_be(sb, n, 20) : read_u16_le(sb, n, 20);
    uint16_t block_log = be ? read_u16_be(sb, n, 22) : read_u16_le(sb, n, 22);
    uint16_t major = be ? read_u16_be(sb, n, 28) : read_u16_le(sb, n, 28);
    uint64_t used = be ? read_u64_be(sb, n, 40) : read_u64_le(sb, n, 40);

    if (major != 4) return 0;
    if (comp < 1 || comp > 6) return 0;                         /* gzip lzma lzo xz lz4 zstd */
    if (block_size < 4096 || block_size > (1u << 20)) return 0;
    if ((block_size & (block_size - 1)) != 0) return 0;
    if (block_log < 12 || block_log > 20 || (1u << block_log) != block_size) return 0;
    if (used < SQFS_SUPERBLOCK_SIZE || used > (uint64_t)n) return 0;
    return (size_t)used;
}

/* Find an executable on PATH without invoking a shell. */
static int find_in_path(const char *prog, char *out, size_t out_sz) {
    const char *path = getenv("PATH");
    if (path == NULL || *path == '\0') path = "/usr/local/bin:/usr/bin:/bin";
    char *copy = strdup(path);
    if (copy == NULL) return 0;

    int found = 0;
    char *save = NULL;
    for (char *dir = strtok_r(copy, ":", &save); dir != NULL; dir = strtok_r(NULL, ":", &save)) {
        int n = snprintf(out, out_sz, "%s/%s", *dir ? dir : ".", prog);
        if (n < 0 || (size_t)n >= out_sz) continue;
        struct stat st;
        if (stat(out, &st) == 0 && S_ISREG(st.st_mode) && access(out, X_OK) == 0) {
            found = 1;
            break;
        }
    }
    free(copy);
    return found;
}

int squashfs_available(void) {
    char resolved[512];
    return find_in_path("unsquashfs", resolved, sizeof(resolved));
}

static int dir_has_entries(const char *path) {
    DIR *d = opendir(path);
    if (d == NULL) return 0;
    int has = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0) { has = 1; break; }
    }
    closedir(d);
    return has;
}

int squashfs_extract(const uint8_t *data, size_t size, size_t offset, const char *out_dir) {
    if (data == NULL || out_dir == NULL || *out_dir == '\0') return -1;

    size_t sqfs_size = squashfs_superblock_size(data, size, offset);
    if (sqfs_size == 0) return -1;

    char unsquashfs[1024];
    if (!find_in_path("unsquashfs", unsquashfs, sizeof(unsquashfs))) return -1;

    /* The image is copied out to a private temp file; unsquashfs needs a seekable file. */
    char tmpfile[] = "/tmp/automata_sqfs_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) return -1;

    const uint8_t *src = data + offset;
    size_t written = 0;
    while (written < sqfs_size) {
        ssize_t w = write(fd, src + written, sqfs_size - written);
        if (w <= 0) {
            close(fd);
            unlink(tmpfile);
            return -1;
        }
        written += (size_t)w;
    }
    close(fd);

    mkdirp(out_dir);
    struct stat st;
    if (stat(out_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        unlink(tmpfile);
        return -1;
    }

    /* Never let a path be parsed as an option. */
    char dest[1024];
    if (out_dir[0] == '-') snprintf(dest, sizeof(dest), "./%s", out_dir);
    else snprintf(dest, sizeof(dest), "%s", out_dir);

    pid_t pid = fork();
    if (pid < 0) {
        unlink(tmpfile);
        return -1;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        char *argv[] = { "unsquashfs", "-f", "-d", dest, tmpfile, NULL };
        execv(unsquashfs, argv);
        _exit(127);
    }

    int status = 0;
    pid_t w;
    do { w = waitpid(pid, &status, 0); } while (w < 0 && errno == EINTR);
    unlink(tmpfile);

    if (w < 0) return -1;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
    /* Non-root runs cannot create device nodes, which makes unsquashfs exit non-zero
     * even though the tree was extracted. Accept a populated output directory. */
    if (WIFEXITED(status) && WEXITSTATUS(status) != 127 && dir_has_entries(dest)) return 0;
    return -1;
}
