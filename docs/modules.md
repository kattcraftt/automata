# Automata — Module Reference (v0.2.0)

This document provides a comprehensive technical reference for all 13 modules comprising the automata v0.2.0 firmware analysis engine.

---

## Table of Modules

| #   | Module       | Header File                          | Implementation          | Purpose                                                              |
| --- | ------------ | ------------------------------------ | ----------------------- | -------------------------------------------------------------------- |
| 1   | **util**     | `engine/include/automata/util.h`     | `engine/src/util.c`     | Memory mapping, bounds-checked binary readers, path utilities        |
| 2   | **entropy**  | `engine/include/automata/entropy.h`  | `engine/src/entropy.c`  | Shannon entropy, byte histogram, and sliding window entropy map      |
| 3   | **elf**      | `engine/include/automata/elf.h`      | `engine/src/elf.c`      | ELF binary parsing and security mitigation assessment (NX/PIE/RELRO) |
| 4   | **strings**  | `engine/include/automata/strings.h`  | `engine/src/strings.c`  | Printable ASCII string extraction with configurable threshold        |
| 5   | **identify** | `engine/include/automata/identify.h` | `engine/src/identify.c` | Signature scanning against 22 file/filesystem/bootloader formats     |
| 6   | **extract**  | `engine/include/automata/extract.h`  | `engine/src/extract.c`  | GZIP and LZMA/XZ stream extraction with 256MB bomb protection        |
| 7   | **secrets**  | `engine/include/automata/secrets.h`  | `engine/src/secrets.c`  | Table-driven credential and private key scanner (17 patterns)        |
| 8   | **hash**     | `engine/include/automata/hash.h`     | `engine/src/hash.c`     | Fast FNV-1a hash, byte diffing, and FIPS 180-4 SHA-256               |
| 9   | **report**   | `engine/include/automata/report.h`   | `engine/src/report.c`   | Structured JSON serialization and ANSI color terminal output         |
| 10  | **squashfs** | `engine/include/automata/squashfs.h` | `engine/src/squashfs.c` | SquashFS filesystem extraction via unsquashfs subprocess             |
| 11  | **sbom**     | `engine/include/automata/sbom.h`     | `engine/src/sbom.c`     | Software Bill of Materials component detection (15 families)         |
| 12  | **cve**      | `engine/include/automata/cve.h`      | `engine/src/cve.c`      | Vulnerability correlation matching 40 known IoT CVEs                 |
| 13  | **test**     | _(internally declared)_              | `engine/src/test.c`     | Built-in test suite executing 11 self-tests                          |

---

## 1. util

### Purpose

Provides foundational zero-copy memory mapping, bounds-checked endian-safe binary integer readers, safe string copying, and directory creation utilities.

### Header

`engine/include/automata/util.h`

### Data Structures

```c
typedef struct {
    uint8_t *data;    /* Pointer to memory-mapped buffer */
    size_t size;      /* Size of mapped file in bytes */
    int fd;           /* Open file descriptor */
} mapped_file_t;
```

### Functions

```c
int map_file(const char *path, mapped_file_t *out_mapped);
```

- **Params**: `path` (file path to map), `out_mapped` (pointer to output structure).
- **Return**: `0` on success, `-1` on error (file not found, permission denied, `fstat` failure, or `mmap` failure).
- **Behavior**: Opens the file read-only and maps it with `PROT_READ` and `MAP_PRIVATE`.

```c
void unmap_file(mapped_file_t *mapped);
```

- **Params**: `mapped` (pointer to active mapping).
- **Return**: `void`.
- **Behavior**: Unmaps the virtual memory region via `munmap()`, closes `fd`, and zeroes all structure fields.

```c
uint16_t read_u16_le(const uint8_t *data, size_t size, size_t offset);
uint16_t read_u16_be(const uint8_t *data, size_t size, size_t offset);
uint32_t read_u32_le(const uint8_t *data, size_t size, size_t offset);
uint32_t read_u32_be(const uint8_t *data, size_t size, size_t offset);
uint64_t read_u64_le(const uint8_t *data, size_t size, size_t offset);
uint64_t read_u64_be(const uint8_t *data, size_t size, size_t offset);
```

- **Params**: `data` (binary buffer), `size` (buffer size in bytes), `offset` (byte index to read from).
- **Return**: Decoded unsigned integer in host byte order, or `0` if the read exceeds `size`.
- **Behavior**: Validates `offset + sizeof(T) <= size` before reading. Prevents segmentation faults and out-of-bounds reads.

```c
char *safe_strncpy(char *dest, const char *src, size_t n);
```

- **Params**: `dest` (destination buffer), `src` (null-terminated source string), `n` (buffer size).
- **Return**: Pointer to `dest`.
- **Behavior**: Copies at most `n - 1` characters and guarantees null-termination at `dest[n - 1]`.

```c
int mkdirp(const char *path);
```

- **Params**: `path` (directory path to create).
- **Return**: `0` on success, `-1` on error.
- **Behavior**: Recursively creates all parent directories using `mkdir()` with mode `0755` (analogous to `mkdir -p`).

### Implementation Notes

- All memory mapped via `map_file()` must be released using `unmap_file()`.
- Safe integer readers eliminate manual endianness bit-shifts across parsers.

### Dependencies

`<stdint.h>`, `<stddef.h>`, `<sys/mman.h>`, `<sys/stat.h>`, `<fcntl.h>`, `<unistd.h>`.

---

## 2. entropy

### Purpose

Calculates Shannon entropy metrics, generates byte frequency distributions, and creates sliding-window entropy maps to detect encrypted or compressed regions.

### Header

`engine/include/automata/entropy.h`

### Data Structures

```c
typedef struct {
    double *values;       /* Dynamically allocated array of entropy values */
    size_t count;         /* Number of elements in values array */
    size_t window_size;   /* Window size in bytes (e.g., 4096) */
    size_t step_size;     /* Step stride in bytes (e.g., 1024) */
} entropy_map_t;
```

### Functions

```c
double entropy_calculate(const uint8_t *data, size_t size);
```

- **Params**: `data` (byte buffer), `size` (buffer size).
- **Return**: Shannon entropy value as a `double` between `0.0` and `8.0`. Returns `0.0` if `size == 0` or `data == NULL`.
- **Behavior**: Counts byte frequencies $p(x)$ and computes $H = -\sum_{i=0}^{255} p(x_i) \log_2 p(x_i)$.

```c
void entropy_sliding_window(const uint8_t *data, size_t size, size_t window_size,
                            double *out_values, size_t max_values, size_t *out_count);
```

- **Params**: `data`, `size`, `window_size`, `out_values` (pre-allocated array), `max_values`, `out_count`.
- **Return**: `void`.
- **Behavior**: Slides a non-overlapping or stepping window across `data`, filling `out_values`.

```c
void entropy_byte_histogram(const uint8_t *data, size_t size, size_t *out_counts);
```

- **Params**: `data`, `size`, `out_counts` (must point to `size_t[256]`).
- **Return**: `void`.
- **Behavior**: Tallies the occurrences of each byte value `0..255`. Uses x86_64 assembly acceleration (`asm/entropy_x86_64.S`) if `HAVE_ASM` is defined.

```c
int entropy_sliding_map(const uint8_t *data, size_t size,
                        size_t window_size, size_t step_size,
                        entropy_map_t *out);
```

- **Params**: `data`, `size`, `window_size` (e.g., 4096), `step_size` (e.g., 1024), `out` (output structure).
- **Return**: `0` on success, `-1` on invalid arguments or allocation failure.
- **Behavior**: Computes total windows as `(size - window_size) / step_size + 1`. Dynamically allocates `out->values` with `malloc()` and populates each window's entropy.

```c
void entropy_map_free(entropy_map_t *map);
```

- **Params**: `map` (pointer to active entropy map).
- **Return**: `void`.
- **Behavior**: Frees `map->values` and resets `map->count = 0`.

### Implementation Notes

- Pure zeros yield `0.0` entropy; encrypted or compressed data yields values close to `8.0`.
- In `cmd_scan()`, values from `entropy_map_t` are rendered as a Unicode block sparkline (` ▂▃▄▅▆▇█`).

### Dependencies

`<stdint.h>`, `<stddef.h>`, `<stdlib.h>`, `<math.h>`.

---

## 3. elf

### Purpose

Parses 32-bit and 64-bit ELF binaries to extract machine architecture, endianness, and security hardening flags (NX, PIE, RELRO, stripped).

### Header

`engine/include/automata/elf.h`

### Data Structures

```c
typedef struct {
    uint8_t ei_class;       /* 1 = 32-bit (ELFCLASS32), 2 = 64-bit (ELFCLASS64) */
    uint8_t ei_data;        /* 1 = Little-Endian (ELFDATA2LSB), 2 = Big-Endian (ELFDATA2MSB) */
    uint16_t e_type;        /* ELF object type (ET_EXEC, ET_DYN, etc.) */
    uint16_t e_machine;     /* Architecture code (EM_386, EM_X86_64, EM_ARM, EM_MIPS, etc.) */
    int has_nx;             /* 1 = Non-Executable stack enforced (PT_GNU_STACK without PF_X) */
    int has_relro;          /* 1 = Read-Only Relocations enabled (PT_GNU_RELRO segment present) */
    int has_bind_now;       /* 1 = Immediate Binding enabled (DT_BIND_NOW or DF_BIND_NOW) */
    int is_pie;             /* 1 = Position-Independent Executable (ET_DYN with PT_INTERP) */
    int is_stripped;        /* 1 = Symbol table (.symtab) stripped from binary */
} elf_info_t;
```

### Functions

```c
int elf_parse_buf(const uint8_t *data, size_t size, elf_info_t *out_info);
```

- **Params**: `data` (pointer to ELF header `\x7fELF`), `size` (remaining bytes), `out_info`.
- **Return**: `0` on success, `-1` on parse error or invalid header.
- **Behavior**: Validates magic bytes, decodes 32-bit or 64-bit headers using appropriate endian readers, iterates program headers for `PT_GNU_STACK` and `PT_GNU_RELRO`, inspects dynamic section for `BIND_NOW`, and checks section headers for symbol tables.

```c
int elf_parse_file(const char *path, elf_info_t *out_info);
```

- **Params**: `path` (file path on disk), `out_info`.
- **Return**: `0` on success, `-1` on error.
- **Behavior**: Maps file via `map_file()` and calls `elf_parse_buf()`.

```c
const char *elf_arch_string(uint16_t e_machine);
```

- **Params**: `e_machine` (architecture machine code).
- **Return**: String name (e.g., `"x86_64"`, `"x86"`, `"ARM"`, `"MIPS"`, `"AArch64"`, `"PowerPC"`, `"RISC-V"`).

### Implementation Notes

- Operates safely on both 32-bit and 64-bit ELF binaries without structure misalignment.

### Dependencies

`automata/util.h`, `<stdint.h>`, `<stddef.h>`.

---

## 4. strings

### Purpose

Extracts printable ASCII strings meeting a minimum length threshold and tracks their offsets within the binary.

### Header

`engine/include/automata/strings.h`

### Data Structures

```c
typedef struct {
    size_t offset;          /* Byte offset where string starts */
    char value[256];        /* Extracted ASCII string (null-terminated) */
    size_t length;          /* Length of string in bytes */
} extracted_string_t;
```

### Functions

```c
int string_extract(const uint8_t *data, size_t size, size_t min_len,
                   extracted_string_t *out_strings, size_t max_strings,
                   size_t *out_count);
```

- **Params**: `data`, `size`, `min_len` (minimum consecutive printable characters, e.g. 4), `out_strings` (pre-allocated array), `max_strings`, `out_count`.
- **Return**: `0` on success, `-1` on invalid arguments.
- **Behavior**: Scans for sequences of ASCII printable characters (`0x20` to `0x7E`). Truncates strings exceeding 255 bytes while maintaining null-termination.

### Implementation Notes

- Operates with zero heap allocations, storing findings directly into caller-provided stack/heap buffers.

### Dependencies

`<stdint.h>`, `<stddef.h>`, `<ctype.h>`.

---

## 5. identify

### Purpose

Performs signature scanning across binary firmware against a comprehensive database of 22 file formats, archive headers, filesystems, and bootloader images.

### Header

`engine/include/automata/identify.h`

### Data Structures

```c
typedef struct {
    const uint8_t *pattern;     /* Magic byte sequence */
    size_t pattern_len;         /* Pattern length in bytes */
    const char *label;          /* Human-readable label */
    sig_type_t type;            /* Stable enum ID (SIG_GZIP, SIG_SQUASHFS_LE, ...) */
    sig_validate_fn validate;   /* Optional header validator; NULL = length-based confidence */
} signature_t;

typedef struct {
    size_t offset;              /* Byte offset where match was found */
    const char *label;          /* Label of matched signature */
    float confidence;           /* 0..1; validators may return values such as 0.3, 0.4, 0.9 */
    sig_type_t type;            /* Matched signature type */
} finding_t;
```

### Functions

```c
int identify_scan(const uint8_t *data, size_t size,
                  finding_t *out_findings, size_t max_findings,
                  size_t *out_count);
```

- **Params**: `data`, `size`, `out_findings` (pre-allocated array), `max_findings`, `out_count`.
- **Return**: `0` on success, `-1` on error.
- **Behavior**: Scans each byte position against all entries in `builtin_signatures[]`. Populates up to `max_findings` records.

### Built-in Signature Database (22 Signatures)

| #   | Format Label         | Magic Pattern (Bytes) | Length | Confidence |
| --- | -------------------- | --------------------- | ------ | ---------- |
| 1   | **ELF Binary**       | `\x7fELF`             | 4      | 1.00       |
| 2   | **ZIP Archive**      | `PK\x03\x04`          | 4      | 1.00       |
| 3   | **GZIP Archive**     | `\x1f\x8b`            | 2      | 0.50       |
| 4   | **XZ Archive**       | `\xfd7zXZ\x00`        | 6      | 1.00       |
| 5   | **SquashFS (BE)**    | `sqsh`                | 4      | 1.00       |
| 6   | **SquashFS (LE)**    | `hsqs`                | 4      | 1.00       |
| 7   | **SquashFS (LZMA)**  | `\x71\x6c\x7a\x73`    | 4      | 1.00       |
| 8   | **JFFS2 (LE)**       | `\x85\x19`            | 2      | 0.50       |
| 9   | **JFFS2 (BE)**       | `\x19\x85`            | 2      | 0.50       |
| 10  | **U-Boot Image**     | `\x27\x05\x19\x56`    | 4      | 1.00       |
| 11  | **LZMA**             | `\x5d\x00\x00`        | 3      | 0.70       |
| 12  | **Bzip2**            | `BZh`                 | 3      | 0.70       |
| 13  | **CramFS**           | `\x45\x3d\xcd\x28`    | 4      | 1.00       |
| 14  | **UBIFS**            | `\x31\x18\x10\x06`    | 4      | 1.00       |
| 15  | **Android Boot**     | `ANDROID!`            | 8      | 1.00       |
| 16  | **PEM Certificate**  | `-----BEGIN`          | 10     | 1.00       |
| 17  | **Device Tree Blob** | `\xd0\x0d\xfe\xed`    | 4      | 1.00       |
| 18  | **cpio (newc)**      | `070701`              | 6      | 1.00       |
| 19  | **PE/COFF**          | `MZ`                  | 2      | 0.50       |
| 20  | **7-Zip**            | `7z\xbc\xaf\x27\x1c`  | 6      | 1.00       |
| 21  | **Zstandard**        | `\x28\xb5\x2f\xfd`    | 4      | 1.00       |
| 22  | **LZ4 Frame**        | `\x04\x22\x4d\x18`    | 4      | 1.00       |

### Confidence Heuristic

- **1.0 (High)**: Pattern length $\ge 4$ bytes. Extremely reliable.
- **0.7 (Medium)**: Pattern length $= 3$ bytes. Highly probable.
- **0.5 (Low)**: Pattern length $= 2$ bytes. May produce false positives in dense high-entropy regions.

### Dependencies

`<stdint.h>`, `<stddef.h>`, `<string.h>`.

---

## 6. extract

### Purpose

Extracts GZIP and LZMA/XZ compressed data streams to disk with decompression limits to prevent denial-of-service via decompression bombs.

### Header

`engine/include/automata/extract.h`

### Data Structures

```c
typedef struct {
    char path[512];             /* Path to extracted file on disk */
    char type[64];              /* Compression type: "gzip", "lzma", "xz" */
    size_t offset;              /* Byte offset where stream began */
    size_t compressed_size;     /* Compressed bytes consumed */
    size_t decompressed_size;   /* Decompressed bytes written */
} extract_result_t;
```

### Functions

```c
int extract_gzip(const uint8_t *data, size_t size, size_t offset,
                 const char *out_dir, extract_result_t *out_res);
```

- **Params**: `data`, `size`, `offset` (where `\x1f\x8b` starts), `out_dir`, `out_res`.
- **Return**: `0` on success, `-1` on decompression error.
- **Behavior**: Uses `zlib`'s `inflateInit2()` with window bits `16 + MAX_WBITS` to unpack raw gzip streams.

```c
int extract_lzma(const uint8_t *data, size_t size, size_t offset,
                 const char *out_dir, extract_result_t *out_res);
```

- **Params**: `data`, `size`, `offset`, `out_dir`, `out_res`.
- **Return**: `0` on success, `-1` on decompression error.
- **Behavior**: Uses `liblzma`'s `lzma_auto_decoder()` to unpack LZMA and XZ streams.

```c
int extract_all(const uint8_t *data, size_t size, const char *out_dir,
                extract_result_t *out_results, size_t max_results,
                size_t *out_count);
```

- **Params**: `data`, `size`, `out_dir`, `out_results`, `max_results`, `out_count`.
- **Return**: `0` on success.
- **Behavior**: Runs `identify_scan()` to find all GZIP, LZMA, and XZ offsets, then decompresses each stream into `out_dir`.

### Implementation Notes

- **Zip Bomb Safeguard**: Enforces a hard decompression limit of **256 MB** (`256 * 1024 * 1024` bytes). Decompression terminates immediately if output exceeds this threshold.

### Dependencies

`automata/identify.h`, `automata/util.h`, `zlib`, `liblzma`.

---

## 7. secrets

### Purpose

Table-driven pattern matching engine that discovers embedded private keys, certificates, API credentials, passwords, and tokens with context extraction.

### Header

`engine/include/automata/secrets.h`

### Data Structures

```c
typedef enum {
    SECRET_PRIVATE_KEY,
    SECRET_CERTIFICATE,
    SECRET_PASSWORD,
    SECRET_API_KEY,
    SECRET_SSH_KEY,
    SECRET_AWS_KEY,
    SECRET_GENERIC_TOKEN,
    SECRET_HARDCODED_CRED
} secret_type_t;

typedef struct {
    size_t offset;              /* Byte offset where secret was discovered */
    secret_type_t type;         /* Classification enum */
    char description[128];      /* Descriptive label */
    char context[256];          /* Sanitized 64-byte surrounding context */
    float confidence;           /* Confidence score between 0.0 and 1.0 */
} secret_finding_t;
```

### Functions

```c
int secrets_scan(const uint8_t *data, size_t size,
                 secret_finding_t *out_findings, size_t max_findings,
                 size_t *out_count);
```

- **Params**: `data`, `size`, `out_findings` (pre-allocated array), `max_findings`, `out_count`.
- **Return**: `0` on success, `-1` on error.
- **Behavior**: Scans data across the 17-pattern table. Validates alphanumeric constraints, extracts 64 bytes of sanitized context, and advances offset past match.

```c
const char *secret_type_string(secret_type_t type);
```

- **Params**: `type` enum.
- **Return**: Human-readable uppercase string (e.g., `"PRIVATE_KEY"`, `"AWS_KEY"`).

### Secret Patterns Table (17 Patterns)

| #   | Pattern String                    | Length | Type                    | Confidence | Description            | Case Insensitive | Alnum Check |
| --- | --------------------------------- | ------ | ----------------------- | ---------- | ---------------------- | ---------------- | ----------- |
| 1   | `-----BEGIN RSA PRIVATE KEY-----` | 31     | `SECRET_PRIVATE_KEY`    | 1.00       | RSA Private Key        | No               | None        |
| 2   | `-----BEGIN EC PRIVATE KEY-----`  | 30     | `SECRET_PRIVATE_KEY`    | 1.00       | EC Private Key         | No               | None        |
| 3   | `-----BEGIN PRIVATE KEY-----`     | 27     | `SECRET_PRIVATE_KEY`    | 1.00       | PEM Private Key        | No               | None        |
| 4   | `-----BEGIN DSA PRIVATE KEY-----` | 31     | `SECRET_PRIVATE_KEY`    | 1.00       | DSA Private Key        | No               | None        |
| 5   | `-----BEGIN CERTIFICATE-----`     | 27     | `SECRET_CERTIFICATE`    | 0.90       | X.509 Certificate      | No               | None        |
| 6   | `-----BEGIN SSH`                  | 14     | `SECRET_SSH_KEY`        | 1.00       | SSH Key                | No               | None        |
| 7   | `ssh-rsa AAAA`                    | 12     | `SECRET_SSH_KEY`        | 0.90       | SSH RSA Public Key     | No               | None        |
| 8   | `ssh-ed25519 AAAA`                | 16     | `SECRET_SSH_KEY`        | 0.90       | SSH Ed25519 Public Key | No               | None        |
| 9   | `AKIA`                            | 4      | `SECRET_AWS_KEY`        | 0.80       | AWS Access Key         | No               | 16 chars    |
| 10  | `password=`                       | 9      | `SECRET_PASSWORD`       | 0.60       | Hardcoded password     | Yes              | None        |
| 11  | `passwd=`                         | 7      | `SECRET_PASSWORD`       | 0.60       | Hardcoded password     | Yes              | None        |
| 12  | `secret_key=`                     | 11     | `SECRET_GENERIC_TOKEN`  | 0.70       | Secret key assignment  | No               | None        |
| 13  | `api_key=`                        | 8      | `SECRET_API_KEY`        | 0.70       | API key assignment     | No               | None        |
| 14  | `token=`                          | 6      | `SECRET_GENERIC_TOKEN`  | 0.50       | Token assignment       | No               | None        |
| 15  | `Authorization: Bearer `          | 22     | `SECRET_GENERIC_TOKEN`  | 0.70       | Bearer token           | No               | None        |
| 16  | `root:$`                          | 6      | `SECRET_HARDCODED_CRED` | 0.90       | Root shadow entry      | No               | None        |
| 17  | `admin:`                          | 6      | `SECRET_HARDCODED_CRED` | 0.50       | Admin credential       | No               | None        |

### Implementation Notes

- **Context Extraction**: Captures 32 bytes prior to the offset and 32 bytes following. Any non-printable byte (`< 0x20` or `> 0x7E`), newline, or carriage return is sanitized to `.`.
- **AWS Key Validation**: Verifies that 16 consecutive alphanumeric characters follow `AKIA` before registering a match.

### Dependencies

`<stdint.h>`, `<stddef.h>`, `<ctype.h>`, `<string.h>`.

---

## 8. hash

### Purpose

Calculates cryptographic (FIPS 180-4 SHA-256) and non-cryptographic (FNV-1a) hashes and counts byte differences between memory regions.

### Header

`engine/include/automata/hash.h`

### Functions

```c
uint32_t hash_fnv1a(const uint8_t *data, size_t size);
```

- **Params**: `data`, `size`.
- **Return**: 32-bit FNV-1a hash integer.
- **Behavior**: Initialized with offset basis `2166136261u`, multiplied by prime `16777619u`.

```c
size_t mem_diff_count(const uint8_t *a, const uint8_t *b, size_t size);
```

- **Params**: `a` (buffer 1), `b` (buffer 2), `size` (bytes to compare).
- **Return**: Number of byte indices where `a[i] != b[i]`.

```c
void sha256_hash(const uint8_t *data, size_t size, char out_hex[65]);
```

- **Params**: `data`, `size`, `out_hex` (buffer of at least 65 bytes).
- **Return**: `void`.
- **Behavior**: Computes standard SHA-256 digest and formats it as a 64-character lowercase hex string followed by a null terminator.

### Implementation Notes

- Self-contained, dependency-free cryptographic implementation.

### Dependencies

`<stdint.h>`, `<stddef.h>`.

---

## 9. report

### Purpose

Aggregates scan results from all engine modules and formats output into structured JSON or ANSI-colored human-readable terminal reports.

### Header

`engine/include/automata/report.h`

### Data Structures

```c
typedef struct {
    const char *filename;
    size_t file_size;
    char sha256[65];
    double overall_entropy;
    const finding_t *findings;
    size_t num_findings;
    const extract_result_t *extractions;
    size_t num_extractions;
    const elf_info_t *elfs;
    size_t num_elfs;
    const secret_finding_t *secrets;
    size_t num_secrets;
    const extracted_string_t *strings;
    size_t num_strings;
    double execution_time_ms;
} analysis_result_t;
```

### Functions

```c
int report_json(const analysis_result_t *result, const char *out_path);
```

- **Params**: `result` (pointer to analysis data), `out_path` (file path, or `NULL` for stdout).
- **Return**: `0` on success, `-1` on error.
- **Behavior**: Emits clean, machine-parsable JSON with escaped strings and numeric arrays.

```c
int report_human(const analysis_result_t *result, const char *out_path);
```

- **Params**: `result`, `out_path` (file path, or `NULL` for stdout).
- **Return**: `0` on success, `-1` on error.
- **Behavior**: Renders stylized terminal output with ANSI colors, headers, aligned columns, and metric highlights.

### Dependencies

`automata/identify.h`, `automata/extract.h`, `automata/secrets.h`, `automata/elf.h`, `<stdio.h>`.

---

## 10. squashfs

### Purpose

Validates SquashFS compressed filesystem superblocks, calculates filesystem byte bounds, and unpacks the tree using the host `unsquashfs` utility.

### Header

`engine/include/automata/squashfs.h`

### Functions

```c
int squashfs_available(void);
```

- **Params**: None.
- **Return**: `1` if `unsquashfs` executable is located in `$PATH`, `0` otherwise.
- **Behavior**: Executes `which unsquashfs 2>/dev/null` via `popen()` and checks process exit status.

```c
int squashfs_extract(const uint8_t *data, size_t size, size_t offset, const char *out_dir);
```

- **Params**: `data`, `size`, `offset` (where SquashFS magic resides), `out_dir` (destination directory).
- **Return**: `0` on success, `-1` on error.
- **Behavior**:
  1. Validates magic bytes: little-endian `hsqs` (`0x73717368`) or big-endian `sqsh` (`0x71736873`).
  2. Reads total filesystem size from `bytes_used` field at `offset + 40` using `read_u64_le()` or `read_u64_be()`.
  3. Writes the exact SquashFS image slice to temporary file `/tmp/automata_sqfs_XXXXXX` using `mkstemp()`.
  4. Ensures `out_dir` exists via `mkdirp()`.
  5. Executes `unsquashfs -f -d <out_dir> <tmpfile>`.
  6. Removes the temporary file and returns status.

### Dependencies

`automata/util.h`, `<stdint.h>`, `<stddef.h>`, `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<unistd.h>`.

---

## 11. sbom

### Purpose

Scans raw firmware data for embedded version strings across 15 popular IoT and open-source component families, generating a Software Bill of Materials (SBOM).

### Header

`engine/include/automata/sbom.h`

### Data Structures

```c
typedef struct {
    char name[128];         /* Normalized component name (e.g., "openssl", "busybox") */
    char version[64];       /* Extracted version string (e.g., "1.0.1f", "1.30.1") */
    char source[32];        /* Detection origin ("string", "elf", "config") */
} component_t;
```

### Functions

```c
int sbom_scan(const uint8_t *data, size_t size,
              component_t *out, size_t max,
              size_t *out_count);
```

- **Params**: `data`, `size`, `out` (pre-allocated array), `max`, `out_count`.
- **Return**: `0` on success, `-1` on error.
- **Behavior**: Scans for prefix strings across 15 component families. Extracts subsequent version tokens, deduplicates identical `name + version` pairs, and populates `out`.

### Component Patterns (15 Families)

| #   | Search Prefix      | Normalized Name | Example Match          |
| --- | ------------------ | --------------- | ---------------------- |
| 1   | `"OpenSSL "`       | `openssl`       | `OpenSSL 1.0.2k`       |
| 2   | `"BusyBox v"`      | `busybox`       | `BusyBox v1.30.1`      |
| 3   | `"dropbear_"`      | `dropbear`      | `dropbear_2019.78`     |
| 4   | `"Dropbear v"`     | `dropbear`      | `Dropbear v2020.81`    |
| 5   | `"lighttpd/"`      | `lighttpd`      | `lighttpd/1.4.53`      |
| 6   | `"Linux version "` | `linux-kernel`  | `Linux version 4.9.11` |
| 7   | `"dnsmasq-"`       | `dnsmasq`       | `dnsmasq-2.80`         |
| 8   | `"iptables v"`     | `iptables`      | `iptables v1.6.2`      |
| 9   | `"uClibc "`        | `uclibc`        | `uClibc 0.9.33.2`      |
| 10  | `"musl libc "`     | `musl`          | `musl libc 1.2.2`      |
| 11  | `"mini_httpd/"`    | `mini_httpd`    | `mini_httpd/1.30`      |
| 12  | `"sshd: "`         | `openssh`       | `sshd: OpenSSH_8.2p1`  |
| 13  | `"OpenSSH_"`       | `openssh`       | `OpenSSH_8.4`          |
| 14  | `"curl "`          | `curl`          | `curl 7.68.0`          |
| 15  | `"nginx/"`         | `nginx`         | `nginx/1.18.0`         |

### Version Extraction Logic

Version extraction begins immediately following the prefix. Characters accepted into the version string include digits (`0-9`), periods (`.`), hyphens (`-`), and release patch suffixes (e.g., `1.0.1g`, `9.3p2`). Extraction stops at whitespace, null bytes, or non-version punctuation.

### Dependencies

`<stdint.h>`, `<stddef.h>`, `<ctype.h>`, `<string.h>`.

---

## 12. cve

### Purpose

Correlates detected SBOM components against an embedded database of 40 known IoT CVE vulnerabilities using semantic version comparison.

### Header

`engine/include/automata/cve.h`

### Data Structures

```c
typedef struct {
    char cve_id[20];                /* CVE identifier (e.g., "CVE-2014-0160") */
    char component[128];            /* Target component name (e.g., "openssl") */
    char affected_version[64];      /* Vulnerable version upper bound */
    char fixed_version[64];         /* Fixed version string */
    char severity[16];              /* "CRITICAL", "HIGH", "MEDIUM", "LOW" */
    char description[256];          /* Description of vulnerability */
} cve_entry_t;
```

### Functions

```c
int cve_check(const component_t *components, size_t num_components,
              cve_entry_t *out, size_t max,
              size_t *out_count);
```

- **Params**: `components` (detected SBOM items), `num_components`, `out` (output array), `max`, `out_count`.
- **Return**: `0` on success, `-1` on error.
- **Behavior**: Iterates each component against the internal `known_cves[]` database. Calls `version_compare()` to determine whether the component version falls within the vulnerable threshold. Deduplicates matched CVE IDs.

### Internal Version Comparison Helper

```c
int version_compare(const char *a, const char *b);
```

- Compares two version strings segment-by-segment (split on `.`).
- Evaluates numeric segments integer-wise.
- Compares alphanumeric release suffixes (e.g., `1.0.1f` < `1.0.1g`).
- Returns `-1` if $a < b$, `0` if $a == b$, and `1` if $a > b$.

### Embedded CVE Coverage (40 Known IoT Vulnerabilities)

The static database contains 40 curated vulnerabilities spanning common embedded software:

- **OpenSSL**:
  - `CVE-2014-0160` (CRITICAL) — Heartbleed TLS heartbeat buffer over-read (< 1.0.1g)
  - `CVE-2014-0224` (HIGH) — CCS Injection handshake MITM (< 1.0.1h)
  - `CVE-2015-0204` (HIGH) — FREAK RSA export downgrade (< 1.0.1k)
  - `CVE-2016-2107` (HIGH) — Padding Oracle AES-CBC cipher over-read (< 1.0.2h)
  - `CVE-2022-0778` (HIGH) — BN_mod_sqrt infinite loop DoS (< 1.1.1n)
- **BusyBox**:
  - `CVE-2021-42373` through `CVE-2021-42386` (HIGH) — Applet vulnerabilities in man, awk, hush, etc. (< 1.34.0)
  - `CVE-2022-48174` (CRITICAL) — Ash shell math evaluation stack overflow (< 1.36.1)
- **Dropbear**:
  - `CVE-2016-7406` (CRITICAL) — Format string vulnerability in dropbearconvert (< 2016.74)
  - `CVE-2018-15599` (MEDIUM) — Username enumeration timing attack (< 2018.76)
  - `CVE-2021-36369` (HIGH) — Trivial authentication bypass via algorithmic mismatch (< 2022.82)
- **dnsmasq**:
  - `CVE-2020-25681`, `CVE-2020-25682`, `CVE-2020-25683`, `CVE-2020-25687` (HIGH) — DNSpooq cache poisoning and heap overflow (< 2.83)
  - `CVE-2021-3448` (MEDIUM) — Fixed port allocation DNS rebind (< 2.85)
- **lighttpd**:
  - `CVE-2019-11072` (HIGH) — Heap-based buffer overflow in HTTP/2 handler (< 1.4.54)
  - `CVE-2022-22707` (HIGH) — mod_extforward header parsing buffer overflow (< 1.4.64)
- **curl**:
  - `CVE-2021-22946` (MEDIUM) — TLS downgrade bypass via IMAP/POP3/FTP (< 7.79.0)
  - `CVE-2022-32221` (HIGH) — POST-after-PUT memory corruption (< 7.86.0)
  - `CVE-2023-38545` (CRITICAL) — SOCKS5 host heap-based buffer overflow (< 8.4.0)
- **nginx**:
  - `CVE-2018-16843` (HIGH) — HTTP/2 memory consumption DoS (< 1.15.6)
  - `CVE-2021-23017` (HIGH) — DNS resolver off-by-one 1-byte overwrite (< 1.20.1)
- **Linux Kernel**:
  - `CVE-2016-5195` (HIGH) — Dirty COW privilege escalation (< 4.8.3)
  - `CVE-2019-11477` (HIGH) — SACK Panic integer overflow DoS (< 5.1.10)
  - `CVE-2021-3156` (CRITICAL) — Baron Samedit heap overflow in sudo (< 5.4.0)
  - `CVE-2022-0847` (HIGH) — Dirty Pipe overwrite in page cache (< 5.16.11)
- **OpenSSH**:
  - `CVE-2020-15778` (HIGH) — scp command injection via shell expansion (< 8.3p1)
  - `CVE-2023-38408` (HIGH) — PKCS#11 provider remote code execution in ssh-agent (< 9.3p2)
  - `CVE-2024-6387` (CRITICAL) — regreSSHion unauthenticated remote code execution (< 9.8p1)
- **uClibc**:
  - `CVE-2022-29503` (HIGH) — Predictable DNS transaction IDs (< 1.0.42)
- **mini_httpd**:
  - `CVE-2018-18778` (HIGH) — Arbitrary file read path traversal (< 1.30)
- **iptables**:
  - `CVE-2019-11360` (HIGH) — Buffer overflow in iptables-restore (< 1.8.3)

### Dependencies

`automata/sbom.h`, `<stdint.h>`, `<stddef.h>`, `<stdlib.h>`, `<string.h>`.

---

## 13. test

### Purpose

Internal test harness providing 11 self-tests covering every core engine component, SBOM extraction, and CVE correlation.

### Header

None. Declared externally:

```c
extern int run_all_tests(void);
```

### Functions

```c
int run_all_tests(void);
```

- **Params**: None.
- **Return**: `0` if all tests pass, `1` if any test fails.
- **Behavior**: Executes 11 unit tests using the `RUN_TEST()` harness macro. Prints pass/fail status and final score.

### Unit Tests Covered

1. `test_entropy_zeros`: Asserts that an all-zero buffer yields an entropy value of exactly `0.0`.
2. `test_entropy_uniform`: Asserts that a uniform distribution of all 256 byte values yields an entropy of ~`8.0`.
3. `test_entropy_histogram`: Verifies that `entropy_byte_histogram()` correctly tallies individual byte frequencies.
4. `test_string_extract`: Verifies extraction of embedded ASCII printable strings meeting minimum length limits.
5. `test_identify_scan`: Verifies signature detection of both GZIP (`\x1f\x8b`) and U-Boot Image (`\x27\x05\x19\x56`) headers.
6. `test_secrets_scan`: Tests detection of PEM RSA private key headers (`-----BEGIN RSA PRIVATE KEY-----`).
7. `test_hash_fnv1a`: Validates FNV-1a 32-bit hash calculations against reference vectors.
8. `test_bounds_readers`: Tests little-endian and big-endian bounds-checked integer readers (`read_u16_le`, `read_u16_be`) and verifies out-of-bounds safety.
9. `test_sha256`: Tests FIPS 180-4 SHA-256 hash calculation against empty string and known digest values.
10. `test_sbom_scan`: Verifies detection of `"BusyBox v1.30.1"` into component `"busybox"` with version `"1.30.1"`.
11. `test_cve_check`: Asserts that an `"openssl"` component with version `"1.0.1f"` triggers Heartbleed (`CVE-2014-0160`).

### Dependencies

All engine module headers (`automata/automata.h`, `automata/sbom.h`, `automata/cve.h`), `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<math.h>`.
