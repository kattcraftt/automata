# Automata Modules API Documentation

This document describes the public API, data structures, and implementation notes for each module in the `automata` engine.

## util (util.h)
**Purpose**: Provides foundational utilities for memory mapping and bounds-checked data reading.

**Header**: `engine/include/util.h`

### Data Structures
- `mapped_file_t`: 
  - `uint8_t *data`: Pointer to the mapped memory region.
  - `size_t size`: Size of the mapped region.
  - `int fd`: File descriptor for the opened file.

### Functions
- `uint16_t read_u16_le(const uint8_t *data, size_t size, size_t offset)`: Reads a 16-bit little-endian integer. Returns `0` on OOB.
- `uint16_t read_u16_be(const uint8_t *data, size_t size, size_t offset)`: Reads a 16-bit big-endian integer. Returns `0` on OOB.
- `uint32_t read_u32_le(const uint8_t *data, size_t size, size_t offset)`: Reads a 32-bit little-endian integer. Returns `0` on OOB.
- `uint32_t read_u32_be(const uint8_t *data, size_t size, size_t offset)`: Reads a 32-bit big-endian integer. Returns `0` on OOB.
- `uint64_t read_u64_le(const uint8_t *data, size_t size, size_t offset)`: Reads a 64-bit little-endian integer. Returns `0` on OOB.
- `uint64_t read_u64_be(const uint8_t *data, size_t size, size_t offset)`: Reads a 64-bit big-endian integer. Returns `0` on OOB.
- `int map_file(const char *path, mapped_file_t *out_mapped)`: Maps a file into memory. Returns `0` on success, `-1` on error. Uses `mmap` with a fallback to `malloc` + `fread`.
- `void unmap_file(mapped_file_t *mapped)`: Unmaps the file (uses `munmap` or `free` based on how it was mapped).
- `void safe_strncpy(char *dest, const char *src, size_t n)`: Safely copies strings, guaranteeing null-termination.
- `int mkdirp(const char *path, mode_t mode)`: Recursively creates a directory path.

**Implementation Notes**: Relies on POSIX `mmap` for performance (zero-copy analysis) but includes robust fallbacks.
**Dependencies**: None.

## entropy (entropy.h)
**Purpose**: Calculates Shannon entropy to identify packed or compressed regions.

**Header**: `engine/include/entropy.h`

### Functions
- `double entropy_calculate(const uint8_t *data, size_t size)`: Calculates overall Shannon entropy using byte frequency. Returns a value between `0.0` and `8.0`.
- `void entropy_sliding_window(const uint8_t *data, size_t size, size_t window_size, ...)`: Computes windowed entropy for anomaly detection.
- `void entropy_byte_histogram(const uint8_t *data, size_t size, size_t out_counts[256])`: Computes the frequency of each byte value.

**Implementation Notes**: Uses standard logarithmic summation for entropy. A highly optimized x86_64 assembly version is available.
**Dependencies**: `util.h`

## elf (elf.h)
**Purpose**: Parses ELF headers and extracts binary metadata.

**Header**: `engine/include/elf.h`

### Data Structures
- `elf_info_t`:
  - `ei_class`: Architecture class (32 or 64).
  - `ei_data`: Endianness (LE or BE).
  - `e_type`: Object file type.
  - `e_machine`: Target architecture.
  - `has_nx`: NX bit status.
  - `has_relro`: RELRO status.
  - `has_bind_now`: Bind now status.
  - `is_pie`: Position Independent Executable flag.
  - `is_stripped`: Stripped binary flag.

### Functions
- `int elf_parse_buf(const uint8_t *data, size_t size, elf_info_t *out)`: Parses an ELF from a memory buffer. Returns `0` on success.
- `int elf_parse_file(const char *path, elf_info_t *out)`: Maps a file via `map_file` and then calls `elf_parse_buf`.
- `const char* elf_arch_string(uint16_t e_machine)`: Returns human-readable architecture string (e.g., "MIPS", "ARM").

**Implementation Notes**: Gracefully handles both 32-bit and 64-bit ELF formats and different endianness.
**Dependencies**: `util.h`

## strings (strings.h)
**Purpose**: Extracts printable ascii and unicode strings from raw binary data.

**Header**: `engine/include/strings.h`

### Data Structures
- `extracted_string_t`:
  - `size_t offset`: Offset in the file.
  - `char value[256]`: The extracted string data.
  - `size_t length`: Length of the string.

### Functions
- `int string_extract(const uint8_t *data, size_t size, size_t min_len, extracted_string_t *out_strings, size_t max_strings, size_t *out_count)`: Scans for and extracts printable strings matching the minimum length criteria.

**Implementation Notes**: Optimized to quickly reject non-printable characters.
**Dependencies**: `util.h`

## identify (identify.h)
**Purpose**: Scans data against known file format and structure signatures.

**Header**: `engine/include/identify.h`

### Data Structures
- `signature_t`:
  - `const uint8_t *pattern`: The byte pattern to match.
  - `size_t pattern_len`: Length of the pattern.
  - `const char *label`: Human-readable label for the signature.
- `finding_t`:
  - `size_t offset`: Match offset.
  - `const char *label`: The matched label.
  - `float confidence`: Confidence score.

### Global Variables
- `extern signature_t builtin_signatures[]`: Array of built-in signatures.
- `extern size_t num_builtin_signatures`: Number of signatures in the array.

### Functions
- `int identify_scan(const uint8_t *data, size_t size, finding_t *out_findings, size_t max_findings, size_t *out_count)`: Scans the buffer against `builtin_signatures[]`.

**Implementation Notes**: Confidence scores are assigned based on pattern length: 1.0 for 4+ byte patterns, 0.7 for 3-byte, and 0.5 for 2-byte.
**Dependencies**: None. (Standalone)

## extract (extract.h)
**Purpose**: Decompresses and extracts embedded archives (zlib/LZMA).

**Header**: `engine/include/extract.h`

### Data Structures
- `extract_result_t`:
  - `char path[512]`: Path to extracted file.
  - `char type[64]`: Type of compression.
  - `size_t offset`: Offset of compressed data.
  - `size_t compressed`: Compressed size.
  - `size_t decompressed`: Decompressed size.

### Functions
- `int extract_gzip(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res)`: Extracts a GZIP stream using `inflateInit2`. Returns `0` on success.
- `int extract_lzma(const uint8_t *data, size_t size, size_t offset, const char *out_dir, extract_result_t *out_res)`: Extracts an LZMA/XZ stream using `lzma_auto_decoder`. Returns `0` on success.
- `int extract_all(const uint8_t *data, size_t size, const char *out_dir, extract_result_t *out_results, size_t max_results, size_t *out_count)`: Scans and extracts all supported compression streams.

**Implementation Notes**: Enforces a strict 256MB decompression limit to prevent zip bombs.
**Dependencies**: `identify.h`, `util.h`, `zlib`, `liblzma`

## secrets (secrets.h)
**Purpose**: Scans for embedded credentials, keys, and tokens.

**Header**: `engine/include/secrets.h`

### Data Structures
- `secret_type_t` (enum): `PRIVATE_KEY`, `CERTIFICATE`, `PASSWORD`, `API_KEY`, `SSH_KEY`, `AWS_KEY`, `GENERIC_TOKEN`, `HARDCODED_CRED`.
- `secret_finding_t`:
  - `size_t offset`: Offset of the secret.
  - `secret_type_t type`: Type of secret found.
  - `char description[128]`: Description of the secret.
  - `char context[256]`: Surrounding context.
  - `float confidence`: Confidence score.

### Functions
- `int secrets_scan(const uint8_t *data, size_t size, secret_finding_t *out_findings, size_t max_findings, size_t *out_count)`: Scans for secrets.
- `const char* secret_type_string(secret_type_t type)`: Converts the enum to a string.

**Implementation Notes**: Currently implements detection for `-----BEGIN PRIVATE KEY-----` and `password=`.
**Dependencies**: `util.h`

## hash (hash.h)
**Purpose**: Cryptographic and non-cryptographic hashing functions.

**Header**: `engine/include/hash.h`

### Functions
- `uint32_t hash_fnv1a(const uint8_t *data, size_t size)`: Computes an FNV-1a 32-bit hash.
- `size_t mem_diff_count(const uint8_t *a, const uint8_t *b, size_t size)`: Returns the number of differing bytes between two regions.
- `void sha256_hash(const uint8_t *data, size_t size, uint8_t out[32])`: A compact FIPS 180-4 compliant SHA-256 implementation.

**Implementation Notes**: FNV-1a is useful for fast non-cryptographic lookups. SHA-256 is used for file identification.
**Dependencies**: `util.h`

## report (report.h)
**Purpose**: Generates analysis reports in human-readable or JSON formats.

**Header**: `engine/include/report.h`

### Data Structures
- `analysis_result_t`: Aggregates all analysis results.
  - `filename`: Target filename.
  - `file_size`: Target file size.
  - `sha256`: SHA-256 hash.
  - `overall_entropy`: Shannon entropy.
  - `findings`: Array of signature findings.
  - `extractions`: Array of extraction results.
  - `elfs`: Array of parsed ELF headers.
  - `secrets`: Array of secret findings.
  - `num_strings`: Total extracted strings.
  - `analysis_time_secs`: Duration of the analysis.

### Functions
- `void report_json(const analysis_result_t *result, const char *out_path)`: Writes the result in JSON format. Writes to `stdout` if `out_path` is `NULL`.
- `void report_human(const analysis_result_t *result, const char *out_path)`: Writes human-readable output with ANSI color codes. Writes to `stdout` if `out_path` is `NULL`.

**Implementation Notes**: Handles formatting of multiple stack-allocated result arrays.
**Dependencies**: `identify.h`, `extract.h`, `secrets.h`, `elf.h`, `util.h`
