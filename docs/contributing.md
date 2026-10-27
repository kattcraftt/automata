# Contributing to Automata (v0.2.0)

Thank you for contributing to **automata**, a high-performance firmware analysis engine written in C17. This guide outlines development setup, coding standards, step-by-step procedures for extending the engine, and our git workflow.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Code Style & Standards](#code-style--standards)
- [Adding a New Module](#adding-a-new-module-step-by-step)
- [Adding Signatures](#adding-signatures)
- [Adding Secret Patterns](#adding-secret-patterns)
- [Adding SBOM Component Patterns](#adding-sbom-component-patterns)
- [Adding CVE Entries](#adding-cve-entries)
- [Adding Tests](#adding-tests)
- [Project Layout](#project-layout)
- [Git Workflow](#git-workflow)

---

## Development Setup

### System Dependencies

Automata requires a C17 compiler, CMake 3.16+, zlib, liblzma, and optionally `squashfs-tools` (`unsquashfs`).

#### Arch Linux

```bash
sudo pacman -S base-devel cmake zlib xz squashfs-tools
```

#### Ubuntu / Debian

```bash
sudo apt install build-essential cmake zlib1g-dev liblzma-dev squashfs-tools
```

#### Automated Script

You can also run the bootstrap script from the repository root:

```bash
./scripts/bootstrap.sh
```

### Build Instructions

Configure and compile the engine using standard CMake commands:

```bash
# 1. Configure the build directory (Debug mode recommended during development)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug

# 2. Build the project using all CPU cores
cmake --build build -j$(nproc)

# 3. Run self-tests using the built binary
./build/engine/automata test

# Or via CTest:
ctest --test-dir build --output-on-failure

# 4. Install locally to ~/.local/bin
cmake --install build

# 5. Run tests from anywhere once installed
automata test
```

> [!TIP]
> You can enable automatic local installation on every build by passing `-DAUTOMATA_AUTO_INSTALL=ON` to CMake:
>
> ```bash
> cmake -S . -B build -DAUTOMATA_AUTO_INSTALL=ON
> cmake --build build -j$(nproc)
> ```

---

## Code Style & Standards

All C source code in `engine/` must strictly adhere to the following principles:

1. **Language Standard**: ISO C17 (`-std=c17` / `-std=gnu17`).
2. **License Header**: Every C source file (`.c`), assembly file (`.S`), and header file (`.h`) must start with the exact copyright banner:
   ```c
   /* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
   ```
3. **Fixed-Width Types**: Use standard `<stdint.h>` types for binary data and offsets (`uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `size_t`). Never use raw `long` or unstructured `char*` buffers for binary parsing.
4. **Bounds Checking**: **Never perform unchecked pointer arithmetic or raw pointer dereferences on binary buffers.** Always read through `util.h` helper functions:
   - `read_u16_le()`, `read_u16_be()`
   - `read_u32_le()`, `read_u32_be()`
   - `read_u64_le()`, `read_u64_be()`
5. **Pointer Validation**: Every public API function must check input pointers for `NULL` before performing any operations:
   ```c
   if (!data || !out) {
       return -1;
   }
   ```
6. **Zero-Copy & Heap Minimization**: Avoid `malloc()` in hot scanning loops. Use stack-allocated arrays or caller-provided output buffers. Where dynamic allocation is unavoidable (such as in `entropy_sliding_map()`), provide a corresponding free function (`entropy_map_free()`) and document ownership.
7. **Warning Cleanliness**: All code must compile cleanly with `-Wall -Wextra -Werror` compliance. No unused variables, unhandled switch cases, or signed/unsigned comparison warnings.

---

## Adding a New Module (Step-by-Step)

Follow this 6-step procedure when introducing a new analysis module (e.g., `mymodule`):

### 1. Create the Public Header

Create `engine/include/automata/mymodule.h`:

```c
/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#ifndef AUTOMATA_MYMODULE_H
#define AUTOMATA_MYMODULE_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    size_t offset;
    char description[128];
} mymodule_finding_t;

int mymodule_scan(const uint8_t *data, size_t size,
                  mymodule_finding_t *out, size_t max,
                  size_t *out_count);

#endif /* AUTOMATA_MYMODULE_H */
```

### 2. Implement the Module

Create `engine/src/mymodule.c`:

```c
/* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
#include "automata/mymodule.h"
#include "automata/util.h"
#include <string.h>

int mymodule_scan(const uint8_t *data, size_t size,
                  mymodule_finding_t *out, size_t max,
                  size_t *out_count) {
    if (!data || !out || !out_count) return -1;

    size_t count = 0;
    /* Analysis implementation */
    *out_count = count;
    return 0;
}
```

### 3. Expose in Master Header

Edit `engine/include/automata/automata.h` and add:

```c
#include "automata/mymodule.h"
```

### 4. Register in CMake

Edit `engine/CMakeLists.txt` and append `src/mymodule.c` to `ENGINE_SOURCES`:

```cmake
set(ENGINE_SOURCES
    src/util.c
    ...
    src/mymodule.c
    src/test.c
)
```

### 5. Add Unit Tests

Edit `engine/src/test.c`:

```c
static int test_mymodule(void) {
    uint8_t sample[] = { 0x01, 0x02, 0x03, 0x04 };
    mymodule_finding_t findings[10];
    size_t count = 0;
    int rc = mymodule_scan(sample, sizeof(sample), findings, 10, &count);
    ASSERT(rc == 0);
    return 0; /* pass */
}
```

Register the test in `run_all_tests()`:

```c
RUN_TEST(test_mymodule);
```

### 6. Build and Verify

Compile and run the test suite:

```bash
cmake --build build -j$(nproc) && ./build/engine/automata test
```

---

## Adding Signatures

To add new magic byte patterns or file signatures, edit `engine/src/identify.c` and append an entry to `builtin_signatures[]`:

```c
{ (const uint8_t *)"\x1f\x8b", 2, "GZIP Archive" },
```

### Struct Layout

```c
typedef struct {
    const uint8_t *pattern;     /* Magic byte sequence */
    size_t pattern_len;         /* Pattern length in bytes */
    const char *label;          /* Descriptive name displayed in findings */
} signature_t;
```

> [!NOTE]
> The engine assigns confidence automatically based on `pattern_len`:
>
> - 4+ bytes $\rightarrow$ `1.0` confidence
> - 3 bytes $\rightarrow$ `0.7` confidence
> - 2 bytes $\rightarrow$ `0.5` confidence

---

## Adding Secret Patterns

To add a pattern to the credential scanner, edit `engine/src/secrets.c` and add an entry to the static `patterns[]` table:

```c
{ "password=", 9, SECRET_PASSWORD, 0.6, "Hardcoded password", 1, 0, 0 },
```

### Field Definitions

```c
typedef struct {
    const char *pattern;        /* Pattern string to match */
    size_t len;                 /* Length of pattern string */
    secret_type_t type;         /* secret_type_t enum classification */
    float confidence;           /* Confidence rating (0.0 to 1.0) */
    const char *description;    /* Human-readable description */
    int case_insensitive;       /* 1 = case-insensitive match (tolower), 0 = exact */
    int needs_alnum_check;      /* 1 = verify N alphanumeric characters follow */
    int alnum_count;            /* Number of alphanumeric characters required */
} secret_pattern_t;
```

---

## Adding SBOM Component Patterns

To detect a new software package or library in the SBOM scanner, edit `engine/src/sbom.c` and add an entry to `patterns[]`:

```c
{ "OpenSSL ", 8, "openssl", 1 },
```

### Field Definitions

```c
typedef struct {
    const char *prefix;         /* Prefix string identifying the component */
    size_t prefix_len;          /* Byte length of prefix string */
    const char *comp_name;      /* Normalized component name (lowercase) */
    int version_follows;        /* 1 = version string follows immediately */
} comp_pattern_t;
```

The version extractor automatically collects consecutive version tokens (digits, dots, hyphens, and release suffixes such as `1.0.1g` or `9.3p2`) and deduplicates matches.

---

## Adding CVE Entries

To register an offline vulnerability for SBOM correlation, edit `engine/src/cve.c` and add an entry to `known_cves[]`:

```c
{ "CVE-2014-0160", "openssl", "1.0.1f", "1.0.1g", "CRITICAL", "Heartbleed - TLS heartbeat buffer over-read" },
```

### Field Definitions

```c
typedef struct {
    char cve_id[20];            /* CVE ID (e.g. "CVE-2022-48174") */
    char component[128];        /* Normalized component name matching SBOM */
    char affected_version[64];  /* Upper bound of vulnerable version range */
    char fixed_version[64];     /* First version where bug was fixed */
    char severity[16];          /* "CRITICAL", "HIGH", "MEDIUM", or "LOW" */
    char description[256];      /* Concise summary of vulnerability */
} cve_entry_t;
```

---

## Adding Tests

All unit tests are consolidated in `engine/src/test.c`.

1. **Write the test function**:
   ```c
   static int test_feature_x(void) {
       /* Setup and assertions */
       ASSERT(1 == 1);
       return 0; /* 0 indicates pass, 1 indicates failure */
   }
   ```
2. **Register in `run_all_tests()`**:
   ```c
   int run_all_tests(void) {
       printf("=== automata engine tests ===\n\n");
       ...
       RUN_TEST(test_feature_x);
       ...
       return (tests_passed == tests_run) ? 0 : 1;
   }
   ```
3. **Run the suite**:
   ```bash
   automata test
   ```

---

## Project Layout

Automata follows a clean multi-layer project structure:

- **`engine/`** — High-performance C core engine (the primary deliverable). Contains 14 `.c` implementation files, 13 public `.h` headers, x86_64 assembly acceleration, and CTest integration.
- **`ml/`** — Python machine learning scaffold (`scikit-learn`) for training firmware classifiers and anomaly detectors.
- **`platform/`** — Web platform scaffold (FastAPI, Celery worker, PostgreSQL, Redis, and Docker Compose).
- **`scripts/`** — Build and development helper scripts (e.g., `bootstrap.sh`).
- **`docs/`** — Complete technical documentation, architecture specifications, module references, and developer guides.

---

## Git Workflow

To maintain repository stability and traceable change logs:

1. **Branching**: Always branch from `main`:
   ```bash
   git checkout -b feat/my-new-feature
   ```
2. **Atomic Commits**: Keep commits focused and logically grouped. Avoid massive mixed-concern commits.
3. **Pre-Push Validation**: Always run the self-test suite before committing or pushing:
   ```bash
   automata test
   ```
4. **Conventional Commits**: Format commit messages according to standard conventional commit types:
   - `feat:` — New functionality or module additions (e.g., `feat: add squashfs extractor module`)
   - `fix:` — Bug fixes or bounds check corrections (e.g., `fix: prevent out-of-bounds read in elf parser`)
   - `docs:` — Documentation additions or revisions (e.g., `docs: update architecture for v0.2.0`)
   - `refactor:` — Code restructuring without functional changes (e.g., `refactor: extract test harness to test.c`)
   - `test:` — Test suite additions or updates
