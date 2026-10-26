# automata

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)]()

**automata** is a high-performance native firmware analysis engine written in C. It provides deep inspection of firmware blobs, extracting embedded data and detecting security vulnerabilities.

```
   ___         __                  __
  / _ | __ __ / /_ ___  __ _  ___ / /_ ___ _
 / __ |/ // // __// _ \/  ' \/ _ `/ __// _ `/
/_/ |_|\_,_/ \__/ \___/_/_/_/\_,_/\__/ \_,_/
   firmware analysis engine v0.1.0
```

## Features

- **Magic Signature Scanning**: Detects 124+ common file types and headers in raw firmware images.
- **Shannon Entropy Analysis**: Visualizes data randomness to locate compressed or encrypted regions.
- **Data Extraction**: Supports automatic decompression and extraction of GZIP, LZMA, and XZ regions.
- **ELF Binary Detection & Security Assessment**: Analyzes embedded executables for security features (NX, PIE, RELRO) and checks if they are stripped.
- **Secrets & Credential Detection**: Identifies hardcoded passwords, keys, and other sensitive information.
- **String Extraction**: Efficiently extracts human-readable strings from binaries.
- **Hashing**: Computes FNV-1a and SHA-256 hashes for fingerprinting.
- **Reporting**: Outputs results in both human-readable format and JSON for automated pipelines.

## Project Structure

```
automata/
├── CMakeLists.txt              # Root CMake (delegates to engine/)
├── engine/
│   ├── CMakeLists.txt          # Engine build config
│   ├── include/automata/       # Public headers
│   │   ├── automata.h          # Master header (includes all)
│   │   ├── util.h              # Memory mapping, bounds-checked readers
│   │   ├── entropy.h           # Shannon entropy
│   │   ├── elf.h               # ELF parser
│   │   ├── strings.h           # String extraction
│   │   ├── identify.h          # Signature scanning
│   │   ├── extract.h           # Gzip/LZMA extraction
│   │   ├── secrets.h           # Secret/credential detection
│   │   ├── hash.h              # FNV-1a + SHA-256
│   │   └── report.h            # JSON/human output
│   ├── src/                    # Implementation (.c files)
│   ├── data/signatures.h       # Embedded firmware signature database
│   ├── asm/entropy_x86_64.S    # x86_64 ASM acceleration
│   └── tests/test_engine.c     # Unit tests (9 tests)
├── ml/                         # ML classifier (future)
│   ├── training/               # Dataset generation + model training
│   ├── models/                 # Trained model storage
│   └── inference.py            # Inference bridge
├── platform/                   # Web platform (future)
│   ├── api/                    # FastAPI backend
│   ├── db/                     # SQLAlchemy models
│   ├── workers/                # Celery async workers
│   ├── docker-compose.yml      # Full stack compose
│   └── Dockerfile
├── scripts/bootstrap.sh        # Dependency installer
├── docs/                       # Documentation
├── LICENSE                     # MIT
└── VERSION                     # 0.1.0
```

## Building

### Dependencies

- C17 compliant compiler
- CMake
- zlib (`zlib1g-dev`)
- liblzma / xz-utils (`liblzma-dev`)

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install build-essential cmake zlib1g-dev liblzma-dev
```

**Arch Linux:**
```bash
sudo pacman -S base-devel cmake zlib xz
```

Alternatively, use the included bootstrap script:
```bash
./scripts/bootstrap.sh
```

### Build Instructions

1. Configure the build with CMake:
   ```bash
   cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
   ```

2. Compile the project:
   ```bash
   cmake --build build -j$(nproc)
   ```
3. Install the project:
   ```bash
   cmake --install build --prefix ~/.local     # or /usr/local (needs sudo)
   ```

The build process produces:
- `build/engine/automata`: The main CLI analysis tool.
- `build/engine/libautomata.so`: Shared library for integration with other tools.
- `build/engine/test_engine`: Unit test binary.

## Usage

```
automata [OPTIONS] <firmware_file>

Options:
  -j          JSON output mode
  -e          Extract compressed regions
  -v          Verbose output (stderr)
  -o DIR      Output directory for extractions
  --version   Print version
  --help      Show help
```

### Examples

Analyze a firmware blob and show human-readable output:
```bash
automata firmware.bin
```

Output results in JSON format (useful for scripting):
```bash
automata -j firmware.bin
```

Extract recognized compressed regions (e.g., LZMA, GZIP) and enable verbose output:
```bash
automata -e -v firmware.bin
```

Extract regions to a specific output directory:
```bash
automata -e -o ./out firmware.bin
```

## Example Output

```text
   ___         __                  __
  / _ | __ __ / /_ ___  __ _  ___ / /_ ___ _
 / __ |/ // // __// _ \/  ' \/ _ `/ __// _ `/
/_/ |_|\_,_/ \__/ \___/_/_/_/\_,_/\__/ \_,_/
   firmware analysis engine v0.1.0

Analysis Report: tenda-ac2100_firmware_dump.bin
Size: 8388608 bytes
SHA256: a2c44242e6e24126...
Entropy: 7.7974
Time: 0.11s

--- Findings (124) ---
  0x8d60  : GZIP Archive (conf: 0.50)
  ...
--- Secrets (2) ---
  0x7e1469 : PASSWORD [Hardcoded password assignment] (conf: 0.80)
```

## Testing

The project includes a robust test suite covering entropy analysis, string extraction, signature scanning, secret detection, and hashing algorithms. 

Run the tests with:
```bash
./build/engine/test_engine
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Josh Harnet Ravago
