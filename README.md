# automata

**automata** is a high-performance native firmware analysis engine written in C. It provides deep inspection of firmware blobs, extracting embedded data and detecting security vulnerabilities.

---

```
             ___         __                   __
            / _ | __ __ / /_ ___  __ _  ___  / /_ ___ _
           / __ |/ // // __// _ \/  ' \/ _ `/ __// _ `/
          /_/ |_|\_,_/ \__/ \___/_/_/_/\_,_/\__/ \_,_/
             firmware analysis engine v0.2.0
```

---

> [!WARNING]
> **Work in progress (v0.2.0, pre-alpha).** automata is under active development.
> Results may be incomplete or wrong. Known gaps: no recursive extraction yet
> (secrets/SBOM/ELF checks only scan the raw image, not unpacked filesystems),
> CVE data is a small built-in table, and JFFS2/UBIFS/CramFS are detected but not
> extracted. Don't rely on it for real security decisions yet. See [roadmap](docs/roadmap.md).

---

## Features

- **22-Signature Pattern Scanning:** High-speed binary pattern matcher covering 22 firmware formats and container types:
  - Compressed archives: GZIP, LZMA (raw stream), XZ, Bzip2, 7-Zip, Zstandard, LZ4 Frame, ZIP
  - Filesystems: SquashFS (Little-Endian, Big-Endian, LZMA-variant), JFFS2 (Little-Endian, Big-Endian), CramFS, UBIFS
  - Executables & Bootloaders: ELF binaries (32/64-bit), PE/COFF, U-Boot legacy images, Android Boot images
  - Structured data: Device Tree Blobs (DTB/FDT), cpio (newc format), PEM Certificates
- **Shannon Entropy Analysis & Sparkline Visualization:** Computes Shannon entropy (0.0 to 8.0 bits/byte) with sliding-window analysis and renders inline terminal ASCII sparklines to visualize compressed, encrypted, and padded regions.
- **Embedded Stream Extraction:** Decompresses GZIP and LZMA/XZ compressed streams directly from binary firmware offsets with zip-bomb safeguards (256 MB output limit).
- **SquashFS Filesystem Extraction:** Superblock inspection and automated unpacking via system `unsquashfs`.
- **ELF Binary Security Auditing:** In-memory ELF header and segment analysis identifying target architecture, endianness, and security mitigations:
  - Non-Executable Stack (`NX` via `PT_GNU_STACK`)
  - Position-Independent Executable (`PIE`)
  - Read-Only Relocations (`RELRO` via `PT_GNU_RELRO`)
  - Symbol table stripping (`.symtab`)
- **17-Pattern Table-Driven Secret Scanner:** Table-driven credential and secret detection with contextual byte extraction:
  - RSA, EC, DSA, and generic PEM private keys
  - X.509 certificates and SSH private/public keys (`ssh-rsa`, `ssh-ed25519`)
  - AWS access key IDs (`AKIA` with alphanumeric validation)
  - Hardcoded password assignments (`password=`, `passwd=`)
  - Tokens and API keys (`api_key=`, `secret_key=`, `token=`, `Authorization: Bearer`)
  - Shadow file entries (`root:$`) and administrative accounts (`admin:`)
- **Software Bill of Materials (SBOM) Generation:** Detects and extracts component version strings across 15 software families: Linux Kernel, BusyBox, OpenSSL, Dropbear SSH, OpenSSH, lighttpd, nginx, mini_httpd, dnsmasq, iptables, uClibc, musl libc, curl, and more.
- **Offline CVE Correlation:** Evaluates detected SBOM components against an embedded database of 40 critical IoT vulnerabilities (including Heartbleed, Shellshock, regreSSHion, Dirty Pipe, Dirty COW, DNSpooq, and BusyBox stack overflows).
- **Cryptographic & Non-Cryptographic Hashing:** Compact FIPS 180-4 SHA-256 implementation alongside 64-bit FNV-1a hashing.
- **Dual Reporting Engines:** Human-readable ANSI color reports for terminal analysis and structured JSON output for automated security pipelines.
- **11 Built-in Self-Tests:** Integrated test suite runnable directly via `automata test`.

---

## Project Structure

```
automata/
├── CMakeLists.txt
├── LICENSE
├── VERSION
├── README.md
├── engine/
│   ├── CMakeLists.txt
│   ├── include/automata/     # 13 headers
│   │   ├── automata.h        # Master header
│   │   ├── util.h
│   │   ├── entropy.h
│   │   ├── elf.h
│   │   ├── strings.h
│   │   ├── identify.h
│   │   ├── extract.h
│   │   ├── secrets.h
│   │   ├── hash.h
│   │   ├── report.h
│   │   ├── squashfs.h
│   │   ├── sbom.h
│   │   └── cve.h
│   ├── src/                  # 14 source files
│   │   ├── main.c
│   │   ├── util.c
│   │   ├── entropy.c
│   │   ├── elf.c
│   │   ├── strings.c
│   │   ├── identify.c
│   │   ├── extract.c
│   │   ├── secrets.c
│   │   ├── hash.c
│   │   ├── report.c
│   │   ├── squashfs.c
│   │   ├── sbom.c
│   │   ├── cve.c
│   │   └── test.c
│   ├── asm/entropy_x86_64.S
├── ml/
├── platform/
├── scripts/bootstrap.sh
└── docs/
```

---

## Installation & Build Instructions

### 1. Install Dependencies

**Arch Linux:**

```bash
sudo pacman -S base-devel cmake zlib xz squashfs-tools
```

**Ubuntu / Debian:**

```bash
sudo apt install build-essential cmake zlib1g-dev liblzma-dev squashfs-tools
```

Alternatively, run the automated bootstrap script:

```bash
./scripts/bootstrap.sh
```

### 2. Configure & Build

```bash
# Configure the build system (Debug or Release)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug

# Compile using all available CPU cores
cmake --build build -j$(nproc)
```

The build produces:

- `build/engine/automata` — CLI executable with embedded test suite
- `build/engine/libautomata.so` — Shared library for API integration

### 3. Run Self-Tests

```bash
automata test   # or: ./build/engine/automata test
```

### 4. Install (Optional)

Install the binary to `~/.local/bin` (or custom prefix set via `CMAKE_INSTALL_PREFIX`):

```bash
cmake --install build
```

Ensure `~/.local/bin` is in your `$PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

## CLI Usage

```
automata scan <file> [-j] [-e] [-r] [-v] [-o DIR]   Full analysis
automata test                                       Run 11 self-tests
automata extract <file> [-o DIR] [-r]               Extract only
automata info <file>                                Quick file info
automata version                                    Print version
automata help                                       Help
```

### Options

| Flag | Argument | Description                                                     |
| ---- | -------- | --------------------------------------------------------------- |
| `-j` | None     | Enable machine-readable JSON output                             |
| `-e` | None     | Extract identified compressed regions to disk                   |
| `-r` | None     | Recursive extraction (unpack and scan nested filesystems)       |
| `-v` | None     | Verbose logging output to stderr                                |
| `-o` | `DIR`    | Output directory for extractions (default: `<file>.extracted/`) |

---

## Example Output

Running `automata scan` on an IoT firmware image:

```
   ___         __                   __
  / _ | __ __ / /_ ___  __ _  ___  / /_ ___ _
 / __ |/ // // __// _ \/  ' \/ _ `/ __// _ `/
/_/ |_|\_,_/ \__/ \___/_/_/_/\_,_/\__/ \_,_/
   firmware analysis engine v0.2.0

Analysis Report: tenda-ac2100_firmware_dump.bin
File Size:       8388608 bytes (8.00 MB)
SHA-256:         a2c44242e6e241263a87af12504c385cbbee0176df9f086e3f5b736b4ef84a14
Overall Entropy: 7.7974 bits/byte
Analysis Time:   0.142s

Entropy Sparkline:
  [0x00000000] ▂▄▅▆▇███████████████████████████████████████████████████████████ [0x00800000]

--- Signature Findings (18) ---
  0x00000000 : U-Boot Image Header (conf: 1.00)
  0x00010000 : Device Tree Blob (conf: 1.00)
  0x00040000 : GZIP Archive (conf: 0.50)
  0x00180000 : SquashFS (LE) (conf: 1.00)
  0x00520000 : JFFS2 (LE) (conf: 0.50)
  0x00780000 : PEM Certificate (conf: 1.00)

--- ELF Binaries (3) ---
  0x00192a40 : MIPS (32-bit, Little-Endian, Executable)
               [NX: No]  [PIE: No]  [RELRO: No]  [Stripped: Yes]
  0x00210bc0 : MIPS (32-bit, Little-Endian, Executable)
               [NX: No]  [PIE: No]  [RELRO: No]  [Stripped: Yes]
  0x0035f100 : MIPS (32-bit, Little-Endian, Shared Library)
               [NX: Yes] [PIE: Yes] [RELRO: Partial] [Stripped: Yes]

--- Hardcoded Secrets & Credentials (3) ---
  0x00780000 : [CERTIFICATE] X.509 Certificate (conf: 0.90)
               Context: -----BEGIN CERTIFICATE-----MIIDXTCCAkWgAwIBAgIJAP...
  0x007821a0 : [PRIVATE_KEY] RSA Private Key (conf: 1.00)
               Context: -----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEA...
  0x007e1469 : [PASSWORD] Hardcoded password (conf: 0.60)
               Context: ...admin_pass=Firewall2024!&login_name=root...

--- Components (SBOM) (4) ---
  linux-kernel     2.6.36      (string)
  busybox          1.30.1      (string)
  openssl          1.0.1f      (string)
  dropbear         2016.74     (string)

--- CVE Matches (6) ---
  [CRITICAL] CVE-2014-0160 (openssl <= 1.0.1f)
             Heartbleed - TLS heartbeat information disclosure buffer over-read
  [HIGH]     CVE-2014-0224 (openssl <= 1.0.1h)
             OpenSSL CCS injection vulnerability
  [CRITICAL] CVE-2022-48174 (busybox <= 1.36.1)
             BusyBox ash shell stack-based buffer overflow
  [HIGH]     CVE-2021-42374 (busybox <= 1.34.0)
             BusyBox unlzma out-of-bounds heap read
  [CRITICAL] CVE-2016-7406 (dropbear <= 2016.74)
             Dropbear format string vulnerability in dropbear_lookup()
  [HIGH]     CVE-2016-5195 (linux-kernel <= 4.8.3)
             Dirty COW privilege escalation
```

---

## Testing

The test runner is compiled directly into the binary and executed via `automata test`. All 11 tests validate algorithmic correctness, bounds safety, and security heuristics:

| #   | Test Identifier          | Subsystem      | Description & Validation Target                                                                                                            |
| --- | ------------------------ | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | `test_entropy_zeros`     | Entropy        | Verifies that Shannon entropy of an all-zero buffer evaluates strictly to `0.0000`.                                                        |
| 2   | `test_entropy_uniform`   | Entropy        | Verifies that a uniform distribution of all 256 byte values evaluates to maximum entropy (`~8.0000`).                                      |
| 3   | `test_entropy_histogram` | Entropy        | Validates 256-bin frequency histogram generation on non-uniform byte arrays.                                                               |
| 4   | `test_string_extract`    | Strings        | Ensures extraction of printable ASCII sequences meeting or exceeding the minimum length threshold while filtering binary noise.            |
| 5   | `test_identify_scan`     | Identification | Validates multi-signature identification on raw buffers containing GZIP and U-Boot image headers.                                          |
| 6   | `test_secrets_scan`      | Secrets        | Tests table-driven credential detection on synthetic buffers containing PEM/RSA private key patterns.                                      |
| 7   | `test_hash_fnv1a`        | Hashing        | Validates 64-bit FNV-1a hash generation against known reference test vectors (empty string offset basis, non-empty buffers).               |
| 8   | `test_bounds_readers`    | Utilities      | Tests safe little-endian and big-endian integer readers (`read_u16_le`, `read_u16_be`, etc.) including out-of-bounds guards.               |
| 9   | `test_sha256`            | Hashing        | Tests FIPS 180-4 SHA-256 implementation against standard test vectors (`e3b0c44...` for empty string).                                     |
| 10  | `test_sbom_scan`         | SBOM           | Tests component version pattern extraction and normalization (e.g., matching `BusyBox v1.30.1`).                                           |
| 11  | `test_cve_check`         | CVE Matching   | Validates version comparison logic and offline CVE correlation against known vulnerable components (e.g., Heartbleed on OpenSSL `1.0.1f`). |

Running all tests:

```bash
automata test
```

Expected output:

```
=== automata engine tests ===

PASS: test_entropy_zeros
PASS: test_entropy_uniform
PASS: test_entropy_histogram
PASS: test_string_extract
PASS: test_identify_scan
PASS: test_secrets_scan
PASS: test_hash_fnv1a
PASS: test_bounds_readers
PASS: test_sha256
PASS: test_sbom_scan
PASS: test_cve_check

11/11 tests passed
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
