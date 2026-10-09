# Automata Firmware Analysis Engine - Roadmap

A comprehensive development roadmap organized by phases. This serves as the project's north star — what we want to achieve and in what order.

## Vision
`automata` aims to be a complete firmware security analysis toolkit: a native C engine for speed, ML classifiers for smart detection, and a web platform for team collaboration.

## Phase 1: Engine Core (CURRENT — v0.1.x)
Status: ✅ Mostly complete
- [x] Shannon entropy analysis
- [x] Magic signature scanning (6 builtin signatures)
- [x] GZIP + LZMA/XZ extraction
- [x] ELF binary security assessment (NX, PIE, RELRO)
- [x] Hardcoded secret detection (2 patterns)
- [x] String extraction
- [x] SHA-256 + FNV-1a hashing
- [x] JSON + human-readable reports
- [x] Unit tests (9/9 passing)
- [ ] **Expand signature database** — currently only 6 signatures (gzip, elf, zip, xz, squashfs LE/BE). Need 20+ covering: JFFS2, U-Boot, LZMA raw, bzip2, CramFS, UBIFS, Android boot, DTB/FDT, cpio, PE/MZ, Realtek CSYS, YAFFS, 7z, zstd, LZ4, certificate PEM blocks
- [ ] **Expand secrets scanner** — currently only 2 patterns. Need 16+ covering: RSA/EC/SSH private keys, certificates, ssh-rsa/ed25519 pubkeys, AKIA AWS keys (with alnum validation), password=/passwd= (case-insensitive), secret_key=, api_key=, token=, Authorization: Bearer, root:$ shadow entries, admin: credentials
- [ ] **Recursive extraction** — extract SquashFS/JFFS2 filesystems, then scan extracted files
- [ ] **SquashFS unpacker** — native unsquashfs integration or custom implementation
- [ ] **Entropy visualization data** — sliding window entropy for graphing
- [ ] **SBOM generation** — software bill of materials from extracted filesystem
- [ ] **CVE correlation** — match identified components against NVD/CVE databases

## Phase 2: Advanced Analysis (v0.2.x)
- [ ] **Binary hardening audit** — deeper ELF analysis: ASLR, stack canaries, FORTIFY_SOURCE, non-exec stack, RPATH/RUNPATH issues
- [ ] **Crypto detection** — find hardcoded crypto constants (AES S-boxes, DES permutation tables, RSA key material)
- [ ] **Command injection vectors** — detect calls to system(), popen(), exec* in disassembled code
- [ ] **Filesystem analysis** — parse extracted SquashFS/JFFS2/UBIFS and analyze file permissions, SUID binaries, world-writable files
- [ ] **Network service detection** — identify listening ports/services from config files
- [ ] **Bootloader analysis** — U-Boot environment parsing, boot command chain analysis
- [ ] **Custom signature rules** — YARA-like rule engine for user-defined patterns
- [ ] **Plugin system** — loadable .so modules for custom analyzers

## Phase 3: ML Integration (v0.3.x)
- [ ] **Training data pipeline** — generate labeled dataset from known firmware samples
- [ ] **Vulnerability classifier** — scikit-learn model to classify firmware risk level
- [ ] **Anomaly detection** — entropy-based anomaly detection for obfuscated/encrypted regions
- [ ] **Component identification** — ML-based identification of SDK versions, chipset families
- [ ] **Python bridge** — ctypes/cffi binding from Python to libautomata.so

## Phase 4: Platform (v1.0.x)
- [ ] **FastAPI backend** — REST API for firmware upload/analysis
- [ ] **PostgreSQL storage** — analysis results, firmware metadata, user data
- [ ] **Redis + Celery** — async analysis job queue
- [ ] **Docker deployment** — docker-compose for full stack
- [ ] **Web dashboard** — React/Vue frontend for results visualization
- [ ] **Team features** — multi-user, projects, sharing, notifications
- [ ] **CI/CD pipeline** — GitHub Actions for automated testing and releases

## Research Areas
List these as topics to investigate:
- Firmware emulation (QEMU-based dynamic analysis)
- Symbolic execution for vulnerability discovery
- Taint analysis on firmware binaries
- IoT protocol analysis (MQTT, CoAP, Zigbee)
- Supply chain analysis (component provenance)
- Comparison with existing tools: binwalk, EMBA, FirmWalker, firmware-analysis-toolkit
