# Automata Firmware Analysis Engine - Roadmap

A comprehensive development roadmap organized by phases. This serves as the project's north star — tracking delivered milestones, current development priorities, and long-term architectural objectives.

---

## Vision

`automata` aims to be a complete, self-contained firmware security analysis platform: combining a native C17 engine for raw speed and zero-dependency binary triage, machine learning classifiers for intelligent detection of obfuscated code and unknown components, and a modern web platform for team collaboration and compliance reporting.

---

## Phase 1: Engine Core (IN PROGRESS — v0.2.0) 🚧

<!--Status: Core analysis pipeline delivered and verified across real-world embedded firmware dumps.-->

- [x] Shannon entropy analysis
- [x] Magic signature scanning (22 builtin signatures)
- [x] GZIP + LZMA/XZ extraction
- [x] ELF binary security assessment (NX, PIE, RELRO)
- [x] Hardcoded secret detection (17 patterns)
- [x] String extraction
- [x] SHA-256 + FNV-1a hashing
- [x] JSON + human-readable reports
- [x] Unit tests (11/11 passing)
- [x] Expanded signature database (6 → 22 patterns)
- [x] Expanded secrets scanner (2 → 17 patterns, table-driven)
- [x] Entropy visualization data (sliding window + sparkline)
- [x] SBOM generation (15 component families)
- [x] CVE correlation (40 known IoT CVEs)
- [x] SquashFS extraction (via unsquashfs)
- [x] CLI subcommand architecture (scan/test/extract/info/version/help)
- [ ] Recursive extraction — extract filesystems, then scan contents
- [ ] JFFS2/UBIFS/CramFS filesystem extraction
- [ ] Bzip2/Zstandard/LZ4 extraction support

---

## Phase 2: Advanced Analysis (v0.3.x)

Focus: Deep static binary inspection, attack surface mapping, and heuristic vulnerability detection.

- [ ] **Binary hardening audit** — deeper ELF analysis: ASLR, stack canaries, FORTIFY_SOURCE, non-exec stack, RPATH/RUNPATH issues
- [ ] **Crypto detection** — find hardcoded crypto constants (AES S-boxes, DES permutation tables, RSA key material)
- [ ] **Command injection vectors** — detect calls to `system()`, `popen()`, `exec*` in disassembled code
- [ ] **Filesystem analysis** — parse extracted SquashFS/JFFS2/UBIFS and analyze file permissions, SUID binaries, world-writable files
- [ ] **Network service detection** — identify listening ports/services from config files
- [ ] **Bootloader analysis** — U-Boot environment parsing, boot command chain analysis
- [ ] **Custom signature rules** — YARA-like rule engine for user-defined patterns
- [ ] **Plugin system** — loadable `.so` modules for custom analyzers

---

## Phase 3: ML Integration (v0.4.x)

Focus: Machine-learning models for entropy classification, firmware anomaly detection, and automated component profiling.

- [ ] **Training data pipeline** — generate labeled dataset from known firmware samples
- [ ] **Vulnerability classifier** — scikit-learn model to classify firmware risk level
- [ ] **Anomaly detection** — entropy-based anomaly detection for obfuscated/encrypted regions
- [ ] **Component identification** — ML-based identification of SDK versions, chipset families
- [ ] **Python bridge** — ctypes/cffi binding from Python to `libautomata.so`

---

## Phase 4: Platform (v1.0.x)

Focus: Scalable backend, distributed workers, multi-tenant database, and web dashboard.

- [ ] **FastAPI backend** — REST API for firmware upload/analysis
- [ ] **PostgreSQL storage** — analysis results, firmware metadata, user data
- [ ] **Redis + Celery** — async analysis job queue
- [ ] **Docker deployment** — docker-compose for full stack
- [ ] **Web dashboard** — React/Vue frontend for results visualization
- [ ] **Team features** — multi-user, projects, sharing, notifications
- [ ] **CI/CD pipeline** — GitHub Actions for automated testing and releases

---

## Research Areas

Continuous exploration topics to integrate into future versions:

- **Firmware emulation** — QEMU-based dynamic analysis and full-system emulation
- **Symbolic execution** — automated vulnerability discovery in parsed binary routines
- **Taint analysis** — tracking untrusted input from network interfaces to internal memory
- **IoT protocol analysis** — MQTT, CoAP, Zigbee, and proprietary radio protocol fuzzing
- **Supply chain analysis** — component provenance and software pedigree tracking
- **Ecosystem benchmarking** — comparative evaluations against binwalk, EMBA, FirmWalker, and FAT
