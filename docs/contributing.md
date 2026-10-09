# Contributing to Automata

Welcome to the `automata` project! This guide will help you get started with contributing to the firmware analysis engine.

## Development Setup

To build and test `automata`, you will need a C compiler and CMake installed.

1. **Clone the repository:**
   ```bash
   git clone <repository_url>
   cd automata
   ```

2. **Build the project:**
   ```bash
   cmake -B build -S .
   cmake --build build
   ```

3. **Run the tests:**
   ```bash
   ./build/engine/test_engine
   ```

## Code Style

- **C17 Standard:** Ensure your code is compatible with the C17 standard.
- **License Header:** Every source file must include the following MIT license header:
  ```c
  /* automata - firmware analysis engine. MIT License, Copyright (c) 2026 Josh Harnet Ravago */
  ```
- **Data Types:** Use `stdint.h` types for binary data (e.g., `uint8_t`, `uint16_t`, `uint32_t`).
- **Bounds Checking:** Bounds-check ALL pointer reads via `read_u16_le`/`be` etc from `util.h`.
- **NULL Checking:** NULL-check all pointer parameters.
- **Memory Allocation:** Avoid dynamic allocation in hot paths where possible.
- **Warnings:** Code should compile cleanly with `-Wall -Wextra`.

## Adding a New Module

To add a new analysis module to the engine:

1. Create a header file in `engine/include/automata/mymodule.h`.
2. Create the implementation file in `engine/src/mymodule.c`.
3. Include your new header in `engine/include/automata/automata.h`.
4. Add the new source file to `ENGINE_SOURCES` in `engine/CMakeLists.txt`.
5. Add unit tests for your module in `engine/tests/test_engine.c`.
6. Build and verify:
   ```bash
   cmake --build build && ./build/engine/test_engine
   ```

## Adding Signatures

To add a new magic signature for scanning, edit `engine/src/identify.c` and add an entry to the `builtin_signatures[]` array:

```c
{ (const uint8_t *)"\x1f\x8b", 2, "GZIP Archive" },
```

The fields are: `{pattern bytes, pattern length, human label}`.

## Adding Secret Patterns

To add a new hardcoded secret pattern for detection, edit `engine/src/secrets.c` and add the pattern to the `if/else` chain in the `secrets_scan()` function.

## Testing

- All tests are located in `engine/tests/test_engine.c`.
- To add a new test, create a static function that returns `0` for pass and `1` for fail:
  ```c
  static int test_xxx(void) {
      // ... test logic ...
      return 0;
  }
  ```
- Register the new test in the `main()` function using the `RUN_TEST` macro:
  ```c
  RUN_TEST(test_xxx);
  ```
- Run the tests via: `./build/engine/test_engine`

## Project Layout Convention

- `engine/` — C core (the main product)
- `ml/` — Python ML pipeline (scikit-learn)
- `platform/` — Web platform (FastAPI + Docker)
- `scripts/` — Build/deploy helpers
- `docs/` — Documentation

## Git Workflow

- Always branch off from the `main` branch.
- Keep your commits atomic and write descriptive commit messages.
- Always run the tests and ensure they pass before pushing your changes.
