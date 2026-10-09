# automata engine build configuration
cmake_minimum_required(VERSION 3.16)

# Source files
set(ENGINE_SOURCES
    src/util.c
    src/entropy.c
    src/elf.c
    src/strings.c
    src/identify.c
    src/hash.c
    src/extract.c
    src/secrets.c
    src/report.c
)

# ASM on x86_64 only
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    list(APPEND ENGINE_SOURCES asm/entropy_x86_64.S)
    add_compile_definitions(HAVE_ASM)
endif()

# Shared library (for Python bridge later)
add_library(automata_lib SHARED ${ENGINE_SOURCES})
target_include_directories(automata_lib PUBLIC include ${CMAKE_CURRENT_SOURCE_DIR}/data)
target_link_libraries(automata_lib m z lzma)
target_compile_options(automata_lib PRIVATE -Wall -Wextra -O2 -fPIC -fstack-protector-strong)
set_target_properties(automata_lib PROPERTIES OUTPUT_NAME "automata")

# Main executable
add_executable(automata ${ENGINE_SOURCES} src/main.c)
target_include_directories(automata PRIVATE include ${CMAKE_CURRENT_SOURCE_DIR}/data)
target_link_libraries(automata m z lzma)
target_compile_options(automata PRIVATE -Wall -Wextra -O2 -fstack-protector-strong)

# Test executable
add_executable(test_engine tests/test_engine.c ${ENGINE_SOURCES})
target_include_directories(test_engine PRIVATE include ${CMAKE_CURRENT_SOURCE_DIR}/data)
target_link_libraries(test_engine m z lzma)
target_compile_options(test_engine PRIVATE -Wall -Wextra -O2 -fstack-protector-strong)
