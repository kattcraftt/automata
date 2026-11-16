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
    src/squashfs.c
    src/sbom.c
    src/cve.c
    src/tree.c
    src/fwhdr.c
    src/fsextract.c
    src/test.c
)

# ASM on x86_64 only
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    list(APPEND ENGINE_SOURCES asm/entropy_x86_64.S)
    add_compile_definitions(HAVE_ASM)
endif()

# Optional codecs: bzip2, zstd and lz4 extraction is compiled in when the development files are found
set(OPTIONAL_LIBS "")
set(OPTIONAL_INCLUDES "")
find_package(BZip2)
if(BZIP2_FOUND)
    add_compile_definitions(HAVE_BZIP2)
    list(APPEND OPTIONAL_LIBS ${BZIP2_LIBRARIES})
    list(APPEND OPTIONAL_INCLUDES ${BZIP2_INCLUDE_DIR})
endif()
find_library(ZSTD_LIBRARY zstd)
find_path(ZSTD_INCLUDE_DIR zstd.h)
if(ZSTD_LIBRARY AND ZSTD_INCLUDE_DIR)
    add_compile_definitions(HAVE_ZSTD)
    list(APPEND OPTIONAL_LIBS ${ZSTD_LIBRARY})
    list(APPEND OPTIONAL_INCLUDES ${ZSTD_INCLUDE_DIR})
endif()
find_library(LZ4_LIBRARY lz4)
find_path(LZ4_INCLUDE_DIR lz4frame.h)
if(LZ4_LIBRARY AND LZ4_INCLUDE_DIR)
    add_compile_definitions(HAVE_LZ4)
    list(APPEND OPTIONAL_LIBS ${LZ4_LIBRARY})
    list(APPEND OPTIONAL_INCLUDES ${LZ4_INCLUDE_DIR})
endif()
message(STATUS "automata optional codecs: bzip2=${BZIP2_FOUND} zstd=${ZSTD_LIBRARY} lz4=${LZ4_LIBRARY}")

# Shared library (for Python bridge later)
add_library(automata_lib SHARED ${ENGINE_SOURCES})
target_include_directories(automata_lib PUBLIC include ${CMAKE_CURRENT_SOURCE_DIR}/data ${OPTIONAL_INCLUDES})
target_link_libraries(automata_lib m z lzma ${OPTIONAL_LIBS})
target_compile_options(automata_lib PRIVATE -Wall -Wextra -O2 -fPIC -fstack-protector-strong)
set_target_properties(automata_lib PROPERTIES OUTPUT_NAME "automata")

# Main executable
add_executable(automata ${ENGINE_SOURCES} src/main.c)
target_include_directories(automata PRIVATE include ${CMAKE_CURRENT_SOURCE_DIR}/data ${OPTIONAL_INCLUDES})
target_link_libraries(automata m z lzma ${OPTIONAL_LIBS})
target_compile_options(automata PRIVATE -Wall -Wextra -O2 -fstack-protector-strong)

include(GNUInstallDirs)
install(TARGETS automata RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# CTest integration
enable_testing()
add_test(NAME engine_tests COMMAND automata test)

# Auto-install after build
option(AUTOMATA_AUTO_INSTALL "Install automata after building" OFF)
if(AUTOMATA_AUTO_INSTALL)
  add_custom_command(TARGET automata POST_BUILD
    COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR}
    COMMENT "Installing automata to ${CMAKE_INSTALL_PREFIX}/bin")
endif()
