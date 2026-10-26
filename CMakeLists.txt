cmake_minimum_required(VERSION 3.16)
project(automata C ASM)
set(CMAKE_C_STANDARD 17)

# Default to a per-user prefix
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "$ENV{HOME}/.local" CACHE PATH "Install prefix" FORCE)
endif()

enable_testing()
add_subdirectory(engine)
