#===============================================================================
# Root CMakeLists.txt for DLPatch project
#===============================================================================

cmake_minimum_required(VERSION 3.10)
project(DLPatch VERSION 1.0.0 LANGUAGES CXX)

#===============================================================================
# Project configuration
#===============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Detect number of CPU cores for parallel build
include(ProcessorCount)
ProcessorCount(NCPUS)
if(NCPUS EQUAL 0)
    set(NCPUS 2)
endif()
message(STATUS "Parallel build: ${NCPUS} cores available")

#===============================================================================
# Build type configuration
#===============================================================================

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    message(STATUS "Build type: Release (default)")
endif()

#===============================================================================
# External dependencies
#===============================================================================

find_package(nlohmann_json CONFIG REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBCAP IMPORTED_TARGET libcap)
if(LIBCAP_FOUND)
    set(HAVE_LIBCAP TRUE)
    message(STATUS "libcap found - capability support available")
else()
    set(HAVE_LIBCAP FALSE)
    message(FATAL_ERROR "libcap is REQUIRED for ptrace capabilities. Install libcap-dev.")
endif()

#===============================================================================
# Include directories
#===============================================================================

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/headers
    ${CMAKE_CURRENT_SOURCE_DIR}/headers/backend
    ${CMAKE_CURRENT_SOURCE_DIR}/headers/daemon
    ${CMAKE_CURRENT_SOURCE_DIR}/headers/frontend
    ${CMAKE_CURRENT_BINARY_DIR}
)

#===============================================================================
# Version header generation
#===============================================================================

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/version.h"
    @ONLY
)

#===============================================================================
# Main executable: dlpatch
#===============================================================================

add_executable(dlpatch src/main/frontend.cpp)

target_compile_definitions(dlpatch PRIVATE
    $<$<CONFIG:Debug>:DEBUG>
    $<$<NOT:$<CONFIG:Debug>>:NDEBUG>
)

if(HAVE_LIBCAP)
    target_compile_definitions(dlpatch PRIVATE HAVE_LIBCAP)
endif()

target_link_libraries(dlpatch PRIVATE dl pthread nlohmann_json::nlohmann_json)
if(LIBCAP_FOUND)
    target_link_libraries(dlpatch PRIVATE PkgConfig::LIBCAP)
endif()

#===============================================================================
# Daemon executable: dlpatchd
#===============================================================================

add_executable(dlpatchd src/daemon/daemon.cpp)

target_compile_definitions(dlpatchd PRIVATE
    $<$<CONFIG:Debug>:DEBUG>
    $<$<NOT:$<CONFIG:Debug>>:NDEBUG>
)

if(HAVE_LIBCAP)
    target_compile_definitions(dlpatchd PRIVATE HAVE_LIBCAP)
endif()

target_link_libraries(dlpatchd PRIVATE dl pthread nlohmann_json::nlohmann_json)
if(LIBCAP_FOUND)
    target_link_libraries(dlpatchd PRIVATE PkgConfig::LIBCAP)
endif()

#===============================================================================
# Tests (DISABLED IN RELEASE)
#===============================================================================

# Tests are completely disabled in release branch
# lib_target is also excluded

#===============================================================================
# Installation
#===============================================================================

install(TARGETS dlpatch dlpatchd RUNTIME DESTINATION bin)

#===============================================================================
# Capabilities target (REQUIRED for ptrace)
#===============================================================================

find_program(SETCAP setcap REQUIRED)
find_program(SUDO sudo REQUIRED)

# Target to set capabilities on installed files
add_custom_target(cap-installed
    COMMAND ${SUDO} ${SETCAP} cap_sys_ptrace=eip ${CMAKE_INSTALL_PREFIX}/bin/dlpatch
    COMMAND ${SUDO} ${SETCAP} cap_sys_ptrace=eip ${CMAKE_INSTALL_PREFIX}/bin/dlpatchd
    COMMENT "Setting CAP_SYS_PTRACE on installed binaries (REQUIRED for ptrace)"
    VERBATIM
)

# Target to set capabilities on build files
add_custom_target(cap-build
    COMMAND ${SUDO} ${SETCAP} cap_sys_ptrace=eip $<TARGET_FILE:dlpatch>
    COMMAND ${SUDO} ${SETCAP} cap_sys_ptrace=eip $<TARGET_FILE:dlpatchd>
    COMMENT "Setting CAP_SYS_PTRACE on build binaries (REQUIRED for ptrace)"
    VERBATIM
)

# Alias for backward compatibility
add_custom_target(cap
    COMMAND ${CMAKE_COMMAND} -E echo "Use 'make cap-installed' for installed files or 'make cap-build' for build files"
)

#===============================================================================
# Interactive installation script (WITH automatic capabilities)
#===============================================================================

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/install_script.sh.in"
    "${CMAKE_CURRENT_BINARY_DIR}/install_script.sh"
    @ONLY
)

add_custom_target(install-interactive
    COMMAND chmod +x ${CMAKE_CURRENT_BINARY_DIR}/install_script.sh
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/install_script.sh
    COMMENT "Running interactive installation (will set CAP_SYS_PTRACE)"
    USES_TERMINAL
    VERBATIM
)

#===============================================================================
# Wrapper script for easy build + install + capabilities
#===============================================================================

set(INSTALL_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/install.sh")
file(WRITE ${INSTALL_SCRIPT}
"#!/bin/bash
# DLPatch build and install wrapper
# Automatically sets CAP_SYS_PTRACE (required for ptrace)

set -e

echo \"========================================\"
echo \"Building DLPatch with ${NCPUS} cores...\"
echo \"========================================\"

cd \"${CMAKE_BINARY_DIR}\" && make -j${NCPUS}

echo \"========================================\"
echo \"Installing DLPatch interactively...\"
echo \"(Will ask for sudo to set CAP_SYS_PTRACE)\"
echo \"========================================\"
cd \"${CMAKE_BINARY_DIR}\" && make install-interactive

echo \"========================================\"
echo \"Done! Verifying capabilities:\"
echo \"========================================\"
getcap \$(which dlpatch) 2>/dev/null || echo \"⚠️  CAP_SYS_PTRACE not set!\"
echo \"\"
echo \"If capabilities missing, run:\"
echo \"  cd ${CMAKE_BINARY_DIR} && sudo make cap-installed\"
")

execute_process(COMMAND chmod +x ${INSTALL_SCRIPT})
add_custom_target(wrapper ALL COMMAND chmod +x ${INSTALL_SCRIPT})

#===============================================================================
# Info target
#===============================================================================

add_custom_target(info
    COMMAND ${CMAKE_COMMAND} -E echo "========================================"
    COMMAND ${CMAKE_COMMAND} -E echo "DLPatch v${PROJECT_VERSION}"
    COMMAND ${CMAKE_COMMAND} -E echo "========================================"
    COMMAND ${CMAKE_COMMAND} -E echo "  Parallel cores: ${NCPUS}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Build type: ${CMAKE_BUILD_TYPE}"
    COMMAND ${CMAKE_COMMAND} -E echo "  Tests enabled: NO (release)"
    COMMAND ${CMAKE_COMMAND} -E echo "  libcap support: YES (required)"
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "Commands:"
    COMMAND ${CMAKE_COMMAND} -E echo "  ./install.sh                    # Build + install + capabilities"
    COMMAND ${CMAKE_COMMAND} -E echo "  cd build && make -jN            # Build only"
    COMMAND ${CMAKE_COMMAND} -E echo "  cd build && make install-interactive # Install + capabilities"
    COMMAND ${CMAKE_COMMAND} -E echo "  sudo make cap-installed         # Set capabilities (if missing)"
    COMMAND ${CMAKE_COMMAND} -E echo "========================================"
)

#===============================================================================
# Configure-time summary
#===============================================================================

message(STATUS "")
message(STATUS "=== DLPatch ${PROJECT_VERSION} RELEASE BUILD ===")
message(STATUS "Tests: DISABLED")
message(STATUS "lib_target: EXCLUDED")
message(STATUS "Parallel build: ${NCPUS} cores")
message(STATUS "libcap: REQUIRED - capabilities will be set automatically")
message(STATUS "")
message(STATUS "QUICK START:")
message(STATUS "  ./install.sh")
message(STATUS "")
message(STATUS "This will: build, install, and set CAP_SYS_PTRACE")
message(STATUS "================================================")
