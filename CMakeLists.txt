#===============================================================================
# Root CMakeLists.txt for LivePatching project
#===============================================================================

cmake_minimum_required(VERSION 3.10)
project(LivePatching LANGUAGES CXX)

#===============================================================================
# Project configuration
#===============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

#===============================================================================
# Build type configuration - controls DEBUG/NDEBUG macros
#===============================================================================

# Print build type information
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    message(STATUS "Build type not specified, defaulting to Release")
else()
    message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
endif()

# Set DEBUG/NDEBUG macros based on build type
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG)
    message(STATUS "DEBUG macro defined - verbose logging enabled")
else()
    add_definitions(-DNDEBUG)
    message(STATUS "NDEBUG macro defined - debug logging disabled")
endif()

#===============================================================================
# External dependencies
#===============================================================================

# JSON library for communication protocol
find_package(nlohmann_json CONFIG REQUIRED)

# libcap for capability management (optional)
find_library(LIB_CAP NAMES cap)
if(NOT LIB_CAP)
    message(WARNING "libcap not found. Install libcap-dev or equivalent for capability support.")
endif()

#===============================================================================
# Include directories
#===============================================================================

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/headers
    ${CMAKE_CURRENT_SOURCE_DIR}/headers/backend
    ${CMAKE_CURRENT_SOURCE_DIR}/headers/daemon
    ${CMAKE_CURRENT_SOURCE_DIR}/headers/frontend
)

#===============================================================================
# Main executable: dl_manager
#===============================================================================

add_executable(dl_manager
    src/main/frontend.cpp
)

target_link_libraries(dl_manager PRIVATE 
    dl 
    pthread
    nlohmann_json::nlohmann_json
    ${LIB_CAP}
)

#===============================================================================
# Daemon executable: dl_manager_daemon
#===============================================================================

add_executable(dl_manager_daemon
    src/daemon/daemon.cpp
)

target_link_libraries(dl_manager_daemon PRIVATE 
    dl 
    pthread
    nlohmann_json::nlohmann_json
    ${LIB_CAP}
)

#===============================================================================
# Installation
#===============================================================================

install(TARGETS dl_manager dl_manager_daemon RUNTIME DESTINATION bin)

#===============================================================================
# Capability management (ptrace without root)
#===============================================================================

find_program(SETCAP setcap REQUIRED)
find_program(SUDO sudo REQUIRED)

# Post-build commands to set capabilities and setuid bit
add_custom_command(TARGET dl_manager POST_BUILD
    COMMAND ${SUDO} ${SETCAP} cap_sys_ptrace=eip $<TARGET_FILE:dl_manager>
    COMMAND ${SUDO} ${SETCAP} cap_sys_ptrace=eip $<TARGET_FILE:dl_manager_daemon>
    COMMAND ${SUDO} chmod u+s $<TARGET_FILE:dl_manager>
    COMMAND ${SUDO} chmod u+s $<TARGET_FILE:dl_manager_daemon>
    COMMAND echo "✅ CAP_SYS_PTRACE capability and setuid bit added successfully"
    COMMENT "Adding CAP_SYS_PTRACE and setuid to allow ptrace without sudo (requires password)"
)

# Custom target for manual capability setting
add_custom_target(cap
    COMMAND sudo ${SETCAP} cap_sys_ptrace=eip $<TARGET_FILE:dl_manager>
    COMMAND sudo ${SETCAP} cap_sys_ptrace=eip $<TARGET_FILE:dl_manager_daemon>
    COMMENT "Granting CAP_SYS_PTRACE capability to executables (requires sudo password)"
)

# Display capability information
message(STATUS "")
message(STATUS "=== Ptrace Capability Note ===")
message(STATUS "To trace processes not started by this program, you need CAP_SYS_PTRACE capability.")
message(STATUS "The build system automatically adds this capability during build (requires sudo).")
message(STATUS "If you need to reapply it later, use: make cap")
message(STATUS "================================")

#===============================================================================
# Tests (optional)
#===============================================================================

option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()
