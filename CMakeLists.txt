# Корневой CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(LivePatching LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Поиск библиотеки nlohmann_json
find_package(nlohmann_json CONFIG REQUIRED)

# Поиск библиотеки libcap
find_library(LIB_CAP NAMES cap)
if(NOT LIB_CAP)
    message(WARNING "libcap not found. Install libcap-dev or equivalent for capability support.")
endif()

# Директории с заголовками
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/headers
    ${CMAKE_CURRENT_SOURCE_DIR}/headers/backend
    ${CMAKE_CURRENT_SOURCE_DIR}/headers/daemon
    ${CMAKE_CURRENT_SOURCE_DIR}/headers/frontend
)

# Основная утилита
add_executable(dl_manager
    src/main/frontend.cpp
)

target_link_libraries(dl_manager PRIVATE 
    dl 
    pthread
    nlohmann_json::nlohmann_json
    ${LIB_CAP}
)

# Демон
add_executable(dl_manager_daemon
    src/daemon/daemon.cpp
)

target_link_libraries(dl_manager_daemon PRIVATE 
    dl 
    pthread
    nlohmann_json::nlohmann_json
    ${LIB_CAP}
)

install(TARGETS dl_manager dl_manager_daemon RUNTIME DESTINATION bin)

# Проверка наличия setcap
find_program(SETCAP setcap)
if(NOT SETCAP)
    message(WARNING "setcap not found. Install libcap-bin or equivalent to enable capability setting.")
endif()

# Инструкция по установке capability
message(STATUS "")
message(STATUS "=== Ptrace Capability Note ===")
message(STATUS "To trace processes not started by this program, you need CAP_SYS_PTRACE capability.")
message(STATUS "Run the following commands after build (requires sudo):")
message(STATUS "  sudo setcap cap_sys_ptrace=eip ${CMAKE_BINARY_DIR}/dl_manager")
message(STATUS "  sudo setcap cap_sys_ptrace=eip ${CMAKE_BINARY_DIR}/dl_manager_daemon")
message(STATUS "Or use the 'cap' target: make cap")
message(STATUS "================================")

# Цель для установки capability (требует sudo)
if(SETCAP)
    add_custom_target(cap
        COMMAND sudo ${SETCAP} cap_sys_ptrace=eip $<TARGET_FILE:dl_manager>
        COMMAND sudo ${SETCAP} cap_sys_ptrace=eip $<TARGET_FILE:dl_manager_daemon>
        COMMENT "Granting CAP_SYS_PTRACE capability to executables (requires sudo password)"
    )
endif()

find_program(SETCAP setcap REQUIRED)
find_program(SUDO sudo REQUIRED)

add_custom_command(TARGET dl_manager POST_BUILD
    COMMAND ${SUDO} ${SETCAP} cap_sys_ptrace=eip $<TARGET_FILE:dl_manager>
    COMMAND ${SUDO} ${SETCAP} cap_sys_ptrace=eip $<TARGET_FILE:dl_manager_daemon>
    COMMAND ${SUDO} chmod u+s $<TARGET_FILE:dl_manager>
    COMMAND ${SUDO} chmod u+s $<TARGET_FILE:dl_manager_daemon>
    COMMAND echo "✅ CAP_SYS_PTRACE capability and setuid bit added successfully"
    COMMENT "Adding CAP_SYS_PTRACE and setuid to allow ptrace without sudo (requires password)"
)

# Тесты
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    add_subdirectory(tests)
endif()
