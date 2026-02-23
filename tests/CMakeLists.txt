# tests/CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(LivePatchingTests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Пути к заголовкам и библиотекам
set(HEADERS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../headers)
set(LIB_TARGET_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../lib_target)

# Include directories
include_directories(
    ${HEADERS_DIR}
    ${HEADERS_DIR}/backend
    ${LIB_TARGET_DIR}
)

#-----------------------------------------------------------------------------
# Тестовые библиотеки
#-----------------------------------------------------------------------------

# Версия 1 библиотеки (оригинальная)
add_library(math_ops SHARED ${LIB_TARGET_DIR}/math_ops.cpp)
set_target_properties(math_ops PROPERTIES 
    OUTPUT_NAME "math_ops"
    PREFIX "lib"
)

# Версия 2 библиотеки (первая модификация)
add_library(math_ops_v2 SHARED ${LIB_TARGET_DIR}/math_ops_v2.cpp)
set_target_properties(math_ops_v2 PROPERTIES 
    OUTPUT_NAME "math_ops_v2"
    PREFIX "lib"
)

# Версия 3 библиотеки (вторая модификация)
add_library(math_ops_v3 SHARED ${LIB_TARGET_DIR}/math_ops_v3.cpp)
set_target_properties(math_ops_v3 PROPERTIES 
    OUTPUT_NAME "math_ops_v3"
    PREFIX "lib"
)

# Маленькая тестовая библиотека для GOT-патча (v1)
add_library(tiny_math_ops_v1 SHARED ${LIB_TARGET_DIR}/tiny_math_ops_v1.cpp)
set_target_properties(tiny_math_ops_v1 PROPERTIES 
    OUTPUT_NAME "tiny_math_ops_v1" 
    PREFIX "lib"
)

# Маленькая тестовая библиотека для GOT-патча (v2)
add_library(tiny_math_ops_v2 SHARED ${LIB_TARGET_DIR}/tiny_math_ops_v2.cpp)
set_target_properties(tiny_math_ops_v2 PROPERTIES 
    OUTPUT_NAME "tiny_math_ops_v2" 
    PREFIX "lib"
)

#-----------------------------------------------------------------------------
# Тестовые программы
#-----------------------------------------------------------------------------

# Целевая программа (использует math_ops)
add_executable(target_program target_program.cpp)
target_link_libraries(target_program PRIVATE math_ops dl)

# Программа сканера для math_ops
add_executable(scanner_test scanner_test.cpp)
target_link_libraries(scanner_test PRIVATE dl)

# Отладочная программа для просмотра maps
add_executable(debug_maps debug_maps.cpp)

# Целевая программа для маленькой библиотеки (использует tiny_math_ops_v1)
add_executable(target_program_tiny target_program_tiny.cpp)
target_link_libraries(target_program_tiny PRIVATE tiny_math_ops_v1 dl)

# Программа для замены маленькой библиотеки
add_executable(tiny_scanner_test tiny_scanner_test.cpp)
target_link_libraries(tiny_scanner_test PRIVATE dl)

#-----------------------------------------------------------------------------
# Установка
#-----------------------------------------------------------------------------
install(TARGETS 
    math_ops math_ops_v2 math_ops_v3 
    tiny_math_ops_v1 tiny_math_ops_v2 
    LIBRARY DESTINATION lib
)

install(TARGETS 
    target_program scanner_test debug_maps 
    target_program_tiny tiny_scanner_test 
    RUNTIME DESTINATION bin
)

#-----------------------------------------------------------------------------
# Информация
#-----------------------------------------------------------------------------
message(STATUS "Test targets built:")
message(STATUS "  Libraries: math_ops, math_ops_v2, math_ops_v3, tiny_math_ops_v1, tiny_math_ops_v2")
message(STATUS "  Executables: target_program, scanner_test, debug_maps, target_program_tiny, tiny_scanner_test")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
