cmake_minimum_required(VERSION 3.10)
project(LivePatching LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Пути к библиотекам
set(LIB_TARGET_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib_target)

# Версия 1 библиотеки (оригинальная)
add_library(math_ops SHARED ${LIB_TARGET_DIR}/math_ops.cpp)
target_include_directories(math_ops PUBLIC ${LIB_TARGET_DIR})
set_target_properties(math_ops PROPERTIES 
    OUTPUT_NAME "math_ops"
    PREFIX "lib"
)

# Версия 2 библиотеки (первая модификация)
add_library(math_ops_v2 SHARED ${LIB_TARGET_DIR}/math_ops_v2.cpp)
target_include_directories(math_ops_v2 PUBLIC ${LIB_TARGET_DIR})
set_target_properties(math_ops_v2 PROPERTIES 
    OUTPUT_NAME "math_ops_v2"
    PREFIX "lib"
)

# Версия 3 библиотеки (вторая модификация)
add_library(math_ops_v3 SHARED ${LIB_TARGET_DIR}/math_ops_v3.cpp)
target_include_directories(math_ops_v3 PUBLIC ${LIB_TARGET_DIR})
set_target_properties(math_ops_v3 PROPERTIES 
    OUTPUT_NAME "math_ops_v3"
    PREFIX "lib"
)

# Целевая программа (использует библиотеку)
add_executable(target_program src/target_program.cpp)
target_include_directories(target_program PRIVATE ${LIB_TARGET_DIR})
target_link_libraries(target_program PRIVATE math_ops dl)

# Программа сканера
add_executable(scanner_test src/scanner_test.cpp)
target_include_directories(scanner_test PRIVATE headers ${LIB_TARGET_DIR})
target_link_libraries(scanner_test PRIVATE dl)

# Отладочная программа
add_executable(debug_maps src/debug_maps.cpp)
target_include_directories(debug_maps PRIVATE headers)

install(TARGETS math_ops math_ops_v2 math_ops_v3 LIBRARY DESTINATION lib)
install(TARGETS target_program scanner_test debug_maps RUNTIME DESTINATION bin)

# Дополнительная информация при сборке
message(STATUS "Build configuration:")
message(STATUS "  Libraries will be installed to: ${CMAKE_INSTALL_PREFIX}/lib")
message(STATUS "  Executables will be installed to: ${CMAKE_INSTALL_PREFIX}/bin")
message(STATUS "  Library versions: v1 (math_ops), v2 (math_ops_v2), v3 (math_ops_v3)")

# Маленькая тестовая библиотека для GOT-патча
add_library(tiny_math_ops_v1 SHARED lib_target/tiny_math_ops_v1.cpp)
target_include_directories(tiny_math_ops_v1 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib_target)
set_target_properties(tiny_math_ops_v1 PROPERTIES OUTPUT_NAME "tiny_math_ops_v1" PREFIX "lib")

add_library(tiny_math_ops_v2 SHARED lib_target/tiny_math_ops_v2.cpp)
target_include_directories(tiny_math_ops_v2 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/lib_target)
set_target_properties(tiny_math_ops_v2 PROPERTIES OUTPUT_NAME "tiny_math_ops_v2" PREFIX "lib")

# Целевая программа для маленькой библиотеки
add_executable(target_program_tiny src/target_program_tiny.cpp)
target_include_directories(target_program_tiny PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib_target)
target_link_libraries(target_program_tiny PRIVATE tiny_math_ops_v1 dl)

# Программа для замены маленькой библиотеки
add_executable(tiny_scanner_test src/tiny_scanner_test.cpp)
target_include_directories(tiny_scanner_test PRIVATE headers ${CMAKE_CURRENT_SOURCE_DIR}/lib_target)
target_link_libraries(tiny_scanner_test PRIVATE dl)
