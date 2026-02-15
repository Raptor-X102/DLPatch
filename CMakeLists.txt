cmake_minimum_required(VERSION 3.10)
project(LivePatching LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Динамическая библиотека
add_library(math_ops SHARED lib_target/math_ops.cpp)
target_include_directories(math_ops PUBLIC lib_target)

# Целевая программа (использует библиотеку)
add_executable(target_program src/target_program.cpp)
target_link_libraries(target_program PRIVATE math_ops)

# Программа сканера
add_executable(scanner_test src/scanner_test.cpp)
target_include_directories(scanner_test PRIVATE headers)

# Отладочная программа
add_executable(debug_maps src/debug_maps.cpp)

install(TARGETS math_ops LIBRARY DESTINATION lib)
install(TARGETS target_program scanner_test debug_maps RUNTIME DESTINATION bin)
