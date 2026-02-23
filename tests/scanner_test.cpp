#include "DL_Manager.hpp"
#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <thread>
#include <chrono>

void print_separator(const std::string& title) {
    std::cout << "\n" << std::string(80, '=') << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << std::string(80, '=') << std::endl;
}

void test_single_function_replace(DL_Manager& manager, const std::string& target, 
                                   const std::string& new_lib, const std::string& func) {
    print_separator("Testing single function replace: " + func);
    std::cout << "Replacing " << target << " with " << new_lib << " for function " << func << std::endl;
    
    bool result = manager.replace_library(target, new_lib, func);
    std::cout << "Result: " << (result ? "SUCCESS" : "FAILURE") << std::endl;
    manager.print_library_tracker();
    
    // Даем время целевой программе выполниться с новой функцией
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

void test_all_functions_replace(DL_Manager& manager, const std::string& target, 
                                 const std::string& new_lib) {
    print_separator("Testing replace all functions");
    std::cout << "Replacing " << target << " with " << new_lib << " for ALL functions" << std::endl;
    
    bool result = manager.replace_library(target, new_lib, "all");
    std::cout << "Result: " << (result ? "SUCCESS" : "FAILURE") << std::endl;
    manager.print_library_tracker();
    
    std::this_thread::sleep_for(std::chrono::seconds(3));
}

void test_sequence(DL_Manager& manager) {
    print_separator("Testing replacement sequence v1 -> v2 -> v3");
    
    std::string base_path = "/home/kotlyarovm/Documents/VSCode/4sem_26/Final_project/Live_patching/build/";
    std::string v1 = base_path + "libmath_ops.so";
    std::string v2 = base_path + "libmath_ops_v2.so";
    std::string v3 = base_path + "libmath_ops_v3.so";
    
    // Тест 1: Замена одной функции (add)
    test_single_function_replace(manager, v1, v2, "add");
    
    // Тест 2: Замена другой функции (multiply)
    test_single_function_replace(manager, v1, v2, "multiply");
    
    // Тест 3: Замена всех функций сразу
    test_all_functions_replace(manager, v1, v3);
    
    // Тест 4: Попытка прямой замены v1 -> v3 (должна определить, что v3 уже загружена)
    test_all_functions_replace(manager, v1, v3);
    
    // Тест 5: Проверка выгрузки старых версий
    print_separator("Checking library tracker after sequence");
    manager.print_library_tracker();
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pid>" << std::endl;
        return -1;
    }
    
    pid_t pid = atoi(argv[1]);
    DL_Manager manager(pid);
    
    std::cout << "Testing multi-library replacement with PID " << pid << std::endl;
    std::cout << "Make sure target program is running with multiple math functions" << std::endl;
    
    // Запускаем последовательность тестов
    test_sequence(manager);
    
    print_separator("All tests completed");
    return 0;
}
