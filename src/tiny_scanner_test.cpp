#include "DL_Manager.hpp"
#include <iostream>
#include <thread>
#include <chrono>

void print_separator(const std::string& title) {
    std::cout << "\n" << std::string(80, '=') << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << std::string(80, '=') << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pid>" << std::endl;
        return -1;
    }
    
    pid_t pid = atoi(argv[1]);
    DL_Manager manager(pid);
    
    std::string base_path = "/home/kotlyarovm/Documents/VSCode/4sem_26/Final_project/Live_patching/build/";
    std::string v1 = base_path + "libtiny_math_ops_v1.so";
    std::string v2 = base_path + "libtiny_math_ops_v2.so";
    
    // 1. Сначала применяем патчи
    print_separator("Applying patches");
    bool replace_result = manager.replace_library(v1, v2, "all");
    std::cout << "Replace result: " << (replace_result ? "SUCCESS" : "FAILURE") << std::endl;
    manager.print_library_tracker();
    
    // Даем время программе поработать с новыми функциями
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    // 2. Откатываем одну функцию
    print_separator("Rolling back zero function");
    bool rollback_func_result = manager.rollback_function(v1, "zero");
    std::cout << "Rollback zero result: " << (rollback_func_result ? "SUCCESS" : "FAILURE") << std::endl;
    manager.print_library_tracker();
    
    std::this_thread::sleep_for(std::chrono::seconds(3));
    
    // 3. Откатываем все функции
    print_separator("Rolling back all functions");
    bool rollback_all_result = manager.rollback_library(v1);
    std::cout << "Rollback all result: " << (rollback_all_result ? "SUCCESS" : "FAILURE") << std::endl;
    manager.print_library_tracker();
    
    return 0;
}
