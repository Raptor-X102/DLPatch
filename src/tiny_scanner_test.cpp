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
    
    print_separator("Testing GOT patch on tiny functions");
    
    // Получаем базовый адрес библиотеки
    LibraryInfo info = manager.get_library_info("libtiny_math_ops_v1.so");
    if (info.base_addr == 0) {
        std::cerr << "Target library not loaded!" << std::endl;
        return -1;
    }
    
    // Выводим размеры функций
    std::cout << "\nFunction sizes in original library:\n";
    std::cout << "  zero: " << manager.get_symbol_size(info.base_addr, "zero") << " bytes\n";
    std::cout << "  one: " << manager.get_symbol_size(info.base_addr, "one") << " bytes\n";
    std::cout << "  forty_two: " << manager.get_symbol_size(info.base_addr, "forty_two") << " bytes\n";
    std::cout << "  max: " << manager.get_symbol_size(info.base_addr, "max") << " bytes\n";
    std::cout << "  add: " << manager.get_symbol_size(info.base_addr, "add") << " bytes\n";
    std::cout << "\nThreshold for GOT patch: 16 bytes\n";
    
    // Заменяем все функции
    std::cout << "\nReplacing all functions with v2...\n";
    bool result = manager.replace_library(v1, v2, "all");
    std::cout << "Result: " << (result ? "SUCCESS" : "FAILURE") << std::endl;
    
    manager.print_library_tracker();
    
    return 0;
}
