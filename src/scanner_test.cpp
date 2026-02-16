#include "DL_Manager.hpp"
#include <iostream>
#include <iomanip>
#include <unistd.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pid>" << std::endl;
        return -1;
    }
    
    pid_t pid = atoi(argv[1]);
    DL_Manager manager(pid);
    
    std::cout << "Testing multi-library replacement with PID " << pid << std::endl;
    
    // Replace libmath_ops.so with v2
    std::cout << "\n--- Replacement 1: v1 -> v2 ---" << std::endl;
    bool result1 = manager.replace_library("libmath_ops.so", 
                                           "/home/kotlyarovm/Documents/VSCode/4sem_26/Final_project/Live_patching/build/libmath_ops_v2.so",
                                           "perform_op");
    std::cout << "Result: " << (result1 ? "SUCCESS" : "FAILURE") << std::endl;
    manager.print_library_tracker();
    
    sleep(2); // Let the target process run a bit
    
    // Replace with v3 (should unload v2 automatically)
    std::cout << "\n--- Replacement 2: v2 -> v3 ---" << std::endl;
    bool result2 = manager.replace_library("libmath_ops.so", 
                                           "/home/kotlyarovm/Documents/VSCode/4sem_26/Final_project/Live_patching/build/libmath_ops_v3.so",
                                           "perform_op");
    std::cout << "Result: " << (result2 ? "SUCCESS" : "FAILURE") << std::endl;
    manager.print_library_tracker();
    
    // Try direct replacement v1 -> v3 (should detect already loaded)
    std::cout << "\n--- Replacement 3: v1 -> v3 (direct) ---" << std::endl;
    bool result3 = manager.replace_library("libmath_ops.so", 
                                           "/home/kotlyarovm/Documents/VSCode/4sem_26/Final_project/Live_patching/build/libmath_ops_v3.so",
                                           "perform_op");
    std::cout << "Result: " << (result3 ? "SUCCESS" : "FAILURE") << std::endl;
    manager.print_library_tracker();
    
    return 0;
}
