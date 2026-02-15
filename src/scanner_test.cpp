#include "DL_Manager.hpp"
#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <dirent.h>      // Add this for directory operations
#include <cctype>        // Add this for isdigit
#include <fstream>
#include <string>
#include <vector>

void print_separator(const std::string& title) {
    std::cout << "\n" << std::string(80, '=') << std::endl;
    std::cout << "  " << title << std::endl;
    std::cout << std::string(80, '=') << std::endl;
}

void test_get_loaded_libraries(DL_Manager& manager) {
    print_separator("TEST: get_loaded_libraries()");
    
    auto libs = manager.get_loaded_libraries();
    std::cout << "Found " << libs.size() << " unique libraries:" << std::endl;
    
    for (size_t i = 0; i < libs.size(); ++i) {
        std::cout << "  [" << std::setw(2) << i << "] " << libs[i] << std::endl;
    }
}

void test_get_library_info(DL_Manager& manager, const std::string& lib_pattern) {
    print_separator("TEST: get_library_info(\"" + lib_pattern + "\")");
    
    LibraryInfo info = manager.get_library_info(lib_pattern);
    
    if (info.path.empty()) {
        std::cout << "No library matching pattern \"" << lib_pattern << "\" found" << std::endl;
        return;
    }
    
    std::cout << "Library: " << info.path << std::endl;
    std::cout << "Base address: 0x" << std::hex << info.base_addr << std::dec << std::endl;
    std::cout << "Total size: " << info.size << " bytes" << std::endl;
    std::cout << "Segments: " << info.segments.size() << std::endl;
    
    for (size_t i = 0; i < info.segments.size(); ++i) {
        std::cout << "  Segment " << i << ": 0x" << std::hex 
                  << info.segments[i].first << " - 0x" 
                  << info.segments[i].second << std::dec
                  << " (" << (info.segments[i].second - info.segments[i].first) << " bytes)" << std::endl;
    }
}

void test_is_safe_to_replace(DL_Manager& manager, const std::string& lib_pattern) {
    print_separator("TEST: is_safe_to_replace(\"" + lib_pattern + "\")");
    
    std::cout << "Checking if it's safe to replace library..." << std::endl;
    
    bool safe = manager.is_safe_to_replace(lib_pattern);
    
    if (safe) {
        std::cout << "✓ RESULT: SAFE to replace - no threads are using the library" << std::endl;
    } else {
        std::cout << "✗ RESULT: NOT SAFE to replace - some threads are still using the library" << std::endl;
    }
}

void test_thread_stack_info(pid_t pid) {
    print_separator("TEST: Thread Stack Information");
    
    // Get all threads using /proc/pid/task directory
    std::vector<pid_t> tids;
    std::string task_path = "/proc/" + std::to_string(pid) + "/task/";
    
    DIR* dir = opendir(task_path.c_str());
    if (!dir) {
        std::cerr << "Failed to open " << task_path << std::endl;
        return;
    }
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // Check if entry is a directory and name is a number (tid)
        if (entry->d_type == DT_DIR) {
            bool is_number = true;
            for (int i = 0; entry->d_name[i]; ++i) {
                if (!isdigit(entry->d_name[i])) {
                    is_number = false;
                    break;
                }
            }
            if (is_number) {
                tids.push_back(atoi(entry->d_name));
            }
        }
    }
    closedir(dir);
    
    std::cout << "Process " << pid << " has " << tids.size() << " threads:" << std::endl;
    
    struct StackInfo {
        uintptr_t start;
        uintptr_t end;
        size_t size;
    };
    
    for (pid_t tid : tids) {
        // Read thread's stack info from /proc/<tid>/maps
        StackInfo stack = {0, 0, 0};
        std::string maps_path = "/proc/" + std::to_string(tid) + "/maps";
        std::ifstream maps_file(maps_path);
        
        if (maps_file.is_open()) {
            std::string line;
            while (std::getline(maps_file, line)) {
                // Look for stack mapping - "[stack]" for main thread
                if (line.find("[stack]") != std::string::npos) {
                    size_t dash = line.find('-');
                    if (dash != std::string::npos) {
                        stack.start = std::stoul(line.substr(0, dash), nullptr, 16);
                        stack.end = std::stoul(line.substr(dash + 1), nullptr, 16);
                        stack.size = stack.end - stack.start;
                        break;
                    }
                }
                // For other threads, look for rw-p anonymous mapping that's likely the stack
                else if (line.find("rw-p") != std::string::npos && line.find("00:00") != std::string::npos) {
                    size_t dash = line.find('-');
                    if (dash != std::string::npos) {
                        uintptr_t start = std::stoul(line.substr(0, dash), nullptr, 16);
                        uintptr_t end = std::stoul(line.substr(dash + 1), nullptr, 16);
                        size_t size = end - start;
                        // Thread stacks are typically 8MB
                        if (size >= 1024 * 1024 && size <= 16 * 1024 * 1024) {
                            stack.start = start;
                            stack.end = end;
                            stack.size = size;
                            break;
                        }
                    }
                }
            }
            maps_file.close();
        }
        
        std::cout << "  Thread " << tid << ": ";
        if (stack.size > 0) {
            std::cout << "stack 0x" << std::hex << stack.start << " - 0x" << stack.end 
                      << std::dec << " (" << stack.size << " bytes)";
        } else {
            std::cout << "no stack info found (thread might be using default stack)";
        }
        std::cout << std::endl;
    }
}

void test_with_different_libraries(DL_Manager& manager) {
    print_separator("TEST: Testing with different library patterns");
    
    // Test patterns
    std::vector<std::string> patterns = {
        "libc.so",
        "libstdc++",
        "libm.so",
        "ld-linux",
        "nonexistent_library.so"
    };
    
    for (const auto& pattern : patterns) {
        std::cout << "\nTesting pattern: \"" << pattern << "\"" << std::endl;
        std::cout << std::string(40, '-') << std::endl;
        
        LibraryInfo info = manager.get_library_info(pattern);
        if (info.path.empty()) {
            std::cout << "  → No library found" << std::endl;
        } else {
            std::cout << "  → Found: " << info.path << std::endl;
            std::cout << "  → Base: 0x" << std::hex << info.base_addr << std::dec << std::endl;
            std::cout << "  → Segments: " << info.segments.size() << std::endl;
        }
        
        bool safe = manager.is_safe_to_replace(pattern);
        std::cout << "  → Safe to replace: " << (safe ? "YES" : "NO") << std::endl;
    }
}

void test_symbol_address(DL_Manager& manager, const std::string& lib_pattern, const std::string& sym_name) {
    std::cout << "\n--- Testing symbol \"" << sym_name << "\" in library \"" << lib_pattern << "\" ---" << std::endl;
    LibraryInfo info = manager.get_library_info(lib_pattern);
    if (info.base_addr == 0) {
        std::cout << "  Library not found." << std::endl;
        return;
    }
    uintptr_t addr = manager.get_symbol_address(info.base_addr, sym_name);
    if (addr != 0) {
        std::cout << "  Symbol found at: 0x" << std::hex << addr << std::dec << std::endl;
    } else {
        std::cout << "  Symbol not found." << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        std::cerr << "Usage: " << argv[0] << " <pid> [library_pattern]" << std::endl;
        std::cerr << "  If library_pattern is provided, only test that specific library" << std::endl;
        return -1;
    }
    
    pid_t pid = atoi(argv[1]);
    
    std::cout << "Testing DL_Manager with PID " << pid << std::endl;
    std::cout << "Make sure the process exists and you have permission to access it" << std::endl;
    
    std::string proc_path = "/proc/" + std::to_string(pid);
    if (access(proc_path.c_str(), F_OK) != 0) {
        std::cerr << "Error: Process " << pid << " does not exist" << std::endl;
        return -1;
    }
    
    DL_Manager manager(pid);
    
    if (argc == 3) {
        std::string pattern = argv[2];
        std::cout << "Testing only library pattern: \"" << pattern << "\"" << std::endl;
        manager.print_loaded_libraries();
        test_get_library_info(manager, pattern);
        test_is_safe_to_replace(manager, pattern);
        return 0;
    }
    
    // Полный набор тестов
    std::cout << "\nRunning full test suite..." << std::endl;
    
    manager.print_loaded_libraries();
    test_get_loaded_libraries(manager);
    test_thread_stack_info(pid);
    test_with_different_libraries(manager);
    test_get_library_info(manager, "libc.so");
    test_is_safe_to_replace(manager, "libc.so");
    
    // Проверка наличия libmath_ops.so
    auto libs = manager.get_loaded_libraries();
    bool has_math_ops = false;
    for (const auto& lib : libs) {
        if (lib.find("libmath_ops.so") != std::string::npos) {
            has_math_ops = true;
            break;
        }
    }
    
    if (has_math_ops) {
        print_separator("TEST: Custom math_ops library");
        std::cout << "Found libmath_ops.so in process" << std::endl;
        test_get_library_info(manager, "libmath_ops.so");
        test_is_safe_to_replace(manager, "libmath_ops.so");
        
        // ---------- НОВЫЙ БЛОК: ПОДМЕНА БИБЛИОТЕКИ ----------
        print_separator("TEST: replace_library for libmath_ops.so");
        
        // Путь к новой версии библиотеки (предполагаем, что она находится в той же директории)
        std::string new_lib_path = "/home/kotlyarovm/Documents/VSCode/4sem_26/Final_project/Live_patching/build/libmath_ops_v2.so";
        
        if (access(new_lib_path.c_str(), F_OK) == 0) {
            std::cout << "Attempting to replace libmath_ops.so with " << new_lib_path << std::endl;
            std::cout << "Note: This requires root privileges and the target process must be stopped." << std::endl;
            
            bool replaced = manager.replace_library("libmath_ops.so", new_lib_path);
            
            if (replaced) {
                std::cout << "✓ SUCCESS: Library replaced with version 2" << std::endl;
                std::cout << "Check the target process output to confirm: it should now print '[MATH_LIB V2] ...'" << std::endl;
            } else {
                std::cout << "✗ FAILURE: Library replacement failed" << std::endl;
            }
        } else {
            std::cout << "New library version not found at: " << new_lib_path << std::endl;
            std::cout << "Please compile math_ops_v2.cpp and place it in the build directory." << std::endl;
        }
        // ------------------------------------------------------
    }
    
    print_separator("All tests completed");
    return 0;
}
