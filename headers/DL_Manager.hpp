#ifndef LIBRARY_SCANNER_HPP
#define LIBRARY_SCANNER_HPP

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <sys/types.h>

struct LibraryInfo {
    std::string path;
    uintptr_t base_addr;
    size_t size;
    std::vector<std::pair<uintptr_t, uintptr_t>> segments;
};

struct TrackedLibrary {
    std::string path;
    uintptr_t handle;        // handle from dlopen
    uintptr_t base_addr;      // base address in memory
    std::string target_function; // function that was patched (e.g., "perform_op")
    std::vector<std::string> patched_libraries; // libraries that were patched to point to this one
    bool is_active;           // whether this library is currently the target of any patch
    bool is_original;         // whether this is the original library (should never be unloaded)
    
    TrackedLibrary() : handle(0), base_addr(0), is_active(false), is_original(false) {}
    TrackedLibrary(const std::string& p, uintptr_t h, uintptr_t addr, const std::string& func) 
        : path(p), handle(h), base_addr(addr), target_function(func), is_active(false), is_original(false) {}
};

class DL_Manager {
public:
    explicit DL_Manager(pid_t pid) : pid_(pid), dlopen_addr_(0), dlclose_addr_(0), syscall_insn_(0) {
        init_addresses();
    }

    std::vector<std::string> get_loaded_libraries() const;
    LibraryInfo get_library_info(const std::string& lib_name) const;
    bool is_safe_to_replace(const std::string& lib_name) const;
    void print_loaded_libraries() const;
    uintptr_t get_symbol_address(uintptr_t lib_base, const std::string& sym_name) const;
    
    // New method for multi-library management
    bool replace_library(const std::string& target_lib_pattern, 
                     const std::string& new_lib_path,
                     const std::string& target_function = "all");
    
    // Utility methods
    void print_library_tracker() const;
    bool unload_library(const std::string& lib_path);

private:
    pid_t pid_;
    uintptr_t dlopen_addr_;
    uintptr_t dlclose_addr_;
    uintptr_t syscall_insn_;
    
    // Track all libraries we've loaded and their relationships
    std::map<std::string, TrackedLibrary> tracked_libraries_;
    
    // Initialize required addresses from libc
    void init_addresses();
    
    // Helper methods
    bool is_library_already_loaded(const std::string& lib_path, uintptr_t& base_addr, uintptr_t& handle);
    uintptr_t find_syscall_instruction(uintptr_t libc_base);
    bool test_syscall(pid_t tid);
    
    // Thread management
    std::vector<pid_t> stop_threads_and_prepare_main(pid_t& main_tid, struct user_regs_struct& saved_regs);
    
    // Library loading/unloading
    uintptr_t load_new_library(pid_t tid, const std::string& lib_path, 
                               uintptr_t& out_handle, struct user_regs_struct& saved_regs);
    bool unload_library_by_handle(pid_t tid, uintptr_t handle, struct user_regs_struct& saved_regs);
    
    // Patching
    bool apply_patch(pid_t tid, uintptr_t old_func, uintptr_t new_func, 
                     struct user_regs_struct& saved_regs);
    
    // Cleanup after patch
    void cleanup_old_libraries(const std::string& target_lib_path, 
                               const std::string& new_lib_path,
                               pid_t tid,
                               struct user_regs_struct& saved_regs);

    std::vector<std::pair<std::string, uintptr_t>> get_function_symbols(uintptr_t lib_base) const;
    
    bool apply_all_patches(pid_t tid, uintptr_t old_base, uintptr_t new_base,
                           const std::string& target_function,
                           struct user_regs_struct& saved_regs);
};

#include "DL_Manager_get_lib_data.ipp"
#include "DL_Manager_check.ipp"
#include "DL_Manager_extract_funcs_from_lib.ipp"
#include "DL_manager_replace.ipp"

#endif // LIBRARY_SCANNER_HPP
