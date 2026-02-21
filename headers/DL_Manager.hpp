// DL_Manager.hpp
#ifndef LIBRARY_SCANNER_HPP
#define LIBRARY_SCANNER_HPP

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <sys/types.h>
#include <sys/user.h>  // Add this for user_regs_struct
#include "logging.hpp"

struct LibraryInfo {
    std::string path;
    uintptr_t base_addr;
    size_t size;
    std::vector<std::pair<uintptr_t, uintptr_t>> segments;
};

struct TrackedLibrary {
    std::string path;
    uintptr_t handle;          // handle from dlopen
    uintptr_t base_addr;        // base address in memory
    std::vector<std::string> patched_functions; // functions patched from other libs
    std::vector<std::string> provided_functions; // all functions this library exports
    std::vector<std::string> patched_libraries; // libraries that were patched to point to this one
    bool is_active;              // whether this library is currently the target of any patch
    bool is_original;            // whether this is the original library (should never be unloaded)
    
    TrackedLibrary() : handle(0), base_addr(0), is_active(false), is_original(false) {}
    
    TrackedLibrary(const std::string& p, uintptr_t h, uintptr_t addr, const std::string& func) 
        : path(p), handle(h), base_addr(addr), is_active(false), is_original(false) {
        provided_functions.push_back(func);
    }
    
    TrackedLibrary(const std::string& p, uintptr_t h, uintptr_t addr, 
                   const std::vector<std::string>& functions) 
        : path(p), handle(h), base_addr(addr), provided_functions(functions), 
          is_active(false), is_original(false) {}
};

struct SymbolInfo {
    std::string name;
    uintptr_t addr;
    size_t size;
    
    SymbolInfo() : addr(0), size(0) {}
    SymbolInfo(const std::string& n, uintptr_t a, size_t s) : name(n), addr(a), size(s) {}
};

struct ThreadContext {
    pid_t tid;
    struct user_regs_struct regs;
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
    size_t get_symbol_size(uintptr_t lib_base, const std::string& sym_name) const;
    std::vector<SymbolInfo> get_function_symbols(uintptr_t lib_base) const;
    
    bool replace_library(const std::string& target_lib_pattern, 
                     const std::string& new_lib_path,
                     const std::string& target_function = "all");
    
    void print_library_tracker() const;
    bool unload_library(const std::string& lib_path);

private:
    pid_t pid_;
    uintptr_t dlopen_addr_;
    uintptr_t dlclose_addr_;
    uintptr_t syscall_insn_;
    
    std::map<std::string, TrackedLibrary> tracked_libraries_;
    
    void init_addresses();
    
    bool is_library_already_loaded(const std::string& lib_path, uintptr_t& base_addr, uintptr_t& handle);
    uintptr_t find_syscall_instruction(uintptr_t libc_base);
    bool test_syscall(pid_t tid);
    
    std::vector<pid_t> stop_threads_and_prepare_main(pid_t& main_tid, struct user_regs_struct& saved_regs);
    
    uintptr_t allocate_remote_memory(pid_t tid, size_t size);
    bool write_shellcode_with_verification(pid_t tid, uintptr_t shellcode_addr,
                                           uintptr_t path_addr, uintptr_t result_addr);
    bool execute_shellcode_and_get_handle(pid_t tid, uintptr_t shellcode_addr,
                                          struct user_regs_struct& saved_regs,
                                          uintptr_t& out_handle);
    uintptr_t get_loaded_library_base(const std::string& lib_path) const;
    
    uintptr_t load_new_library(pid_t tid, const std::string& lib_path, 
                               uintptr_t& out_handle, struct user_regs_struct& saved_regs);
    bool unload_library_by_handle(pid_t tid, uintptr_t handle, struct user_regs_struct& saved_regs);
    
    bool apply_patch(pid_t tid, uintptr_t old_func, uintptr_t new_func,
                     size_t old_func_size, const std::string& func_name,
                     struct user_regs_struct& saved_regs);
    
    void cleanup_old_libraries(const std::string& target_lib_path, 
                               const std::string& new_lib_path,
                               pid_t tid,
                               struct user_regs_struct& saved_regs);
    
    bool apply_all_patches(pid_t tid, uintptr_t old_base, uintptr_t new_base,
                       const std::string& new_lib_path,
                       const std::string& target_function,
                       struct user_regs_struct& saved_regs);
    
    bool check_preconditions(const std::string& target_lib_pattern);
    bool ensure_new_library_loaded(pid_t tid, const std::string& new_lib_path,
                                   uintptr_t& new_lib_base, uintptr_t& new_handle,
                                   struct user_regs_struct& saved_regs);
    bool apply_patches_and_update_tracker(pid_t tid, uintptr_t target_base, uintptr_t new_base,
                                          const std::string& new_lib_path, const std::string& target_func,
                                          struct user_regs_struct& saved_regs);
    
    bool wait_for_threads_to_leave_library(const std::vector<pid_t>& all_tids,
                                           const std::vector<std::pair<uintptr_t, uintptr_t>>& segments,
                                           std::vector<pid_t>& stopped_tids,
                                           int max_attempts = 50,
                                           int retry_us = 10000);
};

#include "DL_Manager_get_lib_data.ipp"
#include "DL_Manager_check.ipp"
#include "DL_Manager_extract_funcs_from_lib.ipp"
#include "DL_manager_replace.ipp"

#endif // LIBRARY_SCANNER_HPPendif // LIBRARY_SCANNER_HPP
