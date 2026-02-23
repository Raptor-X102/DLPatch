// DL_Manager.hpp
#ifndef DL_MANAGER_HPP
#define DL_MANAGER_HPP

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <sys/types.h>
#include <sys/user.h>
#include "logging.hpp"

//=============================================================================
// Data structures
//=============================================================================

// Information about a loaded library
struct LibraryInfo {
    std::string path;    // Full path to the library file
    uintptr_t base_addr; // Base address where library is loaded
    size_t size;         // Total size of the library in memory
    std::vector<std::pair<uintptr_t, uintptr_t>>
        segments; // Memory segments [start, end)
};

// Tracked library state with rollback data
struct TrackedLibrary {
    std::string path;                           // Library path (used as key)
    uintptr_t handle;                           // Handle returned by dlopen
    uintptr_t base_addr;                        // Base address in memory
    std::vector<std::string> 
        patched_functions; // Functions patched from other libraries
    std::vector<std::string> 
        provided_functions; // All functions this library exports
    std::vector<std::string>
        patched_libraries; // Libraries that were patched to point to this one
    bool is_active;        // Whether this library is currently the target of any patch
    bool is_original;      // Whether this is the original library (never unloaded)
    std::map<std::string, std::vector<uint8_t>>
        saved_original_bytes; // Original bytes for JMP patch rollback
    std::map<std::string, uintptr_t>
        saved_original_got; // Original GOT values for GOT patch rollback

    // Constructors
    TrackedLibrary()
        : handle(0)
        , base_addr(0)
        , is_active(false)
        , is_original(false) {}

    TrackedLibrary(const std::string &p,
                   uintptr_t h,
                   uintptr_t addr,
                   const std::string &func)
        : path(p)
        , handle(h)
        , base_addr(addr)
        , is_active(false)
        , is_original(false) {
        provided_functions.push_back(func);
    }

    TrackedLibrary(const std::string &p,
                   uintptr_t h,
                   uintptr_t addr,
                   const std::vector<std::string> &functions)
        : path(p)
        , handle(h)
        , base_addr(addr)
        , provided_functions(functions)
        , is_active(false)
        , is_original(false) {}
};

// Symbol information
struct SymbolInfo {
    std::string name; // Symbol name
    uintptr_t addr;   // Symbol address in memory
    size_t size;      // Symbol size in bytes

    // Constructors
    SymbolInfo()
        : addr(0)
        , size(0) {}
    SymbolInfo(const std::string &n, uintptr_t a, size_t s)
        : name(n)
        , addr(a)
        , size(s) {}
};

// Thread context for stop/resume operations
struct ThreadContext {
    pid_t tid;                    // Thread ID
    struct user_regs_struct regs; // Saved registers
};

// Dynamic section information parsed from ELF
struct DynamicInfo {
    uintptr_t strtab = 0;     // DT_STRTAB - string table
    uintptr_t symtab = 0;     // DT_SYMTAB - symbol table
    uintptr_t jmprel = 0;     // DT_JMPREL - PLT relocations
    size_t pltrelsz = 0;      // DT_PLTRELSZ - size of PLT relocations
    uint64_t pltrel_type = 0; // DT_PLTREL - type of relocations (DT_RELA or DT_REL)
    size_t strsz = 0;         // DT_STRSZ - size of string table
    size_t syment = 0;        // DT_SYMENT - size of symbol table entry
    uintptr_t hash = 0;       // DT_HASH - ELF hash table
    uintptr_t gnu_hash = 0;   // DT_GNU_HASH - GNU hash table
};

//=============================================================================
// Main class
//=============================================================================

class DL_Manager {
public:
    // Constructor - initializes addresses from libc
    DL_Manager(pid_t pid)
        : pid_(pid)
        , dlopen_addr_(0)
        , dlclose_addr_(0)
        , syscall_insn_(0) {
        init_addresses();
    }

    void set_tracked_libraries(const std::map<std::string, TrackedLibrary> &libs) {
        tracked_libraries_ = libs;
    }

    const std::map<std::string, TrackedLibrary> &get_tracked_libraries() const {
        return tracked_libraries_;
    }

    //-------------------------------------------------------------------------
    // Library information methods (DL_Manager_get_lib_data.ipp)
    //-------------------------------------------------------------------------
    std::vector<std::string>
    get_loaded_libraries() const; // Get list of loaded libraries
    LibraryInfo get_library_info(
        const std::string &lib_name) const; // Get info about specific library
    void print_loaded_libraries() const;    // Print all loaded libraries

    //-------------------------------------------------------------------------
    // Safety checks (DL_Manager_check.ipp)
    //-------------------------------------------------------------------------
    bool is_safe_to_replace(
        const std::string &lib_name) const; // Check if library can be safely replaced

    //-------------------------------------------------------------------------
    // Symbol lookup methods (DL_Manager_extract_funcs_from_lib.ipp)
    //-------------------------------------------------------------------------
    uintptr_t
    get_symbol_address(uintptr_t lib_base,
                       const std::string &sym_name) const; // Get symbol address
    size_t get_symbol_size(uintptr_t lib_base,
                           const std::string &sym_name) const; // Get symbol size
    std::vector<SymbolInfo>
    get_function_symbols(uintptr_t lib_base) const; // Get all function symbols

    //-------------------------------------------------------------------------
    // GOT entry lookup (DL_Manager_GOT.ipp)
    //-------------------------------------------------------------------------
    uintptr_t
    find_got_entry(uintptr_t lib_base,
                   const std::string &sym_name) const; // Find GOT entry for symbol

    //-------------------------------------------------------------------------
    // Main patching interface (DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    bool replace_library(
        const std::string &target_lib_pattern,
        const std::string &new_lib_path,
        const std::string &target_function = "all");  // Replace library/function
                                                      //
    bool unload_library(const std::string &lib_path); // Unload unused library

    //-------------------------------------------------------------------------
    // Library tracker (DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    void print_library_tracker() const; // Print status of tracked libraries

    //-------------------------------------------------------------------------
    // Cache management (DL_Manager_cache.ipp)
    //-------------------------------------------------------------------------
    void invalidate_cache(uintptr_t lib_base = 0); // Invalidate cache (0 = all)
    void print_cache_stats() const;                // Print cache statistics

    //-------------------------------------------------------------------------
    // Rollback operations (DL_Manager_rollback.ipp)
    //-------------------------------------------------------------------------
    bool
    rollback_library(const std::string &lib_path); // Rollback all patches for library
    bool rollback_function(const std::string &lib_path,
                           const std::string &func_name); // Rollback single function

    //-------------------------------------------------------------------------
    // Architecture layer helpers (declaration only - implemented in
    // DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    bool read_remote_memory_raw(uintptr_t addr, void *buffer, size_t size) const;

private:
    // Core members
    pid_t pid_;              // Target process PID
    uintptr_t dlopen_addr_;  // Address of dlopen in target
    uintptr_t dlclose_addr_; // Address of dlclose in target
    uintptr_t syscall_insn_; // Address of syscall instruction

    std::map<std::string, TrackedLibrary>
        tracked_libraries_; // Tracked libraries by path

    // Cache structure
    struct CachedLibraryData {
        std::vector<SymbolInfo> symbols; // Cached symbols
        std::map<std::string, uintptr_t>
            got_entries; // Cached GOT entries by symbol name
        bool parsed;     // Whether cache is valid

        // Constructor
        CachedLibraryData()
            : parsed(false) {}
    };

    mutable std::map<uintptr_t, CachedLibraryData>
        library_cache_; // Cache by base address

    //-------------------------------------------------------------------------
    // Initialization (DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    void init_addresses(); // Initialize dlopen/dlclose/syscall addresses

    //-------------------------------------------------------------------------
    // Syscall helpers (DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    uintptr_t
    find_syscall_instruction(uintptr_t libc_base); // Find syscall instruction in libc
    bool test_syscall(pid_t tid);                  // Test remote syscall mechanism

    //-------------------------------------------------------------------------
    // Library loading helpers (DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    bool is_library_already_loaded(const std::string &lib_path,
                                   uintptr_t &base_addr,
                                   uintptr_t &handle);
    bool is_library_active(const std::string &lib_path) const;
    uintptr_t get_loaded_library_base(const std::string &lib_path) const;

    //-------------------------------------------------------------------------
    // Thread control (DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    bool prepare_thread_for_injection(pid_t tid, struct user_regs_struct &prepared_regs);
    std::vector<pid_t>
    stop_threads_and_prepare_main(pid_t &main_tid, struct user_regs_struct &saved_regs);
    bool wait_for_threads_to_leave_library(
        const std::vector<pid_t> &all_tids,
        const std::vector<std::pair<uintptr_t, uintptr_t>> &segments,
        std::vector<pid_t> &stopped_tids,
        int max_attempts = 50,
        int retry_us = 10000);

    //-------------------------------------------------------------------------
    // Remote memory operations (DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    uintptr_t allocate_remote_memory(pid_t tid, size_t size);
    bool write_shellcode(pid_t tid,
                                           uintptr_t shellcode_addr,
                                           uintptr_t path_addr,
                                           uintptr_t result_addr);
    bool execute_shellcode_and_get_handle(pid_t tid,
                                          uintptr_t shellcode_addr,
                                          struct user_regs_struct &saved_regs,
                                          uintptr_t &out_handle);

    //-------------------------------------------------------------------------
    // Library loading/unloading (DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    uintptr_t load_new_library(pid_t tid,
                               const std::string &lib_path,
                               uintptr_t &out_handle,
                               struct user_regs_struct &saved_regs);
    bool unload_library_by_handle(pid_t tid,
                                  uintptr_t handle,
                                  struct user_regs_struct &saved_regs);

    //-------------------------------------------------------------------------
    // Patching methods (DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    void cleanup_old_libraries(const std::string &target_lib_path,
                               const std::string &new_lib_path,
                               pid_t tid,
                               struct user_regs_struct &saved_regs);

    bool apply_patch(pid_t tid,
                     const std::string &target_lib_path,
                     uintptr_t old_func,
                     uintptr_t new_func,
                     size_t old_func_size,
                     const std::string &func_name,
                     struct user_regs_struct &saved_regs);

    bool apply_all_patches(pid_t tid,
                           const std::string &target_lib_path,
                           uintptr_t old_base,
                           uintptr_t new_base,
                           const std::string &new_lib_path,
                           const std::string &target_function,
                           struct user_regs_struct &saved_regs);

    bool check_preconditions(const std::string &target_lib_pattern);
    bool ensure_new_library_loaded(pid_t tid,
                                   const std::string &new_lib_path,
                                   uintptr_t &new_lib_base,
                                   uintptr_t &new_handle,
                                   struct user_regs_struct &saved_regs);

    //-------------------------------------------------------------------------
    // Cache methods (DL_Manager_cache.ipp)
    //-------------------------------------------------------------------------
    void ensure_cache(uintptr_t lib_base) const;
    std::vector<SymbolInfo> parse_symbols_from_dynamic(uintptr_t lib_base,
                                                       const DynamicInfo &info) const;
    std::map<std::string, uintptr_t> parse_got_entries(uintptr_t lib_base,
                                                       const DynamicInfo &info) const;
};

//=============================================================================
// Include implementations
//=============================================================================

#include "arch.hpp"                              // Architecture-specific definitions
#include "DL_Manager_helpers.ipp"                // Basic read/write functions
#include "DL_Manager_parse_elf.ipp"              // ELF parsing utilities
#include "DL_Manager_cache.ipp"                  // Cache management implementation
#include "DL_Manager_GOT.ipp"                    // GOT entry lookup implementation
#include "DL_Manager_get_lib_data.ipp"           // Library information implementation
#include "DL_Manager_check.ipp"                  // Safety check implementation
#include "DL_Manager_extract_funcs_from_lib.ipp" // Symbol extraction implementation
#include "DL_Manager_replace.ipp"                // Main patching implementation
#include "DL_Manager_rollback.ipp"               // Rollback implementation

#endif // DL_MANAGER_HPP
