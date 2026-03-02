// DL_Manager.hpp
#ifndef DL_MANAGER_HPP
#define DL_MANAGER_HPP

#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dirent.h>
#include <elf.h>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include "daemon.hpp"
#include "logging.hpp"
#include "DL_Manager_types.hpp"

// Constants
static const size_t REMOTE_MEM_SIZE = 4096;
static const size_t SHELLCODE_PATH_OFFSET = 256;
static const size_t SHELLCODE_RESULT_OFFSET = 512;
static const time_t MTIME_TOLERANCE = 1;

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

    //-------------------------------------------------------------------------
    // Tracked libraries setters/getters (DL_Manager.hpp - inline)
    //-------------------------------------------------------------------------
    void set_tracked_libraries(const std::map<std::string, TrackedLibrary> &libs) {
        tracked_libraries_ = libs;
        tracker_initialized_ = true;
        LOG_DBG("Tracker set with %zu libraries, marked as initialized", libs.size());
    }

    const std::map<std::string, TrackedLibrary> &get_tracked_libraries() const {
        return tracked_libraries_;
    }

    //=============================================================================
    // PUBLIC INTERFACE
    //=============================================================================

    //-------------------------------------------------------------------------
    // Library information methods (DL_Manager_get_lib_data.ipp)
    //-------------------------------------------------------------------------
    std::vector<LibraryInfo> get_loaded_libraries(); // Get list of loaded libraries
    LibraryInfo
    get_library_info(const std::string &lib_name); // Get info about specific library
    void print_loaded_libraries();                 // Print all loaded libraries

    //-------------------------------------------------------------------------
    // Safety checks (DL_Manager_check.ipp)
    //-------------------------------------------------------------------------
    bool is_safe_to_replace(
        const std::string &lib_name); // Check if library can be safely replaced

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
    bool unload_library(const std::string &lib_path); // Unload unused library

    //-------------------------------------------------------------------------
    // Library tracker status (DL_Manager_replace.ipp)
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
    // Architecture layer helpers (DL_Manager_memory.ipp)
    //-------------------------------------------------------------------------
    bool read_remote_memory_raw(uintptr_t addr,
                                void *buffer,
                                size_t size) const; // Read memory from target process

private:
    // Core members
    pid_t pid_;              // Target process PID
    uintptr_t dlopen_addr_;  // Address of dlopen in target
    uintptr_t dlclose_addr_; // Address of dlclose in target
    uintptr_t syscall_insn_; // Address of syscall instruction
    bool tracker_initialized_;

    std::map<std::string, TrackedLibrary>
        tracked_libraries_; // Tracked libraries by path

    mutable std::map<uintptr_t, CachedLibraryData>
        library_cache_; // Cache by base address

    //=============================================================================
    // PRIVATE METHODS - organized by implementation file
    //=============================================================================

    //-------------------------------------------------------------------------
    // Initialization methods (DL_Manager_get_lib_data.ipp)
    //-------------------------------------------------------------------------
    void init_tracker_if_needed(); // Initialize tracker with loaded libraries
    std::vector<LibraryInfo> parse_maps() const;

    //-------------------------------------------------------------------------
    // Initialization methods (DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    void init_addresses(); // Initialize dlopen/dlclose/syscall addresses

    //-------------------------------------------------------------------------
    // Symbol lookup helpers (DL_Manager_extract_funcs_from_lib.ipp)
    //-------------------------------------------------------------------------
    const SymbolInfo *find_symbol_direct(uintptr_t lib_base,
                                         const std::string &sym_name) const;
    bool is_exported_function(const SymbolInfo &sym) const;

    //-------------------------------------------------------------------------
    // Cache methods (DL_Manager_cache.ipp)
    //-------------------------------------------------------------------------
    void ensure_cache(uintptr_t lib_base) const;
    std::vector<SymbolInfo> parse_symbols_from_dynamic(uintptr_t lib_base,
                                                       const DynamicInfo &info) const;
    std::map<std::string, uintptr_t> parse_got_entries(uintptr_t lib_base,
                                                       const DynamicInfo &info) const;

    //-------------------------------------------------------------------------
    // Remote memory operations (DL_Manager_memory.ipp)
    //-------------------------------------------------------------------------
    uintptr_t allocate_remote_memory(pid_t tid, size_t size);
    bool write_shellcode(pid_t tid,
                         uintptr_t shellcode_addr,
                         uintptr_t path_addr,
                         uintptr_t result_addr);

    //-------------------------------------------------------------------------
    // Thread control (DL_Manager_threads.ipp)
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
    bool freeze_threads_outside_library(
        const std::vector<pid_t> &all_tids,
        const std::vector<std::pair<uintptr_t, uintptr_t>> &segments,
        std::vector<ThreadContext> &contexts);
    void select_worker_thread(const std::vector<ThreadContext> &contexts,
                              pid_t &worker_tid);

    //-------------------------------------------------------------------------
    // Library loading helpers (DL_Manager_load.ipp)
    //-------------------------------------------------------------------------
    bool test_syscall(pid_t tid);
    bool execute_shellcode_and_get_handle(pid_t tid,
                                          uintptr_t shellcode_addr,
                                          struct user_regs_struct &saved_regs,
                                          uintptr_t &out_handle);
    uintptr_t load_new_library(pid_t tid,
                               const std::string &lib_path,
                               uintptr_t &out_handle,
                               struct user_regs_struct &saved_regs);
    bool unload_library_by_handle(pid_t tid,
                                  uintptr_t handle,
                                  struct user_regs_struct &saved_regs);
    bool is_library_already_loaded(const std::string &lib_path,
                                   uintptr_t &base_addr,
                                   uintptr_t &handle);
    bool is_library_in_maps(const std::string &lib_path, uintptr_t &base_addr) const;
    uintptr_t get_loaded_library_base(const std::string &lib_path) const;

    //-------------------------------------------------------------------------
    // Tracker management (DL_Manager_tracker.ipp)
    //-------------------------------------------------------------------------
    bool is_library_active(const std::string &lib_path) const;
    void record_patched_library(const std::string &normalized_new,
                                const std::string &target_path);
    void update_active_status(const std::string &original_path,
                              const std::string &new_path);
    void update_tracked_file_info(TrackedLibrary &lib,
                                  time_t mtime,
                                  size_t size,
                                  bool info_ok);
    void ensure_target_in_tracker(const std::string &normalized_target,
                                  const std::string &clean_path,
                                  uintptr_t target_base,
                                  time_t target_mtime,
                                  size_t target_size,
                                  bool target_info_ok);

    //-------------------------------------------------------------------------
    // Patching methods (DL_Manager_patch.ipp)
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
                     const std::string &func_name);
    bool apply_all_patches(pid_t tid,
                           const std::string &target_lib_path,
                           uintptr_t old_base,
                           uintptr_t new_base,
                           const std::string &new_lib_path,
                           const std::string &target_function);

    //-------------------------------------------------------------------------
    // State checking methods (DL_Manager_state.ipp)
    //-------------------------------------------------------------------------
    bool check_preconditions(const std::string &target_lib_pattern);
    LoadResult check_library_state(const std::string &lib_path,
                                   uintptr_t &base,
                                   uintptr_t &handle,
                                   bool check_active_only = false);
    LoadResult ensure_new_library_loaded(pid_t tid,
                                         const std::string &new_lib_path,
                                         uintptr_t &new_lib_base,
                                         uintptr_t &new_handle,
                                         struct user_regs_struct &saved_regs);

    //-------------------------------------------------------------------------
    // Validation helpers (used in replace_library) - DL_Manager_replace.ipp
    //-------------------------------------------------------------------------
    bool validate_target_library(const std::string &target_lib_pattern,
                                 LibraryInfo &target_info,
                                 std::string &clean_path,
                                 std::string &normalized_path);
    bool check_target_safety(const std::string &normalized_target,
                             time_t target_mtime,
                             size_t target_size,
                             bool target_info_ok);

    //-------------------------------------------------------------------------
    // Syscall helpers (DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    uintptr_t find_syscall_instruction(uintptr_t libc_base);
};

//=============================================================================
// Include implementations in strict dependency order
//=============================================================================

// Architecture-specific definitions (syscall numbers, register access, shellcode generation)
#include "arch.hpp" 

// ----- Core utilities -----------------------------------------------------
// Basic helpers: string trimming, path normalization, file info, memory reading
#include "DL_Manager_helpers.ipp"

// ----- ELF parsing --------------------------------------------------------
// ELF header, dynamic section parsing, symbol iteration
#include "DL_Manager_parse_elf.ipp" 

// ----- Caching layer ------------------------------------------------------
// Symbol and GOT entry caching for performance (uses parse_elf)
#include "DL_Manager_cache.ipp"

// ----- GOT manipulation ---------------------------------------------------
// GOT entry lookup using cache
#include "DL_Manager_GOT.ipp"

// ----- Remote memory operations -------------------------------------------
// Remote memory allocation (mmap), writing, shellcode management (uses helpers)
#include "DL_Manager_memory.ipp"

// ----- Thread control -----------------------------------------------------
// Thread enumeration, stopping, resuming, safety checks (uses helpers, memory for register dumps)
#include "DL_Manager_threads.ipp"

// ----- Library loading / unloading ----------------------------------------
// Loading new libraries via dlopen, unloading via dlclose, remote syscall testing (uses memory, threads)
#include "DL_Manager_load.ipp"

// ----- Library state tracking ---------------------------------------------
// Management of tracked libraries status (active/original, patched libraries list) (uses helpers)
#include "DL_Manager_tracker.ipp" 

// ----- Library information from /proc/pid/maps ---------------------------
// Parsing /proc/pid/maps, initializing tracker, getting library info (uses helpers, tracker)
#include "DL_Manager_get_lib_data.ipp" 

// ----- Safety checks ------------------------------------------------------
// Checking if it's safe to replace a library (threads not inside) (uses get_lib_data, threads)
#include "DL_Manager_check.ipp" 

// ----- Symbol extraction --------------------------------------------------
// Getting function symbols, addresses, sizes, filtering exported functions (uses parse_elf, cache)
#include "DL_Manager_extract_funcs_from_lib.ipp" 

// ----- Patching implementation --------------------------------------------
// Applying JMP and GOT patches to redirect functions (uses GOT, extract_funcs, memory)
#include "DL_Manager_patch.ipp" 

// ----- Library state evaluation -------------------------------------------
// Checking if library needs reloading, loading new version if necessary (uses load, helpers, tracker)
#include "DL_Manager_state.ipp" 

// ----- Main replacement logic ---------------------------------------------
// Core replace_library function and its helpers (uses everything above)
#include "DL_Manager_replace.ipp" 

// ----- Rollback functionality ---------------------------------------------
// Rolling back patches for a library or a single function (uses threads, GOT, extract_funcs, memory)
#include "DL_Manager_rollback.ipp" 

#endif // DL_MANAGER_HPP
