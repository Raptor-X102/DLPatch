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

// Constants
static const size_t REMOTE_MEM_SIZE = 4096;
static const size_t SHELLCODE_PATH_OFFSET = 256;
static const size_t SHELLCODE_RESULT_OFFSET = 512;
static const time_t MTIME_TOLERANCE = 1;

//=============================================================================
// Data structures
//=============================================================================

// Information about a loaded library
// DL_Manager.hpp - update LibraryInfo structure with constructor

// Information about a loaded library
struct LibraryInfo {
    std::string path;    // Full path to the library file
    uintptr_t base_addr; // Base address where library is loaded
    size_t size;         // Total size of the library in memory
    bool is_original;    // Whether this is the original library (never unloaded)
    bool is_active;      // Whether this library is currently the target of any patch
    std::vector<std::pair<uintptr_t, uintptr_t>>
        segments; // Memory segments [start, end)

    // Default constructor
    LibraryInfo() 
        : base_addr(0)
        , size(0)
        , is_original(false)
        , is_active(false) {}
        
    // Constructor with basic parameters
    LibraryInfo(const std::string& p, uintptr_t addr, size_t sz)
        : path(p)
        , base_addr(addr)
        , size(sz)
        , is_original(false)
        , is_active(false) {}
};

struct StackInfo {
    uintptr_t start;
    uintptr_t end;
    size_t size;
};

// Tracked library state with rollback data
struct TrackedLibrary {
    std::string path;                           // Library path (used as key)
    uintptr_t handle;                           // Handle returned by dlopen
    uintptr_t base_addr;                        // Base address in memory
    std::vector<std::string> patched_functions; // Functions patched from other libraries
    std::vector<std::string> provided_functions; // All functions this library exports
    std::vector<std::string>
        patched_libraries; // Libraries that were patched to point to this one
    bool is_active;        // Whether this library is currently the target of any patch
    bool is_original;      // Whether this is the original library (never unloaded)
    std::map<std::string, std::vector<uint8_t>>
        saved_original_bytes; // Original bytes for JMP patch rollback
    std::map<std::string, uintptr_t>
        saved_original_got; // Original GOT values for GOT patch rollback

    // Fields for library identification
    time_t mtime;     // File modification time
    size_t file_size; // File size

        // Constructors
    TrackedLibrary()
        : handle(0)
        , base_addr(0)
        , is_active(false)
        , is_original(false)
        , mtime(0)           // Явно инициализируем нулем
        , file_size(0) {}    // Явно инициализируем нулем

    TrackedLibrary(const std::string &p,
                   uintptr_t h,
                   uintptr_t addr,
                   const std::string &func)
        : path(p)
        , handle(h)
        , base_addr(addr)
        , is_active(false)
        , is_original(false)
        , mtime(0)           // Явно инициализируем нулем
        , file_size(0) {     // Явно инициализируем нулем
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
        , is_original(false)
        , mtime(0)           // Явно инициализируем нулем
        , file_size(0) {}    // Явно инициализируем нулем
};

// Symbol information
struct SymbolInfo {
    std::string name;
    uintptr_t addr;
    size_t size;
    int type;      // STT_FUNC, STT_OBJECT, etc.
    int bind;      // STB_GLOBAL, STB_LOCAL, STB_WEAK
    int visibility; // STV_DEFAULT, STV_HIDDEN, STV_PROTECTED
    
    SymbolInfo(const std::string& n, uintptr_t a, size_t s, 
               int t = STT_FUNC, int b = STB_GLOBAL, int v = STV_DEFAULT)
        : name(n), addr(a), size(s), type(t), bind(b), visibility(v) {}
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

enum class LoadResult {
    NOT_FOUND,         // Library not found in tracker or maps
    CHANGED,           // File changed, needs reload
    LOADED_NEW,        // New copy of library was loaded
    USED_EXISTING,     // Existing copy used (file unchanged, but library may be inactive)
    ALREADY_ACTIVE,    // Library already active and unchanged - nothing to do
    FAILED             // Failed to load library
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
        tracker_initialized_ = true;  // Помечаем как инициализированный, чтобы не перезаписывать
        LOG_DBG("Tracker set with %zu libraries, marked as initialized", libs.size());
    }

    const std::map<std::string, TrackedLibrary> &get_tracked_libraries() const {
        return tracked_libraries_;
    }

    //-------------------------------------------------------------------------
    // Library information methods (DL_Manager_get_lib_data.ipp)
    //-------------------------------------------------------------------------
    std::vector<LibraryInfo>
    get_loaded_libraries(); // Get list of loaded libraries
    LibraryInfo get_library_info(
        const std::string &lib_name); // Get info about specific library
    void print_loaded_libraries();    // Print all loaded libraries
    std::vector<LibraryInfo> parse_maps() const;

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
    bool is_exported_function(const SymbolInfo& sym) const;

    const SymbolInfo* find_symbol_direct(uintptr_t lib_base, const std::string& sym_name) const;
    //-------------------------------------------------------------------------
    // GOT entry lookup (DL_Manager_GOT.ipp)
    //-------------------------------------------------------------------------
    uintptr_t
    find_got_entry(uintptr_t lib_base,
                   const std::string &sym_name) const; // Find GOT entry for symbol

    //-------------------------------------------------------------------------
    // Main patching interface (DL_Manager_replace.ipp)
    //-------------------------------------------------------------------------
    bool validate_target_library(const std::string& target_lib_pattern, 
                                  LibraryInfo& target_info,
                                  std::string& clean_path,
                                  std::string& normalized_path);
    
    bool check_target_safety(const std::string& normalized_target,
                              time_t target_mtime,
                              size_t target_size,
                              bool target_info_ok);
    
    void ensure_target_in_tracker(const std::string& normalized_target,
                                   const std::string& clean_path,
                                   uintptr_t target_base,
                                   time_t target_mtime,
                                   size_t target_size,
                                   bool target_info_ok);
    
    bool freeze_threads_outside_library(const std::vector<pid_t>& all_tids,
                                         const std::vector<std::pair<uintptr_t, uintptr_t>>& segments,
                                         std::vector<ThreadContext>& contexts);
    
    void select_worker_thread(const std::vector<ThreadContext>& contexts, pid_t& worker_tid);
    
    void update_active_status(const std::string& normalized_new);
    
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
    bool tracker_initialized_;

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
    // New initialization method
    //-------------------------------------------------------------------------
    void init_tracker_if_needed();  // Will be called from methods that need it 

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

    bool is_library_in_maps(const std::string &lib_path, uintptr_t &base_addr) const;
    bool is_library_active(const std::string &lib_path) const;
    uintptr_t get_loaded_library_base(const std::string &lib_path) const;

    void record_patched_library(const std::string& normalized_new, const std::string& target_path);
    void update_active_status(const std::string& original_path, const std::string& new_path);
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
                     const std::string &func_name);

    bool apply_all_patches(pid_t tid,
                           const std::string &target_lib_path,
                           uintptr_t old_base,
                           uintptr_t new_base,
                           const std::string &new_lib_path,
                           const std::string &target_function);

    bool check_preconditions(const std::string &target_lib_pattern);
    LoadResult check_library_state(const std::string& lib_path,
                                    uintptr_t& base, 
                                    uintptr_t& handle,
                                    bool check_active_only = false);
    
    // Load library (needs thread)
    LoadResult ensure_new_library_loaded(pid_t tid,
                                         const std::string& new_lib_path,
                                         uintptr_t& new_lib_base,
                                         uintptr_t& new_handle,
                                         struct user_regs_struct& saved_regs);

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

//=============================================================================
// Include implementations in strict dependency order
// No forward declarations needed – each module provides what later ones require
//=============================================================================

#include "arch.hpp"                              // Architecture-specific definitions (syscall numbers, register access, shellcode generation)

// ----- Core utilities -----------------------------------------------------
#include "DL_Manager_helpers.ipp"                // Basic helpers: string trimming, path normalization, file info, memory reading

// ----- ELF parsing --------------------------------------------------------
#include "DL_Manager_parse_elf.ipp"              // ELF header, dynamic section parsing, symbol iteration

// ----- Caching layer ------------------------------------------------------
#include "DL_Manager_cache.ipp"                   // Symbol and GOT entry caching for performance (uses parse_elf)

// ----- GOT manipulation ---------------------------------------------------
#include "DL_Manager_GOT.ipp"                     // GOT entry lookup using cache

// ----- Remote memory operations -------------------------------------------
#include "DL_Manager_memory.ipp"                   // Remote memory allocation (mmap), writing, shellcode management (uses helpers)

// ----- Thread control -----------------------------------------------------
#include "DL_Manager_threads.ipp"                  // Thread enumeration, stopping, resuming, safety checks (uses helpers, memory for register dumps)

// ----- Library loading / unloading ----------------------------------------
#include "DL_Manager_load.ipp"                      // Loading new libraries via dlopen, unloading via dlclose, remote syscall testing (uses memory, threads)

// ----- Library state tracking ---------------------------------------------
#include "DL_Manager_tracker.ipp"                    // Management of tracked libraries status (active/original, patched libraries list) (uses helpers)

// ----- Library information from /proc/pid/maps ---------------------------
#include "DL_Manager_get_lib_data.ipp"               // Parsing /proc/pid/maps, initializing tracker, getting library info (uses helpers, tracker)

// ----- Safety checks ------------------------------------------------------
#include "DL_Manager_check.ipp"                       // Checking if it's safe to replace a library (threads not inside) (uses get_lib_data, threads)

// ----- Symbol extraction --------------------------------------------------
#include "DL_Manager_extract_funcs_from_lib.ipp"      // Getting function symbols, addresses, sizes, filtering exported functions (uses parse_elf, cache)

// ----- Patching implementation --------------------------------------------
#include "DL_Manager_patch.ipp"                        // Applying JMP and GOT patches to redirect functions (uses GOT, extract_funcs, memory)

// ----- Library state evaluation -------------------------------------------
#include "DL_Manager_state.ipp"                        // Checking if library needs reloading, loading new version if necessary (uses load, helpers, tracker)

// ----- Main replacement logic ---------------------------------------------
#include "DL_Manager_replace.ipp"                      // Core replace_library function and its helpers (uses everything above)

// ----- Rollback functionality ---------------------------------------------
#include "DL_Manager_rollback.ipp"                     // Rolling back patches for a library or a single function (uses threads, GOT, extract_funcs, memory)
                                                       
#endif // DL_MANAGER_HPP
