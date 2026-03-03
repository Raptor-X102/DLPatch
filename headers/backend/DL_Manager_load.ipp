//=============================================================================
// DL_Manager_load.ipp
// Remote library loading and unloading via shellcode injection
//=============================================================================

/**
 * @brief Load a new library in the target process using remote code injection
 * @param tid Thread ID to execute the loading code
 * @param lib_path Path to the library file to load
 * @param out_handle [out] Handle returned by dlopen
 * @param saved_regs Saved registers of the worker thread (will be restored)
 * @return Base address of loaded library, or 0 on failure
 * 
 * This function:
 * 1. Allocates remote memory for shellcode, path, and result
 * 2. Writes library path and shellcode to remote memory
 * 3. Executes shellcode that calls dlopen
 * 4. Reads the resulting handle from remote memory
 * 5. Finds the library base address in /proc/pid/maps
 * 6. Cleans up remote memory
 */
uintptr_t DL_Manager::load_new_library(pid_t tid, const std::string& lib_path,
                                        uintptr_t& out_handle,
                                        struct user_regs_struct& saved_regs) {
    if (dlopen_addr_ == 0 || syscall_insn_ == 0) {
        LOG_ERR("Required addresses not initialized");
        return 0;
    }

    LOG_INFO("Loading new library: %s", lib_path.c_str());
    LOG_DBG("dlopen_addr=0x%lx, syscall_insn=0x%lx", dlopen_addr_, syscall_insn_);

#ifdef DEBUG
    // Debug-only thorough validation
    if (kill(tid, 0) == -1) {
        LOG_ERR("Thread %d is no longer alive: %s", tid, strerror(errno));
        return 0;
    }
    
    struct user_regs_struct check_regs;
    if (ptrace(PTRACE_GETREGS, tid, nullptr, &check_regs) == -1) {
        LOG_ERR("Thread %d not accessible via ptrace: %s", tid, strerror(errno));
        return 0;
    }
    LOG_DBG("Thread %d is accessible, IP=0x%llx", tid, (unsigned long long)Arch::get_ip(check_regs));
    
    uintptr_t test_result;
    if (!Arch::remote_syscall(tid, test_result, Arch::SYS_GETPID, 0, 0, 0, 0, 0, 0, syscall_insn_)) {
        LOG_ERR("remote_syscall test failed before allocation");
        
        LOG_ERR("Dumping thread %d state:", tid);
        if (ptrace(PTRACE_GETREGS, tid, nullptr, &check_regs) == 0) {
            LOG_ERR("  IP=0x%llx, SP=0x%llx", 
                    (unsigned long long)Arch::get_ip(check_regs),
                    (unsigned long long)Arch::get_sp(check_regs));
        }
        
        LOG_DBG("Attempting to re-attach to thread %d", tid);
        ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        usleep(10000);
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == 0) {
            waitpid(tid, nullptr, 0);
            LOG_DBG("Re-attach successful");
            
            if (ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs) == 0) {
                LOG_DBG("Registers restored");
            }
        }
        
        return 0;
    }
    LOG_DBG("remote_syscall test passed, result=%lu", test_result);
#endif

    // Allocate remote memory for shellcode
    uintptr_t remote_mem = allocate_remote_memory(tid, REMOTE_MEM_SIZE);
    if (remote_mem == 0) {
        LOG_ERR("Failed to allocate remote memory");
        return 0;
    }
    LOG_DBG("Remote memory allocated at 0x%lx", remote_mem);

    // Calculate addresses for path and result
    uintptr_t path_addr = remote_mem + SHELLCODE_PATH_OFFSET;
    uintptr_t result_addr = remote_mem + SHELLCODE_RESULT_OFFSET;
    
    LOG_DBG("path_addr = 0x%lx, result_addr = 0x%lx", path_addr, result_addr);

    // Write library path to remote memory
    if (!write_remote_memory(tid, path_addr, lib_path.c_str(), lib_path.size() + 1)) {
        LOG_ERR("Failed to write library path");
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }
    LOG_DBG("Library path written to remote memory");

#ifdef DEBUG
    // Verify path was written correctly
    char path_check[256] = {0};
    if (read_remote_memory(tid, path_addr, path_check, lib_path.size() + 1)) {
        LOG_DBG("Path verification: %s", path_check);
    }
#endif

    // Write shellcode
    if (!write_shellcode(tid, remote_mem, path_addr, result_addr)) {
        LOG_ERR("Failed to write shellcode");
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }
    LOG_DBG("Shellcode written to remote memory");

    // Execute shellcode and get dlopen handle
    if (!execute_shellcode_and_get_handle(tid, remote_mem, saved_regs, out_handle)) {
        LOG_ERR("Failed to execute shellcode and get handle");
        remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);
        return 0;
    }

    // Clean up remote memory
    LOG_DBG("Cleaning up remote memory");
    remote_munmap(pid_, remote_mem, REMOTE_MEM_SIZE, syscall_insn_);

    // Find base address of newly loaded library in /proc/pid/maps
    uintptr_t new_lib_base = get_loaded_library_base(lib_path);
    if (new_lib_base == 0) {
        LOG_ERR("Failed to find new library base in maps");
        return 0;
    }

    LOG_DBG("New library loaded: base=0x%lx, handle=0x%lx", new_lib_base, out_handle);
    return new_lib_base;
}

/**
 * @brief Unload a library by its handle using remote code injection
 * @param tid Thread ID to execute the unloading code
 * @param handle Handle returned by dlopen
 * @param saved_regs Saved registers of the worker thread (will be restored)
 * @return true if unload succeeded, false otherwise
 * 
 * Similar to load_new_library but calls dlclose instead of dlopen.
 */
bool DL_Manager::unload_library_by_handle(pid_t tid, uintptr_t handle,
                                           struct user_regs_struct& saved_regs) {
    if (dlclose_addr_ == 0 || syscall_insn_ == 0) {
        LOG_ERR("Required addresses not initialized");
        return false;
    }
    
    if (handle == 0) {
        LOG_ERR("Invalid handle (0)");
        return false;
    }
    
    // Allocate remote memory for unload shellcode
    size_t mem_size = 4096;
    uintptr_t remote_mem = remote_mmap(tid, mem_size,
                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
                                       syscall_insn_);
    if (remote_mem == 0) {
        LOG_ERR("Failed to allocate remote memory for unload");
        return false;
    }
    
    uintptr_t result_addr = remote_mem + 256;
    
    LOG_DBG("Unloading library with handle = 0x%lx", handle);
    LOG_DBG("Shellcode at: 0x%lx", remote_mem);
    LOG_DBG("Result addr: 0x%lx", result_addr);
    LOG_DBG("dlclose addr: 0x%lx", dlclose_addr_);
    
    auto shellcode = Arch::generate_dlclose_shellcode(handle, dlclose_addr_, result_addr);
    
    // Clear result area before execution
    uint64_t zero = 0;
    if (!write_remote_memory(tid, result_addr, &zero, sizeof(zero))) {
        LOG_ERR("Failed to clear result area");
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return false;
    }
    
    if (!write_remote_memory(tid, remote_mem, shellcode.data(), shellcode.size())) {
        LOG_ERR("Failed to write unload shellcode");
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return false;
    }
    
    struct user_regs_struct new_regs = saved_regs;
    Arch::set_ip(new_regs, remote_mem);
    
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &new_regs) == -1) {
        LOG_ERR("ptrace SETREGS failed: %s", strerror(errno));
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return false;
    }
    
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
        LOG_ERR("ptrace CONT failed: %s", strerror(errno));
        remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
        return false;
    }
    
    int status;
    waitpid(tid, &status, 0);
    
    bool success = false;
    uint64_t dlclose_result = 0;
    
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        LOG_DBG("Thread stopped with signal %d", sig);
        
        if (sig == SIGTRAP) {
            if (read_remote_memory(tid, result_addr, &dlclose_result, sizeof(dlclose_result))) {
                LOG_DBG("dlclose returned %lu", dlclose_result);
                success = (dlclose_result == 0);
            } else {
                LOG_ERR("Failed to read dlclose result");
            }
        } else {
            LOG_ERR("Unexpected signal %d during unload", sig);
            Arch::dump_registers(tid, this);
        }
    } else {
        LOG_ERR("Unexpected wait status: %d", status);
    }
    
    ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs);
    remote_munmap(pid_, remote_mem, mem_size, syscall_insn_);
    
    if (success) {
        LOG_DBG("Successfully unloaded library with handle 0x%lx", handle);
    }
    
    return success;
}

/**
 * @brief Unload a library by its path (public API)
 * @param lib_path Path to the library to unload
 * @return true if unload succeeded, false otherwise
 * 
 * Only non-original, inactive libraries can be unloaded.
 * A library is considered inactive if:
 * 1. It is not marked as original
 * 2. It does not provide any functions in function_providers_ map
 * 3. It is not referenced by any other library (patched_by empty)
 */
bool DL_Manager::unload_library(const std::string& lib_path) {
    std::string normalized = normalize_path(lib_path);
    
    auto it = tracked_libraries_.find(normalized);
    if (it == tracked_libraries_.end()) {
        LOG_ERR("Library %s not found in tracker", lib_path.c_str());
        return false;
    }
    
    TrackedLibrary& lib = it->second;
    
    // Check if library is original
    if (lib.is_original) {
        LOG_ERR("Cannot unload original library: %s", lib_path.c_str());
        return false;
    }
    
    // Check if library provides any functions
    bool provides_functions = false;
    for (const auto& [func_name, provider] : function_providers_) {
        if (provider == normalized) {
            provides_functions = true;
            LOG_DBG("Library %s provides function %s", lib_path.c_str(), func_name.c_str());
            break;
        }
    }
    
    if (provides_functions) {
        LOG_ERR("Cannot unload library that provides active functions: %s", lib_path.c_str());
        return false;
    }
    
    // Check if library is referenced by others
    if (!lib.patched_by.empty()) {
        LOG_ERR("Cannot unload library that is still referenced by %zu other libraries: %s", 
                lib.patched_by.size(), lib_path.c_str());
        
#ifdef DEBUG
        for (const auto& ref : lib.patched_by) {
            LOG_DBG("  - referenced by: %s", ref.c_str());
        }
#endif
        return false;
    }
    
    LOG_INFO("Unloading library: %s", lib_path.c_str());
    
    std::vector<pid_t> tids = get_all_threads(pid_);
    std::vector<ThreadContext> contexts;
    
    if (!stop_all_threads(tids, contexts)) {
        LOG_ERR("Failed to stop threads");
        return false;
    }
    
    pid_t worker_tid = pid_;
    bool found = false;
    for (const auto& ctx : contexts) {
        if (ctx.tid == worker_tid) {
            found = true;
            break;
        }
    }
    if (!found && !contexts.empty()) {
        worker_tid = contexts[0].tid;
        LOG_DBG("Main thread not found, using thread %d for unload", worker_tid);
    }
    
    struct user_regs_struct prepared_regs;
    if (!prepare_thread_for_injection(worker_tid, prepared_regs)) {
        restore_and_detach_all(contexts);
        return false;
    }
    
#ifdef DEBUG
    if (!test_syscall(worker_tid)) {
        LOG_ERR("Syscall test failed before unload");
        restore_and_detach_all(contexts);
        return false;
    }
#endif
    
    LOG_DBG("Calling unload_library_by_handle with handle=0x%lx", lib.handle);
    bool result = unload_library_by_handle(worker_tid, lib.handle, prepared_regs);
    
    if (result) {
        invalidate_cache(lib.base_addr);
        tracked_libraries_.erase(it);
        LOG_INFO("Library %s successfully unloaded", lib_path.c_str());
    } else {
        LOG_ERR("Failed to unload library %s", lib_path.c_str());
    }
    
    restore_and_detach_all(contexts);
    
    return result;
}

/**
 * @brief Check if a library is present in /proc/pid/maps
 * @param lib_path Path to check
 * @param base_addr [out] Base address if found
 * @return true if library found in maps
 */
bool DL_Manager::is_library_in_maps(const std::string& lib_path, uintptr_t& base_addr) const {
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) return false;
    
    std::string line;
    while (std::getline(maps_file, line)) {
        if (line.find(lib_path) != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                base_addr = std::stoul(line.substr(0, dash), nullptr, 16);
                return true;
            }
        }
    }
    return false;
}

/**
 * @brief Check if library is already loaded (in tracker or in maps)
 * @param lib_path Path to check
 * @param base_addr [out] Base address if found
 * @param handle [out] Handle if found in tracker, 0 if only in maps
 * @return true if library found
 */
bool DL_Manager::is_library_already_loaded(const std::string& lib_path, uintptr_t& base_addr, uintptr_t& handle) {
    std::string normalized = normalize_path(lib_path);
    
    auto it = tracked_libraries_.find(normalized);
    if (it != tracked_libraries_.end()) {
        base_addr = it->second.base_addr;
        handle = it->second.handle;
        return true;
    }
    
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) return false;
    
    std::string line;
    while (std::getline(maps_file, line)) {
        if (line.find(lib_path) != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                base_addr = std::stoul(line.substr(0, dash), nullptr, 16);
                handle = 0;
                return true;
            }
        }
    }
    return false;
}

/**
 * @brief Get base address of loaded library from /proc/pid/maps
 * @param lib_path Path to find
 * @return Base address or 0 if not found
 */
uintptr_t DL_Manager::get_loaded_library_base(const std::string& lib_path) const {
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps_file(maps_path);
    if (!maps_file.is_open()) return 0;
    
    std::string line;
    while (std::getline(maps_file, line)) {
        if (line.find(lib_path) != std::string::npos) {
            size_t dash = line.find('-');
            if (dash != std::string::npos) {
                return std::stoul(line.substr(0, dash), nullptr, 16);
            }
        }
    }
    return 0;
}

/**
 * @brief Execute shellcode and retrieve dlopen result
 * @param tid Thread to execute shellcode
 * @param shellcode_addr Address of shellcode in remote process
 * @param saved_regs Saved registers (will be restored)
 * @param out_handle [out] Handle returned by dlopen
 * @return true if successful
 */
bool DL_Manager::execute_shellcode_and_get_handle(pid_t tid, uintptr_t shellcode_addr,
                                                   struct user_regs_struct& saved_regs,
                                                   uintptr_t& out_handle) {
    struct user_regs_struct new_regs = saved_regs;
    Arch::set_ip(new_regs, shellcode_addr);
    
    LOG_DBG("Setting IP to 0x%lx, original SP=0x%lx", shellcode_addr, Arch::get_sp(saved_regs));
    
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &new_regs) == -1) {
        LOG_ERR("ptrace SETREGS failed: %s", strerror(errno));
        return false;
    }
    
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) == -1) {
        LOG_ERR("ptrace CONT failed: %s", strerror(errno));
        return false;
    }
    
    int status;
    waitpid(tid, &status, 0);
    
    uintptr_t handle = 0;
    uintptr_t result_addr = shellcode_addr + SHELLCODE_RESULT_OFFSET;
    
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        LOG_DBG("Thread stopped with signal %d", sig);
        
        if (sig == SIGTRAP) {
            LOG_DBG("Got SIGTRAP, reading dlopen result");
            if (read_remote_memory(tid, result_addr, &handle, sizeof(handle))) {
                LOG_DBG("dlopen returned handle 0x%lx", handle);
                if (handle != 0) {
                    out_handle = handle;
                    
                    if (ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs) == -1) {
                        LOG_ERR("Failed to restore registers after shellcode: %s", strerror(errno));
                    }
                    
                    return true;
                } else {
                    LOG_ERR("dlopen returned NULL handle");
                }
            } else {
                LOG_ERR("Failed to read handle from result_addr");
            }
        } else if (sig == SIGSEGV) {
            LOG_ERR("Segmentation fault in shellcode");
            
            siginfo_t siginfo;
            if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &siginfo) == 0) {
                LOG_ERR("Fault address: 0x%lx, code: %d", 
                        (uintptr_t)siginfo.si_addr, siginfo.si_code);
            }
            
            Arch::dump_registers(tid, this);
        } else {
            LOG_ERR("Unexpected signal %d after shellcode", sig);
        }
    } else if (WIFEXITED(status)) {
        LOG_ERR("Thread exited with status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        LOG_ERR("Thread terminated with signal %d", WTERMSIG(status));
    } else {
        LOG_ERR("Unexpected wait status %d", status);
    }
    
    LOG_INFO("Restoring original registers after error");
    if (ptrace(PTRACE_SETREGS, tid, nullptr, &saved_regs) == -1) {
        LOG_ERR("Failed to restore registers after shellcode: %s", strerror(errno));
    }
    
    return false;
}
